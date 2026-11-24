package com.zerotrust.service;

import com.zerotrust.dto.request.TransactionCreateRequest;
import com.zerotrust.dto.response.TransactionResponse;
import com.zerotrust.entity.Account;
import com.zerotrust.entity.Customer;
import com.zerotrust.entity.Transaction;
import com.zerotrust.entity.enums.*;
import com.zerotrust.exception.ResourceNotFoundException;
import com.zerotrust.exception.ValidationException;
import com.zerotrust.repository.AccountRepository;
import com.zerotrust.repository.TransactionRepository;
import com.zerotrust.security.abac.AbacPolicyEnforcer;
import com.zerotrust.security.abac.SecurityAction;
import com.zerotrust.security.abac.SecurityContext;
import com.zerotrust.security.abac.SecurityResource;
import com.zerotrust.security.abac.SecuritySubject;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.util.UUID;

/**
 * Enterprise Financial Transaction Service with Row-Level Locking, Dual-Entry Ledger,
 * Deadlock-Free Ordering, and Persistent Idempotency.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class TransactionService {

    private final TransactionRepository transactionRepository;
    private final AccountRepository accountRepository;
    private final AbacPolicyEnforcer abacPolicyEnforcer;
    private final AuditService auditService;
    private final NotificationService notificationService;
    private final IdempotencyService idempotencyService;
    private final jakarta.persistence.EntityManager entityManager;

    private static final BigDecimal MAX_TRANSACTION_LIMIT = new BigDecimal("10000000.00");
    private static final BigDecimal HIGH_VALUE_ALERT_THRESHOLD = new BigDecimal("10000.00");

    @Transactional(readOnly = true)
    public TransactionResponse getTransactionById(UUID id, SecuritySubject subject) {
        Transaction txn = transactionRepository.findById(id)
            .orElseThrow(() -> new ResourceNotFoundException("Transaction not found: " + id));

        Customer customer = txn.getAccount().getCustomer();
        SecurityResource resource = SecurityResource.of("TRANSACTION", id.toString(), customer.getAssignedEmployeeId());
        abacPolicyEnforcer.enforce(subject, resource, SecurityAction.READ, SecurityContext.standard());

        return TransactionResponse.from(txn);
    }

    @Transactional(readOnly = true)
    public Page<TransactionResponse> getTransactionsByAccountId(UUID accountId, SecuritySubject subject, Pageable pageable) {
        Account account = accountRepository.findById(accountId)
            .orElseThrow(() -> new ResourceNotFoundException("Account not found: " + accountId));

        Customer customer = account.getCustomer();
        SecurityResource resource = SecurityResource.of("ACCOUNT", accountId.toString(), customer.getAssignedEmployeeId());
        abacPolicyEnforcer.enforce(subject, resource, SecurityAction.READ, SecurityContext.standard());

        return transactionRepository.findByAccountId(accountId, pageable).map(TransactionResponse::from);
    }

    /**
     * Executes a financial transaction directly without external idempotency key.
     */
    @Transactional(rollbackFor = Exception.class)
    public TransactionResponse executeTransaction(TransactionCreateRequest request, SecuritySubject subject) {
        return executeTransaction(request, subject, null);
    }

    /**
     * Executes a financial transaction wrapped in persistent idempotency guarantees when a key is provided.
     */
    @Transactional(rollbackFor = Exception.class)
    public TransactionResponse executeTransaction(TransactionCreateRequest request, SecuritySubject subject, SecurityContext context, String idempotencyKey) {
        if (idempotencyKey != null && !idempotencyKey.isBlank()) {
            String userId = subject != null && subject.userId() != null ? subject.userId().toString() : "ANONYMOUS";
            return idempotencyService.executeWithIdempotency(
                idempotencyKey,
                userId,
                request,
                TransactionResponse.class,
                () -> processTransactionInternal(request, subject, context)
            );
        }

        return processTransactionInternal(request, subject, context);
    }

    @Transactional(rollbackFor = Exception.class)
    public TransactionResponse executeTransaction(TransactionCreateRequest request, SecuritySubject subject, String idempotencyKey) {
        return executeTransaction(request, subject, SecurityContext.standard(), idempotencyKey);
    }

    /**
     * Core atomic business execution: validates amounts, enforces locks, and updates balances.
     */
    private TransactionResponse processTransactionInternal(TransactionCreateRequest request, SecuritySubject subject, SecurityContext context) {
        validateMonetaryAmount(request.amount());

        if (request.type() == TransactionType.TRANSFER) {
            return processTransfer(request, subject, context);
        } else if (request.type() == TransactionType.DEPOSIT || request.type() == TransactionType.WITHDRAWAL) {
            return processSingleAccountTransaction(request, subject, context);
        } else {
            throw new ValidationException("Unsupported transaction type: " + request.type());
        }
    }

    /**
     * Executes deposit or withdrawal with row-level pessimistic locking.
     */
    private TransactionResponse processSingleAccountTransaction(TransactionCreateRequest request, SecuritySubject subject, SecurityContext context) {
        Account account = accountRepository.findByIdWithLock(request.accountId())
            .orElseThrow(() -> new ResourceNotFoundException("Account not found: " + request.accountId()));

        Customer customer = account.getCustomer();
        SecurityResource resource = SecurityResource.of("ACCOUNT", account.getId().toString(), customer.getAssignedEmployeeId(), customer.getRiskTier().name());
        abacPolicyEnforcer.enforce(subject, resource, SecurityAction.EXECUTE_TRANSACTION, context != null ? context : SecurityContext.standard());

        if (account.getStatus() != AccountStatus.ACTIVE) {
            throw new ValidationException("Cannot process transaction on " + account.getStatus() + " account");
        }

        BigDecimal amount = request.amount();
        BigDecimal newBalance;

        if (request.type() == TransactionType.DEPOSIT) {
            newBalance = account.getBalance().add(amount);
        } else { // WITHDRAWAL
            if (account.getBalance().compareTo(amount) < 0) {
                throw new ValidationException(String.format(
                    "Insufficient funds. Available: %s %s, Requested: %s %s",
                    account.getBalance(), account.getCurrency(), amount, account.getCurrency()
                ));
            }
            newBalance = account.getBalance().subtract(amount);
        }

        account.setBalance(newBalance);
        accountRepository.save(account);

        String refNumber = "TXN-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();
        Transaction txn = Transaction.builder()
            .account(account)
            .referenceNumber(refNumber)
            .amount(amount)
            .type(request.type())
            .status(TransactionStatus.COMPLETED)
            .description(request.description())
            .sourceAccount(account.getAccountNumber())
            .destinationAccount(request.destinationAccount())
            .build();

        Transaction saved = transactionRepository.save(txn);
        logTransactionAudit(subject, request.type().name(), saved, account, amount, refNumber);
        triggerHighValueAlertIfNeeded(amount, account, subject, saved.getId());

        return TransactionResponse.from(saved);
    }

    /**
     * Executes an atomic dual-entry fund transfer with ordered locking to prevent deadlocks.
     */
    private TransactionResponse processTransfer(TransactionCreateRequest request, SecuritySubject subject, SecurityContext context) {
        if (request.destinationAccount() == null || request.destinationAccount().isBlank()) {
            throw new ValidationException("Destination account number is required for transfers");
        }

        // 1. Initial lookup to identify both entities and check basic constraints
        Account initialSource = accountRepository.findById(request.accountId())
            .orElseThrow(() -> new ResourceNotFoundException("Source account not found: " + request.accountId()));

        Account initialDest = accountRepository.findByAccountNumber(request.destinationAccount().trim())
            .orElseThrow(() -> new ResourceNotFoundException("Destination account not found: " + request.destinationAccount()));

        // Self-transfer validation
        if (initialSource.getId().equals(initialDest.getId()) ||
            initialSource.getAccountNumber().equalsIgnoreCase(initialDest.getAccountNumber())) {
            throw new ValidationException("Self-transfers to the same account are not permitted");
        }

        // Account status validations
        if (initialSource.getStatus() != AccountStatus.ACTIVE) {
            throw new ValidationException("Source account is " + initialSource.getStatus());
        }
        if (initialDest.getStatus() != AccountStatus.ACTIVE) {
            throw new ValidationException("Destination account is " + initialDest.getStatus());
        }

        // Currency compatibility validation
        if (!initialSource.getCurrency().equalsIgnoreCase(initialDest.getCurrency())) {
            throw new ValidationException(String.format(
                "Currency mismatch: Source account is %s but destination account is %s",
                initialSource.getCurrency(), initialDest.getCurrency()
            ));
        }

        // Authorization check on source account ownership and risk classification
        Customer sourceCustomer = initialSource.getCustomer();
        SecurityResource sourceResource = SecurityResource.of("ACCOUNT", initialSource.getId().toString(), sourceCustomer.getAssignedEmployeeId(), sourceCustomer.getRiskTier().name());
        abacPolicyEnforcer.enforce(subject, sourceResource, SecurityAction.EXECUTE_TRANSACTION, context != null ? context : SecurityContext.standard());

        // 2. Consistent Deadlock-Free Ordered Locking
        UUID firstId = initialSource.getId().compareTo(initialDest.getId()) < 0 ? initialSource.getId() : initialDest.getId();
        UUID secondId = initialSource.getId().compareTo(initialDest.getId()) < 0 ? initialDest.getId() : initialSource.getId();

        Account firstLocked = accountRepository.findByIdWithLock(firstId)
            .orElseThrow(() -> new ResourceNotFoundException("Account lock failed for: " + firstId));
        Account secondLocked = accountRepository.findByIdWithLock(secondId)
            .orElseThrow(() -> new ResourceNotFoundException("Account lock failed for: " + secondId));

        entityManager.refresh(firstLocked);
        entityManager.refresh(secondLocked);

        Account lockedSource = initialSource.getId().equals(firstId) ? firstLocked : secondLocked;
        Account lockedDest = initialDest.getId().equals(firstId) ? firstLocked : secondLocked;

        BigDecimal amount = request.amount();

        // Check source balance
        if (lockedSource.getBalance().compareTo(amount) < 0) {
            throw new ValidationException(String.format(
                "Insufficient funds for transfer. Available: %s %s, Requested: %s %s",
                lockedSource.getBalance(), lockedSource.getCurrency(), amount, lockedSource.getCurrency()
            ));
        }

        // 3. Atomically update both account balances
        lockedSource.setBalance(lockedSource.getBalance().subtract(amount));
        lockedDest.setBalance(lockedDest.getBalance().add(amount));

        accountRepository.save(lockedSource);
        accountRepository.save(lockedDest);

        // 4. Create linked dual-entry ledger records
        UUID correlationId = UUID.randomUUID();
        String sourceRef = "TXN-OUT-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();
        String destRef = "TXN-IN-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();

        Transaction debitTxn = Transaction.builder()
            .account(lockedSource)
            .referenceNumber(sourceRef)
            .amount(amount)
            .type(TransactionType.TRANSFER)
            .status(TransactionStatus.COMPLETED)
            .description("Transfer to " + lockedDest.getAccountNumber() + ": " + request.description())
            .sourceAccount(lockedSource.getAccountNumber())
            .destinationAccount(lockedDest.getAccountNumber())
            .correlationId(correlationId)
            .build();

        Transaction creditTxn = Transaction.builder()
            .account(lockedDest)
            .referenceNumber(destRef)
            .amount(amount)
            .type(TransactionType.TRANSFER)
            .status(TransactionStatus.COMPLETED)
            .description("Transfer received from " + lockedSource.getAccountNumber() + ": " + request.description())
            .sourceAccount(lockedSource.getAccountNumber())
            .destinationAccount(lockedDest.getAccountNumber())
            .correlationId(correlationId)
            .build();

        Transaction savedDebit = transactionRepository.save(debitTxn);
        transactionRepository.save(creditTxn);

        logTransactionAudit(subject, "TRANSFER_DEBIT", savedDebit, lockedSource, amount, sourceRef);
        triggerHighValueAlertIfNeeded(amount, lockedSource, subject, savedDebit.getId());

        log.info("Successfully executed atomic transfer: {} {} from {} to {}. CorrelationId={}",
            amount, lockedSource.getCurrency(), lockedSource.getAccountNumber(), lockedDest.getAccountNumber(), correlationId);

        return TransactionResponse.from(savedDebit);
    }

    private void validateMonetaryAmount(BigDecimal amount) {
        if (amount == null || amount.compareTo(BigDecimal.ZERO) <= 0) {
            throw new ValidationException("Transaction amount must be strictly positive");
        }
        if (amount.stripTrailingZeros().scale() > 2) {
            throw new ValidationException("Transaction amount cannot have more than 2 decimal places");
        }
        if (amount.compareTo(MAX_TRANSACTION_LIMIT) > 0) {
            throw new ValidationException("Transaction amount exceeds maximum limit of 10,000,000.00");
        }
    }

    private void logTransactionAudit(SecuritySubject subject, String action, Transaction txn,
                                     Account account, BigDecimal amount, String refNumber) {
        auditService.log(
            subject != null && subject.userId() != null ? subject.userId().toString() : "UNKNOWN",
            subject != null ? subject.email() : "SYSTEM",
            "EXECUTE_" + action,
            "TRANSACTION",
            txn.getId().toString(),
            "127.0.0.1",
            "Syvora-Core",
            AuditStatus.SUCCESS,
            amount.compareTo(HIGH_VALUE_ALERT_THRESHOLD) >= 0 ? 30 : 0,
            String.format("Executed %s of %s %s on account %s. Ref: %s",
                action, amount, account.getCurrency(), account.getAccountNumber(), refNumber)
        );
    }

    private void triggerHighValueAlertIfNeeded(BigDecimal amount, Account account, SecuritySubject subject, UUID txnId) {
        if (amount.compareTo(HIGH_VALUE_ALERT_THRESHOLD) >= 0) {
            try {
                notificationService.createNotification(
                    "High-Value Transaction Detected",
                    String.format("Transaction of %s %s executed on account %s by %s",
                        amount, account.getCurrency(), account.getAccountNumber(),
                        subject != null ? subject.email() : "Unknown"),
                    Severity.HIGH,
                    "SECURITY",
                    null, null, null,
                    "/transactions?id=" + txnId,
                    "Syvora Threat Monitor",
                    "SECURITY"
                );
            } catch (Exception ex) {
                log.warn("Could not broadcast high-value transaction alert: {}", ex.getMessage());
            }
        }
    }
}
