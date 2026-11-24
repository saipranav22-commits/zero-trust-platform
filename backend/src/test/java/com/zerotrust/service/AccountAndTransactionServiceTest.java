package com.zerotrust.service;

import com.zerotrust.dto.request.TransactionCreateRequest;
import com.zerotrust.dto.response.TransactionResponse;
import com.zerotrust.entity.Account;
import com.zerotrust.entity.Customer;
import com.zerotrust.entity.Transaction;
import com.zerotrust.entity.enums.*;
import com.zerotrust.exception.ValidationException;
import com.zerotrust.repository.AccountRepository;
import com.zerotrust.repository.TransactionRepository;
import com.zerotrust.security.abac.AbacPolicyEnforcer;
import com.zerotrust.security.abac.SecuritySubject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;

import java.math.BigDecimal;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AccountAndTransactionServiceTest {

    @Mock
    private TransactionRepository transactionRepository;

    @Mock
    private AccountRepository accountRepository;

    @Mock
    private AbacPolicyEnforcer abacPolicyEnforcer;

    @Mock
    private AuditService auditService;

    @Mock
    private NotificationService notificationService;

    @Mock
    private jakarta.persistence.EntityManager entityManager;

    @Mock
    private IdempotencyService idempotencyService;

    @InjectMocks
    private TransactionService transactionService;

    private final UUID employeeId = UUID.randomUUID();
    private final UUID accountId = UUID.randomUUID();
    private Customer customer;
    private Account account;
    private SecuritySubject employeeSubject;

    @BeforeEach
    void setUp() {
        employeeSubject = new SecuritySubject(employeeId, "employee@zerotrust.com", Set.of("ROLE_EMPLOYEE"), Map.of());

        customer = Customer.builder()
            .id(UUID.randomUUID())
            .customerNumber("CUST-1001")
            .assignedEmployeeId(employeeId)
            .build();

        account = Account.builder()
            .id(accountId)
            .customer(customer)
            .accountNumber("ACC-1001")
            .balance(new BigDecimal("1000.00"))
            .status(AccountStatus.ACTIVE)
            .currency("USD")
            .build();
    }

    @Test
    @DisplayName("Deposit transaction updates balance and saves transaction")
    void shouldProcessDepositSuccessfully() {
        when(accountRepository.findByIdWithLock(accountId)).thenReturn(Optional.of(account));
        when(transactionRepository.save(any(Transaction.class))).thenAnswer(inv -> {
            Transaction t = inv.getArgument(0);
            t.setId(UUID.randomUUID());
            return t;
        });

        TransactionCreateRequest request = new TransactionCreateRequest(
            accountId,
            new BigDecimal("250.00"),
            TransactionType.DEPOSIT,
            "Payroll deposit",
            null
        );

        TransactionResponse response = transactionService.executeTransaction(request, employeeSubject);

        assertThat(response).isNotNull();
        assertThat(account.getBalance()).isEqualByComparingTo("1250.00");
        verify(accountRepository).save(account);
        verify(transactionRepository).save(any(Transaction.class));
    }

    @Test
    @DisplayName("Withdrawal with insufficient funds throws ValidationException")
    void shouldRejectWithdrawalWhenInsufficientFunds() {
        when(accountRepository.findByIdWithLock(accountId)).thenReturn(Optional.of(account));

        TransactionCreateRequest request = new TransactionCreateRequest(
            accountId,
            new BigDecimal("5000.00"), // balance is only 1000.00
            TransactionType.WITHDRAWAL,
            "ATM withdrawal",
            null
        );

        assertThatThrownBy(() -> transactionService.executeTransaction(request, employeeSubject))
            .isInstanceOf(ValidationException.class)
            .hasMessageContaining("Insufficient funds");

        verify(transactionRepository, never()).save(any());
    }

    @Test
    @DisplayName("BOLA check fails when unauthorized user attempts transaction")
    void shouldBlockTransactionWhenAbacEnforcementFails() {
        when(accountRepository.findByIdWithLock(accountId)).thenReturn(Optional.of(account));
        doThrow(new AccessDeniedException("Ownership violation"))
            .when(abacPolicyEnforcer).enforce(any(), any(), any(), any());

        SecuritySubject attackerSubject = new SecuritySubject(UUID.randomUUID(), "attacker@zerotrust.com", Set.of("ROLE_EMPLOYEE"), Map.of());
        TransactionCreateRequest request = new TransactionCreateRequest(
            accountId,
            new BigDecimal("100.00"),
            TransactionType.DEPOSIT,
            "Deposit attempt",
            null
        );

        assertThatThrownBy(() -> transactionService.executeTransaction(request, attackerSubject))
            .isInstanceOf(AccessDeniedException.class)
            .hasMessageContaining("Ownership violation");
    }

    @Test
    @DisplayName("Complete atomic transfer debits source, credits destination and links correlation ID")
    void shouldExecuteAtomicTransferSuccessfully() {
        UUID destAccountId = UUID.randomUUID();
        Account destAccount = Account.builder()
            .id(destAccountId)
            .customer(Customer.builder().id(UUID.randomUUID()).build())
            .accountNumber("ACC-2002")
            .balance(new BigDecimal("500.00"))
            .status(AccountStatus.ACTIVE)
            .currency("USD")
            .build();

        when(accountRepository.findById(accountId)).thenReturn(Optional.of(account));
        when(accountRepository.findByAccountNumber("ACC-2002")).thenReturn(Optional.of(destAccount));

        when(accountRepository.findByIdWithLock(accountId)).thenReturn(Optional.of(account));
        when(accountRepository.findByIdWithLock(destAccountId)).thenReturn(Optional.of(destAccount));
        when(transactionRepository.save(any(Transaction.class))).thenAnswer(inv -> {
            Transaction t = inv.getArgument(0);
            t.setId(UUID.randomUUID());
            return t;
        });

        TransactionCreateRequest request = new TransactionCreateRequest(
            accountId,
            new BigDecimal("300.00"),
            TransactionType.TRANSFER,
            "Rent payment",
            "ACC-2002"
        );

        TransactionResponse response = transactionService.executeTransaction(request, employeeSubject);

        assertThat(response).isNotNull();
        assertThat(account.getBalance()).isEqualByComparingTo("700.00"); // 1000 - 300
        assertThat(destAccount.getBalance()).isEqualByComparingTo("800.00"); // 500 + 300
        assertThat(response.correlationId()).isNotNull();

        verify(accountRepository).save(account);
        verify(accountRepository).save(destAccount);
        verify(transactionRepository, times(2)).save(any(Transaction.class));
    }

    @Test
    @DisplayName("Self-transfer must be rejected with ValidationException")
    void shouldRejectSelfTransfer() {
        when(accountRepository.findById(accountId)).thenReturn(Optional.of(account));
        when(accountRepository.findByAccountNumber(account.getAccountNumber())).thenReturn(Optional.of(account));

        TransactionCreateRequest request = new TransactionCreateRequest(
            accountId,
            new BigDecimal("100.00"),
            TransactionType.TRANSFER,
            "Self transfer attempt",
            account.getAccountNumber()
        );

        assertThatThrownBy(() -> transactionService.executeTransaction(request, employeeSubject))
            .isInstanceOf(ValidationException.class)
            .hasMessageContaining("Self-transfers to the same account are not permitted");
    }

    @Test
    @DisplayName("Monetary validation rejects negative or over-precision amounts")
    void shouldRejectInvalidMonetaryAmounts() {
        TransactionCreateRequest negativeRequest = new TransactionCreateRequest(
            accountId,
            new BigDecimal("-50.00"),
            TransactionType.DEPOSIT,
            "Negative deposit",
            null
        );

        assertThatThrownBy(() -> transactionService.executeTransaction(negativeRequest, employeeSubject))
            .isInstanceOf(ValidationException.class)
            .hasMessageContaining("strictly positive");

        TransactionCreateRequest overPrecisionRequest = new TransactionCreateRequest(
            accountId,
            new BigDecimal("50.123"),
            TransactionType.DEPOSIT,
            "Fractional cent deposit",
            null
        );

        assertThatThrownBy(() -> transactionService.executeTransaction(overPrecisionRequest, employeeSubject))
            .isInstanceOf(ValidationException.class)
            .hasMessageContaining("cannot have more than 2 decimal places");
    }

    @Test
    @DisplayName("EntityManager refresh failure during transfer throws PersistenceException and is not swallowed")
    void shouldPropagatePersistenceExceptionWhenEntityManagerRefreshFails() {
        UUID destAccountId = UUID.randomUUID();
        Account destAccount = Account.builder()
            .id(destAccountId)
            .customer(Customer.builder().id(UUID.randomUUID()).build())
            .accountNumber("ACC-2002")
            .balance(new BigDecimal("500.00"))
            .status(AccountStatus.ACTIVE)
            .currency("USD")
            .build();

        when(accountRepository.findById(accountId)).thenReturn(Optional.of(account));
        when(accountRepository.findByAccountNumber("ACC-2002")).thenReturn(Optional.of(destAccount));
        when(accountRepository.findByIdWithLock(accountId)).thenReturn(Optional.of(account));
        when(accountRepository.findByIdWithLock(destAccountId)).thenReturn(Optional.of(destAccount));

        doThrow(new jakarta.persistence.PersistenceException("Database connection timeout during refresh"))
            .when(entityManager).refresh(any(Account.class));

        TransactionCreateRequest request = new TransactionCreateRequest(
            accountId,
            new BigDecimal("300.00"),
            TransactionType.TRANSFER,
            "Rent payment",
            "ACC-2002"
        );

        assertThatThrownBy(() -> transactionService.executeTransaction(request, employeeSubject))
            .isInstanceOf(jakarta.persistence.PersistenceException.class)
            .hasMessageContaining("Database connection timeout during refresh");

        assertThat(account.getBalance()).isEqualByComparingTo("1000.00");
        verify(transactionRepository, never()).save(any(Transaction.class));
    }
}
