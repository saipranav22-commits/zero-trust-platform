package com.zerotrust.service;

import com.zerotrust.dto.request.AccountCreateRequest;
import com.zerotrust.dto.response.AccountResponse;
import com.zerotrust.entity.Account;
import com.zerotrust.entity.Customer;
import com.zerotrust.entity.enums.AccountStatus;
import com.zerotrust.entity.enums.AuditStatus;
import com.zerotrust.exception.ResourceNotFoundException;
import com.zerotrust.exception.ValidationException;
import com.zerotrust.repository.AccountRepository;
import com.zerotrust.security.abac.AbacPolicyEnforcer;
import com.zerotrust.security.abac.SecurityAction;
import com.zerotrust.security.abac.SecurityContext;
import com.zerotrust.security.abac.SecurityResource;
import com.zerotrust.security.abac.SecuritySubject;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Service managing customer financial accounts with ABAC object-level ownership checks.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AccountService {

    private final AccountRepository accountRepository;
    private final CustomerService customerService;
    private final AbacPolicyEnforcer abacPolicyEnforcer;
    private final AuditService auditService;

    @Transactional(readOnly = true)
    public AccountResponse getAccountById(UUID id, SecuritySubject subject) {
        Account account = findEntityById(id);
        Customer customer = account.getCustomer();

        // Enforce object-level authorization on customer ownership
        SecurityResource resource = SecurityResource.of("ACCOUNT", id.toString(), customer.getAssignedEmployeeId());
        abacPolicyEnforcer.enforce(subject, resource, SecurityAction.READ, SecurityContext.standard());

        return AccountResponse.from(account);
    }

    @Transactional(readOnly = true)
    public List<AccountResponse> getAccountsByCustomerId(UUID customerId, SecuritySubject subject) {
        Customer customer = customerService.findEntityById(customerId);

        // Enforce authorization on parent customer
        SecurityResource resource = SecurityResource.of("CUSTOMER", customerId.toString(), customer.getAssignedEmployeeId());
        abacPolicyEnforcer.enforce(subject, resource, SecurityAction.READ, SecurityContext.standard());

        return accountRepository.findByCustomerId(customerId).stream()
            .map(AccountResponse::from)
            .collect(Collectors.toList());
    }

    @Transactional
    public AccountResponse createAccount(AccountCreateRequest request, SecuritySubject subject) {
        Customer customer = customerService.findEntityById(request.customerId());

        // Enforce UPDATE permission on customer
        SecurityResource resource = SecurityResource.of("CUSTOMER", customer.getId().toString(), customer.getAssignedEmployeeId());
        abacPolicyEnforcer.enforce(subject, resource, SecurityAction.UPDATE, SecurityContext.standard());

        if (accountRepository.existsByAccountNumber(request.accountNumber())) {
            throw new ValidationException("Account number already exists: " + request.accountNumber());
        }

        Account account = Account.builder()
            .customer(customer)
            .accountNumber(request.accountNumber())
            .accountType(request.accountType())
            .balance(request.initialBalance())
            .currency(request.currency() != null ? request.currency() : "USD")
            .status(AccountStatus.ACTIVE)
            .build();

        Account saved = accountRepository.save(account);

        auditService.log(
            subject.userId() != null ? subject.userId().toString() : "UNKNOWN",
            subject.email(),
            "CREATE_ACCOUNT",
            "ACCOUNT",
            saved.getId().toString(),
            "127.0.0.1",
            "Syvora-Core",
            AuditStatus.SUCCESS,
            0,
            "Opened account " + saved.getAccountNumber() + " for customer " + customer.getCustomerNumber()
        );

        return AccountResponse.from(saved);
    }

    @Transactional
    public AccountResponse updateAccountStatus(UUID id, AccountStatus status, SecuritySubject subject) {
        Account account = findEntityById(id);
        Customer customer = account.getCustomer();

        // Enforce UPDATE permission on account
        SecurityResource resource = SecurityResource.of("ACCOUNT", id.toString(), customer.getAssignedEmployeeId());
        abacPolicyEnforcer.enforce(subject, resource, SecurityAction.UPDATE, SecurityContext.standard());

        account.setStatus(status);
        Account updated = accountRepository.save(account);

        auditService.log(
            subject.userId() != null ? subject.userId().toString() : "UNKNOWN",
            subject.email(),
            "UPDATE_ACCOUNT_STATUS",
            "ACCOUNT",
            id.toString(),
            "127.0.0.1",
            "Syvora-Core",
            AuditStatus.SUCCESS,
            5,
            "Updated account " + account.getAccountNumber() + " status to " + status
        );

        return AccountResponse.from(updated);
    }

    public Account findEntityById(UUID id) {
        return accountRepository.findById(id)
            .orElseThrow(() -> new ResourceNotFoundException("Account not found: " + id));
    }
}
