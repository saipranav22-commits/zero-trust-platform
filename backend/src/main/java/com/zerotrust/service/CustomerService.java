package com.zerotrust.service;

import com.zerotrust.dto.request.CustomerCreateRequest;
import com.zerotrust.dto.request.CustomerUpdateRequest;
import com.zerotrust.dto.response.AccountResponse;
import com.zerotrust.dto.response.CustomerDetailResponse;
import com.zerotrust.dto.response.CustomerResponse;
import com.zerotrust.entity.Customer;
import com.zerotrust.entity.enums.AuditStatus;
import com.zerotrust.entity.enums.KycStatus;
import com.zerotrust.entity.enums.RiskTier;
import com.zerotrust.exception.ResourceNotFoundException;
import com.zerotrust.exception.ValidationException;
import com.zerotrust.repository.AccountRepository;
import com.zerotrust.repository.CustomerRepository;
import com.zerotrust.security.abac.AbacPolicyEnforcer;
import com.zerotrust.security.abac.SecurityAction;
import com.zerotrust.security.abac.SecurityContext;
import com.zerotrust.security.abac.SecurityResource;
import com.zerotrust.security.abac.SecuritySubject;
import jakarta.persistence.criteria.Predicate;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Enterprise Customer Profile Management with ABAC Object-Level Authorization.
 * Guarantees Zero Trust isolation and protects against BOLA / IDOR.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CustomerService {

    private final CustomerRepository customerRepository;
    private final AccountRepository accountRepository;
    private final AbacPolicyEnforcer abacPolicyEnforcer;
    private final AuditService auditService;

    @Value("${app.demo.mutations-disabled:false}")
    private boolean demoMutationsDisabled;

    @Transactional(readOnly = true)
    public Page<CustomerResponse> getCustomers(
            String search, KycStatus kycStatus, RiskTier riskTier,
            SecuritySubject subject, Pageable pageable) {

        Specification<Customer> spec = (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            // Object-level isolation: Employees ONLY query customers assigned to them!
            if (subject.hasRole("ROLE_EMPLOYEE") && !subject.hasRole("ROLE_ADMIN")) {
                if (subject.userId() == null) {
                    predicates.add(cb.disjunction()); // Anonymous / unidentifiable employee sees nothing
                } else {
                    predicates.add(cb.equal(root.get("assignedEmployeeId"), subject.userId()));
                }
            }

            if (StringUtils.hasText(search)) {
                String pattern = "%" + search.trim().toLowerCase() + "%";
                predicates.add(cb.or(
                    cb.like(cb.lower(root.get("firstName")), pattern),
                    cb.like(cb.lower(root.get("lastName")), pattern),
                    cb.like(cb.lower(root.get("customerNumber")), pattern),
                    cb.like(cb.lower(root.get("email")), pattern)
                ));
            }

            if (kycStatus != null) {
                predicates.add(cb.equal(root.get("kycStatus"), kycStatus));
            }

            if (riskTier != null) {
                predicates.add(cb.equal(root.get("riskTier"), riskTier));
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };

        return customerRepository.findAll(spec, pageable).map(CustomerResponse::from);
    }

    @Transactional
    public CustomerResponse getCustomerById(UUID id, SecuritySubject subject) {
        Customer customer = findEntityById(id);

        // Object-level authorization check
        SecurityResource resource = SecurityResource.of("CUSTOMER", id.toString(), customer.getAssignedEmployeeId(), customer.getRiskTier().name());
        abacPolicyEnforcer.enforce(subject, resource, SecurityAction.READ, SecurityContext.standard());

        // Audit read access on customer data
        auditService.log(
            subject.userId() != null ? subject.userId().toString() : "UNKNOWN",
            subject.email(),
            "READ_CUSTOMER",
            "CUSTOMER",
            id.toString(),
            "127.0.0.1",
            "Syvora-Core",
            AuditStatus.SUCCESS,
            0,
            "Customer record retrieved: " + customer.getCustomerNumber()
        );

        return CustomerResponse.from(customer);
    }

    @Transactional(readOnly = true)
    public CustomerDetailResponse getCustomerDetails(UUID id, SecuritySubject subject) {
        Customer customer = findEntityById(id);

        // Object-level authorization check
        SecurityResource resource = SecurityResource.of("CUSTOMER", id.toString(), customer.getAssignedEmployeeId(), customer.getRiskTier().name());
        abacPolicyEnforcer.enforce(subject, resource, SecurityAction.READ, SecurityContext.standard());

        List<AccountResponse> accounts = accountRepository.findByCustomerId(id).stream()
            .map(AccountResponse::from)
            .collect(Collectors.toList());

        return new CustomerDetailResponse(CustomerResponse.from(customer), accounts);
    }

    @Transactional
    public String getSensitiveCustomerData(UUID id, SecuritySubject subject, SecurityContext context) {
        Customer customer = findEntityById(id);

        // Object-level authorization check: VIEW_SENSITIVE policy evaluation
        SecurityResource resource = SecurityResource.of("CUSTOMER", id.toString(), customer.getAssignedEmployeeId(), customer.getRiskTier().name());
        abacPolicyEnforcer.enforce(subject, resource, SecurityAction.VIEW_SENSITIVE, context);

        auditService.log(
            subject.userId() != null ? subject.userId().toString() : "UNKNOWN",
            subject.email(),
            "VIEW_SENSITIVE_DATA",
            "CUSTOMER",
            id.toString(),
            context != null ? context.sourceIp() : "127.0.0.1",
            "Syvora-Core",
            AuditStatus.SUCCESS,
            0,
            "Decrypted sensitive synthetic tax ID retrieved for customer " + customer.getCustomerNumber()
        );

        return customer.getSyntheticTaxId();
    }

    @Transactional
    public CustomerResponse createCustomer(CustomerCreateRequest request, SecuritySubject subject) {
        // Enforce CREATE permission
        SecurityResource genericResource = SecurityResource.of("CUSTOMER", "NEW", null);
        abacPolicyEnforcer.enforce(subject, genericResource, SecurityAction.CREATE, SecurityContext.standard());

        if (customerRepository.existsByCustomerNumber(request.customerNumber())) {
            throw new ValidationException("Customer number already exists: " + request.customerNumber());
        }
        if (customerRepository.existsByEmail(request.email())) {
            throw new ValidationException("Customer email already registered: " + request.email());
        }

        UUID assignedId = request.assignedEmployeeId();
        // If employee creates customer without specifying assigned ID, default to themselves
        if (assignedId == null && subject.hasRole("ROLE_EMPLOYEE")) {
            assignedId = subject.userId();
        }

        Customer customer = Customer.builder()
            .customerNumber(request.customerNumber())
            .firstName(request.firstName())
            .lastName(request.lastName())
            .email(request.email())
            .phoneNumber(request.phoneNumber())
            .kycStatus(request.kycStatus() != null ? request.kycStatus() : KycStatus.PENDING)
            .riskTier(request.riskTier() != null ? request.riskTier() : RiskTier.LOW)
            .assignedEmployeeId(assignedId)
            .syntheticTaxId(request.syntheticTaxId())
            .annualIncome(request.annualIncome())
            .creditScore(request.creditScore())
            .build();

        Customer saved = customerRepository.save(customer);

        auditService.log(
            subject.userId() != null ? subject.userId().toString() : "UNKNOWN",
            subject.email(),
            "CREATE_CUSTOMER",
            "CUSTOMER",
            saved.getId().toString(),
            "127.0.0.1",
            "Syvora-Core",
            AuditStatus.SUCCESS,
            0,
            "Created customer: " + saved.getCustomerNumber()
        );

        return CustomerResponse.from(saved);
    }

    @Transactional
    public CustomerResponse updateCustomer(UUID id, CustomerUpdateRequest request, SecuritySubject subject, SecurityContext context) {
        Customer customer = findEntityById(id);

        // Object-level authorization check
        SecurityResource resource = SecurityResource.of("CUSTOMER", id.toString(), customer.getAssignedEmployeeId(), customer.getRiskTier().name());
        abacPolicyEnforcer.enforce(subject, resource, SecurityAction.UPDATE, context != null ? context : SecurityContext.standard());

        if (request.firstName() != null) customer.setFirstName(request.firstName());
        if (request.lastName() != null) customer.setLastName(request.lastName());
        if (request.email() != null) {
            if (!request.email().equalsIgnoreCase(customer.getEmail()) && customerRepository.existsByEmail(request.email())) {
                throw new ValidationException("Customer email already registered: " + request.email());
            }
            customer.setEmail(request.email());
        }
        if (request.phoneNumber() != null) customer.setPhoneNumber(request.phoneNumber());
        if (request.kycStatus() != null) customer.setKycStatus(request.kycStatus());
        if (request.riskTier() != null) customer.setRiskTier(request.riskTier());
        if (request.annualIncome() != null) customer.setAnnualIncome(request.annualIncome());
        if (request.creditScore() != null) customer.setCreditScore(request.creditScore());

        // Reassignment of employee requires ADMIN role
        if (request.assignedEmployeeId() != null && !request.assignedEmployeeId().equals(customer.getAssignedEmployeeId())) {
            if (!subject.hasRole("ROLE_ADMIN")) {
                throw new org.springframework.security.access.AccessDeniedException("Only administrators can reassign customer ownership");
            }
            customer.setAssignedEmployeeId(request.assignedEmployeeId());
        }

        Customer updated = customerRepository.save(customer);

        auditService.log(
            subject.userId() != null ? subject.userId().toString() : "UNKNOWN",
            subject.email(),
            "UPDATE_CUSTOMER",
            "CUSTOMER",
            id.toString(),
            "127.0.0.1",
            "Syvora-Core",
            AuditStatus.SUCCESS,
            0,
            "Updated customer: " + updated.getCustomerNumber()
        );

        return CustomerResponse.from(updated);
    }

    @Transactional
    public CustomerResponse updateCustomer(UUID id, CustomerUpdateRequest request, SecuritySubject subject) {
        return updateCustomer(id, request, subject, SecurityContext.standard());
    }

    @Transactional
    public void deleteCustomer(UUID id, SecuritySubject subject, SecurityContext context) {
        if (demoMutationsDisabled) {
            throw new org.springframework.security.access.AccessDeniedException(
                "Administrative mutations (customer deletion) are disabled in the public demonstration environment to protect baseline state."
            );
        }
        Customer customer = findEntityById(id);

        // Object-level authorization check: only Admin can delete
        SecurityResource resource = SecurityResource.of("CUSTOMER", id.toString(), customer.getAssignedEmployeeId(), customer.getRiskTier().name());
        abacPolicyEnforcer.enforce(subject, resource, SecurityAction.DELETE, context != null ? context : SecurityContext.standard());

        customerRepository.delete(customer);

        auditService.log(
            subject.userId() != null ? subject.userId().toString() : "UNKNOWN",
            subject.email(),
            "DELETE_CUSTOMER",
            "CUSTOMER",
            id.toString(),
            "127.0.0.1",
            "Syvora-Core",
            AuditStatus.SUCCESS,
            10,
            "Deleted customer: " + customer.getCustomerNumber()
        );
    }

    @Transactional
    public void deleteCustomer(UUID id, SecuritySubject subject) {
        deleteCustomer(id, subject, SecurityContext.standard());
    }

    public Customer findEntityById(UUID id) {
        return customerRepository.findById(id)
            .orElseThrow(() -> new ResourceNotFoundException("Customer not found: " + id));
    }
}
