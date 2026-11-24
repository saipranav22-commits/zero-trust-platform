package com.zerotrust.integration;

import com.zerotrust.dto.response.CustomerResponse;
import com.zerotrust.entity.Customer;
import com.zerotrust.entity.enums.KycStatus;
import com.zerotrust.entity.enums.RiskTier;
import com.zerotrust.repository.CustomerRepository;
import com.zerotrust.security.abac.SecurityContext;
import com.zerotrust.security.abac.SecuritySubject;
import com.zerotrust.service.CustomerService;
import com.zerotrust.service.RedisSecurityService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.test.context.ActiveProfiles;

import java.math.BigDecimal;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@ActiveProfiles("test")
class CustomerEncryptionIntegrationTest {

    @MockBean
    private RedisSecurityService redisSecurityService;

    @Autowired
    private CustomerRepository customerRepository;

    @Autowired
    private CustomerService customerService;

    @Autowired
    private com.zerotrust.security.crypto.CustomerEncryptionBackfillService backfillService;

    @Autowired
    private com.zerotrust.service.TransactionService transactionService;

    @Autowired
    private com.zerotrust.repository.AccountRepository accountRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private UUID employeeId;
    private UUID unauthorizedEmployeeId;
    private UUID adminId;

    @BeforeEach
    void setUp() {
        when(redisSecurityService.isTokenRevoked(anyString())).thenReturn(false);
        when(redisSecurityService.isIpBlocked(anyString())).thenReturn(false);

        employeeId = UUID.randomUUID();
        unauthorizedEmployeeId = UUID.randomUUID();
        adminId = UUID.randomUUID();
    }

    @Test
    @DisplayName("Field-Level AES-256-GCM Encryption: Raw database column is encrypted, entity is decrypted, API masks by default")
    void testFieldLevelEncryptionAndAccessControl() {
        String rawSyntheticTaxId = "SYN-9876-5432";
        Customer customer = Customer.builder()
            .customerNumber("CUST-ENC-" + UUID.randomUUID().toString().substring(0, 8))
            .firstName("Synthetic")
            .lastName("Customer")
            .email("synthetic-" + UUID.randomUUID().toString().substring(0, 8) + "@example.test")
            .phoneNumber("+1-555-0199")
            .kycStatus(KycStatus.VERIFIED)
            .riskTier(RiskTier.LOW)
            .assignedEmployeeId(employeeId)
            .syntheticTaxId(rawSyntheticTaxId)
            .annualIncome(new BigDecimal("150000.00"))
            .creditScore(790)
            .build();

        Customer saved = customerRepository.save(customer);

        // 1. Inspect raw PostgreSQL / H2 database column directly using JDBC
        String rawDbValue = jdbcTemplate.queryForObject(
            "SELECT synthetic_tax_id FROM customers WHERE id = ?",
            String.class,
            saved.getId()
        );

        assertThat(rawDbValue).isNotNull();
        assertThat(rawDbValue).startsWith("v1:");
        assertThat(rawDbValue).isNotEqualTo(rawSyntheticTaxId);
        assertThat(rawDbValue).doesNotContain(rawSyntheticTaxId);

        // 2. Load entity via JPA: EncryptedStringConverter transparently decrypts
        Customer loaded = customerRepository.findById(saved.getId()).orElseThrow();
        assertThat(loaded.getSyntheticTaxId()).isEqualTo(rawSyntheticTaxId);

        // 3. Normal API read (CustomerResponse): Masks sensitive tax ID
        SecuritySubject assignedEmployeeSubject = new SecuritySubject(employeeId, "assigned@zerotrust.com", Set.of("ROLE_EMPLOYEE"), Map.of());
        CustomerResponse response = customerService.getCustomerById(saved.getId(), assignedEmployeeSubject);
        assertThat(response.maskedTaxId()).isEqualTo("SYN-***-5432");

        // 4. Unauthorized employee BOLA: Cannot view unmasked sensitive data (throws AccessDeniedException / 403)
        SecuritySubject unauthorizedSubject = new SecuritySubject(unauthorizedEmployeeId, "other@zerotrust.com", Set.of("ROLE_EMPLOYEE"), Map.of());
        assertThatThrownBy(() -> customerService.getSensitiveCustomerData(saved.getId(), unauthorizedSubject, SecurityContext.standard()))
            .isInstanceOf(AccessDeniedException.class);

        // 5. Authorized Admin: Can retrieve decrypted unmasked sensitive data under normal context
        SecuritySubject adminSubject = new SecuritySubject(adminId, "admin@zerotrust.com", Set.of("ROLE_ADMIN"), Map.of());
        String decryptedTaxId = customerService.getSensitiveCustomerData(saved.getId(), adminSubject, SecurityContext.standard());
        assertThat(decryptedTaxId).isEqualTo(rawSyntheticTaxId);

        // 6. Contextual Risk Denial: In elevated threat context, even Admin is denied VIEW_SENSITIVE
        SecurityContext elevatedContext = SecurityContext.of("198.51.100.99", "CRITICAL", 85);
        assertThatThrownBy(() -> customerService.getSensitiveCustomerData(saved.getId(), adminSubject, elevatedContext))
            .isInstanceOf(AccessDeniedException.class)
            .hasMessageContaining("ownership violation / insufficient privilege");
    }

    @Test
    @DisplayName("Backfill Migration: Legacy unencrypted database rows are safely migrated and encrypted in place")
    void testBackfillMigrationForLegacyPlaintextRecords() {
        UUID legacyId = UUID.randomUUID();
        String legacyTaxId = "SYN-LEGACY-7744";

        // Insert legacy plaintext record directly using raw SQL
        jdbcTemplate.update(
            "INSERT INTO customers (id, customer_number, first_name, last_name, email, synthetic_tax_id, kyc_status, risk_tier, created_at, updated_at) " +
            "VALUES (?, ?, 'Legacy', 'User', ?, ?, 'VERIFIED', 'LOW', NOW(), NOW())",
            legacyId, "CUST-LEGACY-" + UUID.randomUUID().toString().substring(0, 8),
            "legacy-" + UUID.randomUUID().toString().substring(0, 8) + "@example.test",
            legacyTaxId
        );

        // Verify initial raw DB value is unencrypted
        String initialDbValue = jdbcTemplate.queryForObject(
            "SELECT synthetic_tax_id FROM customers WHERE id = ?", String.class, legacyId
        );
        assertThat(initialDbValue).isEqualTo(legacyTaxId);

        // Execute backfill migration
        int migrated = backfillService.executeBackfill();
        assertThat(migrated).isGreaterThanOrEqualTo(1);

        // Verify raw DB value is now encrypted with v1: prefix
        String postMigrationDbValue = jdbcTemplate.queryForObject(
            "SELECT synthetic_tax_id FROM customers WHERE id = ?", String.class, legacyId
        );
        assertThat(postMigrationDbValue).startsWith("v1:");
        assertThat(postMigrationDbValue).doesNotContain(legacyTaxId);

        // Verify entity loading retrieves decrypted plaintext
        Customer loaded = customerRepository.findById(legacyId).orElseThrow();
        assertThat(loaded.getSyntheticTaxId()).isEqualTo(legacyTaxId);

        // Verify zero unencrypted records remain across the entire database
        Integer unencryptedCount = jdbcTemplate.queryForObject(
            "SELECT count(*) FROM customers WHERE synthetic_tax_id IS NOT NULL AND synthetic_tax_id NOT LIKE 'v1:%'",
            Integer.class
        );
        assertThat(unencryptedCount).isEqualTo(0);
    }

    @Test
    @DisplayName("Contextual ABAC: Financial transactions are denied before mutation during elevated risk conditions")
    void testFinancialTransactionBlockedInElevatedRisk() {
        Customer customer = customerRepository.save(Customer.builder()
            .customerNumber("CUST-TX-" + UUID.randomUUID().toString().substring(0, 8))
            .firstName("Fin")
            .lastName("Customer")
            .email("fin-" + UUID.randomUUID().toString().substring(0, 8) + "@example.test")
            .kycStatus(KycStatus.VERIFIED)
            .riskTier(RiskTier.LOW)
            .assignedEmployeeId(employeeId)
            .syntheticTaxId("SYN-1111-2222")
            .build());

        com.zerotrust.entity.Account account = accountRepository.save(com.zerotrust.entity.Account.builder()
            .customer(customer)
            .accountNumber("ACC-TEST-" + UUID.randomUUID().toString().substring(0, 8))
            .accountType(com.zerotrust.entity.enums.AccountType.CHECKING)
            .balance(new BigDecimal("10000.00"))
            .currency("USD")
            .status(com.zerotrust.entity.enums.AccountStatus.ACTIVE)
            .build());

        com.zerotrust.dto.request.TransactionCreateRequest txRequest = new com.zerotrust.dto.request.TransactionCreateRequest(
            account.getId(),
            new BigDecimal("500.00"),
            com.zerotrust.entity.enums.TransactionType.WITHDRAWAL,
            "ATM Cash Withdrawal",
            null
        );

        SecuritySubject employeeSubject = new SecuritySubject(employeeId, "employee@zerotrust.com", Set.of("ROLE_EMPLOYEE"), Map.of());

        // Under elevated threat context, transaction execution MUST be blocked
        SecurityContext elevatedContext = SecurityContext.of("198.51.100.42", "CRITICAL", 85);
        assertThatThrownBy(() -> transactionService.executeTransaction(txRequest, employeeSubject, elevatedContext, null))
            .isInstanceOf(AccessDeniedException.class)
            .hasMessageContaining("ownership violation / insufficient privilege");

        // Verify balance was NOT mutated (atomic fail-closed protection)
        com.zerotrust.entity.Account refreshedAccount = accountRepository.findById(account.getId()).orElseThrow();
        assertThat(refreshedAccount.getBalance()).isEqualByComparingTo(new BigDecimal("10000.00"));
    }
}
