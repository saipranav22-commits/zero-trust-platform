package com.zerotrust.integration;

import com.zerotrust.dto.response.AuditChainVerificationResult;
import com.zerotrust.entity.AuditLog;
import com.zerotrust.entity.Customer;
import com.zerotrust.entity.User;
import com.zerotrust.entity.enums.AuditStatus;
import com.zerotrust.entity.enums.KycStatus;
import com.zerotrust.entity.enums.RiskTier;
import com.zerotrust.repository.AuditLogRepository;
import com.zerotrust.repository.CustomerRepository;
import com.zerotrust.repository.UserRepository;
import com.zerotrust.security.JwtTokenProvider;
import com.zerotrust.service.AuditService;
import com.zerotrust.service.CustomerService;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.PostgreSQLContainer;

import java.math.BigDecimal;
import java.net.Socket;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * PostgreSQL Integration Regression Test for Sensitive Customer Data Endpoint
 * Verifies that CustomerService.getSensitiveCustomerData() correctly handles
 * the write-capable transaction boundary required for audit logging and pessimistic
 * anchor locking against real PostgreSQL, while strictly enforcing ABAC access control.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class SensitiveCustomerPostgresIntegrationTest {

    private static PostgreSQLContainer<?> testcontainersPostgres;
    private static String activePostgresJdbcUrl;
    private static boolean postgresAvailable = false;
    private static String postgresUser = "zerotrust";
    private static String postgresPassword = "zerotrust123";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private CustomerRepository customerRepository;

    @Autowired
    private CustomerService customerService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private AuditService auditService;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    private Customer testCustomer;
    private UUID employeeId;
    private String adminToken;
    private String employeeToken;
    private String analystToken;

    private static final String SENSITIVE_TAX_ID = "SYN-9988-7766";

    @BeforeAll
    static void initPostgres() {
        if (postgresAvailable) {
            return;
        }

        // 1. Check if external or CI PostgreSQL URL is provided via environment
        String envUrl = System.getenv("POSTGRES_JDBC_URL");
        if (envUrl == null || envUrl.isBlank()) {
            envUrl = System.getenv("SPRING_DATASOURCE_URL");
        }
        if (envUrl != null && envUrl.startsWith("jdbc:postgresql://")) {
            String host = System.getenv("POSTGRES_HOST") != null ? System.getenv("POSTGRES_HOST") : "127.0.0.1";
            int port = 5432;
            try {
                String clean = envUrl.substring("jdbc:postgresql://".length());
                int slashIdx = clean.indexOf('/');
                String hostPort = slashIdx > 0 ? clean.substring(0, slashIdx) : clean;
                int colonIdx = hostPort.indexOf(':');
                if (colonIdx > 0) {
                    host = hostPort.substring(0, colonIdx);
                    port = Integer.parseInt(hostPort.substring(colonIdx + 1));
                } else if (!hostPort.isBlank()) {
                    host = hostPort;
                }
            } catch (Exception ignored) {
            }

            try (Socket socket = new Socket(host, port)) {
                activePostgresJdbcUrl = envUrl;
                if (System.getenv("POSTGRES_USER") != null) {
                    postgresUser = System.getenv("POSTGRES_USER");
                } else if (System.getenv("SPRING_DATASOURCE_USERNAME") != null) {
                    postgresUser = System.getenv("SPRING_DATASOURCE_USERNAME");
                }
                if (System.getenv("POSTGRES_PASSWORD") != null) {
                    postgresPassword = System.getenv("POSTGRES_PASSWORD");
                } else if (System.getenv("SPRING_DATASOURCE_PASSWORD") != null) {
                    postgresPassword = System.getenv("SPRING_DATASOURCE_PASSWORD");
                }
                postgresAvailable = true;
            } catch (Exception ignored) {
            }
        }

        // 2. Check standard port 5432 (GitHub Actions service container or local postgres)
        if (!postgresAvailable) {
            try (Socket socket = new Socket("127.0.0.1", 5432)) {
                activePostgresJdbcUrl = "jdbc:postgresql://127.0.0.1:5432/zerotrust_db";
                postgresAvailable = true;
            } catch (Exception ignored) {
            }
        }

        // 2b. Check local port 5433 (local demo postgres instance)
        if (!postgresAvailable) {
            try (Socket socket = new Socket("127.0.0.1", 5433)) {
                activePostgresJdbcUrl = "jdbc:postgresql://127.0.0.1:5433/zerotrust_demo";
                postgresUser = "zerotrust";
                postgresPassword = "";
                postgresAvailable = true;
            } catch (Exception ignored) {
            }
        }

        // 3. Check isolated container port 5438
        if (!postgresAvailable) {
            try (Socket socket = new Socket("127.0.0.1", 5438)) {
                activePostgresJdbcUrl = "jdbc:postgresql://127.0.0.1:5438/zerotrust_test";
                postgresAvailable = true;
            } catch (Exception ignored) {
            }
        }

        // 4. Try Testcontainers if Docker is available
        if (!postgresAvailable) {
            try {
                if (DockerClientFactory.instance().isDockerAvailable()) {
                    testcontainersPostgres = new PostgreSQLContainer<>("postgres:16-alpine")
                            .withDatabaseName("zerotrust_test")
                            .withUsername("zerotrust")
                            .withPassword("zerotrust123");
                    testcontainersPostgres.start();
                    activePostgresJdbcUrl = testcontainersPostgres.getJdbcUrl();
                    postgresAvailable = true;
                }
            } catch (Throwable ignored) {
            }
        }

        boolean isCI = "true".equalsIgnoreCase(System.getenv("CI"))
                || "true".equalsIgnoreCase(System.getenv("GITHUB_ACTIONS"));
        if (isCI && !postgresAvailable) {
            org.junit.jupiter.api.Assertions.fail(
                    "CRITICAL CI FAILURE: PostgreSQL 16 service container is required in CI but is not reachable.");
        }

        assumeTrue(postgresAvailable,
                "SKIPPED: PostgreSQL is not accessible. A real PostgreSQL instance is required for this test.");
    }

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        initPostgres();
        if (postgresAvailable && activePostgresJdbcUrl != null) {
            registry.add("spring.datasource.url", () -> activePostgresJdbcUrl);
            registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
            registry.add("spring.datasource.username", () -> postgresUser);
            registry.add("spring.datasource.password", () -> postgresPassword);
            registry.add("spring.flyway.enabled", () -> "true");
            registry.add("spring.jpa.hibernate.ddl-auto", () -> "validate");
            registry.add("spring.jpa.properties.hibernate.dialect", () -> "org.hibernate.dialect.PostgreSQLDialect");
        }
    }

    @BeforeEach
    void setUp() {
        assumeTrue(postgresAvailable, "PostgreSQL not available");

        User employeeUser = userRepository.findByEmail("employee@zerotrust.com")
                .orElseGet(() -> userRepository.findAll().stream().findFirst().orElseThrow());
        employeeId = employeeUser.getId();

        User adminUser = userRepository.findByEmail("admin@zerotrust.com")
                .orElse(employeeUser);
        UUID adminId = adminUser.getId();

        User analystUser = userRepository.findByEmail("analyst@zerotrust.com")
                .orElse(employeeUser);
        UUID analystId = analystUser.getId();

        adminToken = jwtTokenProvider.generateAccessToken(adminId, "admin@zerotrust.com", List.of("ROLE_ADMIN"));
        employeeToken = jwtTokenProvider.generateAccessToken(employeeId, "employee@zerotrust.com", List.of("ROLE_EMPLOYEE"));
        analystToken = jwtTokenProvider.generateAccessToken(analystId, "analyst@zerotrust.com", List.of("ROLE_SECURITY_ANALYST"));

        testCustomer = customerRepository.save(Customer.builder()
                .customerNumber("CUST-SENS-" + UUID.randomUUID().toString().substring(0, 8))
                .firstName("Sensitive")
                .lastName("Client")
                .email("sens-" + UUID.randomUUID().toString().substring(0, 8) + "@example.test")
                .phoneNumber("+1-555-0188")
                .kycStatus(KycStatus.VERIFIED)
                .riskTier(RiskTier.LOW)
                .assignedEmployeeId(employeeId)
                .syntheticTaxId(SENSITIVE_TAX_ID)
                .annualIncome(new BigDecimal("200000.00"))
                .creditScore(800)
                .build());
    }

    @Test
    @DisplayName("Authorized Admin accesses sensitive customer endpoint: returns 200, decrypted tax ID, and persists audit log in PostgreSQL")
    void testAdminAccessesSensitiveDataSuccessfullyWithAuditInPostgres() throws Exception {
        mockMvc.perform(get("/api/customers/" + testCustomer.getId() + "/sensitive")
                .header("Authorization", "Bearer " + adminToken)
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.customerId").value(testCustomer.getId().toString()))
                .andExpect(jsonPath("$.data.syntheticTaxId").value(SENSITIVE_TAX_ID));

        // Verify that audit log was transactionally persisted to PostgreSQL
        List<AuditLog> auditLogs = auditLogRepository.findTop50ByOrderByCreatedAtDesc();
        assertThat(auditLogs).isNotEmpty();

        AuditLog sensitiveAudit = auditLogs.stream()
                .filter(l -> "VIEW_SENSITIVE_DATA".equals(l.getAction()) && testCustomer.getId().toString().equals(l.getResourceId()))
                .findFirst()
                .orElse(null);

        assertThat(sensitiveAudit).isNotNull();
        assertThat(sensitiveAudit.getStatus()).isEqualTo(AuditStatus.SUCCESS);
        assertThat(sensitiveAudit.getResourceType()).isEqualTo("CUSTOMER");
        assertThat(sensitiveAudit.getResourceId()).isEqualTo(testCustomer.getId().toString());
        assertThat(sensitiveAudit.getUserEmail()).isEqualTo("admin@zerotrust.com");

        // Verify that the audit cryptographic chain remains intact in PostgreSQL
        AuditChainVerificationResult chainResult = auditService.verifyChain(null, null);
        assertThat(chainResult.chainValid()).isTrue();
    }

    @Test
    @DisplayName("Unauthorized Employee is denied access to sensitive tax ID: returns 403 Forbidden without leaking data")
    void testEmployeeCannotAccessSensitiveCustomerData() throws Exception {
        mockMvc.perform(get("/api/customers/" + testCustomer.getId() + "/sensitive")
                .header("Authorization", "Bearer " + employeeToken)
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.status").value(403))
                .andExpect(jsonPath("$.data").doesNotExist());
    }

    @Test
    @DisplayName("Security Analyst is denied access to sensitive tax ID: returns 403 Forbidden without leaking data")
    void testSecurityAnalystCannotAccessSensitiveCustomerData() throws Exception {
        mockMvc.perform(get("/api/customers/" + testCustomer.getId() + "/sensitive")
                .header("Authorization", "Bearer " + analystToken)
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.status").value(403))
                .andExpect(jsonPath("$.data").doesNotExist());
    }

    @Test
    @DisplayName("Unauthenticated request is rejected: returns 401 without sensitive data exposure")
    void testUnauthenticatedRequestIsRejected() throws Exception {
        mockMvc.perform(get("/api/customers/" + testCustomer.getId() + "/sensitive")
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isUnauthorized());
    }
}
