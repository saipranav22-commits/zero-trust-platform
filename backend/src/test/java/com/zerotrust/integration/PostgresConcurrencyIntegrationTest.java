package com.zerotrust.integration;

import com.zerotrust.dto.request.TransactionCreateRequest;
import com.zerotrust.dto.response.TransactionResponse;
import com.zerotrust.entity.Account;
import com.zerotrust.entity.Customer;
import com.zerotrust.entity.IdempotencyRecord;
import com.zerotrust.entity.enums.AccountStatus;
import com.zerotrust.entity.enums.AccountType;
import com.zerotrust.entity.enums.TransactionType;
import com.zerotrust.exception.ValidationException;
import com.zerotrust.repository.AccountRepository;
import com.zerotrust.repository.CustomerRepository;
import com.zerotrust.repository.IdempotencyRecordRepository;
import com.zerotrust.repository.TransactionRepository;
import com.zerotrust.security.abac.SecuritySubject;
import com.zerotrust.service.TransactionService;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.PostgreSQLContainer;

import java.math.BigDecimal;
import java.net.Socket;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Real PostgreSQL 16 Integration Test for Concurrency, Deadlock Prevention,
 * Atomic Rollback, and Persistent Idempotency.
 */
@SpringBootTest
@ActiveProfiles("test")
@Tag("integration-postgres")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class PostgresConcurrencyIntegrationTest {

    private static PostgreSQLContainer<?> testcontainersPostgres;
    private static String activePostgresJdbcUrl;
    private static boolean postgresAvailable = false;

    @BeforeAll
    static void initPostgres() {
        // 1. Try Testcontainers first if supported by host Docker environment
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
            // Testcontainers transport issue on Windows
        }

        // 2. If Testcontainers did not bind, check for Docker-spawned PostgreSQL 16 on port 5438
        if (!postgresAvailable) {
            try (Socket socket = new Socket("127.0.0.1", 5438)) {
                activePostgresJdbcUrl = "jdbc:postgresql://127.0.0.1:5438/zerotrust_test";
                postgresAvailable = true;
            } catch (Exception ignored) {
                postgresAvailable = false;
            }
        }

        assumeTrue(postgresAvailable,
            "SKIPPED / BLOCKED: PostgreSQL 16 container is not accessible. Docker Desktop or isolated container required.");
    }

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        initPostgres();
        if (postgresAvailable && activePostgresJdbcUrl != null) {
            registry.add("spring.datasource.url", () -> activePostgresJdbcUrl);
            registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
            registry.add("spring.datasource.username", () -> "zerotrust");
            registry.add("spring.datasource.password", () -> "zerotrust123");
            registry.add("spring.flyway.enabled", () -> "true");
            registry.add("spring.jpa.hibernate.ddl-auto", () -> "validate");
            registry.add("spring.jpa.properties.hibernate.dialect", () -> "org.hibernate.dialect.PostgreSQLDialect");
        }
    }

    @AfterAll
    static void tearDown() {
        if (testcontainersPostgres != null && testcontainersPostgres.isRunning()) {
            testcontainersPostgres.stop();
        }
    }

    @Autowired
    private TransactionService transactionService;

    @Autowired
    private AccountRepository accountRepository;

    @Autowired
    private CustomerRepository customerRepository;

    @Autowired
    private TransactionRepository transactionRepository;

    @Autowired
    private IdempotencyRecordRepository idempotencyRecordRepository;

    private UUID adminUserId;
    private SecuritySubject adminSubject;
    private Customer testCustomer;

    @BeforeEach
    void setUp() {
        adminUserId = UUID.randomUUID();
        adminSubject = new SecuritySubject(adminUserId, "admin@zerotrust.com", Set.of("ROLE_ADMIN"), Map.of());

        testCustomer = Customer.builder()
            .customerNumber("CUST-PG16-" + UUID.randomUUID().toString().substring(0, 6))
            .firstName("Postgres16")
            .lastName("Customer")
            .email("pg16." + UUID.randomUUID().toString().substring(0, 6) + "@zerotrust.com")
            .syntheticTaxId("SYN-999-1234")
            .annualIncome(new BigDecimal("120000.00"))
            .creditScore(780)
            .build();
        testCustomer = customerRepository.save(testCustomer);
    }

    @Test
    @Order(1)
    @DisplayName("Step 1: Verify PostgreSQL 16 version and all Flyway migrations V1 through V4 executed")
    void shouldVerifyPostgres16AndFlywayMigrations() throws Exception {
        assertThat(activePostgresJdbcUrl).isNotNull();

        try (Connection conn = DriverManager.getConnection(activePostgresJdbcUrl, "zerotrust", "zerotrust123");
             Statement stmt = conn.createStatement()) {

            // Verify PostgreSQL 16
            ResultSet rsVer = stmt.executeQuery("SELECT version();");
            assertThat(rsVer.next()).isTrue();
            String versionStr = rsVer.getString(1);
            assertThat(versionStr).contains("PostgreSQL 16");

            // Verify Flyway schema history contains all 4 migrations
            ResultSet rsFlyway = stmt.executeQuery("SELECT version, description, success FROM flyway_schema_history ORDER BY installed_rank;");
            int migrationCount = 0;
            while (rsFlyway.next()) {
                migrationCount++;
                assertThat(rsFlyway.getBoolean("success")).isTrue();
            }
            assertThat(migrationCount).isGreaterThanOrEqualTo(4);

            // Verify tables exist in PostgreSQL
            ResultSet rsTables = stmt.executeQuery(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';"
            );
            Set<String> tables = new java.util.HashSet<>();
            while (rsTables.next()) {
                tables.add(rsTables.getString("table_name").toLowerCase());
            }
            assertThat(tables).contains("users", "roles", "notifications", "customers", "accounts", "transactions", "idempotency_records");
        }
    }

    @Test
    @Order(2)
    @DisplayName("Step 3: Test ten simultaneous withdrawals exceeding available funds on PostgreSQL 16")
    void shouldPreventOverspendingUnderConcurrentWithdrawalsOnPostgres() throws Exception {
        Account account = Account.builder()
            .customer(testCustomer)
            .accountNumber("ACC-PG-WITHDRAW-" + UUID.randomUUID().toString().substring(0, 6))
            .accountType(AccountType.CHECKING)
            .balance(new BigDecimal("500.00"))
            .currency("USD")
            .status(AccountStatus.ACTIVE)
            .build();
        account = accountRepository.save(account);
        final UUID accId = account.getId();

        int numberOfThreads = 10;
        BigDecimal withdrawalAmount = new BigDecimal("100.00"); // 10 * 100 = 1000, only 500 available
        ExecutorService executor = Executors.newFixedThreadPool(numberOfThreads);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(numberOfThreads);

        AtomicInteger successCount = new AtomicInteger(0);
        AtomicInteger failureCount = new AtomicInteger(0);

        for (int i = 0; i < numberOfThreads; i++) {
            executor.submit(() -> {
                try {
                    startLatch.await();
                    TransactionCreateRequest req = new TransactionCreateRequest(
                        accId, withdrawalAmount, TransactionType.WITHDRAWAL, "PG16 Concurrent Withdrawal", null
                    );
                    transactionService.executeTransaction(req, adminSubject);
                    successCount.incrementAndGet();
                } catch (ValidationException e) {
                    failureCount.incrementAndGet();
                } catch (Exception e) {
                    failureCount.incrementAndGet();
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        startLatch.countDown();
        boolean completed = doneLatch.await(20, TimeUnit.SECONDS);
        executor.shutdown();

        assertThat(completed).isTrue();
        assertThat(successCount.get()).isEqualTo(5); // Exactly 5 succeed ($500 balance consumed)
        assertThat(failureCount.get()).isEqualTo(5); // Exactly 5 rejected

        Account finalAccount = accountRepository.findById(accId).orElseThrow();
        assertThat(finalAccount.getBalance()).isEqualByComparingTo("0.00"); // Zero balance, no overdraw
    }

    @Test
    @Order(3)
    @DisplayName("Step 3: Test opposing transfers between two accounts on PostgreSQL 16 (deadlock prevention)")
    void shouldPreventDeadlockOnOpposingConcurrentTransfersOnPostgres() throws Exception {
        Account accountA = Account.builder()
            .customer(testCustomer)
            .accountNumber("ACC-PG-A-" + UUID.randomUUID().toString().substring(0, 4))
            .accountType(AccountType.CHECKING)
            .balance(new BigDecimal("1000.00"))
            .currency("USD")
            .status(AccountStatus.ACTIVE)
            .build();
        accountA = accountRepository.save(accountA);

        Account accountB = Account.builder()
            .customer(testCustomer)
            .accountNumber("ACC-PG-B-" + UUID.randomUUID().toString().substring(0, 4))
            .accountType(AccountType.CHECKING)
            .balance(new BigDecimal("1000.00"))
            .currency("USD")
            .status(AccountStatus.ACTIVE)
            .build();
        accountB = accountRepository.save(accountB);

        final UUID idA = accountA.getId();
        final UUID idB = accountB.getId();
        final String numA = accountA.getAccountNumber();
        final String numB = accountB.getAccountNumber();

        int iterations = 10;
        ExecutorService executor = Executors.newFixedThreadPool(2);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(2);
        AtomicInteger successfulTransfers = new AtomicInteger(0);

        executor.submit(() -> {
            try {
                startLatch.await();
                for (int i = 0; i < iterations; i++) {
                    TransactionCreateRequest req = new TransactionCreateRequest(
                        idA, new BigDecimal("10.00"), TransactionType.TRANSFER, "A to B", numB
                    );
                    transactionService.executeTransaction(req, adminSubject);
                    successfulTransfers.incrementAndGet();
                }
            } catch (Exception ignored) {
            } finally {
                doneLatch.countDown();
            }
        });

        executor.submit(() -> {
            try {
                startLatch.await();
                for (int i = 0; i < iterations; i++) {
                    TransactionCreateRequest req = new TransactionCreateRequest(
                        idB, new BigDecimal("10.00"), TransactionType.TRANSFER, "B to A", numA
                    );
                    transactionService.executeTransaction(req, adminSubject);
                    successfulTransfers.incrementAndGet();
                }
            } catch (Exception ignored) {
            } finally {
                doneLatch.countDown();
            }
        });

        startLatch.countDown();
        boolean completed = doneLatch.await(25, TimeUnit.SECONDS);
        executor.shutdown();

        assertThat(completed).isTrue();
        assertThat(successfulTransfers.get()).isEqualTo(iterations * 2);

        Account finalA = accountRepository.findById(idA).orElseThrow();
        Account finalB = accountRepository.findById(idB).orElseThrow();
        // Total balance conserved: 1000 + 1000 = 2000
        assertThat(finalA.getBalance().add(finalB.getBalance())).isEqualByComparingTo("2000.00");
    }

    @Test
    @Order(4)
    @DisplayName("Step 2 & 3: Test duplicate transfers using identical idempotency keys on PostgreSQL 16")
    void shouldPreventDuplicateTransfersWithIdenticalIdempotencyKeyOnPostgres() throws Exception {
        Account source = Account.builder()
            .customer(testCustomer)
            .accountNumber("ACC-IDEMP-SRC-" + UUID.randomUUID().toString().substring(0, 4))
            .accountType(AccountType.CHECKING)
            .balance(new BigDecimal("1000.00"))
            .currency("USD")
            .status(AccountStatus.ACTIVE)
            .build();
        source = accountRepository.save(source);

        Account dest = Account.builder()
            .customer(testCustomer)
            .accountNumber("ACC-IDEMP-DST-" + UUID.randomUUID().toString().substring(0, 4))
            .accountType(AccountType.CHECKING)
            .balance(new BigDecimal("200.00"))
            .currency("USD")
            .status(AccountStatus.ACTIVE)
            .build();
        dest = accountRepository.save(dest);

        String idempotencyKey = "IDEMP-KEY-" + UUID.randomUUID();
        TransactionCreateRequest request = new TransactionCreateRequest(
            source.getId(), new BigDecimal("150.00"), TransactionType.TRANSFER, "Idempotent transfer test", dest.getAccountNumber()
        );

        // First execution
        TransactionResponse firstResponse = transactionService.executeTransaction(request, adminSubject, idempotencyKey);
        assertThat(firstResponse).isNotNull();
        assertThat(firstResponse.amount()).isEqualByComparingTo("150.00");

        // Second execution with identical key and payload: must replay cached response without duplicate debit
        TransactionResponse replayedResponse = transactionService.executeTransaction(request, adminSubject, idempotencyKey);
        assertThat(replayedResponse).isNotNull();
        assertThat(replayedResponse.referenceNumber()).isEqualTo(firstResponse.referenceNumber());
        assertThat(replayedResponse.correlationId()).isEqualTo(firstResponse.correlationId());

        // Balance check: debited exactly ONCE ($150 deducted from 1000 = 850)
        Account finalSource = accountRepository.findById(source.getId()).orElseThrow();
        Account finalDest = accountRepository.findById(dest.getId()).orElseThrow();
        assertThat(finalSource.getBalance()).isEqualByComparingTo("850.00");
        assertThat(finalDest.getBalance()).isEqualByComparingTo("350.00");
    }

    @Test
    @Order(5)
    @DisplayName("Step 2: Reusing identical key with different payload must fail with conflict on PostgreSQL 16")
    void shouldRejectDifferingPayloadWithSameKeyOnPostgres() {
        Account source = Account.builder()
            .customer(testCustomer)
            .accountNumber("ACC-CONFLICT-" + UUID.randomUUID().toString().substring(0, 4))
            .accountType(AccountType.CHECKING)
            .balance(new BigDecimal("1000.00"))
            .currency("USD")
            .status(AccountStatus.ACTIVE)
            .build();
        source = accountRepository.save(source);

        String idempotencyKey = "IDEMP-CONFLICT-" + UUID.randomUUID();
        TransactionCreateRequest request1 = new TransactionCreateRequest(
            source.getId(), new BigDecimal("50.00"), TransactionType.DEPOSIT, "Initial", null
        );
        TransactionCreateRequest request2 = new TransactionCreateRequest(
            source.getId(), new BigDecimal("99.00"), TransactionType.DEPOSIT, "Altered amount", null
        );

        transactionService.executeTransaction(request1, adminSubject, idempotencyKey);

        org.junit.jupiter.api.Assertions.assertThrows(ValidationException.class, () ->
            transactionService.executeTransaction(request2, adminSubject, idempotencyKey)
        );
    }

    @Test
    @Order(6)
    @DisplayName("Step 2 & 3: Failed transfer rolls back account balances and creates no orphaned transactions")
    void shouldRollbackAllChangesOnTransferFailureOnPostgres() {
        Account source = Account.builder()
            .customer(testCustomer)
            .accountNumber("ACC-FAIL-SRC-" + UUID.randomUUID().toString().substring(0, 4))
            .accountType(AccountType.CHECKING)
            .balance(new BigDecimal("500.00"))
            .currency("USD")
            .status(AccountStatus.ACTIVE)
            .build();
        source = accountRepository.save(source);

        Account destEur = Account.builder()
            .customer(testCustomer)
            .accountNumber("ACC-FAIL-EUR-" + UUID.randomUUID().toString().substring(0, 4))
            .accountType(AccountType.CHECKING)
            .balance(new BigDecimal("100.00"))
            .currency("EUR") // Mismatched currency
            .status(AccountStatus.ACTIVE)
            .build();
        destEur = accountRepository.save(destEur);

        long initialTxnCount = transactionRepository.count();

        TransactionCreateRequest request = new TransactionCreateRequest(
            source.getId(), new BigDecimal("100.00"), TransactionType.TRANSFER, "Currency mismatch fail", destEur.getAccountNumber()
        );

        try {
            transactionService.executeTransaction(request, adminSubject);
        } catch (ValidationException expected) {
            // Expected validation failure
        }

        // Verify balance rollback
        Account refreshedSource = accountRepository.findById(source.getId()).orElseThrow();
        Account refreshedDest = accountRepository.findById(destEur.getId()).orElseThrow();
        assertThat(refreshedSource.getBalance()).isEqualByComparingTo("500.00");
        assertThat(refreshedDest.getBalance()).isEqualByComparingTo("100.00");

        // Verify no orphan transaction records created
        assertThat(transactionRepository.count()).isEqualTo(initialTxnCount);
    }
}
