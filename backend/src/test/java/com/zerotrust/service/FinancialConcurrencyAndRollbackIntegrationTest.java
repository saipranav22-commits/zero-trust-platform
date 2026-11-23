package com.zerotrust.service;

import com.zerotrust.dto.request.TransactionCreateRequest;
import com.zerotrust.dto.response.TransactionResponse;
import com.zerotrust.entity.Account;
import com.zerotrust.entity.Customer;
import com.zerotrust.entity.enums.AccountStatus;
import com.zerotrust.entity.enums.AccountType;
import com.zerotrust.entity.enums.TransactionType;
import com.zerotrust.exception.ValidationException;
import com.zerotrust.repository.AccountRepository;
import com.zerotrust.repository.CustomerRepository;
import com.zerotrust.repository.TransactionRepository;
import com.zerotrust.security.abac.SecuritySubject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.math.BigDecimal;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
class FinancialConcurrencyAndRollbackIntegrationTest {

    @Autowired
    private TransactionService transactionService;

    @Autowired
    private AccountRepository accountRepository;

    @Autowired
    private CustomerRepository customerRepository;

    @Autowired
    private TransactionRepository transactionRepository;

    @Autowired
    private PlatformTransactionManager transactionManager;

    private UUID adminUserId;
    private SecuritySubject adminSubject;
    private Customer customer;

    @BeforeEach
    void setUp() {
        adminUserId = UUID.randomUUID();
        adminSubject = new SecuritySubject(adminUserId, "admin@zerotrust.com", Set.of("ROLE_ADMIN"), Map.of());

        customer = Customer.builder()
            .customerNumber("CUST-CONCUR-" + UUID.randomUUID().toString().substring(0, 6))
            .firstName("Integration")
            .lastName("Customer")
            .email("concur." + UUID.randomUUID().toString().substring(0, 6) + "@test.com")
            .syntheticTaxId("SYN-001-9999")
            .annualIncome(new BigDecimal("90000.00"))
            .creditScore(720)
            .build();
        customer = customerRepository.save(customer);
    }

    @Test
    @DisplayName("Pessimistic locking prevents double-spending during concurrent withdrawals")
    void shouldPreventOverspendingUnderConcurrentWithdrawals() throws Exception {
        Account account = Account.builder()
            .customer(customer)
            .accountNumber("ACC-CONCUR-" + UUID.randomUUID().toString().substring(0, 6))
            .accountType(AccountType.CHECKING)
            .balance(new BigDecimal("500.00"))
            .currency("USD")
            .status(AccountStatus.ACTIVE)
            .build();
        account = accountRepository.save(account);
        final UUID accId = account.getId();

        int numberOfThreads = 10;
        BigDecimal withdrawalAmount = new BigDecimal("100.00"); // 10 * 100 = 1000, but only 500 available
        ExecutorService executor = Executors.newFixedThreadPool(numberOfThreads);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(numberOfThreads);

        AtomicInteger successCount = new AtomicInteger(0);
        AtomicInteger failureCount = new AtomicInteger(0);

        for (int i = 0; i < numberOfThreads; i++) {
            executor.submit(() -> {
                try {
                    startLatch.await(); // Synchronize all threads to fire simultaneously
                    TransactionCreateRequest req = new TransactionCreateRequest(
                        accId, withdrawalAmount, TransactionType.WITHDRAWAL, "Parallel withdrawal", null
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
        boolean completed = doneLatch.await(15, TimeUnit.SECONDS);
        executor.shutdown();

        assertThat(completed).isTrue();
        assertThat(successCount.get()).isEqualTo(5); // Exactly 5 withdrawals must succeed ($500 balance exhausted)
        assertThat(failureCount.get()).isEqualTo(5); // Exactly 5 must be rejected with insufficient funds

        Account finalAccount = accountRepository.findById(accId).orElseThrow();
        assertThat(finalAccount.getBalance()).isEqualByComparingTo("0.00"); // No negative balance or double-spending
    }

    @Test
    @DisplayName("Ordered locking prevents deadlocks during opposing concurrent transfers")
    void shouldPreventDeadlockOnOpposingConcurrentTransfers() throws Exception {
        Account accountA = Account.builder()
            .customer(customer)
            .accountNumber("ACC-OPP-A-" + UUID.randomUUID().toString().substring(0, 4))
            .accountType(AccountType.CHECKING)
            .balance(new BigDecimal("1000.00"))
            .currency("USD")
            .status(AccountStatus.ACTIVE)
            .build();
        accountA = accountRepository.save(accountA);

        Account accountB = Account.builder()
            .customer(customer)
            .accountNumber("ACC-OPP-B-" + UUID.randomUUID().toString().substring(0, 4))
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

        // Thread 1: transfers from A to B
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

        // Thread 2: transfers opposing from B to A
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
        boolean completed = doneLatch.await(15, TimeUnit.SECONDS);
        executor.shutdown();

        assertThat(completed).isTrue();
        // Both threads must complete all transfers without encountering deadlock
        assertThat(successfulTransfers.get()).isEqualTo(iterations * 2);

        Account finalA = accountRepository.findById(idA).orElseThrow();
        Account finalB = accountRepository.findById(idB).orElseThrow();
        // Sum of balances must remain exactly preserved: 1000 + 1000 = 2000
        assertThat(finalA.getBalance().add(finalB.getBalance())).isEqualByComparingTo("2000.00");
    }

    @Test
    @DisplayName("Transaction rollback restores account balances if transfer encounters failure")
    void shouldRollbackAllChangesOnTransferFailure() {
        Account sourceAccount = Account.builder()
            .customer(customer)
            .accountNumber("ACC-SRC-ROLLBACK")
            .balance(new BigDecimal("500.00"))
            .currency("USD")
            .status(AccountStatus.ACTIVE)
            .build();
        sourceAccount = accountRepository.save(sourceAccount);

        Account destEurAccount = Account.builder()
            .customer(customer)
            .accountNumber("ACC-DEST-EUR")
            .balance(new BigDecimal("100.00"))
            .currency("EUR") // Incompatible currency!
            .status(AccountStatus.ACTIVE)
            .build();
        destEurAccount = accountRepository.save(destEurAccount);

        TransactionCreateRequest request = new TransactionCreateRequest(
            sourceAccount.getId(),
            new BigDecimal("200.00"),
            TransactionType.TRANSFER,
            "Transfer attempt across mismatched currencies",
            "ACC-DEST-EUR"
        );

        try {
            transactionService.executeTransaction(request, adminSubject);
        } catch (ValidationException e) {
            // Expected validation failure
        }

        // Verify full rollback: source balance must be untouched
        Account refreshedSource = accountRepository.findById(sourceAccount.getId()).orElseThrow();
        Account refreshedDest = accountRepository.findById(destEurAccount.getId()).orElseThrow();

        assertThat(refreshedSource.getBalance()).isEqualByComparingTo("500.00");
        assertThat(refreshedDest.getBalance()).isEqualByComparingTo("100.00");
    }
}
