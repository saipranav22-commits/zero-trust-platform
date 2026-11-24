package com.zerotrust.integration;

import com.zerotrust.dto.response.AuditChainVerificationResult;
import com.zerotrust.entity.AuditCheckpoint;
import com.zerotrust.entity.AuditLog;
import com.zerotrust.entity.enums.AuditStatus;
import com.zerotrust.repository.AuditLogRepository;
import com.zerotrust.service.AuditService;
import com.zerotrust.service.RedisSecurityService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@ActiveProfiles("test")
class AuditChainIntegrityIntegrationTest {

    @MockBean
    private RedisSecurityService redisSecurityService;

    @Autowired
    private AuditService auditService;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private PlatformTransactionManager transactionManager;

    @Test
    @DisplayName("Audit Chain: Sequential logging builds a continuous, verified SHA-256 hash chain")
    void testValidAuditChainContinuityAndCanonicalHashing() {
        // Log 5 distinct sequential events
        for (int i = 1; i <= 5; i++) {
            auditService.log(
                    "user-" + i, "user" + i + "@syvora.local", "ACTION_" + i,
                    "Account", "ACC-" + i, "10.0.0." + i, "Mozilla/5.0",
                    AuditStatus.SUCCESS, i * 10, "{\"attempt\":" + i + "}"
            );
        }

        AuditChainVerificationResult result = auditService.verifyChain(null, null);

        assertThat(result.chainValid()).isTrue();
        assertThat(result.totalRecordsVerified()).isGreaterThanOrEqualTo(5);
        assertThat(result.failureReason()).contains("verified");
    }

    @Test
    @DisplayName("Tamper Detection: Modifying an audit record in-place is immediately detected")
    void testTamperingDetectionOnRecordModification() {
        AuditLog log = auditService.log(
                "tamper-target-user", "victim@syvora.local", "TRANSACTION_TRANSFER",
                "Transaction", "TX-100", "192.168.1.50", "Agent/1.0",
                AuditStatus.SUCCESS, 20, "{\"amount\":100}"
        );

        Long targetSeq = log.getSequenceNumber();

        // Simulate an attacker tampering with the action directly in the DB
        jdbcTemplate.update("UPDATE audit_logs SET action = ? WHERE id = ?", "UNAUTHORIZED_MODIFICATION", log.getId());

        AuditChainVerificationResult result = auditService.verifyChain(targetSeq, targetSeq);

        assertThat(result.chainValid()).isFalse();
        assertThat(result.brokenSequence()).isEqualTo(targetSeq);
        assertThat(result.failureReason()).contains("TAMPERED_RECORD");

        // Revert back so other tests aren't affected
        jdbcTemplate.update("UPDATE audit_logs SET action = ? WHERE id = ?", "TRANSACTION_TRANSFER", log.getId());
    }

    @Test
    @DisplayName("Tamper Detection: Deleting a record from the chain creates a detectable sequence gap")
    void testDeletedRecordDetectionSequenceGap() {
        AuditLog l1 = auditService.log("u1", "u1@syvora.local", "LOGIN", "User", "1", "10.0.0.1", "curl", AuditStatus.SUCCESS, 0, "{}");
        AuditLog l2 = auditService.log("u2", "u2@syvora.local", "VIEW", "Account", "2", "10.0.0.2", "curl", AuditStatus.SUCCESS, 0, "{}");
        AuditLog l3 = auditService.log("u3", "u3@syvora.local", "LOGOUT", "User", "3", "10.0.0.3", "curl", AuditStatus.SUCCESS, 0, "{}");

        Long seqToDelete = l2.getSequenceNumber();
        jdbcTemplate.update("DELETE FROM audit_logs WHERE id = ?", l2.getId());

        AuditChainVerificationResult result = auditService.verifyChain(l1.getSequenceNumber(), l3.getSequenceNumber());

        assertThat(result.chainValid()).isFalse();
        assertThat(result.failureReason()).contains("SEQUENCE_GAP");
        assertThat(result.brokenSequence()).isEqualTo(seqToDelete);
    }

    @Test
    @DisplayName("Tamper Detection: Breaking the cryptographic link between records is detected")
    void testBrokenChainLinkDetection() {
        AuditLog l1 = auditService.log("link-1", "l1@syvora.local", "AUTH_CHALLENGE", "User", "1", "127.0.0.1", "test", AuditStatus.SUCCESS, 0, "{}");
        AuditLog l2 = auditService.log("link-2", "l2@syvora.local", "AUTH_SUCCESS", "User", "2", "127.0.0.1", "test", AuditStatus.SUCCESS, 0, "{}");

        // Tamper with previous_hash of l2
        String forgedHash = "0000000000000000000000000000000000000000000000000000000000000000";
        jdbcTemplate.update("UPDATE audit_logs SET previous_hash = ? WHERE id = ?", forgedHash, l2.getId());

        AuditChainVerificationResult result = auditService.verifyChain(l1.getSequenceNumber(), l2.getSequenceNumber());

        assertThat(result.chainValid()).isFalse();
        assertThat(result.failureReason()).contains("BROKEN_CHAIN_LINK");
        assertThat(result.brokenSequence()).isEqualTo(l2.getSequenceNumber());

        // Cleanup
        jdbcTemplate.update("UPDATE audit_logs SET previous_hash = ? WHERE id = ?", l1.getCurrentHash(), l2.getId());
    }

    @Test
    @DisplayName("Concurrency: Simultaneous audit writes maintain monotonic sequences with zero chain forking")
    void testConcurrentAuditWritesNoForking() throws Exception {
        int threads = 8;
        int logsPerThread = 5;
        int totalExpected = threads * logsPerThread;

        ExecutorService executor = Executors.newFixedThreadPool(threads);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threads);
        List<AuditLog> capturedLogs = Collections.synchronizedList(new ArrayList<>());

        for (int t = 0; t < threads; t++) {
            final int threadId = t;
            executor.submit(() -> {
                try {
                    startLatch.await();
                    for (int i = 0; i < logsPerThread; i++) {
                        AuditLog log = auditService.log(
                                "thread-" + threadId, "worker" + threadId + "@syvora.local", "CONCURRENT_WRITE",
                                "Worker", "W-" + threadId + "-" + i, "127.0.0.1", "jMeter",
                                AuditStatus.SUCCESS, 0, "{\"t\":" + threadId + ",\"i\":" + i + "}"
                        );
                        capturedLogs.add(log);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        startLatch.countDown();
        boolean completed = doneLatch.await(15, TimeUnit.SECONDS);
        executor.shutdown();

        assertThat(completed).isTrue();
        assertThat(capturedLogs).hasSize(totalExpected);

        // Verify all sequence numbers are distinct
        List<Long> sequences = capturedLogs.stream().map(AuditLog::getSequenceNumber).toList();
        long distinctSequences = sequences.stream().distinct().count();
        assertThat(distinctSequences).isEqualTo(totalExpected);

        // Verify chain verification succeeds for the range
        Long minSeq = sequences.stream().min(Long::compareTo).orElseThrow();
        Long maxSeq = sequences.stream().max(Long::compareTo).orElseThrow();

        AuditChainVerificationResult verifyRange = auditService.verifyChain(minSeq, maxSeq);
        assertThat(verifyRange.chainValid()).isTrue();
    }

    @Test
    @DisplayName("Checkpointing: Independently verifiable audit anchor checkpoints are recorded")
    void testAuditCheckpointCreation() {
        auditService.log("check-user", "check@syvora.local", "CHECKPOINT_TEST", "System", "0", "127.0.0.1", "test", AuditStatus.SUCCESS, 0, "{}");

        AuditCheckpoint checkpoint = auditService.createCheckpoint("TEST_SECURITY_OFFICER");

        assertThat(checkpoint.getId()).isNotNull();
        assertThat(checkpoint.getSequenceNumber()).isGreaterThan(0L);
        assertThat(checkpoint.getCheckpointHash()).isNotBlank();
        assertThat(checkpoint.getCreatedBy()).isEqualTo("TEST_SECURITY_OFFICER");

        List<AuditCheckpoint> recents = auditService.getRecentCheckpoints();
        assertThat(recents).isNotEmpty();
    }

    @Test
    @DisplayName("Anchor Protection: Deleting the final audit record is detected by comparison with anchor")
    void testHeadTruncationDetectionAgainstAnchor() {
        AuditLog tailLog = auditService.log(
                "truncation-test", "attacker@syvora.local", "EXFILTRATE",
                "Secret", "999", "127.0.0.1", "curl",
                AuditStatus.SUCCESS, 95, "{\"sensitive\":\"stolen\"}"
        );

        Long tailSeq = tailLog.getSequenceNumber();

        // Attacker deletes the final record to cover tracks
        jdbcTemplate.update("DELETE FROM audit_logs WHERE id = ?", tailLog.getId());

        // Verifying full chain through end (toSeq == null) checks against protected anchor
        AuditChainVerificationResult result = auditService.verifyChain(null, null);

        assertThat(result.chainValid()).isFalse();
        assertThat(result.brokenSequence()).isEqualTo(tailSeq);
        assertThat(result.failureReason()).contains("HEAD_TRUNCATION_DETECTED");
    }
}
