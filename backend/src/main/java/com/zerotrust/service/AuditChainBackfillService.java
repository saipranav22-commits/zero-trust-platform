package com.zerotrust.service;

import com.zerotrust.entity.AuditChainAnchor;
import com.zerotrust.entity.AuditLog;
import com.zerotrust.repository.AuditChainAnchorRepository;
import com.zerotrust.repository.AuditLogRepository;
import com.zerotrust.security.crypto.AuditHasher;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Ensures existing audit logs have monotonic sequence numbers and initializes
 * the audit_chain_anchor singleton row upon startup.
 */
@Slf4j
@Component
@Order(40)
@RequiredArgsConstructor
public class AuditChainBackfillService implements ApplicationRunner {

    private final JdbcTemplate jdbcTemplate;
    private final AuditLogRepository auditLogRepository;
    private final AuditChainAnchorRepository auditChainAnchorRepository;

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        try {
            // Check for unsequenced logs
            List<Map<String, Object>> unsequenced = jdbcTemplate.queryForList(
                    "SELECT id FROM audit_logs WHERE sequence_number IS NULL ORDER BY created_at ASC, id ASC"
            );

            if (!unsequenced.isEmpty()) {
                log.info("⚙️ Found {} unsequenced audit logs. Backfilling sequence numbers and canonical hashes...", unsequenced.size());
                long seq = 1L;
                String prevHash = AuditHasher.GENESIS_HASH;

                for (Map<String, Object> row : unsequenced) {
                    Object rawId = row.get("id");
                    jdbcTemplate.update("UPDATE audit_logs SET sequence_number = ? WHERE id = ?", seq, rawId);
                    seq++;
                }
                log.info("✅ Successfully backfilled sequence numbers for {} audit logs.", unsequenced.size());
            }

            // Ensure anchor exists
            if (auditChainAnchorRepository.findById(1).isEmpty()) {
                var top = auditLogRepository.findTopByOrderBySequenceNumberDesc();
                long lastSeq = top.map(AuditLog::getSequenceNumber).orElse(0L);
                String lastHash = top.map(AuditLog::getCurrentHash).orElse(AuditHasher.GENESIS_HASH);

                AuditChainAnchor anchor = AuditChainAnchor.builder()
                        .id(1)
                        .lastSequence(lastSeq)
                        .lastHash(lastHash)
                        .updatedAt(Instant.now())
                        .build();
                auditChainAnchorRepository.saveAndFlush(anchor);
                log.info("⚓ Initialized audit chain anchor at sequence {} with hash {}", lastSeq, lastHash);
            }
        } catch (Exception e) {
            log.warn("Audit chain backfill skipped or deferred: {}", e.getMessage());
        }
    }
}
