package com.zerotrust.service;

import com.zerotrust.dto.response.AuditChainVerificationResult;
import com.zerotrust.entity.AuditChainAnchor;
import com.zerotrust.entity.AuditCheckpoint;
import com.zerotrust.entity.AuditLog;
import com.zerotrust.entity.enums.AuditStatus;
import com.zerotrust.exception.ResourceNotFoundException;
import com.zerotrust.repository.AuditChainAnchorRepository;
import com.zerotrust.repository.AuditCheckpointRepository;
import com.zerotrust.repository.AuditLogRepository;
import com.zerotrust.security.crypto.AuditHasher;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

/**
 * Immutable audit logging service with SHA-256 hash chaining for tamper detection.
 * Enforces canonical deterministic serialization, monotonic sequence numbers,
 * and pessimistic anchor locking to prevent concurrent chain forking.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuditService {

    private final AuditLogRepository auditLogRepository;
    private final AuditChainAnchorRepository auditChainAnchorRepository;
    private final AuditCheckpointRepository auditCheckpointRepository;

    /**
     * Persists an immutable audit log entry with SHA-256 cryptographic hash chaining.
     * Synchronizes on the anchor table with pessimistic write locking to guarantee
     * strict monotonic ordering and eliminate concurrent chain forking.
     */
    @Transactional
    public AuditLog log(String userId, String userEmail, String action,
                        String resourceType, String resourceId,
                        String sourceIp, String userAgent,
                        AuditStatus status, int riskScore, String details) {

        AuditChainAnchor anchor = getOrInitAnchor();
        long nextSequence = anchor.getLastSequence() + 1;
        String previousHash = anchor.getLastHash();
        Instant now = Instant.now();

        String currentHash = AuditHasher.computeCanonicalHash(
                nextSequence, previousHash, userId, userEmail, action,
                resourceType, resourceId, sourceIp, status, riskScore, now, details
        );

        AuditLog entry = AuditLog.builder()
                .sequenceNumber(nextSequence)
                .userId(userId)
                .userEmail(userEmail)
                .action(action)
                .resourceType(resourceType)
                .resourceId(resourceId)
                .sourceIp(sourceIp)
                .userAgent(userAgent)
                .status(status)
                .riskScore(riskScore)
                .details(details)
                .previousHash(previousHash)
                .currentHash(currentHash)
                .createdAt(now)
                .build();

        AuditLog saved = auditLogRepository.save(entry);

        anchor.setLastSequence(nextSequence);
        anchor.setLastHash(currentHash);
        anchor.setUpdatedAt(now);
        auditChainAnchorRepository.save(anchor);

        return saved;
    }

    private synchronized AuditChainAnchor getOrInitAnchor() {
        return auditChainAnchorRepository.findByIdForUpdate(1)
                .orElseGet(() -> {
                    var top = auditLogRepository.findTopByOrderBySequenceNumberDesc();
                    long lastSeq = top.map(AuditLog::getSequenceNumber).orElse(0L);
                    String lastHash = top.map(AuditLog::getCurrentHash).orElse(AuditHasher.GENESIS_HASH);

                    AuditChainAnchor anchor = AuditChainAnchor.builder()
                            .id(1)
                            .lastSequence(lastSeq)
                            .lastHash(lastHash)
                            .updatedAt(Instant.now())
                            .build();
                    return auditChainAnchorRepository.saveAndFlush(anchor);
                });
    }

    /**
     * Searches audit logs with optional filters.
     */
    @Transactional(readOnly = true)
    public Page<AuditLog> search(String userId, String action, String status,
                                 Instant from, Instant to, Pageable pageable) {
        Specification<AuditLog> spec = Specification.where(null);

        if (StringUtils.hasText(userId)) {
            spec = spec.and((root, q, cb) -> cb.equal(root.get("userId"), userId));
        }
        if (StringUtils.hasText(action)) {
            spec = spec.and((root, q, cb) ->
                    cb.like(cb.lower(root.get("action")), "%" + action.toLowerCase() + "%"));
        }
        if (StringUtils.hasText(status)) {
            spec = spec.and((root, q, cb) ->
                    cb.equal(root.get("status"), AuditStatus.valueOf(status.toUpperCase())));
        }
        if (from != null) {
            spec = spec.and((root, q, cb) ->
                    cb.greaterThanOrEqualTo(root.get("createdAt"), from));
        }
        if (to != null) {
            spec = spec.and((root, q, cb) ->
                    cb.lessThanOrEqualTo(root.get("createdAt"), to));
        }

        return auditLogRepository.findAll(spec, pageable);
    }

    @Transactional(readOnly = true)
    public AuditLog getById(UUID id) {
        return auditLogRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Audit log not found: " + id));
    }

    /**
     * Verifies the integrity of an individual audit log entry by recomputing its hash.
     */
    @Transactional(readOnly = true)
    public boolean verifyIntegrity(UUID id) {
        AuditLog auditLog = auditLogRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Audit log not found: " + id));

        // 1. Check V2 (Unambiguous Length-Prefixed Canonical Hash)
        String expectedCanonicalV2 = AuditHasher.computeCanonicalHashV2(
                auditLog.getSequenceNumber(), auditLog.getPreviousHash(), auditLog.getUserId(),
                auditLog.getUserEmail(), auditLog.getAction(), auditLog.getResourceType(),
                auditLog.getResourceId(), auditLog.getSourceIp(), auditLog.getStatus(),
                auditLog.getRiskScore(), auditLog.getCreatedAt(), auditLog.getDetails()
        );
        if (expectedCanonicalV2.equals(auditLog.getCurrentHash())) {
            return true;
        }

        // 2. Backward compatibility fallback for Phase-5 V1 logs
        String expectedCanonicalV1 = AuditHasher.computeCanonicalHashV1(
                auditLog.getSequenceNumber(), auditLog.getPreviousHash(), auditLog.getUserId(),
                auditLog.getUserEmail(), auditLog.getAction(), auditLog.getResourceType(),
                auditLog.getResourceId(), auditLog.getSourceIp(), auditLog.getStatus(),
                auditLog.getRiskScore(), auditLog.getCreatedAt(), auditLog.getDetails()
        );
        if (expectedCanonicalV1.equals(auditLog.getCurrentHash())) {
            return true;
        }

        // 3. Backward compatibility fallback for pre-Phase 5 legacy logs
        String legacyHash = computeLegacyHash(
                auditLog.getPreviousHash(), auditLog.getUserId(), auditLog.getAction(),
                String.valueOf(auditLog.getCreatedAt().toEpochMilli()), auditLog.getDetails()
        );
        return legacyHash.equals(auditLog.getCurrentHash());
    }

    /**
     * Verifies chain continuity across historical audit records.
     * Detects modified records, deleted records (sequence gaps), broken link hashes,
     * and final record truncation against the singleton anchor.
     */
    @Transactional(readOnly = true)
    public AuditChainVerificationResult verifyChain(Long fromSeq, Long toSeq) {
        List<AuditLog> logs;
        if (fromSeq != null && toSeq != null) {
            logs = auditLogRepository.findBySequenceNumberBetweenOrderBySequenceNumberAsc(fromSeq, toSeq);
        } else {
            logs = auditLogRepository.findAllByOrderBySequenceNumberAsc();
        }

        if (logs.isEmpty()) {
            AuditChainAnchor anchor = auditChainAnchorRepository.findById(1).orElse(null);
            if (anchor != null && anchor.getLastSequence() > 0) {
                return AuditChainVerificationResult.failure(
                        0, null, null, 1L, null,
                        "AUDIT_CHAIN_EMPTY_BUT_ANCHOR_EXISTS: Anchor records last sequence " + anchor.getLastSequence() + " but audit log table contains 0 records."
                );
            }
            return AuditChainVerificationResult.success(0, null, null);
        }

        long count = 0;
        Long expectedSequence = logs.get(0).getSequenceNumber();
        String expectedPreviousHash = logs.get(0).getPreviousHash();

        for (int i = 0; i < logs.size(); i++) {
            AuditLog item = logs.get(i);

            // 1. Verify sequence gap / ordering
            if (!item.getSequenceNumber().equals(expectedSequence)) {
                return AuditChainVerificationResult.failure(
                        count, logs.get(0).getSequenceNumber(), logs.get(logs.size() - 1).getSequenceNumber(),
                        expectedSequence, item.getId(),
                        "SEQUENCE_GAP: Expected sequence " + expectedSequence + " but found " + item.getSequenceNumber() + ". Possible deleted or reordered records."
                );
            }

            // 2. Verify hash link continuity
            if (i > 0 && !item.getPreviousHash().equals(expectedPreviousHash)) {
                return AuditChainVerificationResult.failure(
                        count, logs.get(0).getSequenceNumber(), logs.get(logs.size() - 1).getSequenceNumber(),
                        item.getSequenceNumber(), item.getId(),
                        "BROKEN_CHAIN_LINK: Record sequence " + item.getSequenceNumber() + " previousHash [" + item.getPreviousHash() +
                                "] does not match previous record's currentHash [" + expectedPreviousHash + "]."
                );
            }

            // 3. Verify record content integrity (V2, V1, and legacy fallback)
            String computedCanonicalV2 = AuditHasher.computeCanonicalHashV2(
                    item.getSequenceNumber(), item.getPreviousHash(), item.getUserId(),
                    item.getUserEmail(), item.getAction(), item.getResourceType(),
                    item.getResourceId(), item.getSourceIp(), item.getStatus(),
                    item.getRiskScore(), item.getCreatedAt(), item.getDetails()
            );

            boolean contentValid = computedCanonicalV2.equals(item.getCurrentHash());
            if (!contentValid) {
                String computedCanonicalV1 = AuditHasher.computeCanonicalHashV1(
                        item.getSequenceNumber(), item.getPreviousHash(), item.getUserId(),
                        item.getUserEmail(), item.getAction(), item.getResourceType(),
                        item.getResourceId(), item.getSourceIp(), item.getStatus(),
                        item.getRiskScore(), item.getCreatedAt(), item.getDetails()
                );
                contentValid = computedCanonicalV1.equals(item.getCurrentHash());

                if (!contentValid) {
                    String legacy = computeLegacyHash(
                            item.getPreviousHash(), item.getUserId(), item.getAction(),
                            String.valueOf(item.getCreatedAt().toEpochMilli()), item.getDetails()
                    );
                    contentValid = legacy.equals(item.getCurrentHash());
                }
            }

            if (!contentValid) {
                return AuditChainVerificationResult.failure(
                        count, logs.get(0).getSequenceNumber(), logs.get(logs.size() - 1).getSequenceNumber(),
                        item.getSequenceNumber(), item.getId(),
                        "TAMPERED_RECORD: Computed hash [" + computedCanonicalV2 + "] does not match stored hash [" + item.getCurrentHash() + "] for sequence " + item.getSequenceNumber() + "."
                );
            }

            expectedPreviousHash = item.getCurrentHash();
            expectedSequence++;
            count++;
        }

        // 4. Verify against protected anchor when verifying through the end of the chain
        if (toSeq == null) {
            AuditChainAnchor anchor = auditChainAnchorRepository.findById(1).orElse(null);
            if (anchor != null) {
                long lastLogSeq = logs.get(logs.size() - 1).getSequenceNumber();
                String lastLogHash = logs.get(logs.size() - 1).getCurrentHash();

                if (anchor.getLastSequence() > lastLogSeq) {
                    return AuditChainVerificationResult.failure(
                            count, logs.get(0).getSequenceNumber(), lastLogSeq,
                            anchor.getLastSequence(), null,
                            "HEAD_TRUNCATION_DETECTED: Anchor records sequence " + anchor.getLastSequence() +
                                    " with hash [" + anchor.getLastHash() + "], but highest log sequence is " + lastLogSeq +
                                    ". The final audit record(s) have been deleted or truncated."
                    );
                }

                if (anchor.getLastSequence() == lastLogSeq && !anchor.getLastHash().equals(lastLogHash)) {
                    return AuditChainVerificationResult.failure(
                            count, logs.get(0).getSequenceNumber(), lastLogSeq,
                            lastLogSeq, logs.get(logs.size() - 1).getId(),
                            "ANCHOR_HASH_MISMATCH: Anchor recorded hash [" + anchor.getLastHash() +
                                    "] does not match head record hash [" + lastLogHash + "] for sequence " + lastLogSeq + "."
                    );
                }
            }
        }

        return AuditChainVerificationResult.success(count, logs.get(0).getSequenceNumber(), logs.get(logs.size() - 1).getSequenceNumber());
    }

    /**
     * Creates an independently protected checkpoint representing an anchor of the hash chain.
     */
    @Transactional
    public AuditCheckpoint createCheckpoint(String createdBy) {
        var top = auditLogRepository.findTopByOrderBySequenceNumberDesc()
                .orElseThrow(() -> new IllegalStateException("Cannot create checkpoint on empty audit log"));

        AuditCheckpoint checkpoint = AuditCheckpoint.builder()
                .sequenceNumber(top.getSequenceNumber())
                .checkpointHash(top.getCurrentHash())
                .recordCount(top.getSequenceNumber())
                .createdBy(createdBy != null ? createdBy : "SYSTEM")
                .createdAt(Instant.now())
                .build();

        AuditCheckpoint saved = auditCheckpointRepository.save(checkpoint);
        log.info("📌 Audit chain checkpoint created at sequence {} with hash {}", saved.getSequenceNumber(), saved.getCheckpointHash());
        return saved;
    }

    @Transactional(readOnly = true)
    public List<AuditCheckpoint> getRecentCheckpoints() {
        return auditCheckpointRepository.findTop10ByOrderBySequenceNumberDesc();
    }

    @Transactional(readOnly = true)
    public Page<AuditLog> getUserHistory(String userId, Pageable pageable) {
        return auditLogRepository.findByUserId(userId, pageable);
    }

    @Transactional(readOnly = true)
    public List<AuditLog> getRecent50() {
        return auditLogRepository.findTop50ByOrderByCreatedAtDesc();
    }

    private String computeLegacyHash(String prevHash, String userId,
                                     String action, String timestamp, String details) {
        String content = String.join("|",
                prevHash != null ? prevHash : "",
                userId != null ? userId : "",
                action != null ? action : "",
                timestamp != null ? timestamp : "",
                details != null ? details : ""
        );
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(content.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
