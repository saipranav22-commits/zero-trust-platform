package com.zerotrust.service;

import com.zerotrust.entity.AuditLog;
import com.zerotrust.entity.enums.AuditStatus;
import com.zerotrust.repository.AuditLogRepository;
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
import java.util.Optional;
import java.util.UUID;

/**
 * Immutable audit logging service with SHA-256 hash chaining for tamper detection.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuditService {

    private final AuditLogRepository auditLogRepository;

    /**
     * Persists an immutable audit log entry with hash chaining.
     */
    @Transactional
    public AuditLog log(String userId, String userEmail, String action,
                        String resourceType, String resourceId,
                        String sourceIp, String userAgent,
                        AuditStatus status, int riskScore, String details) {

        // Fetch previous hash for chaining
        String previousHash = auditLogRepository.findTopByOrderByCreatedAtDesc()
            .map(AuditLog::getCurrentHash)
            .orElse("GENESIS");

        Instant now = Instant.now();
        String currentHash = computeHash(previousHash, userId, action, String.valueOf(now.toEpochMilli()), details);

        AuditLog entry = AuditLog.builder()
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

        return auditLogRepository.save(entry);
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

    /**
     * Verifies the integrity of an audit log entry by recomputing its hash.
     */
    @Transactional(readOnly = true)
    public boolean verifyIntegrity(UUID id) {
        AuditLog log = auditLogRepository.findById(id)
            .orElseThrow(() -> new com.zerotrust.exception.ResourceNotFoundException("Audit log not found: " + id));

        String expectedHash = computeHash(
            log.getPreviousHash(), log.getUserId(), log.getAction(),
            String.valueOf(log.getCreatedAt().toEpochMilli()), log.getDetails());

        return expectedHash.equals(log.getCurrentHash());
    }

    /**
     * Returns recent audit logs for a specific user.
     */
    @Transactional(readOnly = true)
    public Page<AuditLog> getUserHistory(String userId, Pageable pageable) {
        return auditLogRepository.findByUserId(userId, pageable);
    }

    @Transactional(readOnly = true)
    public List<AuditLog> getRecent50() {
        return auditLogRepository.findTop50ByOrderByCreatedAtDesc();
    }

    // ─────────────────────────────────────────────
    // HASH UTILITY
    // ─────────────────────────────────────────────

    private String computeHash(String prevHash, String userId,
                                String action, String timestamp, String details) {
        String content = String.join("|",
            prevHash   != null ? prevHash   : "",
            userId     != null ? userId     : "",
            action     != null ? action     : "",
            timestamp  != null ? timestamp  : "",
            details    != null ? details    : ""
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
