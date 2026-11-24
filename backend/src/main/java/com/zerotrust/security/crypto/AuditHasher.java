package com.zerotrust.security.crypto;

import com.zerotrust.entity.enums.AuditStatus;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;

/**
 * Deterministic canonical serialization and SHA-256 hashing utility
 * for tamper-evident audit logging.
 *
 * <p>Version 2 uses Length-Value (LV) length-prefixed canonical serialization
 * to eliminate delimiter ambiguity attacks (e.g., pipe characters injected into user,
 * action, or resource fields).
 *
 * <p>Version 1 (pipe-delimited) is preserved for backwards compatibility with historical logs.
 */
public final class AuditHasher {

    public static final String GENESIS_HASH = "GENESIS";

    private AuditHasher() {}

    /**
     * Computes the SHA-256 hex digest of an arbitrary string input.
     */
    public static String sha256Hex(String input) {
        if (input == null) {
            return "";
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not available in runtime", e);
        }
    }

    /**
     * Length-prefixed UTF-8 field encoding.
     * Format: "{length_in_bytes}:{value}" or "-1:null" for null fields.
     */
    public static String encodeField(String value) {
        if (value == null) {
            return "-1:null";
        }
        int byteLen = value.getBytes(StandardCharsets.UTF_8).length;
        return byteLen + ":" + value;
    }

    /**
     * Default canonical hash computation (Uses V2 Unambiguous Length-Prefixed format).
     */
    public static String computeCanonicalHash(
            Long sequenceNumber,
            String previousHash,
            String userId,
            String userEmail,
            String action,
            String resourceType,
            String resourceId,
            String sourceIp,
            AuditStatus status,
            int riskScore,
            Instant createdAt,
            String details
    ) {
        return computeCanonicalHashV2(
                sequenceNumber, previousHash, userId, userEmail, action,
                resourceType, resourceId, sourceIp, status, riskScore, createdAt, details
        );
    }

    /**
     * Version 2: Unambiguous Length-Prefixed Canonical Serialization.
     * Guarantees delimiter collision resistance across all arbitrary input characters.
     */
    public static String computeCanonicalHashV2(
            Long sequenceNumber,
            String previousHash,
            String userId,
            String userEmail,
            String action,
            String resourceType,
            String resourceId,
            String sourceIp,
            AuditStatus status,
            int riskScore,
            Instant createdAt,
            String details
    ) {
        String detailsDigest = sha256Hex(details);
        long epochMilli = createdAt != null ? createdAt.toEpochMilli() : 0L;
        String prevHashVal = previousHash != null && !previousHash.isBlank() ? previousHash : GENESIS_HASH;
        String statusVal = status != null ? status.name() : AuditStatus.SUCCESS.name();

        String canonical = String.join("|",
                "V2",
                encodeField(sequenceNumber != null ? sequenceNumber.toString() : "0"),
                encodeField(prevHashVal),
                encodeField(userId),
                encodeField(userEmail),
                encodeField(action),
                encodeField(resourceType),
                encodeField(resourceId),
                encodeField(sourceIp),
                encodeField(statusVal),
                encodeField(String.valueOf(riskScore)),
                encodeField(String.valueOf(epochMilli)),
                encodeField(detailsDigest)
        );

        return sha256Hex(canonical);
    }

    /**
     * Version 1: Legacy Phase-5 Pipe-Delimited Serialization.
     * Retained strictly for verifying historical audit logs.
     */
    public static String computeCanonicalHashV1(
            Long sequenceNumber,
            String previousHash,
            String userId,
            String userEmail,
            String action,
            String resourceType,
            String resourceId,
            String sourceIp,
            AuditStatus status,
            int riskScore,
            Instant createdAt,
            String details
    ) {
        String detailsDigest = sha256Hex(details);
        long epochMilli = createdAt != null ? createdAt.toEpochMilli() : 0L;

        String canonical = String.join("|",
                sequenceNumber != null ? sequenceNumber.toString() : "0",
                previousHash != null && !previousHash.isBlank() ? previousHash : GENESIS_HASH,
                userId != null ? userId : "",
                userEmail != null ? userEmail : "",
                action != null ? action : "",
                resourceType != null ? resourceType : "",
                resourceId != null ? resourceId : "",
                sourceIp != null ? sourceIp : "",
                status != null ? status.name() : AuditStatus.SUCCESS.name(),
                String.valueOf(riskScore),
                String.valueOf(epochMilli),
                detailsDigest
        );

        return sha256Hex(canonical);
    }
}
