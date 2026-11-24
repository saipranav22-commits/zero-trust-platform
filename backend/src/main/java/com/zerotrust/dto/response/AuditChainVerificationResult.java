package com.zerotrust.dto.response;

import java.time.Instant;
import java.util.UUID;

/**
 * Result report for audit chain verification across a range of sequence numbers.
 */
public record AuditChainVerificationResult(
        boolean chainValid,
        long totalRecordsVerified,
        Long firstSequence,
        Long lastSequence,
        Long brokenSequence,
        UUID brokenId,
        String failureReason,
        Instant verifiedAt
) {
    public static AuditChainVerificationResult success(long count, Long firstSeq, Long lastSeq) {
        return new AuditChainVerificationResult(
                true,
                count,
                firstSeq,
                lastSeq,
                null,
                null,
                "Audit hash chain integrity verified — zero modifications, deletions or link breaks detected.",
                Instant.now()
        );
    }

    public static AuditChainVerificationResult failure(
            long count,
            Long firstSeq,
            Long lastSeq,
            Long brokenSeq,
            UUID brokenId,
            String reason
    ) {
        return new AuditChainVerificationResult(
                false,
                count,
                firstSeq,
                lastSeq,
                brokenSeq,
                brokenId,
                reason,
                Instant.now()
        );
    }
}
