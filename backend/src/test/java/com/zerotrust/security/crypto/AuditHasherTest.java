package com.zerotrust.security.crypto;

import com.zerotrust.entity.enums.AuditStatus;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class AuditHasherTest {

    @Test
    @DisplayName("V2 length-prefixed encoding eliminates pipe delimiter collision attacks")
    void testPipeDelimiterCollisionResistance() {
        Instant now = Instant.parse("2026-11-24T00:00:00Z");

        // Attack scenario: Attacker attempts to forge record B to collide with record A by shifting a pipe delimiter
        // Record A: userId = "user|1", userEmail = "admin@zerotrust.com"
        String hashA = AuditHasher.computeCanonicalHashV2(
                1L, AuditHasher.GENESIS_HASH, "user|1", "admin@zerotrust.com",
                "LOGIN", "USER", "res-1", "127.0.0.1", AuditStatus.SUCCESS, 0, now, "Normal login"
        );

        // Record B: userId = "user", userEmail = "1|admin@zerotrust.com"
        String hashB = AuditHasher.computeCanonicalHashV2(
                1L, AuditHasher.GENESIS_HASH, "user", "1|admin@zerotrust.com",
                "LOGIN", "USER", "res-1", "127.0.0.1", AuditStatus.SUCCESS, 0, now, "Normal login"
        );

        // In V1 (pure pipe-delimited), these two distinct inputs would produce the identical string:
        // 1|GENESIS|user|1|admin@zerotrust.com|LOGIN|...
        String v1HashA = AuditHasher.computeCanonicalHashV1(
                1L, AuditHasher.GENESIS_HASH, "user|1", "admin@zerotrust.com",
                "LOGIN", "USER", "res-1", "127.0.0.1", AuditStatus.SUCCESS, 0, now, "Normal login"
        );
        String v1HashB = AuditHasher.computeCanonicalHashV1(
                1L, AuditHasher.GENESIS_HASH, "user", "1|admin@zerotrust.com",
                "LOGIN", "USER", "res-1", "127.0.0.1", AuditStatus.SUCCESS, 0, now, "Normal login"
        );
        assertThat(v1HashA).isEqualTo(v1HashB); // Confirms V1 ambiguity exists

        // Under V2, length-prefixed encoding makes them completely distinct:
        assertThat(hashA).isNotEqualTo(hashB);
    }

    @Test
    @DisplayName("Distinguishes null fields from empty strings")
    void testNullVsEmptyStringDistinction() {
        Instant now = Instant.parse("2026-11-24T00:00:00Z");

        // Hash with null userId
        String hashWithNull = AuditHasher.computeCanonicalHashV2(
                1L, AuditHasher.GENESIS_HASH, null, "admin@zerotrust.com",
                "TEST", "RESOURCE", "1", "127.0.0.1", AuditStatus.SUCCESS, 0, now, "details"
        );

        // Hash with empty string userId
        String hashWithEmpty = AuditHasher.computeCanonicalHashV2(
                1L, AuditHasher.GENESIS_HASH, "", "admin@zerotrust.com",
                "TEST", "RESOURCE", "1", "127.0.0.1", AuditStatus.SUCCESS, 0, now, "details"
        );

        assertThat(hashWithNull).isNotEqualTo(hashWithEmpty);
    }

    @Test
    @DisplayName("Handles multi-byte UTF-8 Unicode characters deterministically")
    void testUnicodeHandling() {
        Instant now = Instant.parse("2026-11-24T00:00:00Z");

        String unicodeUserId = "ユーザー_123_🔒";
        String unicodeDetails = "監査ログ: 異常なアクティビティを検出しました (Critical Alert 🚨)";

        String hash1 = AuditHasher.computeCanonicalHashV2(
                1L, AuditHasher.GENESIS_HASH, unicodeUserId, "user@test.jp",
                "ACTION_日本語", "CUSTOMER", "res-unicøde", "2001:db8::1",
                AuditStatus.SUCCESS, 80, now, unicodeDetails
        );

        String hash2 = AuditHasher.computeCanonicalHashV2(
                1L, AuditHasher.GENESIS_HASH, unicodeUserId, "user@test.jp",
                "ACTION_日本語", "CUSTOMER", "res-unicøde", "2001:db8::1",
                AuditStatus.SUCCESS, 80, now, unicodeDetails
        );

        assertThat(hash1).isEqualTo(hash2);
        assertThat(hash1).hasSize(64); // SHA-256 hex string
    }

    @Test
    @DisplayName("Handles timestamp variations and epoch bounds")
    void testTimestampHandling() {
        Instant epochZero = Instant.EPOCH;
        Instant farFuture = Instant.parse("2099-12-31T23:59:59.999Z");

        String hashEpoch = AuditHasher.computeCanonicalHashV2(
                1L, AuditHasher.GENESIS_HASH, "user-1", "user@zerotrust.com",
                "ACTION", "RES", "1", "127.0.0.1", AuditStatus.SUCCESS, 0, epochZero, "details"
        );

        String hashFuture = AuditHasher.computeCanonicalHashV2(
                1L, AuditHasher.GENESIS_HASH, "user-1", "user@zerotrust.com",
                "ACTION", "RES", "1", "127.0.0.1", AuditStatus.SUCCESS, 0, farFuture, "details"
        );

        String hashNullTime = AuditHasher.computeCanonicalHashV2(
                1L, AuditHasher.GENESIS_HASH, "user-1", "user@zerotrust.com",
                "ACTION", "RES", "1", "127.0.0.1", AuditStatus.SUCCESS, 0, null, "details"
        );

        assertThat(hashEpoch).isNotEqualTo(hashFuture);
        assertThat(hashEpoch).isEqualTo(hashNullTime); // Epoch zero matches null fallback
    }

    @Test
    @DisplayName("Preserves backward compatibility for V1 legacy hashes")
    void testV1BackwardCompatibility() {
        Instant now = Instant.parse("2026-11-24T00:00:00Z");

        String v1Hash = AuditHasher.computeCanonicalHashV1(
                5L, "prev-hash-abc", "user-123", "analyst@syvora.local",
                "INCIDENT_ACKNOWLEDGED", "Incident", "inc-id-1", "10.0.0.5",
                AuditStatus.SUCCESS, 75, now, "Analyst assigned"
        );

        assertThat(v1Hash).isNotEmpty();
        assertThat(v1Hash).hasSize(64);
    }
}
