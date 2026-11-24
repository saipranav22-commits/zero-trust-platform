package com.zerotrust.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

/**
 * Persistent storage of revoked access token SHA-256 digests.
 * Ensures that if ephemeral in-memory cache (Redis / Valkey) restarts,
 * previously revoked JWT access tokens remain non-replayable until natural expiry.
 */
@Entity
@Table(name = "revoked_tokens")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RevokedToken {

    @Id
    @Column(name = "token_digest", length = 64, nullable = false)
    private String tokenDigest;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "revoked_at", nullable = false)
    @Builder.Default
    private Instant revokedAt = Instant.now();
}
