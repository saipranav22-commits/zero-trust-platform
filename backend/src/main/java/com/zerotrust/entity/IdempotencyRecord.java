package com.zerotrust.entity;

import com.zerotrust.entity.enums.IdempotencyStatus;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

/**
 * Entity storing idempotency states for financial mutations.
 * Prevents concurrent or duplicate replay of monetary requests.
 */
@Entity
@Table(name = "idempotency_records")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class IdempotencyRecord {

    @Id
    @Column(name = "idempotency_key", nullable = false, length = 128)
    private String key;

    @Column(nullable = false, length = 64)
    private String userId;

    @Column(nullable = false, length = 64)
    private String requestHash;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 30)
    private IdempotencyStatus status;

    @Column(columnDefinition = "TEXT")
    private String responseBody;

    private Integer statusCode;

    @Column(nullable = false)
    @Builder.Default
    private Instant createdAt = Instant.now();

    @Column(nullable = false)
    private Instant expiresAt;
}
