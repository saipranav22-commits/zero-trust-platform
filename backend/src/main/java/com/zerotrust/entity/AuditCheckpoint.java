package com.zerotrust.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

/**
 * Immutable audit chain checkpoint representing an independently verifiable
 * anchor of the hash chain state at a given sequence number.
 */
@Entity
@Table(name = "audit_checkpoints")
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuditCheckpoint {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "sequence_number", nullable = false)
    private Long sequenceNumber;

    @Column(name = "checkpoint_hash", nullable = false, length = 64)
    private String checkpointHash;

    @Column(name = "record_count", nullable = false)
    private Long recordCount;

    @Column(name = "created_by", nullable = false, length = 100)
    private String createdBy;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @PrePersist
    protected void onPersist() {
        if (createdAt == null) {
            createdAt = Instant.now();
        }
    }
}
