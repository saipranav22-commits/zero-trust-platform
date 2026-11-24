package com.zerotrust.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.*;

import java.time.Instant;

/**
 * Singleton anchor for the audit log cryptographic hash chain.
 * Row id = 1 holds the latest sequence number and current hash.
 * Synchronized under row-level pessimistic locking during audit appends
 * to guarantee strict serialization and prevent chain forking.
 */
@Entity
@Table(name = "audit_chain_anchor")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuditChainAnchor {

    @Id
    private Integer id;

    @Column(name = "last_sequence", nullable = false)
    private Long lastSequence;

    @Column(name = "last_hash", nullable = false, length = 64)
    private String lastHash;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;
}
