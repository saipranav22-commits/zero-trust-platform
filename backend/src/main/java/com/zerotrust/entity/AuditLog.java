package com.zerotrust.entity;

import com.zerotrust.entity.enums.AuditStatus;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

/**
 * Immutable audit log entry with SHA-256 hash chaining for tamper detection.
 * Records every significant action in the system.
 * NEVER update or delete audit logs.
 */
@Entity
@Table(name = "audit_logs")
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(length = 255)
    private String userId;

    @Column(length = 255)
    private String userEmail;

    @Column(nullable = false, length = 100)
    private String action;

    @Column(length = 100)
    private String resourceType;

    @Column(length = 255)
    private String resourceId;

    @Column(length = 45)
    private String sourceIp;

    @Column(columnDefinition = "TEXT")
    private String userAgent;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    @Builder.Default
    private AuditStatus status = AuditStatus.SUCCESS;

    @Column(nullable = false)
    @Builder.Default
    private int riskScore = 0;

    /** JSON string with additional context */
    @Column(columnDefinition = "TEXT")
    private String details;

    /** SHA-256 hash of the previous audit log entry */
    @Column(length = 64)
    private String previousHash;

    /** SHA-256 hash of this entry's content (for tamper detection) */
    @Column(length = 64)
    private String currentHash;

    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @PrePersist
    protected void onPersist() {
        if (createdAt == null) {
            createdAt = Instant.now();
        }
    }
}
