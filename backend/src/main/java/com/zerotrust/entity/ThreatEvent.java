package com.zerotrust.entity;

import com.zerotrust.entity.enums.Severity;
import com.zerotrust.entity.enums.ThreatStatus;
import com.zerotrust.entity.enums.ThreatType;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;
import java.util.UUID;

/**
 * Represents a detected security threat event.
 * Immutable after creation except for status transitions.
 */
@Entity
@Table(name = "threat_events")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ThreatEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /** The authenticated user who triggered the threat, if known */
    @Column(length = 255)
    private String userId;

    @Column(length = 255)
    private String userEmail;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 50)
    private ThreatType threatType;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    @Builder.Default
    private Severity severity = Severity.MEDIUM;

    @Column(length = 45)
    private String sourceIp;

    @Column(length = 255)
    private String targetResource;

    @Column(length = 10)
    private String targetMethod;

    /** The actual malicious payload that was detected */
    @Column(columnDefinition = "TEXT")
    private String attackPayload;

    /** The rule name that triggered this detection */
    @Column(length = 255)
    private String detectionRule;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 30)
    @Builder.Default
    private ThreatStatus status = ThreatStatus.DETECTED;

    @Column(length = 255)
    private String resolvedBy;

    private Instant resolvedAt;

    @Column(columnDefinition = "TEXT")
    private String notes;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(nullable = false)
    private Instant updatedAt;
}
