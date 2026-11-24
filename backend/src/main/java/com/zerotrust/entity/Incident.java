package com.zerotrust.entity;

import com.zerotrust.entity.enums.IncidentStatus;
import com.zerotrust.entity.enums.Severity;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Security Incident entity representing an investigation lifecycle.
 * States: OPEN -> ACKNOWLEDGED -> INVESTIGATING -> RESOLVED (with documented reopening).
 */
@Entity
@Table(name = "incidents")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Incident {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "incident_number", nullable = false, unique = true, length = 50)
    private String incidentNumber;

    @Column(nullable = false, length = 255)
    private String title;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 30)
    @Builder.Default
    private IncidentStatus status = IncidentStatus.OPEN;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    @Builder.Default
    private Severity severity = Severity.MEDIUM;

    @Column(length = 100)
    private String category;

    @Column(name = "correlation_id", length = 64)
    private String correlationId;

    @Column(name = "related_threat_event_id", unique = true)
    private UUID relatedThreatEventId;

    @Column(name = "source_ip", length = 45)
    private String sourceIp;

    @Column(name = "target_resource", length = 255)
    private String targetResource;

    @Column(name = "assigned_to", length = 255)
    private String assignedTo;

    @Column(name = "created_by", length = 255)
    private String createdBy;

    @Column(name = "resolution_notes", columnDefinition = "TEXT")
    private String resolutionNotes;

    @Column(name = "resolved_at")
    private Instant resolvedAt;

    @OneToMany(mappedBy = "incident", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @OrderBy("createdAt ASC")
    @Builder.Default
    private List<IncidentTimeline> timeline = new ArrayList<>();

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;
}
