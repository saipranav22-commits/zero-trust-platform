package com.zerotrust.dto.response;

import com.zerotrust.entity.Incident;
import com.zerotrust.entity.IncidentTimeline;
import com.zerotrust.entity.enums.IncidentStatus;
import com.zerotrust.entity.enums.Severity;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Sanitized response representation of a security incident.
 * Excludes raw credentials, tokens, or unmasked attack payloads.
 */
public record IncidentResponse(
        UUID id,
        String incidentNumber,
        String title,
        String description,
        IncidentStatus status,
        Severity severity,
        String category,
        String correlationId,
        UUID relatedThreatEventId,
        String sourceIp,
        String targetResource,
        String assignedTo,
        String createdBy,
        String resolutionNotes,
        Instant resolvedAt,
        Instant createdAt,
        Instant updatedAt,
        List<TimelineEntryResponse> timeline
) {
    public record TimelineEntryResponse(
            UUID id,
            String action,
            IncidentStatus fromStatus,
            IncidentStatus toStatus,
            String performedBy,
            String notes,
            Instant createdAt
    ) {
        public static TimelineEntryResponse from(IncidentTimeline t) {
            return new TimelineEntryResponse(
                    t.getId(),
                    t.getAction(),
                    t.getFromStatus(),
                    t.getToStatus(),
                    t.getPerformedBy(),
                    t.getNotes(),
                    t.getCreatedAt()
            );
        }
    }

    public static IncidentResponse from(Incident incident) {
        List<TimelineEntryResponse> timelineEntries = incident.getTimeline() != null
                ? incident.getTimeline().stream().map(TimelineEntryResponse::from).toList()
                : List.of();

        return new IncidentResponse(
                incident.getId(),
                incident.getIncidentNumber(),
                incident.getTitle(),
                incident.getDescription(),
                incident.getStatus(),
                incident.getSeverity(),
                incident.getCategory(),
                incident.getCorrelationId(),
                incident.getRelatedThreatEventId(),
                incident.getSourceIp(),
                incident.getTargetResource(),
                incident.getAssignedTo(),
                incident.getCreatedBy(),
                incident.getResolutionNotes(),
                incident.getResolvedAt(),
                incident.getCreatedAt(),
                incident.getUpdatedAt(),
                timelineEntries
        );
    }
}
