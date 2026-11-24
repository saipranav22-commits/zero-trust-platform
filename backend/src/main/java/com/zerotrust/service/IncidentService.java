package com.zerotrust.service;

import com.zerotrust.dto.request.IncidentAssignRequest;
import com.zerotrust.dto.request.IncidentCreateRequest;
import com.zerotrust.dto.request.IncidentNoteRequest;
import com.zerotrust.dto.request.IncidentStatusUpdateRequest;
import com.zerotrust.dto.response.IncidentResponse;
import com.zerotrust.entity.Incident;
import com.zerotrust.entity.IncidentTimeline;
import com.zerotrust.entity.ThreatEvent;
import com.zerotrust.entity.enums.AuditStatus;
import com.zerotrust.entity.enums.IncidentStatus;
import com.zerotrust.entity.enums.Severity;
import com.zerotrust.exception.InvalidStateTransitionException;
import com.zerotrust.exception.ResourceNotFoundException;
import com.zerotrust.repository.IncidentRepository;
import com.zerotrust.repository.IncidentTimelineRepository;
import jakarta.persistence.criteria.Predicate;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.time.Year;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Service orchestrating the Security Incident lifecycle.
 * Lifecycle: OPEN -> ACKNOWLEDGED -> INVESTIGATING -> RESOLVED (with documented reopening).
 * Enforces strict transition validation, deduplication, audit trail logging,
 * and real-time security notifications.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class IncidentService {

    private final IncidentRepository incidentRepository;
    private final IncidentTimelineRepository timelineRepository;
    private final AuditService auditService;
    private final NotificationService notificationService;

    private static final AtomicLong INCIDENT_COUNTER = new AtomicLong(System.currentTimeMillis() % 100000);

    /**
     * Creates a new incident manually with duplicate prevention.
     */
    @Transactional
    public IncidentResponse createIncident(IncidentCreateRequest req, String createdBy) {
        if (req.relatedThreatEventId() != null) {
            Optional<Incident> existing = incidentRepository.findByRelatedThreatEventId(req.relatedThreatEventId());
            if (existing.isPresent()) {
                log.info("Duplicate incident creation avoided for threat event ID: {}", req.relatedThreatEventId());
                return IncidentResponse.from(existing.get());
            }
        }

        String incidentNumber = generateIncidentNumber();
        Incident incident = Incident.builder()
                .incidentNumber(incidentNumber)
                .title(req.title())
                .description(req.description())
                .status(IncidentStatus.OPEN)
                .severity(req.severity() != null ? req.severity() : Severity.MEDIUM)
                .category(req.category())
                .correlationId(req.correlationId())
                .relatedThreatEventId(req.relatedThreatEventId())
                .sourceIp(req.sourceIp())
                .targetResource(req.targetResource())
                .assignedTo(req.assignedTo())
                .createdBy(createdBy != null ? createdBy : "ANALYST")
                .build();

        Incident saved = incidentRepository.save(incident);
        // Record initial timeline event
        addTimelineEntry(saved, "CREATED", null, IncidentStatus.OPEN, createdBy, "Incident opened manually");

        // Immutable audit log
        auditService.log(
                createdBy, createdBy, "INCIDENT_CREATED",
                "Incident", saved.getId().toString(),
                req.sourceIp(), null,
                AuditStatus.SUCCESS, mapSeverityToRisk(saved.getSeverity()),
                String.format("Created incident %s: %s", saved.getIncidentNumber(), saved.getTitle())
        );

        // Real-time notification
        notifyIncidentEvent(saved, "New Security Incident Created: " + saved.getIncidentNumber(),
                saved.getTitle(), "INCIDENT_CREATED");

        return IncidentResponse.from(saved);
    }

    /**
     * Automatically creates an incident from a qualifying threat event
     * with duplicate prevention.
     */
    @Transactional
    public Optional<Incident> createAutoIncidentFromThreat(ThreatEvent threat) {
        if (threat == null || threat.getId() == null) {
            return Optional.empty();
        }

        if (incidentRepository.existsByRelatedThreatEventId(threat.getId())) {
            return Optional.empty();
        }

        String incidentNumber = generateIncidentNumber();
        String title = String.format("[Auto] %s detected on %s", threat.getThreatType(), threat.getTargetResource());
        String description = String.format("Automated incident generated from %s severity detection rule: %s",
                threat.getSeverity(), threat.getDetectionRule());

        Incident incident = Incident.builder()
                .incidentNumber(incidentNumber)
                .title(title)
                .description(description)
                .status(IncidentStatus.OPEN)
                .severity(threat.getSeverity())
                .category(threat.getThreatType().name())
                .correlationId(threat.getCorrelationId())
                .relatedThreatEventId(threat.getId())
                .sourceIp(threat.getSourceIp())
                .targetResource(threat.getTargetResource())
                .createdBy("SYSTEM_DETECTION_ENGINE")
                .build();

        Incident saved;
        try {
            saved = incidentRepository.saveAndFlush(incident);
        } catch (org.springframework.dao.DataIntegrityViolationException e) {
            log.info("Concurrent duplicate incident creation avoided for threat event ID: {}", threat.getId());
            return incidentRepository.findByRelatedThreatEventId(threat.getId());
        }

        addTimelineEntry(saved, "AUTO_CREATED", null, IncidentStatus.OPEN,
                "SYSTEM_DETECTION_ENGINE", "Promoted from threat event " + threat.getId());

        auditService.log(
                "SYSTEM", "system@syvora.local", "INCIDENT_AUTO_CREATED",
                "Incident", saved.getId().toString(),
                threat.getSourceIp(), null,
                AuditStatus.SUCCESS, mapSeverityToRisk(saved.getSeverity()),
                String.format("Auto-created incident %s from threat event %s", saved.getIncidentNumber(), threat.getId())
        );

        notifyIncidentEvent(saved, "🚨 Auto-Created Incident: " + saved.getIncidentNumber(),
                saved.getTitle(), "INCIDENT_ALERT");

        return Optional.of(saved);
    }

    /**
     * Executes an authorized state transition with strict validation.
     */
    @Transactional
    public IncidentResponse updateStatus(UUID incidentId, IncidentStatusUpdateRequest req, String performedBy) {
        Incident incident = incidentRepository.findById(incidentId)
                .orElseThrow(() -> new ResourceNotFoundException("Incident not found: " + incidentId));

        IncidentStatus fromStatus = incident.getStatus();
        IncidentStatus toStatus = req.status();

        validateTransition(fromStatus, toStatus, req.notes());

        incident.setStatus(toStatus);
        String actionName;

        if (toStatus == IncidentStatus.RESOLVED) {
            incident.setResolvedAt(Instant.now());
            incident.setResolutionNotes(req.notes());
            actionName = "RESOLVED";
        } else if (fromStatus == IncidentStatus.RESOLVED && toStatus == IncidentStatus.OPEN) {
            incident.setResolvedAt(null);
            actionName = "REOPENED";
        } else if (toStatus == IncidentStatus.ACKNOWLEDGED) {
            actionName = "ACKNOWLEDGED";
        } else {
            actionName = "INVESTIGATING";
        }

        Incident saved = incidentRepository.save(incident);
        addTimelineEntry(saved, actionName, fromStatus, toStatus, performedBy, req.notes());

        auditService.log(
                performedBy, performedBy, "INCIDENT_" + actionName,
                "Incident", saved.getId().toString(),
                saved.getSourceIp(), null,
                AuditStatus.SUCCESS, mapSeverityToRisk(saved.getSeverity()),
                String.format("Incident %s transitioned from %s to %s. Notes: %s",
                        saved.getIncidentNumber(), fromStatus, toStatus, req.notes() != null ? req.notes() : "N/A")
        );

        notifyIncidentEvent(saved, String.format("Incident %s -> %s", saved.getIncidentNumber(), toStatus),
                "Status changed by " + performedBy + ": " + (req.notes() != null ? req.notes() : ""),
                "INCIDENT_UPDATE");

        return IncidentResponse.from(saved);
    }

    /**
     * Assigns the incident to an analyst.
     */
    @Transactional
    public IncidentResponse assignIncident(UUID incidentId, IncidentAssignRequest req, String performedBy) {
        Incident incident = incidentRepository.findById(incidentId)
                .orElseThrow(() -> new ResourceNotFoundException("Incident not found: " + incidentId));

        String previousAssignee = incident.getAssignedTo();
        incident.setAssignedTo(req.assignedTo());
        Incident saved = incidentRepository.save(incident);

        String note = String.format("Assigned from [%s] to [%s]. %s",
                previousAssignee != null ? previousAssignee : "UNASSIGNED",
                req.assignedTo(),
                req.notes() != null ? req.notes() : "");

        addTimelineEntry(saved, "ASSIGNED", incident.getStatus(), incident.getStatus(), performedBy, note);

        auditService.log(
                performedBy, performedBy, "INCIDENT_ASSIGNED",
                "Incident", saved.getId().toString(),
                saved.getSourceIp(), null,
                AuditStatus.SUCCESS, mapSeverityToRisk(saved.getSeverity()),
                String.format("Assigned incident %s to %s", saved.getIncidentNumber(), req.assignedTo())
        );

        return IncidentResponse.from(saved);
    }

    /**
     * Adds an analyst investigation note to the incident timeline.
     */
    @Transactional
    public IncidentResponse addNote(UUID incidentId, IncidentNoteRequest req, String performedBy) {
        Incident incident = incidentRepository.findById(incidentId)
                .orElseThrow(() -> new ResourceNotFoundException("Incident not found: " + incidentId));

        addTimelineEntry(incident, "NOTE_ADDED", incident.getStatus(), incident.getStatus(), performedBy, req.notes());

        auditService.log(
                performedBy, performedBy, "INCIDENT_NOTE_ADDED",
                "Incident", incident.getId().toString(),
                incident.getSourceIp(), null,
                AuditStatus.SUCCESS, mapSeverityToRisk(incident.getSeverity()),
                String.format("Analyst note added to %s by %s", incident.getIncidentNumber(), performedBy)
        );

        return IncidentResponse.from(incident);
    }

    @Transactional(readOnly = true)
    public IncidentResponse getById(UUID id) {
        Incident incident = incidentRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Incident not found: " + id));
        return IncidentResponse.from(incident);
    }

    @Transactional(readOnly = true)
    public Page<IncidentResponse> search(
            String search, IncidentStatus status, Severity severity,
            String category, String assignedTo, Pageable pageable) {

        Specification<Incident> spec = (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            if (StringUtils.hasText(search)) {
                String pattern = "%" + search.trim().toLowerCase() + "%";
                predicates.add(cb.or(
                        cb.like(cb.lower(root.get("title")), pattern),
                        cb.like(cb.lower(root.get("incidentNumber")), pattern),
                        cb.like(cb.lower(root.get("description")), pattern),
                        cb.like(cb.lower(root.get("sourceIp")), pattern)
                ));
            }

            if (status != null) {
                predicates.add(cb.equal(root.get("status"), status));
            }
            if (severity != null) {
                predicates.add(cb.equal(root.get("severity"), severity));
            }
            if (StringUtils.hasText(category)) {
                predicates.add(cb.equal(cb.lower(root.get("category")), category.trim().toLowerCase()));
            }
            if (StringUtils.hasText(assignedTo)) {
                predicates.add(cb.equal(cb.lower(root.get("assignedTo")), assignedTo.trim().toLowerCase()));
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };

        return incidentRepository.findAll(spec, pageable).map(IncidentResponse::from);
    }

    /**
     * Validates permitted lifecycle state transitions:
     * OPEN -> ACKNOWLEDGED
     * OPEN -> INVESTIGATING
     * ACKNOWLEDGED -> INVESTIGATING
     * INVESTIGATING -> RESOLVED (requires resolution notes)
     * RESOLVED -> OPEN (documented reopening; requires reason)
     */
    private void validateTransition(IncidentStatus from, IncidentStatus to, String notes) {
        if (from == to) {
            throw new InvalidStateTransitionException("Incident is already in status " + to);
        }

        boolean valid = switch (from) {
            case OPEN -> (to == IncidentStatus.ACKNOWLEDGED || to == IncidentStatus.INVESTIGATING);
            case ACKNOWLEDGED -> (to == IncidentStatus.INVESTIGATING);
            case INVESTIGATING -> (to == IncidentStatus.RESOLVED);
            case RESOLVED -> (to == IncidentStatus.OPEN);
        };

        if (!valid) {
            throw new InvalidStateTransitionException(
                    String.format("Invalid incident state transition from [%s] to [%s]. Permitted paths: OPEN->ACKNOWLEDGED->INVESTIGATING->RESOLVED or RESOLVED->OPEN.", from, to));
        }

        if (to == IncidentStatus.RESOLVED && !StringUtils.hasText(notes)) {
            throw new InvalidStateTransitionException("Resolution notes are required when resolving an incident.");
        }

        if (from == IncidentStatus.RESOLVED && to == IncidentStatus.OPEN && !StringUtils.hasText(notes)) {
            throw new InvalidStateTransitionException("Reopening reason/notes are required when reopening a resolved incident.");
        }
    }

    private void addTimelineEntry(Incident incident, String action, IncidentStatus from, IncidentStatus to,
                                  String performedBy, String notes) {
        IncidentTimeline timeline = IncidentTimeline.builder()
                .incident(incident)
                .action(action)
                .fromStatus(from)
                .toStatus(to)
                .performedBy(performedBy != null ? performedBy : "SYSTEM")
                .notes(notes)
                .createdAt(Instant.now())
                .build();
        timelineRepository.save(timeline);
        if (incident.getTimeline() == null) {
            incident.setTimeline(new ArrayList<>());
        }
        incident.getTimeline().add(timeline);
    }

    private void notifyIncidentEvent(Incident incident, String title, String description, String iconType) {
        try {
            notificationService.createNotification(
                    title,
                    description,
                    incident.getSeverity(),
                    "INCIDENT",
                    incident.getId(),
                    incident.getRelatedThreatEventId(),
                    null,
                    "/threats?incidentId=" + incident.getId(),
                    incident.getCreatedBy(),
                    iconType
            );
        } catch (Exception e) {
            log.warn("Failed to dispatch notification for incident {}: {}", incident.getIncidentNumber(), e.getMessage());
        }
    }

    private String generateIncidentNumber() {
        return String.format("INC-%d-%05d", Year.now().getValue(), INCIDENT_COUNTER.incrementAndGet() % 100000);
    }

    private int mapSeverityToRisk(Severity severity) {
        if (severity == null) return 50;
        return switch (severity) {
            case CRITICAL -> 90;
            case HIGH -> 75;
            case MEDIUM -> 50;
            case LOW -> 20;
        };
    }
}
