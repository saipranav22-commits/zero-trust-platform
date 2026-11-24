package com.zerotrust.service;

import com.zerotrust.entity.ThreatEvent;
import com.zerotrust.entity.enums.Severity;
import com.zerotrust.entity.enums.ThreatStatus;
import com.zerotrust.entity.enums.ThreatType;
import com.zerotrust.exception.ResourceNotFoundException;
import com.zerotrust.repository.ThreatEventRepository;
import com.zerotrust.threat.DetectionResult;
import com.zerotrust.threat.ThreatDetectionEngine;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Lazy;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import com.zerotrust.threat.ThreatAction;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Orchestrates threat analysis and stores detected events.
 */
@Slf4j
@Service
public class ThreatService {

    private final ThreatEventRepository threatEventRepository;
    private final ThreatDetectionEngine detectionEngine;
    private final NotificationService notificationService;
    private final IncidentService incidentService;

    @org.springframework.beans.factory.annotation.Autowired
    public ThreatService(ThreatEventRepository threatEventRepository,
                         ThreatDetectionEngine detectionEngine,
                         @Lazy NotificationService notificationService,
                         @Lazy IncidentService incidentService) {
        this.threatEventRepository = threatEventRepository;
        this.detectionEngine = detectionEngine;
        this.notificationService = notificationService;
        this.incidentService = incidentService;
    }

    public ThreatService(ThreatEventRepository threatEventRepository,
                         ThreatDetectionEngine detectionEngine,
                         NotificationService notificationService) {
        this(threatEventRepository, detectionEngine, notificationService, null);
    }

    /**
     * Analyzes input for threats. Saves a ThreatEvent if a threat is found.
     * 
     * @return the saved ThreatEvent, or null if input is clean
     */
    @Transactional
    public ThreatEvent analyze(String input, String userId, String userEmail,
            String sourceIp, String targetResource, String method) {
        if (!StringUtils.hasText(input))
            return null;

        DetectionResult result = detectionEngine.analyze(input, sourceIp);
        if (!result.threatDetected())
            return null;

        ThreatEvent event = ThreatEvent.builder()
                .userId(userId)
                .userEmail(userEmail)
                .threatType(result.threatType())
                .severity(result.severity())
                .sourceIp(sourceIp)
                .targetResource(targetResource)
                .targetMethod(method)
                .attackPayload(truncate(input, 2000))
                .detectionRule(result.detectionRule())
                .status(ThreatStatus.DETECTED)
                .build();

        ThreatEvent saved = threatEventRepository.save(event);
        log.warn("🚨 THREAT DETECTED [{}] [{}] from IP={} user={} target={}",
                result.threatType(), result.severity(), sourceIp, userEmail, targetResource);

        // Fire real-time notification
        try {
            String iconType = switch (result.severity()) {
                case CRITICAL -> "CRITICAL";
                case HIGH -> "HIGH";
                default -> "THREAT";
            };
            String desc = String.format("%s attack detected from IP %s targeting %s. Rule matched: %s.",
                    result.threatType().name().replace('_', ' '), sourceIp, targetResource, result.detectionRule());
            notificationService.createNotification(
                    result.threatType().name().replace('_', ' ') + " Detected",
                    desc,
                    result.severity(),
                    "THREAT_DETECTION",
                    saved.getId(), saved.getId(), null,
                    "/threats?id=" + saved.getId(),
                    "Syvora Detection Engine",
                    iconType);
        } catch (Exception ex) {
            log.warn("Could not create notification for threat {}: {}", saved.getId(), ex.getClass().getSimpleName());
        }

        // Phase 5: Auto-create security incident for qualifying threat events
        try {
            if (incidentService != null && (saved.getSeverity() == Severity.CRITICAL || saved.getSeverity() == Severity.HIGH
                    || (saved.getRiskScore() != null && saved.getRiskScore() >= 70))) {
                incidentService.createAutoIncidentFromThreat(saved);
            }
        } catch (Exception ex) {
            log.warn("Could not auto-create incident for threat {}: {}", saved.getId(), ex.getMessage());
        }

        return saved;
    }

    /**
     * Persists a threat event in an independent transaction.
     * Ensures blocked or rejected requests still log threat and notification
     * records.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public ThreatEvent recordThreatEvent(
            String attackPayload,
            String userId,
            String userEmail,
            String sourceIp,
            String targetResource,
            String targetMethod,
            String correlationId,
            DetectionResult result,
            ThreatAction action,
            int riskScore) {
        String sanitizedPayload = sanitizePayload(attackPayload);
        String forensicEvidence = formatForensicMetadata(result, targetMethod, targetResource, sanitizedPayload);

        ThreatEvent event = ThreatEvent.builder()
                .userId(userId)
                .userEmail(userEmail)
                .threatType(result.threatType())
                .severity(result.severity() != null ? result.severity() : Severity.MEDIUM)
                .sourceIp(sourceIp)
                .targetResource(targetResource)
                .targetMethod(targetMethod)
                .attackPayload(truncate(forensicEvidence, 2000))
                .detectionRule(result.detectionRule())
                .status(ThreatStatus.DETECTED)
                .correlationId(correlationId)
                .actionTaken(action.name())
                .riskScore(riskScore)
                .build();

        ThreatEvent saved = threatEventRepository.save(event);
        log.warn("🚨 THREAT RECORDED [{}] [{}] Action={} Score={} IP={} target={} correlation={}",
                result.threatType(), result.severity(), action, riskScore, sourceIp, targetResource, correlationId);

        // Fire real-time notification to analysts and administrators
        try {
            String iconType = switch (result.severity() != null ? result.severity() : Severity.MEDIUM) {
                case CRITICAL -> "CRITICAL";
                case HIGH -> "HIGH";
                default -> "THREAT";
            };
            String title = String.format("%s %s",
                    result.threatType().name().replace('_', ' '),
                    action == ThreatAction.BLOCKED ? "Blocked" : "Detected");
            String desc = String.format(
                    "%s action applied for %s attempt from IP %s on %s %s. Rule: %s. Risk score: %d.",
                    action, result.threatType(), sourceIp, targetMethod, targetResource, result.detectionRule(),
                    riskScore);

            notificationService.createNotification(
                    title,
                    desc,
                    result.severity() != null ? result.severity() : Severity.MEDIUM,
                    "THREAT_DETECTION",
                    saved.getId(),
                    saved.getId(),
                    null,
                    "/threats?id=" + saved.getId(),
                    "Syvora Threat Inspection Engine",
                    iconType);
        } catch (Exception ex) {
            log.warn("Could not dispatch notification for threat event {}: {}", saved.getId(), ex.getClass().getSimpleName());
        }

        // Phase 5: Auto-create security incident for qualifying threat events
        try {
            if (incidentService != null && (saved.getSeverity() == Severity.CRITICAL || saved.getSeverity() == Severity.HIGH
                    || (saved.getRiskScore() != null && saved.getRiskScore() >= 70))) {
                incidentService.createAutoIncidentFromThreat(saved);
            }
        } catch (Exception ex) {
            log.warn("Could not auto-create incident for threat event {}: {}", saved.getId(), ex.getMessage());
        }

        return saved;
    }

    public String formatForensicMetadata(DetectionResult result, String method, String targetResource, String sanitizedPayload) {
        String rule = result != null && result.detectionRule() != null ? result.detectionRule() : "UNKNOWN";
        String type = result != null && result.threatType() != null ? result.threatType().name() : "UNKNOWN";
        // Phase 4 carryover: Avoid storing raw or sanitized request body samples in forensic telemetry.
        // Store only safe allowlisted rule identifiers, target method/path, and redacted summary marker.
        return String.format("evidence=allowlisted; rule=%s; type=%s; target=%s %s; payload_summary=[REDACTED]",
                rule, type, method != null ? method : "UNKNOWN", targetResource != null ? targetResource : "/");
    }

    public String sanitizePayload(String input) {
        if (!StringUtils.hasText(input))
            return "";
        return input
            .replaceAll("(?i)Bearer\\s+[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*", "Bearer [REDACTED_JWT]")
            .replaceAll("(?i)\\b(ey[A-Za-z0-9-_]{10,}\\.[A-Za-z0-9-_]{10,}\\.[A-Za-z0-9-_]{10,})\\b", "[REDACTED_JWT]")
            .replaceAll("(?i)\"(password|passwd|pwd|secret|token|refreshToken|accessToken|apiKey|creditCard|card_number|cardNumber|cvv|cvc|pin|ssn)\"\\s*:\\s*(\"[^\"]*\"|\\d+)", "\"$1\":\"[REDACTED]\"")
            .replaceAll("(?i)(password|passwd|pwd|secret|token|refreshToken|accessToken|apiKey|creditCard|card_number|cardNumber|cvv|cvc|pin|ssn)=[^&; \\t\\r\\n]+", "$1=[REDACTED]")
            .replaceAll("\\b(?:\\d[ -]*?){13,19}\\b", "[REDACTED_CARD]");
    }

    /**
     * Paginated threat search with optional filters.
     */
    @Transactional(readOnly = true)
    public Page<ThreatEvent> search(String threatType, String severity,
            String status, String sourceIp,
            Instant from, Instant to, Pageable pageable) {
        Specification<ThreatEvent> spec = Specification.where(null);

        if (StringUtils.hasText(threatType)) {
            spec = spec.and((r, q, cb) -> cb.equal(r.get("threatType"), ThreatType.valueOf(threatType.toUpperCase())));
        }
        if (StringUtils.hasText(severity)) {
            spec = spec.and((r, q, cb) -> cb.equal(r.get("severity"), Severity.valueOf(severity.toUpperCase())));
        }
        if (StringUtils.hasText(status)) {
            spec = spec.and((r, q, cb) -> cb.equal(r.get("status"), ThreatStatus.valueOf(status.toUpperCase())));
        }
        if (StringUtils.hasText(sourceIp)) {
            spec = spec.and((r, q, cb) -> cb.like(r.get("sourceIp"), "%" + sourceIp + "%"));
        }
        if (from != null) {
            spec = spec.and((r, q, cb) -> cb.greaterThanOrEqualTo(r.get("createdAt"), from));
        }
        if (to != null) {
            spec = spec.and((r, q, cb) -> cb.lessThanOrEqualTo(r.get("createdAt"), to));
        }

        return threatEventRepository.findAll(spec, pageable);
    }

    @Transactional(readOnly = true)
    public ThreatEvent getById(UUID id) {
        return threatEventRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Threat event not found: " + id));
    }

    @Transactional(readOnly = true)
    public List<ThreatEvent> getRecent() {
        return threatEventRepository.findTop10ByOrderByCreatedAtDesc();
    }

    @Transactional
    public ThreatEvent updateStatus(UUID id, ThreatStatus newStatus,
            String resolvedBy, String notes) {
        ThreatEvent event = getById(id);
        event.setStatus(newStatus);
        event.setNotes(notes);
        if (newStatus == ThreatStatus.RESOLVED) {
            event.setResolvedBy(resolvedBy);
            event.setResolvedAt(Instant.now());
        }
        return threatEventRepository.save(event);
    }

    // ─────────────────────────────────────────────
    // ANALYTICS
    // ─────────────────────────────────────────────

    @Transactional(readOnly = true)
    public Map<String, Object> getStatistics(int days) {
        Instant since = Instant.now().minusSeconds((long) days * 86400);

        long totalThreats = threatEventRepository.countByCreatedAtAfter(since);
        long criticalThreats = threatEventRepository.countBySeverityAndCreatedAtAfter(Severity.CRITICAL, since);
        long highThreats = threatEventRepository.countBySeverityAndCreatedAtAfter(Severity.HIGH, since);
        long activeThreats = threatEventRepository.countByStatusIn(
                List.of(ThreatStatus.DETECTED, ThreatStatus.INVESTIGATING));

        Map<String, Long> byType = threatEventRepository.countByThreatTypeSince(since)
                .stream().collect(Collectors.toMap(
                        r -> r[0].toString(), r -> (Long) r[1]));

        Map<String, Long> bySeverity = threatEventRepository.countBySeveritySince(since)
                .stream().collect(Collectors.toMap(
                        r -> r[0].toString(), r -> (Long) r[1]));

        List<Map<String, Object>> timeline = threatEventRepository.findDailyThreatCounts(since)
                .stream().map(r -> Map.<String, Object>of("date", r[0], "count", r[1]))
                .collect(Collectors.toList());

        List<Map<String, Object>> topIps = threatEventRepository
                .findTopSourceIps(since, Pageable.ofSize(10))
                .stream().map(r -> Map.<String, Object>of("ip", r[0], "count", r[1]))
                .collect(Collectors.toList());

        return Map.of(
                "totalThreats", totalThreats,
                "criticalThreats", criticalThreats,
                "highThreats", highThreats,
                "activeThreats", activeThreats,
                "byType", byType,
                "bySeverity", bySeverity,
                "timeline", timeline,
                "topSourceIps", topIps);
    }

    private String truncate(String s, int maxLength) {
        return s != null && s.length() > maxLength ? s.substring(0, maxLength) + "..." : s;
    }
}
