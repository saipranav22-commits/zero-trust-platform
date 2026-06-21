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
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
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
@RequiredArgsConstructor
public class ThreatService {

    private final ThreatEventRepository  threatEventRepository;
    private final ThreatDetectionEngine  detectionEngine;

    /**
     * Analyzes input for threats. Saves a ThreatEvent if a threat is found.
     * @return the saved ThreatEvent, or null if input is clean
     */
    @Transactional
    public ThreatEvent analyze(String input, String userId, String userEmail,
                                String sourceIp, String targetResource, String method) {
        if (!StringUtils.hasText(input)) return null;

        DetectionResult result = detectionEngine.analyze(input, sourceIp);
        if (!result.threatDetected()) return null;

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
        return saved;
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
            spec = spec.and((r, q, cb) ->
                cb.equal(r.get("threatType"), ThreatType.valueOf(threatType.toUpperCase())));
        }
        if (StringUtils.hasText(severity)) {
            spec = spec.and((r, q, cb) ->
                cb.equal(r.get("severity"), Severity.valueOf(severity.toUpperCase())));
        }
        if (StringUtils.hasText(status)) {
            spec = spec.and((r, q, cb) ->
                cb.equal(r.get("status"), ThreatStatus.valueOf(status.toUpperCase())));
        }
        if (StringUtils.hasText(sourceIp)) {
            spec = spec.and((r, q, cb) ->
                cb.like(r.get("sourceIp"), "%" + sourceIp + "%"));
        }
        if (from != null) {
            spec = spec.and((r, q, cb) ->
                cb.greaterThanOrEqualTo(r.get("createdAt"), from));
        }
        if (to != null) {
            spec = spec.and((r, q, cb) ->
                cb.lessThanOrEqualTo(r.get("createdAt"), to));
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

        long totalThreats   = threatEventRepository.countByCreatedAtAfter(since);
        long criticalThreats = threatEventRepository.countBySeverityAndCreatedAtAfter(Severity.CRITICAL, since);
        long highThreats    = threatEventRepository.countBySeverityAndCreatedAtAfter(Severity.HIGH, since);
        long activeThreats  = threatEventRepository.countByStatusIn(
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
            "totalThreats",    totalThreats,
            "criticalThreats", criticalThreats,
            "highThreats",     highThreats,
            "activeThreats",   activeThreats,
            "byType",          byType,
            "bySeverity",      bySeverity,
            "timeline",        timeline,
            "topSourceIps",    topIps
        );
    }

    private String truncate(String s, int maxLength) {
        return s != null && s.length() > maxLength ? s.substring(0, maxLength) + "..." : s;
    }
}
