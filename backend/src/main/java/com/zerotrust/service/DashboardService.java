package com.zerotrust.service;

import com.zerotrust.entity.enums.AuditStatus;
import com.zerotrust.entity.enums.Severity;
import com.zerotrust.entity.enums.ThreatStatus;
import com.zerotrust.repository.AuditLogRepository;
import com.zerotrust.repository.ThreatEventRepository;
import com.zerotrust.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Aggregates data for the security dashboard overview and analytics.
 */
@Service
@RequiredArgsConstructor
public class DashboardService {

    private final ThreatEventRepository threatEventRepository;
    private final AuditLogRepository    auditLogRepository;
    private final UserRepository        userRepository;

    @Transactional(readOnly = true)
    public Map<String, Object> getOverview() {
        Instant last24h = Instant.now().minusSeconds(86400);
        Instant last30d = Instant.now().minusSeconds(30L * 86400);

        long totalThreats24h   = threatEventRepository.countByCreatedAtAfter(last24h);
        long activeThreats      = threatEventRepository.countByStatusIn(
            List.of(ThreatStatus.DETECTED, ThreatStatus.INVESTIGATING));
        long criticalThreats24h = threatEventRepository.countBySeverityAndCreatedAtAfter(Severity.CRITICAL, last24h);
        long highThreats24h     = threatEventRepository.countBySeverityAndCreatedAtAfter(Severity.HIGH, last24h);

        long failedLogins24h    = auditLogRepository.countByStatusAndCreatedAtAfter(AuditStatus.FAILURE, last24h);
        long totalAuditLogs24h  = auditLogRepository.countByCreatedAtAfter(last24h);
        long totalUsers         = userRepository.countActiveUsers();

        // Security Score: penalize for critical + high threats and failed logins
        int securityScore = Math.max(0, (int) (100
            - (criticalThreats24h * 10)
            - (highThreats24h * 5)
            - (failedLogins24h * 2)));
        securityScore = Math.min(100, securityScore);

        var recentThreats = threatEventRepository.findTop10ByOrderByCreatedAtDesc();

        return Map.of(
            "totalThreatsLast24h",   totalThreats24h,
            "activeThreats",         activeThreats,
            "criticalThreatsLast24h",criticalThreats24h,
            "highThreatsLast24h",    highThreats24h,
            "failedLoginsLast24h",   failedLogins24h,
            "totalAuditLogsLast24h", totalAuditLogs24h,
            "totalActiveUsers",      totalUsers,
            "securityScore",         securityScore,
            "recentThreats",         recentThreats
        );
    }

    @Transactional(readOnly = true)
    public Map<String, Object> getThreatAnalytics(int days) {
        Instant since = Instant.now().minusSeconds((long) days * 86400);

        Map<String, Long> byType = threatEventRepository.countByThreatTypeSince(since)
            .stream().collect(Collectors.toMap(r -> r[0].toString(), r -> (Long) r[1]));

        Map<String, Long> bySeverity = threatEventRepository.countBySeveritySince(since)
            .stream().collect(Collectors.toMap(r -> r[0].toString(), r -> (Long) r[1]));

        List<Map<String, Object>> timeline = threatEventRepository.findDailyThreatCounts(since)
            .stream().map(r -> Map.<String, Object>of("date", r[0].toString(), "count", r[1]))
            .collect(Collectors.toList());

        List<Map<String, Object>> topIps = threatEventRepository
            .findTopSourceIps(since, Pageable.ofSize(10))
            .stream().map(r -> Map.<String, Object>of("ip", r[0].toString(), "count", r[1]))
            .collect(Collectors.toList());

        return Map.of(
            "days",       days,
            "byType",     byType,
            "bySeverity", bySeverity,
            "timeline",   timeline,
            "topIps",     topIps
        );
    }

    @Transactional(readOnly = true)
    public Map<String, Object> getUserActivityAnalytics(int days) {
        Instant since = Instant.now().minusSeconds((long) days * 86400);

        long totalActions    = auditLogRepository.countByCreatedAtAfter(since);
        long failedActions   = auditLogRepository.countByStatusAndCreatedAtAfter(AuditStatus.FAILURE, since);
        double failureRate   = totalActions > 0 ? (double) failedActions / totalActions * 100 : 0;

        Map<String, Long> byAction = auditLogRepository.countByActionSince(since)
            .stream().collect(Collectors.toMap(r -> r[0].toString(), r -> (Long) r[1]));

        List<Map<String, Object>> activityTimeline = auditLogRepository.findDailyActivityCounts(since)
            .stream().map(r -> Map.<String, Object>of("date", r[0].toString(), "count", r[1]))
            .collect(Collectors.toList());

        var recentActivity = auditLogRepository.findTop50ByOrderByCreatedAtDesc();

        return Map.of(
            "totalActions",     totalActions,
            "failedActions",    failedActions,
            "failureRate",      Math.round(failureRate * 10.0) / 10.0,
            "byAction",         byAction,
            "activityTimeline", activityTimeline,
            "recentActivity",   recentActivity
        );
    }
}
