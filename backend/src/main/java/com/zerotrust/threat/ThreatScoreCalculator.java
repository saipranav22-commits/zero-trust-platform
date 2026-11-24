package com.zerotrust.threat;

import com.zerotrust.entity.enums.Severity;
import com.zerotrust.service.RedisSecurityService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Deterministic Contextual Threat Scoring Engine.
 * Evaluates rule severity, detection confidence, target endpoint sensitivity,
 * and client abuse history from Redis to compute an explainable risk score (0 - 100).
 */
@Slf4j
@Component
public class ThreatScoreCalculator {

    private final RedisSecurityService redisSecurityService;

    public ThreatScoreCalculator(@Autowired(required = false) RedisSecurityService redisSecurityService) {
        this.redisSecurityService = redisSecurityService;
    }

    public record ScoreResult(int score, ThreatAction action, String justification) {}

    public ScoreResult calculate(DetectionResult detection, String path, String method, String clientIp, String email) {
        if (!detection.threatDetected()) {
            return new ScoreResult(0, ThreatAction.ALLOWED, "No threat pattern matched");
        }

        int score = 0;
        StringBuilder justification = new StringBuilder();

        // 1. Base Score from Rule Severity
        Severity severity = detection.severity() != null ? detection.severity() : Severity.MEDIUM;
        int base = switch (severity) {
            case CRITICAL -> 75;
            case HIGH -> 60;
            case MEDIUM -> 35;
            case LOW -> 15;
        };
        score += base;
        justification.append(String.format("Base severity %s (+%d). ", severity, base));

        // 2. Confidence Adjustment
        if (detection.confidenceScore() >= 0.90) {
            score += 10;
            justification.append("High rule confidence (+10). ");
        } else if (detection.confidenceScore() < 0.70) {
            score -= 10;
            justification.append("Moderate rule confidence (-10). ");
        }

        // 3. Target Endpoint Sensitivity Multiplier
        boolean isFinancialMutation = path.startsWith("/api/transactions") && ("POST".equalsIgnoreCase(method) || "PUT".equalsIgnoreCase(method));
        boolean isAdminMutation = path.startsWith("/api/admin");
        boolean isBankingResource = path.startsWith("/api/customers") || path.startsWith("/api/accounts");

        if (isFinancialMutation || isAdminMutation) {
            score += 20;
            justification.append("Critical financial/admin target endpoint (+20). ");
        } else if (isBankingResource) {
            score += 10;
            justification.append("Banking entity target endpoint (+10). ");
        }

        // 4. Redis Abuse Context
        if (redisSecurityService != null) {
            try {
                if (clientIp != null && redisSecurityService.isIpBlocked(clientIp)) {
                    score += 25;
                    justification.append("Source IP is currently blocked for brute-force abuse (+25). ");
                }
                if (email != null && redisSecurityService.isAccountThrottled(email)) {
                    score += 20;
                    justification.append("Target account is currently throttled (+20). ");
                }
            } catch (Exception ex) {
                log.debug("Redis context check skipped: {}", ex.getMessage());
            }
        }

        // Clamp score between 0 and 100
        int finalScore = Math.max(0, Math.min(100, score));

        // 5. Policy Decision
        ThreatAction action;
        if (severity == Severity.CRITICAL || finalScore >= 70 || (severity == Severity.HIGH && (isFinancialMutation || isAdminMutation))) {
            action = ThreatAction.BLOCKED;
        } else if (finalScore >= 40) {
            action = ThreatAction.FLAGGED;
        } else {
            action = ThreatAction.ALLOWED;
        }

        justification.append(String.format("Final score: %d -> %s", finalScore, action));
        return new ScoreResult(finalScore, action, justification.toString());
    }
}
