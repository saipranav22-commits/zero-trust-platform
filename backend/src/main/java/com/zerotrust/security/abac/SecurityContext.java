package com.zerotrust.security.abac;

import jakarta.servlet.http.HttpServletRequest;

import java.time.Instant;
import java.util.Map;

/**
 * ABAC Environmental Context: Encapsulates temporal, network, risk signals, and environmental variables.
 */
public record SecurityContext(
    Instant timestamp,
    String sourceIp,
    String threatLevel,
    int riskScore,
    Map<String, Object> environmentAttributes
) {
    public SecurityContext(Instant timestamp, String sourceIp, String threatLevel, Map<String, Object> environmentAttributes) {
        this(timestamp, sourceIp, threatLevel, 0, environmentAttributes);
    }

    public boolean isElevatedThreat() {
        return (threatLevel != null && !"NORMAL".equalsIgnoreCase(threatLevel)) || riskScore >= 70;
    }

    public boolean isHighRiskContext() {
        return isElevatedThreat() || "CRITICAL".equalsIgnoreCase(threatLevel) || "HIGH".equalsIgnoreCase(threatLevel);
    }

    public static SecurityContext current(HttpServletRequest request) {
        if (request == null) {
            return standard();
        }
        String ip = (request.getRemoteAddr() != null) ? request.getRemoteAddr() : "127.0.0.1";
        Object threatLevelAttr = request.getAttribute("threatLevel");
        String threatLevel = (threatLevelAttr instanceof String tl) ? tl : "NORMAL";
        Object riskScoreAttr = request.getAttribute("riskScore");
        int riskScore = 0;
        if (riskScoreAttr instanceof Integer i) {
            riskScore = i;
        } else if (riskScoreAttr instanceof Number n) {
            riskScore = n.intValue();
        }
        return new SecurityContext(Instant.now(), ip, threatLevel, riskScore, Map.of());
    }

    public static SecurityContext standard() {
        return new SecurityContext(Instant.now(), "127.0.0.1", "NORMAL", 0, Map.of());
    }

    public static SecurityContext of(String sourceIp, String threatLevel, int riskScore) {
        return new SecurityContext(Instant.now(), sourceIp, threatLevel, riskScore, Map.of());
    }
}
