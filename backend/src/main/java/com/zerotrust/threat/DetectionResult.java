package com.zerotrust.threat;

import com.zerotrust.entity.enums.Severity;
import com.zerotrust.entity.enums.ThreatType;

/**
 * Immutable result of a threat detection scan.
 */
public record DetectionResult(
    boolean threatDetected,
    ThreatType threatType,
    Severity severity,
    String detectionRule,
    String description,
    double confidenceScore
) {
    /** Factory for a clean (non-threatening) result */
    public static DetectionResult clean() {
        return new DetectionResult(false, null, null, null, "No threat detected", 0.0);
    }

    /** Factory for a detected threat */
    public static DetectionResult threat(ThreatType type, Severity severity,
                                          String rule, String description, double confidence) {
        return new DetectionResult(true, type, severity, rule, description, confidence);
    }
}
