package com.zerotrust.threat;

import com.zerotrust.entity.enums.Severity;
import com.zerotrust.entity.enums.ThreatType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ThreatDetectionEngineTest {

    private ThreatDetectionEngine engine;

    @BeforeEach
    void setUp() {
        engine = new ThreatDetectionEngine();
    }

    @Test
    @DisplayName("Should detect SQL Injection patterns")
    void shouldDetectSqlInjection() {
        DetectionResult result1 = engine.analyze("' OR '1'='1", "10.0.0.1");
        assertThat(result1.threatDetected()).isTrue();
        assertThat(result1.threatType()).isEqualTo(ThreatType.SQL_INJECTION);

        DetectionResult result2 = engine.analyze("1 UNION ALL SELECT null, username, password FROM users", "10.0.0.1");
        assertThat(result2.threatDetected()).isTrue();
        assertThat(result2.threatType()).isEqualTo(ThreatType.SQL_INJECTION);
        assertThat(result2.severity()).isEqualTo(Severity.CRITICAL);
    }

    @Test
    @DisplayName("Should detect Cross-Site Scripting (XSS) patterns")
    void shouldDetectXss() {
        DetectionResult result = engine.analyze("<script>alert('xss')</script>", "10.0.0.2");
        assertThat(result.threatDetected()).isTrue();
        assertThat(result.threatType()).isEqualTo(ThreatType.XSS);
        assertThat(result.severity()).isEqualTo(Severity.HIGH);
    }

    @Test
    @DisplayName("Should detect Path Traversal patterns")
    void shouldDetectPathTraversal() {
        DetectionResult result = engine.analyze("../../etc/passwd", "10.0.0.3");
        assertThat(result.threatDetected()).isTrue();
        assertThat(result.threatType()).isEqualTo(ThreatType.PATH_TRAVERSAL);
    }

    @Test
    @DisplayName("Should detect Command Injection patterns")
    void shouldDetectCommandInjection() {
        DetectionResult result = engine.analyze("; ls -la /var/log", "10.0.0.4");
        assertThat(result.threatDetected()).isTrue();
        assertThat(result.threatType()).isEqualTo(ThreatType.COMMAND_INJECTION);
        assertThat(result.severity()).isEqualTo(Severity.CRITICAL);
    }

    @Test
    @DisplayName("Should return clean for safe input")
    void shouldPassCleanInput() {
        DetectionResult result = engine.analyze("John Doe standard account search", "10.0.0.5");
        assertThat(result.threatDetected()).isFalse();
    }
}
