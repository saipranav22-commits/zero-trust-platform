package com.zerotrust.threat;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zerotrust.entity.enums.Severity;
import com.zerotrust.entity.enums.ThreatType;
import com.zerotrust.security.RateLimitingFilter;
import com.zerotrust.service.AuditService;
import com.zerotrust.service.ThreatService;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class ThreatFilterRemediationTest {

    private ThreatDetectionEngine threatDetectionEngine;
    private ThreatScoreCalculator threatScoreCalculator;
    private ThreatService threatService;
    private AuditService auditService;
    private RateLimitingFilter rateLimitingFilter;
    private ObjectMapper objectMapper;
    private ThreatInspectionFilter filter;

    @BeforeEach
    void setUp() {
        threatDetectionEngine = mock(ThreatDetectionEngine.class);
        threatScoreCalculator = mock(ThreatScoreCalculator.class);
        threatService = mock(ThreatService.class);
        auditService = mock(AuditService.class);
        rateLimitingFilter = mock(RateLimitingFilter.class);
        objectMapper = new ObjectMapper();

        filter = new ThreatInspectionFilter(
            threatDetectionEngine,
            threatScoreCalculator,
            threatService,
            auditService,
            rateLimitingFilter,
            objectMapper
        );
        ReflectionTestUtils.setField(filter, "inspectionEnabled", true);

        when(rateLimitingFilter.resolveClientIp(any())).thenReturn("198.51.100.1");
    }

    @Test
    @DisplayName("1. SEC-P3-004: When database persistence throws an exception, blocked request STILL returns 403 and halts chain")
    void testPersistenceFailureStillBlocksRequest() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/customers");
        request.setQueryString("search=' OR '1'='1");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = mock(FilterChain.class);

        DetectionResult sqliResult = DetectionResult.threat(
            ThreatType.SQL_INJECTION, Severity.HIGH, "SQL_OR_TAUTOLOGY", "SQL injection tautology", 0.90
        );
        when(threatDetectionEngine.analyze(anyString(), anyString())).thenReturn(sqliResult);

        ThreatScoreCalculator.ScoreResult scoreResult = new ThreatScoreCalculator.ScoreResult(
            80, ThreatAction.BLOCKED, "Blocked score: 80"
        );
        when(threatScoreCalculator.calculate(any(), any(), any(), any(), any())).thenReturn(scoreResult);

        // Simulate PostgreSQL database outage / DataAccessException during forensic persistence
        doThrow(new org.springframework.dao.DataAccessResourceFailureException("PostgreSQL connection refused"))
            .when(threatService).recordThreatEvent(any(), any(), any(), any(), any(), any(), any(), any(), any(), anyInt());

        filter.doFilter(request, response, filterChain);

        // 1. Status MUST still be 403 Forbidden!
        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getContentAsString()).contains("BLOCKED");
        assertThat(response.getContentAsString()).contains("DEGRADED"); // Persistence degraded flag

        // 2. Downstream filterChain MUST NOT be executed!
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    @DisplayName("2. SEC-P3-003: ThreatService sanitizes sensitive credentials, JWTs, nested JSON and tokens")
    void testThreatServiceSanitizesSensitiveData() {
        ThreatService service = new ThreatService(mock(com.zerotrust.repository.ThreatEventRepository.class), threatDetectionEngine, mock(com.zerotrust.service.NotificationService.class));

        String rawPayload = """
            {
                "user": {
                    "username": "attacker",
                    "password": "MySuperSecretPassword123!",
                    "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signatureGoesHere",
                    "creditCard": "4532015012345678",
                    "cvv": 456
                },
                "token": "secret-api-token-value",
                "attack": "1 UNION SELECT null"
            }
            """;

        String sanitized = service.sanitizePayload(rawPayload);

        assertThat(sanitized).doesNotContain("MySuperSecretPassword123!");
        assertThat(sanitized).doesNotContain("signatureGoesHere");
        assertThat(sanitized).doesNotContain("secret-api-token-value");
        assertThat(sanitized).doesNotContain("456");
        assertThat(sanitized).contains("[REDACTED]");
    }

    @Test
    @DisplayName("3. SEC-P3-001: ThreatInspectionFilter rejects oversized JSON bodies with 413 Payload Too Large")
    void testFilterRejectsOversizedJsonBody() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/customers");
        request.setContentType("application/json");
        request.setContent("{\"padding\":\"".concat("Z".repeat(70000)).concat("\"}").getBytes(StandardCharsets.UTF_8));
        request.addHeader("Content-Length", "75000");

        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = mock(FilterChain.class);

        filter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(413);
        assertThat(response.getContentAsString()).contains("Payload Too Large");
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    @DisplayName("4. SEC-P3-002: Custom security filters have top-level servlet auto-registration disabled")
    void testFilterSecurityBeansHaveDisabledServletRegistration() {
        com.zerotrust.config.SecurityConfig config = new com.zerotrust.config.SecurityConfig(
            mock(com.zerotrust.security.JwtAuthenticationFilter.class),
            rateLimitingFilter,
            filter,
            mock(org.springframework.security.core.userdetails.UserDetailsService.class)
        );

        var jwtReg = config.jwtFilterRegistration(mock(com.zerotrust.security.JwtAuthenticationFilter.class));
        var rateReg = config.rateLimitingFilterRegistration(rateLimitingFilter);
        var threatReg = config.threatInspectionFilterRegistration(filter);

        assertThat(jwtReg.isEnabled()).isFalse();
        assertThat(rateReg.isEnabled()).isFalse();
        assertThat(threatReg.isEnabled()).isFalse();
    }
}
