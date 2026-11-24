package com.zerotrust.threat;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zerotrust.entity.enums.AuditStatus;
import com.zerotrust.security.RateLimitingFilter;
import com.zerotrust.service.AuditService;
import com.zerotrust.service.ThreatService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;

/**
 * Real-Time HTTP Threat Inspection Filter.
 * Inspects incoming request paths, query parameters, and buffered JSON/text request bodies
 * for SQL injection, XSS, path traversal, and command injection patterns.
 * Evaluates contextual risk scores and applies deterministic BLOCK / FLAG / ALLOW policies.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ThreatInspectionFilter extends OncePerRequestFilter {

    private final ThreatDetectionEngine threatDetectionEngine;
    private final ThreatScoreCalculator threatScoreCalculator;
    private final ThreatService threatService;
    private final AuditService auditService;
    private final RateLimitingFilter rateLimitingFilter;
    private final ObjectMapper objectMapper;

    @Value("${app.threat-detection.enabled:true}")
    private boolean inspectionEnabled;

    private static final int MAX_INSPECTABLE_PAYLOAD_BYTES = 65536; // 64 KB

    @Override
    protected boolean shouldNotFilter(@NonNull HttpServletRequest request) {
        String path = request.getRequestURI();
        return !inspectionEnabled
            || path.startsWith("/actuator")
            || path.startsWith("/api-docs")
            || path.startsWith("/swagger-ui")
            || path.equals("/favicon.ico");
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        CachedBodyHttpServletRequest wrappedRequest = new CachedBodyHttpServletRequest(request, MAX_INSPECTABLE_PAYLOAD_BYTES);

        String path = wrappedRequest.getRequestURI();
        String queryString = wrappedRequest.getQueryString();
        String method = wrappedRequest.getMethod();
        String clientIp = rateLimitingFilter.resolveClientIp(wrappedRequest);
        String userId = (String) wrappedRequest.getAttribute("userId");
        String userEmail = (String) wrappedRequest.getAttribute("userEmail");
        String correlationId = wrappedRequest.getHeader("X-Correlation-Id");
        if (!StringUtils.hasText(correlationId)) {
            correlationId = UUID.randomUUID().toString();
        }
        response.setHeader("X-Correlation-Id", correlationId);

        // SEC-P3-001: Reject oversized payloads on text/JSON endpoints with HTTP 413 Payload Too Large
        if (wrappedRequest.isPayloadTooLarge()) {
            log.warn("🛡️ HTTP REQUEST REJECTED (413 Payload Too Large) Path: {} IP: {} Max Allowed: {} bytes",
                path, clientIp, MAX_INSPECTABLE_PAYLOAD_BYTES);
            response.setStatus(HttpStatus.PAYLOAD_TOO_LARGE.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            Map<String, Object> errorBody = Map.of(
                "success", false,
                "status", 413,
                "error", "Payload Too Large",
                "message", "Request body exceeds maximum allowable limit of " + MAX_INSPECTABLE_PAYLOAD_BYTES + " bytes.",
                "correlationId", correlationId
            );
            response.getWriter().write(objectMapper.writeValueAsString(errorBody));
            return; // Halt chain immediately
        }

        // 1. Inspect URI Path
        String decodedPath = path;
        try {
            decodedPath = URLDecoder.decode(path, StandardCharsets.UTF_8);
        } catch (Exception ignored) {}
        DetectionResult pathDetection = threatDetectionEngine.analyze(decodedPath, clientIp);
        if (!pathDetection.threatDetected() && !path.equals(decodedPath)) {
            pathDetection = threatDetectionEngine.analyze(path, clientIp);
        }
        if (pathDetection.threatDetected()) {
            if (handleDetection(wrappedRequest, response, filterChain, decodedPath, pathDetection, path, method, clientIp, userId, userEmail, correlationId)) {
                return; // Blocked
            }
        }

        // 2. Inspect Query Parameters
        if (StringUtils.hasText(queryString)) {
            String decodedQueryString = queryString;
            try {
                decodedQueryString = URLDecoder.decode(queryString, StandardCharsets.UTF_8);
            } catch (Exception ignored) {}
            DetectionResult queryDetection = threatDetectionEngine.analyze(decodedQueryString, clientIp);
            if (!queryDetection.threatDetected() && !queryString.equals(decodedQueryString)) {
                queryDetection = threatDetectionEngine.analyze(queryString, clientIp);
            }
            if (queryDetection.threatDetected()) {
                if (handleDetection(wrappedRequest, response, filterChain, decodedQueryString, queryDetection, path, method, clientIp, userId, userEmail, correlationId)) {
                    return; // Blocked
                }
            }
        }

        // 3. Inspect Parameter Map (parsed parameters)
        for (Map.Entry<String, String[]> entry : wrappedRequest.getParameterMap().entrySet()) {
            for (String val : entry.getValue()) {
                if (StringUtils.hasText(val)) {
                    DetectionResult paramDetection = threatDetectionEngine.analyze(val, clientIp);
                    if (paramDetection.threatDetected()) {
                        if (handleDetection(wrappedRequest, response, filterChain, entry.getKey() + "=" + val, paramDetection, path, method, clientIp, userId, userEmail, correlationId)) {
                            return; // Blocked
                        }
                    }
                }
            }
        }

        // 4. Inspect Body (if text/json and cached)
        if (wrappedRequest.isBodyCached()) {
            String rawBody = wrappedRequest.getBodyAsString();
            if (StringUtils.hasText(rawBody)) {
                String inspectableBody = maskCredentialFields(rawBody, path);
                DetectionResult bodyDetection = threatDetectionEngine.analyze(inspectableBody, clientIp);
                if (bodyDetection.threatDetected()) {
                    if (handleDetection(wrappedRequest, response, filterChain, inspectableBody, bodyDetection, path, method, clientIp, userId, userEmail, correlationId)) {
                        return; // Blocked
                    }
                }
            }
        }

        // Initialize baseline contextual signals if no threat was detected
        if (wrappedRequest.getAttribute("riskScore") == null) {
            wrappedRequest.setAttribute("riskScore", 0);
            wrappedRequest.setAttribute("threatLevel", "NORMAL");
        }

        filterChain.doFilter(wrappedRequest, response);
    }

    private boolean handleDetection(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain,
            String payload,
            DetectionResult detection,
            String path,
            String method,
            String clientIp,
            String userId,
            String userEmail,
            String correlationId) throws IOException, ServletException {

        ThreatScoreCalculator.ScoreResult scoreResult =
            threatScoreCalculator.calculate(detection, path, method, clientIp, userEmail);

        if (scoreResult.action() == ThreatAction.BLOCKED) {
            log.error("🛡️ HTTP THREAT BLOCKED [{} - {}] Path: {} IP: {} Rule: {} Score: {} Correlation: {}",
                detection.threatType(), detection.severity(), path, clientIp, detection.detectionRule(), scoreResult.score(), correlationId);

            boolean persistenceSucceeded = true;
            try {
                // Persist threat event in independent transaction
                threatService.recordThreatEvent(
                    payload, userId, userEmail, clientIp, path, method, correlationId,
                    detection, ThreatAction.BLOCKED, scoreResult.score()
                );

                // Persist audit record
                auditService.log(
                    userId, userEmail, "THREAT_BLOCKED", "API", path, clientIp,
                    request.getHeader("User-Agent"), AuditStatus.BLOCKED, scoreResult.score(),
                    "Request blocked by Threat Inspection Engine: " + detection.detectionRule()
                );
            } catch (Exception ex) {
                persistenceSucceeded = false;
                log.error("⚠️ Operational error: Forensic persistence failed for blocked threat [Correlation: {}]. Database may be unavailable (Error: {})",
                    correlationId, ex.getClass().getSimpleName());
            }

            // CRITICAL: Blocked requests must NEVER reach downstream business logic even if persistence fails
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            Map<String, Object> errorBody = Map.of(
                "success", false,
                "status", 403,
                "message", "Request blocked by Zero Trust Threat Detection Engine: malicious pattern detected.",
                "action", "BLOCKED",
                "actionTaken", "BLOCKED",
                "threatType", detection.threatType().name(),
                "detectionRule", detection.detectionRule(),
                "riskScore", scoreResult.score(),
                "correlationId", correlationId,
                "persistence", persistenceSucceeded ? "COMMITTED" : "DEGRADED"
            );
            response.getWriter().write(objectMapper.writeValueAsString(errorBody));
            return true; // Request halted
        }

        if (scoreResult.action() == ThreatAction.FLAGGED) {
            log.warn("⚠️ HTTP THREAT FLAGGED [{} - {}] Path: {} IP: {} Rule: {} Score: {}",
                detection.threatType(), detection.severity(), path, clientIp, detection.detectionRule(), scoreResult.score());

            // Propagate trusted server-side contextual threat signals to SecurityContext
            request.setAttribute("riskScore", scoreResult.score());
            request.setAttribute("threatLevel", scoreResult.score() >= 70 ? "CRITICAL" : "ELEVATED");

            try {
                threatService.recordThreatEvent(
                    payload, userId, userEmail, clientIp, path, method, correlationId,
                    detection, ThreatAction.FLAGGED, scoreResult.score()
                );

                auditService.log(
                    userId, userEmail, "THREAT_FLAGGED", "API", path, clientIp,
                    request.getHeader("User-Agent"), AuditStatus.SUCCESS, scoreResult.score(),
                    "Suspicious pattern flagged: " + detection.detectionRule()
                );
            } catch (Exception ex) {
                log.warn("Operational warning: Forensic persistence failed for flagged threat [Correlation: {}]. Error: {}",
                    correlationId, ex.getClass().getSimpleName());
            }
        }

        return false; // Request allowed to proceed
    }

    private String maskCredentialFields(String body, String path) {
        if (!StringUtils.hasText(body)) {
            return "";
        }
        // SEC-P3-003: Sanitize sensitive fields (passwords, tokens, pins, cards)
        return body
            .replaceAll("(?i)Bearer\\s+[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*", "Bearer [REDACTED_JWT]")
            .replaceAll("(?i)\\b(ey[A-Za-z0-9-_]{10,}\\.[A-Za-z0-9-_]{10,}\\.[A-Za-z0-9-_]{10,})\\b", "[REDACTED_JWT]")
            .replaceAll("(?i)\"(password|passwd|pwd|secret|token|refreshToken|accessToken|apiKey|creditCard|card_number|cardNumber|cvv|cvc|pin|ssn)\"\\s*:\\s*(\"[^\"]*\"|\\d+)", "\"$1\":\"[REDACTED]\"")
            .replaceAll("(?i)(password|passwd|pwd|secret|token|refreshToken|accessToken|apiKey|creditCard|card_number|cardNumber|cvv|cvc|pin|ssn)=[^&; \\t\\r\\n]+", "$1=[REDACTED]")
            .replaceAll("\\b(?:\\d[ -]*?){13,19}\\b", "[REDACTED_CARD]");
    }
}
