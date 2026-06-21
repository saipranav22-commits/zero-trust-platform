package com.zerotrust.controller;

import com.zerotrust.dto.response.ApiResponse;
import com.zerotrust.service.AiService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/ai")
@RequiredArgsConstructor
@Tag(name = "AI Security Assistant", description = "RAG-powered security intelligence using Gemini AI")
public class AiController {

    private final AiService aiService;

    @PostMapping("/chat")
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY_ANALYST')")
    @Operation(summary = "Chat with AI security assistant",
               description = "Ask security questions. Uses Gemini AI + knowledge base for answers.")
    public ResponseEntity<ApiResponse<Map<String, String>>> chat(
            @RequestBody Map<String, String> body) {
        String question = body.getOrDefault("question", "").trim();
        if (question.isBlank()) {
            return ResponseEntity.badRequest()
                .body(ApiResponse.error("Question cannot be empty"));
        }
        String answer = aiService.chat(question);
        return ResponseEntity.ok(ApiResponse.success(
            Map.of("question", question, "answer", answer),
            "AI response generated"));
    }

    @PostMapping("/explain-threat")
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY_ANALYST')")
    @Operation(summary = "Get AI explanation for a threat event",
               description = "Provides root cause analysis, impact assessment, and remediation steps")
    public ResponseEntity<ApiResponse<Map<String, String>>> explainThreat(
            @RequestBody Map<String, String> body) {
        String threatType     = body.getOrDefault("threatType", "UNKNOWN");
        String severity       = body.getOrDefault("severity", "MEDIUM");
        String sourceIp       = body.getOrDefault("sourceIp", "unknown");
        String attackPayload  = body.getOrDefault("attackPayload", "N/A");
        String detectionRule  = body.getOrDefault("detectionRule", "N/A");
        String targetResource = body.getOrDefault("targetResource", "N/A");

        String explanation = aiService.explainThreat(
            threatType, severity, sourceIp, attackPayload, detectionRule, targetResource);

        return ResponseEntity.ok(ApiResponse.success(
            Map.of("threatType", threatType, "explanation", explanation),
            "Threat explanation generated"));
    }

    @PostMapping("/generate-report")
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY_ANALYST')")
    @Operation(summary = "Generate AI security report",
               description = "Produces an executive security summary based on current metrics")
    public ResponseEntity<ApiResponse<Map<String, Object>>> generateReport(
            @RequestBody Map<String, Object> metrics) {
        int totalThreats   = (int) metrics.getOrDefault("totalThreats", 0);
        int criticalThreats = (int) metrics.getOrDefault("criticalThreats", 0);
        int failedLogins   = (int) metrics.getOrDefault("failedLogins", 0);
        int securityScore  = (int) metrics.getOrDefault("securityScore", 100);

        @SuppressWarnings("unchecked")
        Map<String, Long> threatsByType = (Map<String, Long>) metrics.getOrDefault("threatsByType", Map.of());

        String report = aiService.generateReport(
            totalThreats, criticalThreats, failedLogins, securityScore, threatsByType);

        return ResponseEntity.ok(ApiResponse.success(
            Map.of("report", report, "generatedAt", java.time.Instant.now().toString()),
            "Security report generated"));
    }
}
