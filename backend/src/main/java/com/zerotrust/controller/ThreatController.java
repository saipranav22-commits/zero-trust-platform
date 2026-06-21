package com.zerotrust.controller;

import com.zerotrust.dto.response.ApiResponse;
import com.zerotrust.dto.response.PageResponse;
import com.zerotrust.entity.ThreatEvent;
import com.zerotrust.entity.enums.ThreatStatus;
import com.zerotrust.service.ThreatService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/threats")
@RequiredArgsConstructor
@Tag(name = "Threat Detection", description = "APIs for viewing and analyzing detected security threats")
public class ThreatController {

    private final ThreatService threatService;

    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY_ANALYST', 'AUDITOR')")
    @Operation(summary = "Search threat events with filters")
    public ResponseEntity<ApiResponse<PageResponse<ThreatEvent>>> getThreats(
            @RequestParam(required = false) String threatType,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String sourceIp,
            @RequestParam(required = false) Instant from,
            @RequestParam(required = false) Instant to,
            @PageableDefault(size = 20, sort = "createdAt", direction = Sort.Direction.DESC)
            Pageable pageable) {
        var page = threatService.search(threatType, severity, status, sourceIp, from, to, pageable);
        return ResponseEntity.ok(ApiResponse.success(PageResponse.of(page)));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY_ANALYST', 'AUDITOR')")
    @Operation(summary = "Get a specific threat event by ID")
    public ResponseEntity<ApiResponse<ThreatEvent>> getThreatById(@PathVariable UUID id) {
        return ResponseEntity.ok(ApiResponse.success(threatService.getById(id)));
    }

    @GetMapping("/recent")
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY_ANALYST', 'AUDITOR')")
    @Operation(summary = "Get the 10 most recent threat events")
    public ResponseEntity<ApiResponse<List<ThreatEvent>>> getRecentThreats() {
        return ResponseEntity.ok(ApiResponse.success(threatService.getRecent()));
    }

    @GetMapping("/statistics")
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY_ANALYST')")
    @Operation(summary = "Get threat analytics and statistics")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getStatistics(
            @RequestParam(defaultValue = "30") int days) {
        return ResponseEntity.ok(ApiResponse.success(threatService.getStatistics(days)));
    }

    @PutMapping("/{id}/status")
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY_ANALYST')")
    @Operation(summary = "Update the status of a threat event (investigate, resolve, mark false positive)")
    public ResponseEntity<ApiResponse<ThreatEvent>> updateStatus(
            @PathVariable UUID id,
            @RequestBody Map<String, String> body,
            HttpServletRequest request) {
        ThreatStatus newStatus = ThreatStatus.valueOf(body.get("status").toUpperCase());
        String resolvedBy = (String) request.getAttribute("userEmail");
        String notes = body.get("notes");
        return ResponseEntity.ok(ApiResponse.success(
            threatService.updateStatus(id, newStatus, resolvedBy, notes),
            "Threat status updated"));
    }

    @PostMapping("/analyze")
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY_ANALYST')")
    @Operation(summary = "Analyze arbitrary input for threats (testing endpoint)")
    public ResponseEntity<ApiResponse<Map<String, Object>>> analyzeInput(
            @RequestBody Map<String, String> body,
            HttpServletRequest request) {
        String input      = body.get("input");
        String targetPath = body.getOrDefault("targetPath", "/test");
        String method     = body.getOrDefault("method", "POST");
        String sourceIp   = (String) request.getAttribute("userId");
        String userEmail  = (String) request.getAttribute("userEmail");

        ThreatEvent event = threatService.analyze(
            input, sourceIp, userEmail, request.getRemoteAddr(), targetPath, method);

        if (event != null) {
            return ResponseEntity.ok(ApiResponse.success(
                Map.of("threatDetected", true, "event", event),
                "Threat detected and logged"));
        }
        return ResponseEntity.ok(ApiResponse.success(
            Map.of("threatDetected", false),
            "Input appears clean"));
    }
}
