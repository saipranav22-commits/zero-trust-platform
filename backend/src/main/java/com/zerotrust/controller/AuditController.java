package com.zerotrust.controller;

import com.zerotrust.dto.response.ApiResponse;
import com.zerotrust.dto.response.PageResponse;
import com.zerotrust.entity.AuditLog;
import com.zerotrust.service.AuditService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/audit")
@RequiredArgsConstructor
@Tag(name = "Audit Logs", description = "Immutable audit trail with hash-chain integrity verification")
public class AuditController {

    private final AuditService auditService;

    @GetMapping("/logs")
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY_ANALYST', 'AUDITOR')")
    @Operation(summary = "Search audit logs with filters")
    public ResponseEntity<ApiResponse<PageResponse<AuditLog>>> getLogs(
            @RequestParam(required = false) String userId,
            @RequestParam(required = false) String action,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) Instant from,
            @RequestParam(required = false) Instant to,
            @PageableDefault(size = 20, sort = "createdAt", direction = Sort.Direction.DESC)
            Pageable pageable) {
        var page = auditService.search(userId, action, status, from, to, pageable);
        return ResponseEntity.ok(ApiResponse.success(PageResponse.of(page)));
    }

    @GetMapping("/logs/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY_ANALYST', 'AUDITOR')")
    @Operation(summary = "Get specific audit log by ID")
    public ResponseEntity<ApiResponse<AuditLog>> getLogById(@PathVariable UUID id) {
        return ResponseEntity.ok(ApiResponse.success(auditService.getById(id)));
    }

    @GetMapping("/logs/{id}/verify")
    @PreAuthorize("hasAnyRole('ADMIN', 'AUDITOR')")
    @Operation(summary = "Verify audit log hash integrity", description = "Returns true if the log entry has not been tampered with")
    public ResponseEntity<ApiResponse<Map<String, Object>>> verifyIntegrity(@PathVariable UUID id) {
        boolean valid = auditService.verifyIntegrity(id);
        return ResponseEntity.ok(ApiResponse.success(
            Map.of("logId", id, "integrityValid", valid,
                   "message", valid ? "Log is authentic and untampered"
                                    : "⚠️ Log integrity check FAILED — possible tampering"),
            valid ? "Integrity verified" : "Integrity check failed"
        ));
    }

    @GetMapping("/chain/verify")
    @PreAuthorize("hasAnyRole('ADMIN', 'AUDITOR')")
    @Operation(summary = "Verify audit chain integrity across records", description = "Verifies monotonic sequence, link continuity and cryptographic content hashes")
    public ResponseEntity<ApiResponse<com.zerotrust.dto.response.AuditChainVerificationResult>> verifyChain(
            @RequestParam(required = false) Long fromSeq,
            @RequestParam(required = false) Long toSeq) {
        var result = auditService.verifyChain(fromSeq, toSeq);
        return ResponseEntity.ok(ApiResponse.success(
            result,
            result.chainValid() ? "Chain integrity verified" : "Chain integrity violation detected"
        ));
    }

    @PostMapping("/chain/checkpoint")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Create an immutable audit chain checkpoint")
    public ResponseEntity<ApiResponse<com.zerotrust.entity.AuditCheckpoint>> createCheckpoint(
            org.springframework.security.core.Authentication authentication) {
        String actor = authentication != null ? authentication.getName() : "ADMIN";
        var checkpoint = auditService.createCheckpoint(actor);
        return ResponseEntity.ok(ApiResponse.success(checkpoint, "Checkpoint created"));
    }

    @GetMapping("/chain/checkpoints")
    @PreAuthorize("hasAnyRole('ADMIN', 'AUDITOR')")
    @Operation(summary = "Get recent audit chain checkpoints")
    public ResponseEntity<ApiResponse<List<com.zerotrust.entity.AuditCheckpoint>>> getRecentCheckpoints() {
        return ResponseEntity.ok(ApiResponse.success(auditService.getRecentCheckpoints()));
    }

    @GetMapping("/users/{userId}/history")
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY_ANALYST', 'AUDITOR')")
    @Operation(summary = "Get audit history for a specific user")
    public ResponseEntity<ApiResponse<PageResponse<AuditLog>>> getUserHistory(
            @PathVariable String userId,
            @PageableDefault(size = 20, sort = "createdAt", direction = Sort.Direction.DESC)
            Pageable pageable) {
        var page = auditService.getUserHistory(userId, pageable);
        return ResponseEntity.ok(ApiResponse.success(PageResponse.of(page)));
    }

    @GetMapping("/logs/recent")
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY_ANALYST', 'AUDITOR')")
    @Operation(summary = "Get the 50 most recent audit log entries")
    public ResponseEntity<ApiResponse<List<AuditLog>>> getRecentLogs() {
        return ResponseEntity.ok(ApiResponse.success(auditService.getRecent50()));
    }
}
