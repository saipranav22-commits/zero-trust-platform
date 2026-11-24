package com.zerotrust.controller;

import com.zerotrust.dto.request.IncidentAssignRequest;
import com.zerotrust.dto.request.IncidentCreateRequest;
import com.zerotrust.dto.request.IncidentNoteRequest;
import com.zerotrust.dto.request.IncidentStatusUpdateRequest;
import com.zerotrust.dto.response.ApiResponse;
import com.zerotrust.dto.response.IncidentResponse;
import com.zerotrust.dto.response.PageResponse;
import com.zerotrust.entity.enums.IncidentStatus;
import com.zerotrust.entity.enums.Severity;
import com.zerotrust.service.IncidentService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/incidents")
@RequiredArgsConstructor
@Tag(name = "Incident Management", description = "Security incident lifecycle operations and timeline tracking")
public class IncidentController {

    private final IncidentService incidentService;

    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY_ANALYST', 'AUDITOR')")
    @Operation(summary = "Search and filter security incidents")
    public ResponseEntity<ApiResponse<PageResponse<IncidentResponse>>> search(
            @RequestParam(required = false) String search,
            @RequestParam(required = false) IncidentStatus status,
            @RequestParam(required = false) Severity severity,
            @RequestParam(required = false) String category,
            @RequestParam(required = false) String assignedTo,
            @PageableDefault(size = 20, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable) {
        var page = incidentService.search(search, status, severity, category, assignedTo, pageable);
        return ResponseEntity.ok(ApiResponse.success(PageResponse.of(page)));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY_ANALYST', 'AUDITOR')")
    @Operation(summary = "Get detailed security incident with historical timeline")
    public ResponseEntity<ApiResponse<IncidentResponse>> getById(@PathVariable UUID id) {
        return ResponseEntity.ok(ApiResponse.success(incidentService.getById(id)));
    }

    @PostMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY_ANALYST')")
    @Operation(summary = "Create a new security incident")
    public ResponseEntity<ApiResponse<IncidentResponse>> create(
            @Valid @RequestBody IncidentCreateRequest request,
            Authentication authentication) {
        String createdBy = authentication != null ? authentication.getName() : "ANALYST";
        var incident = incidentService.createIncident(request, createdBy);
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.success(incident, "Incident created"));
    }

    @PutMapping("/{id}/status")
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY_ANALYST')")
    @Operation(summary = "Update incident lifecycle status (Acknowledge, Investigate, Resolve, Reopen)")
    public ResponseEntity<ApiResponse<IncidentResponse>> updateStatus(
            @PathVariable UUID id,
            @Valid @RequestBody IncidentStatusUpdateRequest request,
            Authentication authentication) {
        String performedBy = authentication != null ? authentication.getName() : "ANALYST";
        var incident = incidentService.updateStatus(id, request, performedBy);
        return ResponseEntity.ok(ApiResponse.success(incident, "Incident status updated"));
    }

    @PutMapping("/{id}/assign")
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY_ANALYST')")
    @Operation(summary = "Assign incident to a security analyst")
    public ResponseEntity<ApiResponse<IncidentResponse>> assign(
            @PathVariable UUID id,
            @Valid @RequestBody IncidentAssignRequest request,
            Authentication authentication) {
        String performedBy = authentication != null ? authentication.getName() : "ANALYST";
        var incident = incidentService.assignIncident(id, request, performedBy);
        return ResponseEntity.ok(ApiResponse.success(incident, "Incident assigned"));
    }

    @PostMapping("/{id}/notes")
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY_ANALYST')")
    @Operation(summary = "Add an investigation note to the incident timeline")
    public ResponseEntity<ApiResponse<IncidentResponse>> addNote(
            @PathVariable UUID id,
            @Valid @RequestBody IncidentNoteRequest request,
            Authentication authentication) {
        String performedBy = authentication != null ? authentication.getName() : "ANALYST";
        var incident = incidentService.addNote(id, request, performedBy);
        return ResponseEntity.ok(ApiResponse.success(incident, "Note added to timeline"));
    }
}
