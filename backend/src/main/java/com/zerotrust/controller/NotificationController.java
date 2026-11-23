package com.zerotrust.controller;

import com.zerotrust.dto.response.ApiResponse;
import com.zerotrust.dto.response.PageResponse;
import com.zerotrust.entity.Notification;
import com.zerotrust.entity.enums.Severity;
import com.zerotrust.exception.UnauthorizedException;
import com.zerotrust.service.NotificationService;
import com.zerotrust.service.SseService;
import com.zerotrust.service.SseTicketService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/notifications")
@RequiredArgsConstructor
@Tag(name = "Notification Center", description = "Enterprise notification management with real-time SSE streaming")
public class NotificationController {

    private final NotificationService notificationService;
    private final SseService sseService;
    private final SseTicketService sseTicketService;

    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY_ANALYST', 'AUDITOR')")
    @Operation(summary = "Get all notifications with filters")
    public ResponseEntity<ApiResponse<PageResponse<Notification>>> getNotifications(
            @RequestParam(required = false) String search,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String category,
            @RequestParam(required = false) Boolean isRead,
            @RequestParam(required = false) Instant start,
            @RequestParam(required = false) Instant end,
            @PageableDefault(size = 20, sort = "createdAt", direction = Sort.Direction.DESC)
            Pageable pageable) {
        Severity sev = (severity != null && !severity.isBlank()) ? Severity.valueOf(severity.toUpperCase()) : null;
        var page = notificationService.getNotifications(search, sev, category, isRead, start, end, pageable);
        return ResponseEntity.ok(ApiResponse.success(PageResponse.of(page)));
    }

    @GetMapping("/unread-count")
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY_ANALYST', 'AUDITOR')")
    @Operation(summary = "Get count of unread notifications")
    public ResponseEntity<ApiResponse<Map<String, Long>>> getUnreadCount() {
        long count = notificationService.getUnreadCount();
        return ResponseEntity.ok(ApiResponse.success(Map.of("unreadCount", count)));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY_ANALYST', 'AUDITOR')")
    @Operation(summary = "Get a specific notification by ID")
    public ResponseEntity<ApiResponse<Notification>> getNotification(@PathVariable UUID id) {
        return ResponseEntity.ok(ApiResponse.success(notificationService.getNotification(id)));
    }

    @PatchMapping("/{id}/read")
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY_ANALYST', 'AUDITOR')")
    @Operation(summary = "Mark a notification as read")
    public ResponseEntity<ApiResponse<Notification>> markAsRead(@PathVariable UUID id) {
        return ResponseEntity.ok(ApiResponse.success(
            notificationService.markAsRead(id), "Notification marked as read"));
    }

    @PatchMapping("/read-all")
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY_ANALYST', 'AUDITOR')")
    @Operation(summary = "Mark all notifications as read")
    public ResponseEntity<ApiResponse<Map<String, String>>> markAllAsRead() {
        notificationService.markAllAsRead();
        return ResponseEntity.ok(ApiResponse.success(
            Map.of("message", "All notifications marked as read"), "All notifications marked as read"));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY_ANALYST')")
    @Operation(summary = "Delete a notification")
    public ResponseEntity<ApiResponse<Map<String, String>>> deleteNotification(@PathVariable UUID id) {
        notificationService.deleteNotification(id);
        return ResponseEntity.ok(ApiResponse.success(
            Map.of("message", "Notification deleted"), "Notification deleted"));
    }

    @PostMapping("/stream-ticket")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Generate short-lived single-use SSE stream ticket")
    public ResponseEntity<ApiResponse<Map<String, String>>> generateStreamTicket(
            HttpServletRequest request,
            Authentication authentication) {
        String userId = (String) request.getAttribute("userId");
        String userEmail = authentication != null ? authentication.getName() : (String) request.getAttribute("userEmail");
        java.util.Set<String> roles = (authentication != null && authentication.getAuthorities() != null)
            ? authentication.getAuthorities().stream()
                .map(org.springframework.security.core.GrantedAuthority::getAuthority)
                .collect(java.util.stream.Collectors.toSet())
            : java.util.Set.of();

        String ticket = sseTicketService.createTicket(userId, userEmail, roles);
        return ResponseEntity.ok(ApiResponse.success(Map.of("ticket", ticket), "SSE stream ticket issued"));
    }

    @GetMapping(value = "/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    @Operation(summary = "SSE stream for real-time notifications (requires valid ticket)")
    public SseEmitter streamNotifications(@RequestParam(name = "ticket", required = false) String ticket) {
        if (ticket == null || ticket.isBlank()) {
            throw new UnauthorizedException("Authentication ticket is required for SSE subscription");
        }
        var ticketData = sseTicketService.validateAndConsume(ticket);
        if (ticketData == null) {
            throw new UnauthorizedException("Invalid, expired, or already consumed SSE stream ticket");
        }
        return sseService.registerClient(ticketData.userId(), ticketData.userEmail(), ticketData.roles());
    }
}
