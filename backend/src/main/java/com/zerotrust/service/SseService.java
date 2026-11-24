package com.zerotrust.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zerotrust.entity.Notification;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

@Slf4j
@Service
public class SseService {

    public record SseClient(
            UUID clientId,
            SseEmitter emitter,
            String userId,
            String userEmail,
            java.util.Set<String> roles) {
    }

    public record SseNotificationPayload(
            UUID id,
            String title,
            String description,
            String severity,
            String category,
            boolean isRead,
            String actionUrl,
            String iconType,
            java.time.Instant createdAt) {
        public static SseNotificationPayload from(Notification n) {
            return new SseNotificationPayload(
                    n.getId(),
                    n.getTitle(),
                    n.getDescription(),
                    n.getSeverity() != null ? n.getSeverity().name() : "LOW",
                    n.getCategory(),
                    n.isRead(),
                    n.getActionUrl(),
                    n.getIconType(),
                    n.getCreatedAt());
        }
    }

    private final Map<UUID, SseClient> clients = new ConcurrentHashMap<>();
    private final ObjectMapper objectMapper;
    private final com.zerotrust.repository.UserRepository userRepository;

    public SseService(ObjectMapper objectMapper) {
        this(objectMapper, null);
    }

    @org.springframework.beans.factory.annotation.Autowired
    public SseService(ObjectMapper objectMapper, com.zerotrust.repository.UserRepository userRepository) {
        this.objectMapper = objectMapper;
        this.userRepository = userRepository;
    }

    public SseEmitter registerClient() {
        return registerClient(null, null, java.util.Set.of());
    }

    public SseEmitter registerClient(String userId, String userEmail, java.util.Set<String> roles) {
        // Create emitter with 2 hours timeout
        SseEmitter emitter = new SseEmitter(7200000L);
        UUID clientId = UUID.randomUUID();
        java.util.Set<String> safeRoles = (roles != null) ? java.util.Set.copyOf(roles) : java.util.Set.of();

        SseClient client = new SseClient(clientId, emitter, userId, userEmail, safeRoles);
        clients.put(clientId, client);

        emitter.onCompletion(() -> clients.remove(clientId));
        emitter.onTimeout(() -> clients.remove(clientId));
        emitter.onError((e) -> clients.remove(clientId));

        // Send initial heartbeat
        try {
            emitter.send(SseEmitter.event().name("connection").data("connected"));
        } catch (IOException e) {
            clients.remove(clientId);
        }

        log.debug("SSE client registered: id={}, user={}, roles={}", clientId, userEmail, safeRoles);
        return emitter;
    }

    public void broadcastNotification(Notification notification) {
        log.info("Broadcasting notification [id={}, category={}, severity={}] across {} active SSE clients",
                notification.getId(), notification.getCategory(), notification.getSeverity(), clients.size());

        List<UUID> deadClients = new CopyOnWriteArrayList<>();
        SseNotificationPayload sanitizedPayload = SseNotificationPayload.from(notification);

        for (Map.Entry<UUID, SseClient> entry : clients.entrySet()) {
            SseClient client = entry.getValue();

            // Enforce server-side recipient authorization
            if (!isAuthorizedToReceive(client, notification)) {
                log.debug("Skipping SSE notification for client {} (insufficient role / not target recipient)",
                        client.clientId());
                continue;
            }

            try {
                String json = objectMapper.writeValueAsString(sanitizedPayload);
                client.emitter().send(SseEmitter.event().name("notification").data(json));
            } catch (Exception e) {
                log.warn("Failed to send notification to client: {}", client.clientId());
                deadClients.add(client.clientId());
            }
        }

        // Clean up disconnected clients
        for (UUID deadId : deadClients) {
            clients.remove(deadId);
        }
    }

    /**
     * Determines whether a client connection is authorized to receive a given
     * notification.
     * Revalidates account status and dynamically revoked roles against persistent
     * user state.
     */
    public boolean isAuthorizedToReceive(SseClient client, Notification notification) {
        if (client == null || notification == null) {
            return false;
        }

        java.util.Set<String> effectiveRoles = client.roles();

        // Dynamically revalidate user active status and live roles if database
        // repository is available
        if (userRepository != null && client.userId() != null && !client.userId().isBlank()) {
            try {
                UUID uid = UUID.fromString(client.userId());
                var userOpt = userRepository.findById(uid);
                if (userOpt.isEmpty()) {
                    log.warn("Disconnecting SSE client {}: user {} not found in database", client.clientId(),
                            client.userId());
                    disconnectClient(client.clientId());
                    if (client.emitter() != null) {
                        try {
                            client.emitter().complete();
                        } catch (Exception ignored) {
                        }
                    }
                    return false;
                }
                var user = userOpt.get();
                if (!user.isActive() || user.isAccountCurrentlyLocked()) {
                    log.warn("Disconnecting SSE client {}: account for {} is disabled or locked", client.clientId(),
                            user.getEmail());
                    disconnectClient(client.clientId());
                    if (client.emitter() != null) {
                        try {
                            client.emitter().complete();
                        } catch (Exception ignored) {
                        }
                    }
                    return false;
                }
                // Refresh roles dynamically from database to catch revoked privileges on
                // long-lived connections
                effectiveRoles = java.util.Set.copyOf(user.getRoleNames());
            } catch (IllegalArgumentException ignored) {
                // Non-UUID client identifier
            }
        }

        boolean isAdmin = effectiveRoles.contains("ROLE_ADMIN");
        boolean isAnalyst = effectiveRoles.contains("ROLE_SECURITY_ANALYST");
        boolean isAuditor = effectiveRoles.contains("ROLE_AUDITOR");

        // 1. If notification is specifically targeted to a user
        if (notification.getRelatedUserId() != null) {
            String targetUserId = notification.getRelatedUserId().toString();
            // Admins can see all events; otherwise must match client userId
            return isAdmin || (client.userId() != null && client.userId().equals(targetUserId));
        }

        // 2. Security Threat & Incident Alerts: ADMIN and SECURITY_ANALYST only
        String category = notification.getCategory() != null ? notification.getCategory().toUpperCase() : "";
        if ("THREAT_DETECTION".equals(category) || "INCIDENT".equals(category) || "SECURITY".equals(category)) {
            return isAdmin || isAnalyst;
        }

        // 3. High / Critical severity alerts: ADMIN and SECURITY_ANALYST only
        if (notification.getSeverity() == com.zerotrust.entity.enums.Severity.CRITICAL ||
                notification.getSeverity() == com.zerotrust.entity.enums.Severity.HIGH) {
            return isAdmin || isAnalyst;
        }

        // 4. Audit Log alerts: ADMIN, SECURITY_ANALYST, AUDITOR
        if ("AUDIT".equals(category)) {
            return isAdmin || isAnalyst || isAuditor;
        }

        // 5. General announcements / system notifications: open to all authenticated
        // users
        return true;
    }

    public void disconnectClient(UUID clientId) {
        SseClient removed = clients.remove(clientId);
        if (removed != null && removed.emitter() != null) {
            try {
                removed.emitter().complete();
            } catch (Exception ignored) {
            }
        }
    }

    /**
     * Proactively evicts any active SSE connection associated with a specific user.
     * Invoked immediately upon account lockout, deactivation, or permission
     * changes.
     */
    public void evictClientByUserId(UUID userId) {
        if (userId == null)
            return;
        String uidStr = userId.toString();
        for (Map.Entry<UUID, SseClient> entry : clients.entrySet()) {
            SseClient client = entry.getValue();
            if (uidStr.equals(client.userId())) {
                log.info("Proactively evicting SSE connection for revoked/locked user {}", uidStr);
                disconnectClient(client.clientId());
                if (client.emitter() != null) {
                    try {
                        client.emitter().complete();
                    } catch (Exception ignored) {
                    }
                }
            }
        }
    }

    /**
     * Bounded periodic invalidation: sweeps active connections every 30 seconds and
     * evicts
     * any client whose underlying account has been deactivated, locked, or deleted
     * while idle.
     */
    @Scheduled(fixedRate = 30000)
    public void evictInvalidClients() {
        if (userRepository == null || clients.isEmpty())
            return;
        for (Map.Entry<UUID, SseClient> entry : clients.entrySet()) {
            SseClient client = entry.getValue();
            if (client.userId() == null || client.userId().isBlank())
                continue;
            try {
                UUID uid = UUID.fromString(client.userId());
                var userOpt = userRepository.findById(uid);
                if (userOpt.isEmpty() || !userOpt.get().isActive() || userOpt.get().isAccountCurrentlyLocked()) {
                    log.warn("Periodic eviction: terminating idle SSE client {} (user inactive/locked)",
                            client.clientId());
                    disconnectClient(client.clientId());
                    if (client.emitter() != null) {
                        try {
                            client.emitter().complete();
                        } catch (Exception ignored) {
                        }
                    }
                }
            } catch (Exception ignored) {
            }
        }
    }

    public int getActiveClientCount() {
        return clients.size();
    }
}
