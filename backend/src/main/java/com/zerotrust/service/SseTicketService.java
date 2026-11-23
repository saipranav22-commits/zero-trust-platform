package com.zerotrust.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Service managing short-lived, single-use tickets for Server-Sent Events (SSE).
 *
 * <p>Security Rationale:
 * Standard browser EventSource API does not support custom HTTP headers (such as Authorization: Bearer).
 * Passing long-lived access tokens or refresh tokens in query strings leaks credentials to proxy logs,
 * browser history, and server access logs.
 *
 * <p>This service provides a short-lived (30-second), single-use ticket pattern:
 * 1. An authenticated client requests a ticket via a standard authenticated POST endpoint.
 * 2. The ticket is single-use and consumed immediately upon establishing the SSE connection.
 * 3. Expired or replayed tickets are rejected with 401 Unauthorized.
 */
@Slf4j
@Service
public class SseTicketService {

    public record TicketData(String userId, String userEmail, java.util.Set<String> roles, Instant expiresAt) {
        public TicketData(String userId, String userEmail, Instant expiresAt) {
            this(userId, userEmail, java.util.Set.of(), expiresAt);
        }
    }

    private final Map<String, TicketData> activeTickets = new ConcurrentHashMap<>();
    private final SecureRandom secureRandom = new SecureRandom();
    private static final long TICKET_VALIDITY_SECONDS = 30L;

    /**
     * Issues a short-lived single-use ticket for the authenticated user without explicit roles.
     */
    public String createTicket(String userId, String userEmail) {
        return createTicket(userId, userEmail, java.util.Set.of());
    }

    /**
     * Issues a short-lived single-use ticket for the authenticated user with explicit role entitlements.
     */
    public String createTicket(String userId, String userEmail, java.util.Set<String> roles) {
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        String ticket = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);

        Instant expiresAt = Instant.now().plusSeconds(TICKET_VALIDITY_SECONDS);
        java.util.Set<String> safeRoles = (roles != null) ? java.util.Set.copyOf(roles) : java.util.Set.of();
        activeTickets.put(ticket, new TicketData(userId, userEmail, safeRoles, expiresAt));
        log.debug("Issued SSE stream ticket for user {} with roles {} (valid for {}s)", userEmail, safeRoles, TICKET_VALIDITY_SECONDS);
        return ticket;
    }

    /**
     * Validates and immediately consumes (removes) a ticket.
     * Single-use guarantees that replay attacks are impossible.
     *
     * @return TicketData if valid, or null if invalid, expired, or already consumed.
     */
    public TicketData validateAndConsume(String ticket) {
        if (ticket == null || ticket.isBlank()) {
            return null;
        }

        TicketData data = activeTickets.remove(ticket);
        if (data == null) {
            log.warn("Rejected invalid or already-consumed SSE ticket");
            return null;
        }

        if (data.expiresAt().isBefore(Instant.now())) {
            log.warn("Rejected expired SSE ticket for user {}", data.userEmail());
            return null;
        }

        log.debug("Successfully validated and consumed SSE ticket for user {}", data.userEmail());
        return data;
    }

    /**
     * Purges stale expired tickets periodically to prevent memory accumulation.
     */
    @Scheduled(fixedRate = 60000)
    public void purgeExpiredTickets() {
        Instant now = Instant.now();
        int initialSize = activeTickets.size();
        activeTickets.entrySet().removeIf(entry -> entry.getValue().expiresAt().isBefore(now));
        int purged = initialSize - activeTickets.size();
        if (purged > 0) {
            log.debug("Purged {} expired SSE stream tickets", purged);
        }
    }
}
