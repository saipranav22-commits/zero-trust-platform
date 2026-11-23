package com.zerotrust.security.abac;

import jakarta.servlet.http.HttpServletRequest;

import java.time.Instant;
import java.util.Map;

/**
 * ABAC Environmental Context: Encapsulates temporal, network, and environmental variables.
 */
public record SecurityContext(
    Instant timestamp,
    String sourceIp,
    String threatLevel,
    Map<String, Object> environmentAttributes
) {
    public static SecurityContext current(HttpServletRequest request) {
        String ip = (request != null) ? request.getRemoteAddr() : "127.0.0.1";
        return new SecurityContext(Instant.now(), ip, "NORMAL", Map.of());
    }

    public static SecurityContext standard() {
        return new SecurityContext(Instant.now(), "127.0.0.1", "NORMAL", Map.of());
    }
}
