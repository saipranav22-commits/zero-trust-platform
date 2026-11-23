package com.zerotrust.security.abac;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * ABAC Subject: Encapsulates user identity, role entitlements, and dynamic attributes.
 */
public record SecuritySubject(
    UUID userId,
    String email,
    Set<String> roles,
    Map<String, Object> attributes
) {
    public boolean hasRole(String role) {
        return roles != null && roles.contains(role);
    }

    public static SecuritySubject from(Authentication auth, String userId) {
        if (auth == null) {
            return new SecuritySubject(null, "anonymous", Set.of(), Map.of());
        }
        UUID uid = null;
        if (userId != null && !userId.isBlank()) {
            try {
                uid = UUID.fromString(userId);
            } catch (IllegalArgumentException ignored) {}
        }
        Set<String> roles = auth.getAuthorities() != null
            ? auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet())
            : Set.of();

        return new SecuritySubject(uid, auth.getName(), roles, Map.of());
    }
}
