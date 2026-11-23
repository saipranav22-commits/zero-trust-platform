package com.zerotrust.security;

import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtTokenProviderTest {

    private static final String VALID_SECRET = "secure-production-grade-secret-key-that-is-at-least-256-bits-long!";
    private static final long ACCESS_EXPIRY_MS = 60_000L; // 1 min

    private final JwtTokenProvider tokenProvider = new JwtTokenProvider(VALID_SECRET, ACCESS_EXPIRY_MS);

    @Test
    @DisplayName("Should generate valid JWT access token and extract claims correctly")
    void shouldGenerateAndExtractClaims() {
        UUID userId = UUID.randomUUID();
        String email = "analyst@zerotrust.com";
        List<String> roles = List.of("ROLE_SECURITY_ANALYST");

        String token = tokenProvider.generateAccessToken(userId, email, roles);

        assertThat(token).isNotBlank();
        assertThat(tokenProvider.isTokenValid(token)).isTrue();
        assertThat(tokenProvider.extractUserId(token)).isEqualTo(userId.toString());
        assertThat(tokenProvider.extractEmail(token)).isEqualTo(email);
        assertThat(tokenProvider.extractRoles(token)).containsExactly("ROLE_SECURITY_ANALYST");
        assertThat(tokenProvider.isTokenExpired(token)).isFalse();
    }

    @Test
    @DisplayName("Should detect expired token correctly")
    void shouldDetectExpiredToken() {
        // Provider with negative expiry
        JwtTokenProvider expiredProvider = new JwtTokenProvider(VALID_SECRET, -1000L);
        UUID userId = UUID.randomUUID();

        String token = expiredProvider.generateAccessToken(userId, "test@zerotrust.com", List.of("ROLE_EMPLOYEE"));

        assertThat(tokenProvider.isTokenExpired(token)).isTrue();
        assertThat(tokenProvider.isTokenValid(token)).isFalse();
        assertThatThrownBy(() -> tokenProvider.validateAndGetClaims(token))
            .isInstanceOf(JwtException.class);
    }

    @Test
    @DisplayName("Should fail fast on missing, blank, or weak secrets at configuration time")
    void shouldFailFastOnInvalidSecrets() {
        assertThatThrownBy(() -> new JwtTokenProvider(null, ACCESS_EXPIRY_MS))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("missing or empty");

        assertThatThrownBy(() -> new JwtTokenProvider("   ", ACCESS_EXPIRY_MS))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("missing or empty");

        assertThatThrownBy(() -> new JwtTokenProvider("short-secret-under-32-bytes", ACCESS_EXPIRY_MS))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("at least 256 bits");
    }

    @Test
    @DisplayName("Should generate opaque UUID refresh token")
    void shouldGenerateRefreshToken() {
        String refreshToken = tokenProvider.generateRefreshToken();
        assertThat(refreshToken).isNotBlank();
        assertThat(UUID.fromString(refreshToken)).isNotNull();
    }
}
