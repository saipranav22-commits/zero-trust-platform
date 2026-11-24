package com.zerotrust.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zerotrust.entity.RevokedToken;
import com.zerotrust.repository.RevokedTokenRepository;
import com.zerotrust.service.RedisSecurityService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PersistentTokenRevocationRegressionTest {

    @Mock
    private StringRedisTemplate stringRedisTemplate;
    @Mock
    private ValueOperations<String, String> valueOperations;
    @Mock
    private ObjectMapper objectMapper;
    @Mock
    private RevokedTokenRepository revokedTokenRepository;

    private RedisSecurityService redisSecurityService;

    @BeforeEach
    void setUp() {
        lenient().when(stringRedisTemplate.opsForValue()).thenReturn(valueOperations);
        redisSecurityService = new RedisSecurityService(stringRedisTemplate, objectMapper, revokedTokenRepository);
    }

    @Test
    @DisplayName("Revoking access token must persist to BOTH PostgreSQL and Redis")
    void revokeAccessTokenPersistsToBothPostgresAndRedis() {
        String rawToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.testToken";
        Instant expiresAt = Instant.now().plusSeconds(300);

        redisSecurityService.revokeAccessToken(rawToken, expiresAt);

        // 1. Verify saved to PostgreSQL
        ArgumentCaptor<RevokedToken> entityCaptor = ArgumentCaptor.forClass(RevokedToken.class);
        verify(revokedTokenRepository).save(entityCaptor.capture());
        RevokedToken saved = entityCaptor.getValue();
        assertThat(saved.getTokenDigest()).isNotBlank();
        assertThat(saved.getExpiresAt()).isEqualTo(expiresAt);

        // 2. Verify saved to Redis
        verify(valueOperations).set(startsWith("jwt:denylist:"), eq("revoked"), any(Duration.class));
    }

    @Test
    @DisplayName("Redis cache miss falls back to PostgreSQL: Token is identified as revoked after Redis restart")
    void redisCacheMissFallsBackToPostgresAfterRedisRestart() {
        String rawToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.testTokenAfterRestart";

        // Simulate Redis restart: Redis cache has been wiped -> returns false
        when(stringRedisTemplate.hasKey(startsWith("jwt:denylist:"))).thenReturn(false);

        // PostgreSQL contains persistent record
        when(revokedTokenRepository.existsByTokenDigestAndExpiresAtAfter(anyString(), any(Instant.class)))
                .thenReturn(true);

        boolean isRevoked = redisSecurityService.isTokenRevoked(rawToken);

        // Token must still be detected as revoked
        assertThat(isRevoked).isTrue();

        // Must re-hydrate Redis cache
        verify(valueOperations).set(startsWith("jwt:denylist:"), eq("revoked"), any(Duration.class));
    }

    @Test
    @DisplayName("Redis outage re-throws RedisSecurityException to preserve Zero Trust fail-closed security")
    void redisOutageFailsClosed() {
        String rawToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.testTokenOutage";

        // Simulate Redis connection failure / timeout
        when(stringRedisTemplate.hasKey(startsWith("jwt:denylist:")))
                .thenThrow(new RuntimeException("Redis connection refused on red-xxx:6379"));

        assertThatThrownBy(() -> redisSecurityService.isTokenRevoked(rawToken))
                .isInstanceOf(RedisSecurityService.RedisSecurityException.class)
                .hasMessageContaining("unavailable due to Redis outage");

        // PostgreSQL fallback must NOT mask an active Redis outage (fail-closed integrity)
        verify(revokedTokenRepository, never()).existsByTokenDigestAndExpiresAtAfter(any(), any());
    }

    @Test
    @DisplayName("PostgreSQL error on Redis cache miss must NOT fail open: throws RedisSecurityException")
    void postgresqlErrorOnCacheMissFailsClosed() {
        String rawToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.testTokenPostgresError";

        // Redis cache miss (e.g. after restart or eviction)
        when(stringRedisTemplate.hasKey(startsWith("jwt:denylist:"))).thenReturn(false);

        // PostgreSQL query fails (connection error or database outage)
        when(revokedTokenRepository.existsByTokenDigestAndExpiresAtAfter(anyString(), any(Instant.class)))
                .thenThrow(new org.springframework.dao.DataAccessResourceFailureException("Postgres connection dropped"));

        assertThatThrownBy(() -> redisSecurityService.isTokenRevoked(rawToken))
                .isInstanceOf(RedisSecurityService.RedisSecurityException.class)
                .hasMessageContaining("Persistent token revocation verification failed due to database error");
    }
}
