package com.zerotrust.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zerotrust.security.RateLimitResult;
import com.zerotrust.security.RateLimitTier;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

/**
 * Enterprise Redis-Backed Security State Management Service.
 * Implements atomic distributed rate limiting, brute-force tracking,
 * JWT token revocation denylist, and single-use SSE ticket consumption.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RedisSecurityService {

    private final StringRedisTemplate stringRedisTemplate;
    private final ObjectMapper objectMapper;

    // ─────────────────────────────────────────────
    // ATOMIC LUA SLIDING-WINDOW SCRIPT
    // ─────────────────────────────────────────────
    private static final String SLIDING_WINDOW_LUA = """
        local key = KEYS[1]
        local nowMs = tonumber(ARGV[1])
        local windowMs = tonumber(ARGV[2])
        local maxLimit = tonumber(ARGV[3])
        local memberId = ARGV[4]
        local ttlSeconds = tonumber(ARGV[5])

        redis.call('ZREMRANGEBYSCORE', key, 0, nowMs - windowMs)
        local count = redis.call('ZCARD', key)

        if count < maxLimit then
            redis.call('ZADD', key, nowMs, memberId)
            redis.call('EXPIRE', key, ttlSeconds)
            return {1, maxLimit - count - 1, 0}
        else
            local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
            local resetAfterMs = 0
            if oldest and #oldest >= 2 then
                resetAfterMs = (tonumber(oldest[2]) + windowMs) - nowMs
            end
            local retryAfterSec = math.max(1, math.ceil(resetAfterMs / 1000))
            return {0, 0, retryAfterSec}
        end
        """;

    private final RedisScript<List> slidingWindowScript = new DefaultRedisScript<>(SLIDING_WINDOW_LUA, List.class);

    // ─────────────────────────────────────────────
    // 1. DISTRIBUTED RATE LIMITING
    // ─────────────────────────────────────────────

    public RateLimitResult checkRateLimit(String subjectId, RateLimitTier tier) {
        String key = "ratelimit:" + tier.getTierName() + ":" + subjectId;
        long nowMs = System.currentTimeMillis();
        long windowMs = tier.getDefaultWindowSeconds() * 1000L;
        long ttlSeconds = tier.getDefaultWindowSeconds() + 5L;
        String memberId = nowMs + ":" + UUID.randomUUID().toString().substring(0, 8);

        try {
            List<?> result = stringRedisTemplate.execute(
                slidingWindowScript,
                List.of(key),
                String.valueOf(nowMs),
                String.valueOf(windowMs),
                String.valueOf(tier.getDefaultLimit()),
                memberId,
                String.valueOf(ttlSeconds)
            );

            if (result != null && result.size() >= 3) {
                long allowed = ((Number) result.get(0)).longValue();
                long remaining = ((Number) result.get(1)).longValue();
                long retryAfter = ((Number) result.get(2)).longValue();

                if (allowed == 1L) {
                    return RateLimitResult.allowed(remaining);
                } else {
                    log.warn("Rate limit exceeded for key {} on tier {}. Retry-After: {}s", key, tier, retryAfter);
                    return RateLimitResult.rejected(retryAfter);
                }
            }
            return RateLimitResult.allowed(1);
        } catch (Exception ex) {
            log.error("Redis rate limit check failed for key {} on tier {}: {}", key, tier, ex.getMessage());
            if (tier.isFailClosedOnOutage()) {
                log.warn("FAIL-CLOSED policy enforced for sensitive tier {} during Redis outage", tier);
                return RateLimitResult.outageRejected();
            } else {
                log.warn("FAIL-OPEN policy permitted with warning for tier {} during Redis outage", tier);
                return RateLimitResult.outageAllowed();
            }
        }
    }

    // ─────────────────────────────────────────────
    // 2. DISTRIBUTED BRUTE-FORCE TRACKING
    // ─────────────────────────────────────────────

    private static final int IP_BRUTE_FORCE_THRESHOLD = 10;
    private static final int ACCOUNT_BRUTE_FORCE_THRESHOLD = 5;
    private static final Duration BRUTE_FORCE_WINDOW = Duration.ofMinutes(5);

    public void recordFailedAuth(String clientIp, String email) {
        try {
            if (clientIp != null && !clientIp.isBlank()) {
                String ipKey = "bruteforce:ip:" + clientIp.trim();
                Long count = stringRedisTemplate.opsForValue().increment(ipKey);
                if (count != null && count == 1L) {
                    stringRedisTemplate.expire(ipKey, BRUTE_FORCE_WINDOW);
                }
            }

            if (email != null && !email.isBlank()) {
                String emailHash = sha256Digest(email.trim().toLowerCase());
                String accKey = "bruteforce:account:" + emailHash;
                Long count = stringRedisTemplate.opsForValue().increment(accKey);
                if (count != null && count == 1L) {
                    stringRedisTemplate.expire(accKey, BRUTE_FORCE_WINDOW);
                }
            }
        } catch (Exception ex) {
            log.error("Failed to record brute-force state in Redis: {}", ex.getMessage());
        }
    }

    public boolean isIpBlocked(String clientIp) {
        if (clientIp == null || clientIp.isBlank()) return false;
        try {
            String ipKey = "bruteforce:ip:" + clientIp.trim();
            String val = stringRedisTemplate.opsForValue().get(ipKey);
            if (val != null) {
                int attempts = Integer.parseInt(val);
                return attempts >= IP_BRUTE_FORCE_THRESHOLD;
            }
        } catch (Exception ex) {
            log.warn("Could not query IP brute force tracker in Redis: {}", ex.getMessage());
        }
        return false;
    }

    public boolean isAccountThrottled(String email) {
        if (email == null || email.isBlank()) return false;
        try {
            String emailHash = sha256Digest(email.trim().toLowerCase());
            String accKey = "bruteforce:account:" + emailHash;
            String val = stringRedisTemplate.opsForValue().get(accKey);
            if (val != null) {
                int attempts = Integer.parseInt(val);
                return attempts >= ACCOUNT_BRUTE_FORCE_THRESHOLD;
            }
        } catch (Exception ex) {
            log.warn("Could not query account brute force tracker in Redis: {}", ex.getMessage());
        }
        return false;
    }

    public void resetFailedAccountAuth(String email) {
        if (email == null || email.isBlank()) return;
        try {
            String emailHash = sha256Digest(email.trim().toLowerCase());
            stringRedisTemplate.delete("bruteforce:account:" + emailHash);
        } catch (Exception ex) {
            log.warn("Could not reset account brute force counter in Redis: {}", ex.getMessage());
        }
    }

    public void resetFailedIpAuth(String clientIp) {
        if (clientIp == null || clientIp.isBlank()) return;
        try {
            stringRedisTemplate.delete("bruteforce:ip:" + clientIp.trim());
        } catch (Exception ex) {
            log.warn("Could not reset IP brute force counter in Redis: {}", ex.getMessage());
        }
    }

    /**
     * Resets failed authentication state.
     * Note: In accordance with SEC-002, only the account-specific failure counter is cleared
     * on login. Source IP failure counters remain bounded by their TTL to prevent credential stuffers
     * from resetting their IP abuse counter via a canary account.
     */
    public void resetFailedAuth(String clientIp, String email) {
        resetFailedAccountAuth(email);
    }

    // ─────────────────────────────────────────────
    // 3. JWT ACCESS TOKEN REVOCATION DENYLIST
    // ─────────────────────────────────────────────

    public void revokeAccessToken(String rawToken, Instant expiresAt) {
        if (rawToken == null || rawToken.isBlank()) return;
        String tokenDigest = sha256Digest(rawToken);
        String key = "jwt:denylist:" + tokenDigest;

        long remainingSeconds = Duration.between(Instant.now(), expiresAt).getSeconds();
        if (remainingSeconds <= 0) {
            return; // Token is already expired naturally
        }

        try {
            stringRedisTemplate.opsForValue().set(key, "revoked", Duration.ofSeconds(remainingSeconds));
            log.info("Access token digest {} added to Redis revocation denylist for {}s", tokenDigest, remainingSeconds);
        } catch (Exception ex) {
            log.error("Failed to persist revoked token to Redis denylist: {}", ex.getMessage());
            throw new IllegalStateException("Could not revoke token in distributed denylist", ex);
        }
    }

    public boolean isTokenRevoked(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) return false;
        String tokenDigest = sha256Digest(rawToken);
        String key = "jwt:denylist:" + tokenDigest;

        try {
            Boolean exists = stringRedisTemplate.hasKey(key);
            return Boolean.TRUE.equals(exists);
        } catch (Exception ex) {
            log.error("Redis denylist lookup failed for token digest {}: {}", tokenDigest, ex.getMessage());
            // Signal outage to caller
            throw new RedisSecurityException("Token revocation check unavailable due to Redis outage", ex);
        }
    }

    // ─────────────────────────────────────────────
    // 4. DISTRIBUTED SSE TICKET CONSUMPTION (GETDEL)
    // ─────────────────────────────────────────────

    private static final String GETDEL_LUA = """
        local val = redis.call('GET', KEYS[1])
        if val then
            redis.call('DEL', KEYS[1])
        end
        return val
        """;
    private final RedisScript<String> getDelScript = new DefaultRedisScript<>(GETDEL_LUA, String.class);

    public void saveSseTicket(String ticketId, SseTicketService.TicketData data) {
        if (ticketId == null || data == null) return;
        String key = "sse:ticket:" + ticketId;
        try {
            String json = objectMapper.writeValueAsString(data);
            stringRedisTemplate.opsForValue().set(key, json, Duration.ofSeconds(30));
        } catch (Exception ex) {
            log.error("Failed to store SSE ticket in Redis: {}", ex.getMessage());
            throw new RedisSecurityException("Failed to store SSE ticket in distributed cache", ex);
        }
    }

    public SseTicketService.TicketData consumeSseTicket(String ticketId) {
        if (ticketId == null || ticketId.isBlank()) return null;
        String key = "sse:ticket:" + ticketId;

        try {
            // Atomic GET and DELETE
            String json = stringRedisTemplate.execute(getDelScript, List.of(key));
            if (json == null || json.isBlank()) {
                return null; // Already consumed, expired, or non-existent
            }
            return objectMapper.readValue(json, SseTicketService.TicketData.class);
        } catch (Exception ex) {
            log.error("Failed to atomically consume SSE ticket from Redis: {}", ex.getMessage());
            throw new RedisSecurityException("Failed to consume distributed SSE ticket", ex);
        }
    }

    // ─────────────────────────────────────────────
    // HELPERS
    // ─────────────────────────────────────────────

    public static String sha256Digest(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not available", e);
        }
    }

    public static class RedisSecurityException extends RuntimeException {
        public RedisSecurityException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
