package com.zerotrust.security;

/**
 * Result of a distributed rate-limit check.
 */
public record RateLimitResult(
    boolean allowed,
    long remaining,
    long retryAfterSeconds,
    boolean isOutage
) {
    public static RateLimitResult allowed(long remaining) {
        return new RateLimitResult(true, remaining, 0, false);
    }

    public static RateLimitResult rejected(long retryAfterSeconds) {
        return new RateLimitResult(false, 0, retryAfterSeconds, false);
    }

    public static RateLimitResult outageAllowed() {
        return new RateLimitResult(true, 1, 0, true);
    }

    public static RateLimitResult outageRejected() {
        return new RateLimitResult(false, 0, 30, true);
    }
}
