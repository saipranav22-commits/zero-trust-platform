package com.zerotrust.security;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * Endpoint category tiers for distributed rate limiting and outage fail-mode policy.
 */
@Getter
@RequiredArgsConstructor
public enum RateLimitTier {
    AUTH("auth", 10, 60, true),              // Fail-closed on Redis outage (prevents unthrottled brute force)
    TRANSACTIONS("transactions", 30, 60, true), // Fail-closed on Redis outage (financial ledger protection)
    BANKING("banking", 60, 60, false),          // Fail-open with warning
    ADMIN("admin", 40, 60, true),               // Fail-closed (privileged administration)
    GENERAL("general", 120, 60, false);         // Fail-open with warning

    private final String tierName;
    private final int defaultLimit;
    private final int defaultWindowSeconds;
    private final boolean failClosedOnOutage;
}
