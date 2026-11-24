package com.zerotrust.entity.enums;

/**
 * Explicit lifecycle states for security incidents in SYVORA.
 * Transitions:
 *   OPEN -> ACKNOWLEDGED -> INVESTIGATING -> RESOLVED
 *   Documented Reopening: RESOLVED -> OPEN
 */
public enum IncidentStatus {
    OPEN,
    ACKNOWLEDGED,
    INVESTIGATING,
    RESOLVED
}
