package com.zerotrust.security.abac;

import java.util.Map;
import java.util.UUID;

/**
 * ABAC Resource: Encapsulates the target domain entity, resource type, classification, and ownership.
 */
public record SecurityResource(
    String resourceType,
    String resourceId,
    UUID ownerId,
    String classification,
    Map<String, Object> attributes
) {
    public static SecurityResource of(String type, String id, UUID ownerId) {
        return new SecurityResource(type, id, ownerId, "STANDARD", Map.of());
    }

    public static SecurityResource of(String type, String id, UUID ownerId, String classification) {
        return new SecurityResource(type, id, ownerId, classification, Map.of());
    }
}
