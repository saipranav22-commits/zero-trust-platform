package com.zerotrust.security.abac;

import org.springframework.security.access.AccessDeniedException;

/**
 * ABAC Policy Enforcement Point (PEP).
 * Evaluates Subject, Resource, Action, and Context against Zero Trust policies.
 */
public interface AbacPolicyEnforcer {

    /**
     * Evaluates whether the requested action is permitted.
     *
     * @return true if permitted; false if denied.
     */
    boolean isAllowed(SecuritySubject subject, SecurityResource resource, SecurityAction action, SecurityContext context);

    /**
     * Enforces the policy decision, throwing AccessDeniedException if authorization fails.
     */
    default void enforce(SecuritySubject subject, SecurityResource resource, SecurityAction action, SecurityContext context) {
        if (!isAllowed(subject, resource, action, context)) {
            throw new AccessDeniedException(String.format(
                "Access Denied: Subject [%s] is not authorized to perform action [%s] on resource [%s:%s] (ownership violation / insufficient privilege)",
                subject.email(), action, resource.resourceType(), resource.resourceId()
            ));
        }
    }
}
