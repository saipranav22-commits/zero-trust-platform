package com.zerotrust.security.abac;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Default ABAC Policy Enforcer with Zero Trust Deny-By-Default Semantics.
 * Prevents Broken Object-Level Authorization (BOLA / IDOR) and Horizontal Privilege Escalation.
 */
@Slf4j
@Component("abacPolicyEnforcer")
public class DefaultAbacPolicyEnforcer implements AbacPolicyEnforcer {

    @Override
    public boolean isAllowed(SecuritySubject subject, SecurityResource resource, SecurityAction action, SecurityContext context) {
        if (subject == null || action == null || resource == null) {
            log.warn("ABAC Denial: Null parameters provided in authorization evaluation");
            return false;
        }

        // 1. Full System Administrator Override
        if (subject.hasRole("ROLE_ADMIN")) {
            log.debug("ABAC Grant: Admin role granted action {} on {}:{}", action, resource.resourceType(), resource.resourceId());
            return true;
        }

        // 2. Security Analyst Policies
        if (subject.hasRole("ROLE_SECURITY_ANALYST")) {
            // Read-only access for security telemetry, threat profiling, and risk analysis
            if (action == SecurityAction.READ) {
                return true;
            }
            // Cannot modify customer data or execute transactions
            log.warn("ABAC Denial: Security Analyst denied non-read action {} on {}:{}", action, resource.resourceType(), resource.resourceId());
            return false;
        }

        // 3. Auditor Policies
        if (subject.hasRole("ROLE_AUDITOR")) {
            // Strictly read-only compliance access
            if (action == SecurityAction.READ) {
                return true;
            }
            log.warn("ABAC Denial: Auditor denied non-read action {} on {}:{}", action, resource.resourceType(), resource.resourceId());
            return false;
        }

        // 4. Employee Policies (Strict Object Ownership & BOLA Prevention)
        if (subject.hasRole("ROLE_EMPLOYEE")) {
            // Creation of new customer profiles
            if (action == SecurityAction.CREATE) {
                return true;
            }

            // Deletion of customers is restricted to Admin
            if (action == SecurityAction.DELETE) {
                log.warn("ABAC Denial: Employee cannot delete customer {}:{}", resource.resourceType(), resource.resourceId());
                return false;
            }

            // Viewing unmasked sensitive tax identification is restricted to Admin
            if (action == SecurityAction.VIEW_SENSITIVE) {
                return false;
            }

            // Object-Level Ownership Evaluation:
            // Employee can only READ, UPDATE, or EXECUTE_TRANSACTION on records explicitly assigned to them!
            if (resource.ownerId() != null) {
                if (subject.userId() != null && resource.ownerId().equals(subject.userId())) {
                    log.debug("ABAC Grant: Employee {} verified as assigned owner of {}:{}", subject.userId(), resource.resourceType(), resource.resourceId());
                    return true;
                } else {
                    log.warn("🚨 BOLA VIOLATION DETECTED: Employee {} attempted unauthorized action {} on {}:{} owned by {}",
                        subject.userId(), action, resource.resourceType(), resource.resourceId(), resource.ownerId());
                    return false;
                }
            } else {
                // If unassigned or ownership is unspecified, deny by default
                log.warn("ABAC Denial: Resource {}:{} has no assigned owner", resource.resourceType(), resource.resourceId());
                return false;
            }
        }

        // 5. Deny by Default
        log.warn("ABAC Denial: No matching policy granted action {} for user {} on {}:{}",
            action, subject.email(), resource.resourceType(), resource.resourceId());
        return false;
    }
}
