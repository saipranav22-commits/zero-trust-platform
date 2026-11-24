package com.zerotrust.security.abac;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Default ABAC Policy Enforcer with Zero Trust Deny-By-Default Semantics.
 * Evaluates subject roles, object ownership, requested actions, resource sensitivity,
 * and contextual environmental risk signals.
 * Prevents BOLA/IDOR, horizontal privilege escalation, and unauthorized access in elevated threat contexts.
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

        SecurityContext effectiveContext = (context != null) ? context : SecurityContext.standard();

        // 1. Contextual Anomaly Rule: Elevated Threat Environment Blocks Sensitive / State-Modifying Actions
        if (effectiveContext.isElevatedThreat()) {
            // Under elevated threat (threatLevel != NORMAL or riskScore >= 70), sensitive actions and deletions are locked down
            if (action == SecurityAction.DELETE || action == SecurityAction.VIEW_SENSITIVE || action == SecurityAction.EXECUTE_TRANSACTION) {
                log.warn("🛡️ ABAC Contextual Denial: Action [{}] blocked due to elevated environmental threat level [{}] (Risk score: {}) on resource [{}:{}]",
                    action, effectiveContext.threatLevel(), effectiveContext.riskScore(), resource.resourceType(), resource.resourceId());
                return false;
            }
        }

        // 2. Full System Administrator Policies
        if (subject.hasRole("ROLE_ADMIN")) {
            // Admin is allowed all actions under normal context
            log.debug("ABAC Grant: Admin role granted action {} on {}:{}", action, resource.resourceType(), resource.resourceId());
            return true;
        }

        // 3. Security Analyst Policies
        if (subject.hasRole("ROLE_SECURITY_ANALYST")) {
            // Strictly read-only access for telemetry and threat analysis
            if (action == SecurityAction.READ) {
                return true;
            }
            log.warn("ABAC Denial: Security Analyst denied non-read action {} on {}:{}", action, resource.resourceType(), resource.resourceId());
            return false;
        }

        // 4. Auditor Policies
        if (subject.hasRole("ROLE_AUDITOR")) {
            // Strictly read-only compliance access
            if (action == SecurityAction.READ) {
                return true;
            }
            log.warn("ABAC Denial: Auditor denied non-read action {} on {}:{}", action, resource.resourceType(), resource.resourceId());
            return false;
        }

        // 5. Employee Policies (Strict Object Ownership & Resource Sensitivity)
        if (subject.hasRole("ROLE_EMPLOYEE")) {
            // Customer creation
            if (action == SecurityAction.CREATE) {
                return !effectiveContext.isElevatedThreat();
            }

            // Customer deletion is strictly restricted to Admin
            if (action == SecurityAction.DELETE) {
                log.warn("ABAC Denial: Employee cannot delete customer {}:{}", resource.resourceType(), resource.resourceId());
                return false;
            }

            // Viewing unmasked sensitive tax identification is strictly restricted to Admin
            if (action == SecurityAction.VIEW_SENSITIVE) {
                log.warn("ABAC Denial: Employee cannot view unmasked sensitive tax identification for customer {}:{}",
                    resource.resourceType(), resource.resourceId());
                return false;
            }

            // Resource Sensitivity Rule: CRITICAL risk customer profiles require Admin oversight
            if ("CRITICAL".equalsIgnoreCase(resource.classification())) {
                if (action == SecurityAction.UPDATE || action == SecurityAction.EXECUTE_TRANSACTION) {
                    log.warn("🛡️ ABAC Sensitivity Denial: Employee cannot modify CRITICAL risk customer {}:{}",
                        resource.resourceType(), resource.resourceId());
                    return false;
                }
            }

            // Object-Level Ownership Evaluation (BOLA Prevention)
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
                log.warn("ABAC Denial: Resource {}:{} has no assigned owner", resource.resourceType(), resource.resourceId());
                return false;
            }
        }

        // 6. Deny by Default
        log.warn("ABAC Denial: No matching policy granted action {} for user {} on {}:{}",
            action, subject.email(), resource.resourceType(), resource.resourceId());
        return false;
    }
}
