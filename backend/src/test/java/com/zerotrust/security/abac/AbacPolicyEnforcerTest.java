package com.zerotrust.security.abac;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AbacPolicyEnforcerTest {

    private DefaultAbacPolicyEnforcer enforcer;

    private final UUID employee1Id = UUID.randomUUID();
    private final UUID employee2Id = UUID.randomUUID();
    private final UUID adminId = UUID.randomUUID();
    private final UUID analystId = UUID.randomUUID();
    private final UUID auditorId = UUID.randomUUID();

    private SecuritySubject employee1;
    private SecuritySubject employee2;
    private SecuritySubject admin;
    private SecuritySubject analyst;
    private SecuritySubject auditor;

    @BeforeEach
    void setUp() {
        enforcer = new DefaultAbacPolicyEnforcer();

        employee1 = new SecuritySubject(employee1Id, "employee1@zerotrust.com", Set.of("ROLE_EMPLOYEE"), Map.of());
        employee2 = new SecuritySubject(employee2Id, "employee2@zerotrust.com", Set.of("ROLE_EMPLOYEE"), Map.of());
        admin = new SecuritySubject(adminId, "admin@zerotrust.com", Set.of("ROLE_ADMIN"), Map.of());
        analyst = new SecuritySubject(analystId, "analyst@zerotrust.com", Set.of("ROLE_SECURITY_ANALYST"), Map.of());
        auditor = new SecuritySubject(auditorId, "auditor@zerotrust.com", Set.of("ROLE_AUDITOR"), Map.of());
    }

    @Test
    @DisplayName("Admin must have unrestricted access across all actions and resources")
    void adminHasUnrestrictedAccess() {
        SecurityResource resource = SecurityResource.of("CUSTOMER", "CUST-1", employee1Id);

        assertThat(enforcer.isAllowed(admin, resource, SecurityAction.READ, SecurityContext.standard())).isTrue();
        assertThat(enforcer.isAllowed(admin, resource, SecurityAction.UPDATE, SecurityContext.standard())).isTrue();
        assertThat(enforcer.isAllowed(admin, resource, SecurityAction.DELETE, SecurityContext.standard())).isTrue();
        assertThat(enforcer.isAllowed(admin, resource, SecurityAction.EXECUTE_TRANSACTION, SecurityContext.standard())).isTrue();
        assertThat(enforcer.isAllowed(admin, resource, SecurityAction.VIEW_SENSITIVE, SecurityContext.standard())).isTrue();
    }

    @Test
    @DisplayName("Employee can READ and UPDATE own assigned customer resource")
    void employeeCanAccessOwnCustomer() {
        SecurityResource ownResource = SecurityResource.of("CUSTOMER", "CUST-1", employee1Id);

        assertThat(enforcer.isAllowed(employee1, ownResource, SecurityAction.READ, SecurityContext.standard())).isTrue();
        assertThat(enforcer.isAllowed(employee1, ownResource, SecurityAction.UPDATE, SecurityContext.standard())).isTrue();
        assertThat(enforcer.isAllowed(employee1, ownResource, SecurityAction.EXECUTE_TRANSACTION, SecurityContext.standard())).isTrue();
    }

    @Test
    @DisplayName("BOLA Prevention: Employee CANNOT access another employee's assigned customer")
    void employeeCannotAccessOtherEmployeeCustomer() {
        // Resource owned by employee2
        SecurityResource otherEmployeeResource = SecurityResource.of("CUSTOMER", "CUST-2", employee2Id);

        // Employee 1 attempts access
        assertThat(enforcer.isAllowed(employee1, otherEmployeeResource, SecurityAction.READ, SecurityContext.standard())).isFalse();
        assertThat(enforcer.isAllowed(employee1, otherEmployeeResource, SecurityAction.UPDATE, SecurityContext.standard())).isFalse();
        assertThat(enforcer.isAllowed(employee1, otherEmployeeResource, SecurityAction.EXECUTE_TRANSACTION, SecurityContext.standard())).isFalse();

        // Enforce method must throw AccessDeniedException
        assertThatThrownBy(() -> enforcer.enforce(employee1, otherEmployeeResource, SecurityAction.READ, SecurityContext.standard()))
            .isInstanceOf(AccessDeniedException.class)
            .hasMessageContaining("ownership violation");
    }

    @Test
    @DisplayName("Employee CANNOT delete customers or view unmasked sensitive tax identification")
    void employeeCannotDeleteOrViewUnmaskedSensitive() {
        SecurityResource ownResource = SecurityResource.of("CUSTOMER", "CUST-1", employee1Id);

        assertThat(enforcer.isAllowed(employee1, ownResource, SecurityAction.DELETE, SecurityContext.standard())).isFalse();
        assertThat(enforcer.isAllowed(employee1, ownResource, SecurityAction.VIEW_SENSITIVE, SecurityContext.standard())).isFalse();
    }

    @Test
    @DisplayName("Security Analyst has READ-ONLY access and is denied state-modifying actions")
    void securityAnalystReadOnly() {
        SecurityResource resource = SecurityResource.of("CUSTOMER", "CUST-1", employee1Id);

        assertThat(enforcer.isAllowed(analyst, resource, SecurityAction.READ, SecurityContext.standard())).isTrue();
        assertThat(enforcer.isAllowed(analyst, resource, SecurityAction.UPDATE, SecurityContext.standard())).isFalse();
        assertThat(enforcer.isAllowed(analyst, resource, SecurityAction.DELETE, SecurityContext.standard())).isFalse();
        assertThat(enforcer.isAllowed(analyst, resource, SecurityAction.EXECUTE_TRANSACTION, SecurityContext.standard())).isFalse();
    }

    @Test
    @DisplayName("Auditor has strictly READ-ONLY compliance access")
    void auditorReadOnly() {
        SecurityResource resource = SecurityResource.of("ACCOUNT", "ACC-100", employee1Id);

        assertThat(enforcer.isAllowed(auditor, resource, SecurityAction.READ, SecurityContext.standard())).isTrue();
        assertThat(enforcer.isAllowed(auditor, resource, SecurityAction.CREATE, SecurityContext.standard())).isFalse();
        assertThat(enforcer.isAllowed(auditor, resource, SecurityAction.UPDATE, SecurityContext.standard())).isFalse();
        assertThat(enforcer.isAllowed(auditor, resource, SecurityAction.EXECUTE_TRANSACTION, SecurityContext.standard())).isFalse();
    }

    @Test
    @DisplayName("Deny-by-default on null subject or unassigned owner")
    void denyByDefaultOnMissingAttributes() {
        SecurityResource unassigned = SecurityResource.of("CUSTOMER", "CUST-999", null);
        assertThat(enforcer.isAllowed(employee1, unassigned, SecurityAction.READ, SecurityContext.standard())).isFalse();
        assertThat(enforcer.isAllowed(null, unassigned, SecurityAction.READ, SecurityContext.standard())).isFalse();
    }

    @Test
    @DisplayName("Contextual ABAC: Elevated environmental threat level blocks sensitive and state-modifying actions")
    void elevatedContextBlocksSensitiveActions() {
        SecurityResource resource = SecurityResource.of("CUSTOMER", "CUST-1", employee1Id);
        SecurityContext elevatedContext = SecurityContext.of("198.51.100.99", "CRITICAL", 85);

        // Even Admin is blocked from VIEW_SENSITIVE, DELETE, and EXECUTE_TRANSACTION under elevated threat
        assertThat(enforcer.isAllowed(admin, resource, SecurityAction.VIEW_SENSITIVE, elevatedContext)).isFalse();
        assertThat(enforcer.isAllowed(admin, resource, SecurityAction.DELETE, elevatedContext)).isFalse();
        assertThat(enforcer.isAllowed(admin, resource, SecurityAction.EXECUTE_TRANSACTION, elevatedContext)).isFalse();

        // But Admin is still allowed READ for incident triage
        assertThat(enforcer.isAllowed(admin, resource, SecurityAction.READ, elevatedContext)).isTrue();
    }

    @Test
    @DisplayName("Resource Sensitivity: CRITICAL risk customer profiles deny employee state-modifying actions")
    void criticalRiskCustomerDeniesEmployeeModifications() {
        // Customer profile classified as CRITICAL risk tier
        SecurityResource criticalResource = SecurityResource.of("CUSTOMER", "CUST-CRIT-1", employee1Id, "CRITICAL");

        // Employee can still read own customer
        assertThat(enforcer.isAllowed(employee1, criticalResource, SecurityAction.READ, SecurityContext.standard())).isTrue();

        // But Employee cannot perform UPDATE or EXECUTE_TRANSACTION on CRITICAL risk profiles without admin oversight
        assertThat(enforcer.isAllowed(employee1, criticalResource, SecurityAction.UPDATE, SecurityContext.standard())).isFalse();
        assertThat(enforcer.isAllowed(employee1, criticalResource, SecurityAction.EXECUTE_TRANSACTION, SecurityContext.standard())).isFalse();

        // Admin can update CRITICAL risk profiles under normal context
        assertThat(enforcer.isAllowed(admin, criticalResource, SecurityAction.UPDATE, SecurityContext.standard())).isTrue();
    }
}
