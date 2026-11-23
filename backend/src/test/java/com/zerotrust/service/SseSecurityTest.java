package com.zerotrust.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zerotrust.entity.Notification;
import com.zerotrust.entity.enums.Severity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class SseSecurityTest {

    private SseService sseService;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        objectMapper.findAndRegisterModules();
        sseService = new SseService(objectMapper);
    }

    @Test
    @DisplayName("Employee must NOT be authorized to receive threat detection notifications")
    void employeeShouldNotReceiveThreatDetectionAlerts() {
        SseService.SseClient employeeClient = new SseService.SseClient(
            UUID.randomUUID(),
            new SseEmitter(),
            "emp-001",
            "employee@zerotrust.com",
            Set.of("ROLE_EMPLOYEE")
        );

        Notification threatNotification = Notification.builder()
            .id(UUID.randomUUID())
            .title("SQL Injection Detected")
            .description("Malicious attack attempt detected from 192.168.1.100")
            .severity(Severity.HIGH)
            .category("THREAT_DETECTION")
            .build();

        boolean allowed = sseService.isAuthorizedToReceive(employeeClient, threatNotification);
        assertThat(allowed).isFalse();
    }

    @Test
    @DisplayName("Security Analyst MUST be authorized to receive threat detection notifications")
    void securityAnalystShouldReceiveThreatDetectionAlerts() {
        SseService.SseClient analystClient = new SseService.SseClient(
            UUID.randomUUID(),
            new SseEmitter(),
            "analyst-001",
            "analyst@zerotrust.com",
            Set.of("ROLE_SECURITY_ANALYST")
        );

        Notification threatNotification = Notification.builder()
            .id(UUID.randomUUID())
            .title("SQL Injection Detected")
            .description("Malicious attack attempt detected from 192.168.1.100")
            .severity(Severity.HIGH)
            .category("THREAT_DETECTION")
            .build();

        boolean allowed = sseService.isAuthorizedToReceive(analystClient, threatNotification);
        assertThat(allowed).isTrue();
    }

    @Test
    @DisplayName("Targeted notifications must only be received by the target user or admin, not other employees")
    void targetedNotificationIsolation() {
        UUID targetUserId = UUID.randomUUID();
        UUID otherUserId = UUID.randomUUID();

        SseService.SseClient targetUserClient = new SseService.SseClient(
            UUID.randomUUID(),
            new SseEmitter(),
            targetUserId.toString(),
            "target@zerotrust.com",
            Set.of("ROLE_EMPLOYEE")
        );

        SseService.SseClient otherEmployeeClient = new SseService.SseClient(
            UUID.randomUUID(),
            new SseEmitter(),
            otherUserId.toString(),
            "other@zerotrust.com",
            Set.of("ROLE_EMPLOYEE")
        );

        SseService.SseClient adminClient = new SseService.SseClient(
            UUID.randomUUID(),
            new SseEmitter(),
            "admin-001",
            "admin@zerotrust.com",
            Set.of("ROLE_ADMIN")
        );

        Notification personalNotification = Notification.builder()
            .id(UUID.randomUUID())
            .title("Password Expiration Notice")
            .description("Your credential expires in 3 days")
            .severity(Severity.LOW)
            .category("ACCOUNT")
            .relatedUserId(targetUserId)
            .build();

        assertThat(sseService.isAuthorizedToReceive(targetUserClient, personalNotification)).isTrue();
        assertThat(sseService.isAuthorizedToReceive(otherEmployeeClient, personalNotification)).isFalse();
        assertThat(sseService.isAuthorizedToReceive(adminClient, personalNotification)).isTrue();
    }

    @Test
    @DisplayName("Auditor should receive AUDIT category events but not THREAT_DETECTION events")
    void auditorAccessPermissions() {
        SseService.SseClient auditorClient = new SseService.SseClient(
            UUID.randomUUID(),
            new SseEmitter(),
            "auditor-001",
            "auditor@zerotrust.com",
            Set.of("ROLE_AUDITOR")
        );

        Notification auditNotification = Notification.builder()
            .id(UUID.randomUUID())
            .title("Audit Trail Export Completed")
            .description("Monthly hash chain integrity verified")
            .severity(Severity.LOW)
            .category("AUDIT")
            .build();

        Notification threatNotification = Notification.builder()
            .id(UUID.randomUUID())
            .title("Brute Force Detected")
            .description("5 failed attempts")
            .severity(Severity.HIGH)
            .category("THREAT_DETECTION")
            .build();

        assertThat(sseService.isAuthorizedToReceive(auditorClient, auditNotification)).isTrue();
        assertThat(sseService.isAuthorizedToReceive(auditorClient, threatNotification)).isFalse();
    }

    @Test
    @DisplayName("Dynamically revoked analyst role stops receiving threat detection events")
    void revokedAnalystRoleStopsReceivingThreats() {
        com.zerotrust.repository.UserRepository mockUserRepo = org.mockito.Mockito.mock(com.zerotrust.repository.UserRepository.class);
        SseService dynamicSseService = new SseService(objectMapper, mockUserRepo);

        UUID analystUserId = UUID.randomUUID();
        // User originally connected with ROLE_SECURITY_ANALYST
        SseService.SseClient analystClient = new SseService.SseClient(
            UUID.randomUUID(),
            new SseEmitter(),
            analystUserId.toString(),
            "analyst@zerotrust.com",
            Set.of("ROLE_SECURITY_ANALYST")
        );

        // In database, the analyst role was revoked; user now only has ROLE_EMPLOYEE
        com.zerotrust.entity.Role empRole = com.zerotrust.entity.Role.builder().name("ROLE_EMPLOYEE").build();
        com.zerotrust.entity.User userWithRevokedRole = com.zerotrust.entity.User.builder()
            .id(analystUserId)
            .email("analyst@zerotrust.com")
            .isActive(true)
            .isLocked(false)
            .roles(Set.of(empRole))
            .build();

        org.mockito.Mockito.when(mockUserRepo.findById(analystUserId)).thenReturn(java.util.Optional.of(userWithRevokedRole));

        Notification threatNotification = Notification.builder()
            .id(UUID.randomUUID())
            .title("Brute Force Detected")
            .description("5 failed attempts")
            .severity(Severity.HIGH)
            .category("THREAT_DETECTION")
            .build();

        // Must reject delivery dynamically despite initial connection holding the role
        boolean allowed = dynamicSseService.isAuthorizedToReceive(analystClient, threatNotification);
        assertThat(allowed).isFalse();
    }

    @Test
    @DisplayName("Locked or deactivated user is disconnected and denied event delivery")
    void lockedUserIsDisconnected() {
        com.zerotrust.repository.UserRepository mockUserRepo = org.mockito.Mockito.mock(com.zerotrust.repository.UserRepository.class);
        SseService dynamicSseService = new SseService(objectMapper, mockUserRepo);

        UUID lockedUserId = UUID.randomUUID();
        SseEmitter mockEmitter = org.mockito.Mockito.mock(SseEmitter.class);

        SseService.SseClient client = new SseService.SseClient(
            UUID.randomUUID(),
            mockEmitter,
            lockedUserId.toString(),
            "user@zerotrust.com",
            Set.of("ROLE_ADMIN")
        );

        com.zerotrust.entity.User lockedUser = com.zerotrust.entity.User.builder()
            .id(lockedUserId)
            .email("user@zerotrust.com")
            .isActive(true)
            .isLocked(true) // Account is locked!
            .build();

        org.mockito.Mockito.when(mockUserRepo.findById(lockedUserId)).thenReturn(java.util.Optional.of(lockedUser));

        Notification notification = Notification.builder()
            .id(UUID.randomUUID())
            .title("Platform Announcement")
            .description("Maintenance at midnight")
            .severity(Severity.LOW)
            .category("SYSTEM")
            .build();

        boolean allowed = dynamicSseService.isAuthorizedToReceive(client, notification);
        assertThat(allowed).isFalse();
        org.mockito.Mockito.verify(mockEmitter).complete();
    }

    @Test
    @DisplayName("Idle locked user is proactively evicted by periodic sweep without needing a broadcast event")
    void idleLockedUserIsProactivelyEvictedByPeriodicSweep() {
        com.zerotrust.repository.UserRepository mockUserRepo = org.mockito.Mockito.mock(com.zerotrust.repository.UserRepository.class);
        SseService dynamicSseService = new SseService(objectMapper, mockUserRepo);

        UUID lockedUserId = UUID.randomUUID();
        com.zerotrust.entity.User lockedUser = com.zerotrust.entity.User.builder()
            .id(lockedUserId)
            .email("idle@zerotrust.com")
            .isActive(true)
            .isLocked(true)
            .build();
        org.mockito.Mockito.when(mockUserRepo.findById(lockedUserId)).thenReturn(java.util.Optional.of(lockedUser));

        // Register client directly
        dynamicSseService.registerClient(lockedUserId.toString(), "idle@zerotrust.com", Set.of("ROLE_ADMIN"));
        assertThat(dynamicSseService.getActiveClientCount()).isEqualTo(1);

        // Run periodic sweep
        dynamicSseService.evictInvalidClients();

        // Client must be evicted
        assertThat(dynamicSseService.getActiveClientCount()).isEqualTo(0);
    }

    @Test
    @DisplayName("User connection is immediately terminated on demand via evictClientByUserId")
    void userIsImmediatelyEvictedOnDemand() {
        com.zerotrust.repository.UserRepository mockUserRepo = org.mockito.Mockito.mock(com.zerotrust.repository.UserRepository.class);
        SseService dynamicSseService = new SseService(objectMapper, mockUserRepo);

        UUID targetUserId = UUID.randomUUID();
        dynamicSseService.registerClient(targetUserId.toString(), "target@zerotrust.com", Set.of("ROLE_EMPLOYEE"));
        dynamicSseService.registerClient(UUID.randomUUID().toString(), "other@zerotrust.com", Set.of("ROLE_ADMIN"));
        assertThat(dynamicSseService.getActiveClientCount()).isEqualTo(2);

        dynamicSseService.evictClientByUserId(targetUserId);

        assertThat(dynamicSseService.getActiveClientCount()).isEqualTo(1);
    }
}
