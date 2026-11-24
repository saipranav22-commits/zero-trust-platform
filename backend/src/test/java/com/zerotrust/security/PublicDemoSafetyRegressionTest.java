package com.zerotrust.security;

import com.zerotrust.config.DataInitializer;
import com.zerotrust.entity.Customer;
import com.zerotrust.entity.Role;
import com.zerotrust.entity.User;
import com.zerotrust.repository.AccountRepository;
import com.zerotrust.repository.CustomerRepository;
import com.zerotrust.repository.RoleRepository;
import com.zerotrust.repository.UserRepository;
import com.zerotrust.security.abac.AbacPolicyEnforcer;
import com.zerotrust.security.abac.SecurityContext;
import com.zerotrust.security.abac.SecuritySubject;
import com.zerotrust.service.AuditService;
import com.zerotrust.service.CustomerService;
import com.zerotrust.service.UserService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.core.env.Environment;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PublicDemoSafetyRegressionTest {

    @Mock
    private RoleRepository roleRepository;
    @Mock
    private UserRepository userRepository;
    @Mock
    private CustomerRepository customerRepository;
    @Mock
    private AccountRepository accountRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private Environment environment;
    @Mock
    private AbacPolicyEnforcer abacPolicyEnforcer;
    @Mock
    private AuditService auditService;

    @Test
    @DisplayName("In demo profile, admin account with default password is NEVER seeded without explicit secret")
    void demoProfileDoesNotSeedDefaultAdminWithoutSecret() {
        when(environment.getActiveProfiles()).thenReturn(new String[]{"demo"});
        Role adminRole = Role.builder().name("ROLE_ADMIN").build();
        Role analystRole = Role.builder().name("ROLE_SECURITY_ANALYST").build();
        when(roleRepository.findByName("ROLE_ADMIN")).thenReturn(Optional.of(adminRole));
        when(roleRepository.findByName("ROLE_SECURITY_ANALYST")).thenReturn(Optional.of(analystRole));
        when(userRepository.existsByEmail("admin@zerotrust.com")).thenReturn(false);
        when(userRepository.existsByEmail("demo.analyst@zerotrust.com")).thenReturn(false);
        when(passwordEncoder.encode(any())).thenReturn("hashed-pwd");

        DataInitializer initializer = new DataInitializer(
            roleRepository, userRepository, customerRepository, accountRepository, passwordEncoder, environment
        );
        ReflectionTestUtils.setField(initializer, "seedDemoData", true);
        ReflectionTestUtils.setField(initializer, "demoAdminPassword", ""); // No explicit admin password
        ReflectionTestUtils.setField(initializer, "demoAnalystPassword", "SafeAnalyst@2026!");

        initializer.run(new DefaultApplicationArguments());

        // Verify admin was NOT created
        verify(userRepository, never()).save(argThat(user -> "admin@zerotrust.com".equals(user.getEmail())));

        // Verify least-privilege demo analyst WAS created
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        User created = userCaptor.getValue();
        assertThat(created.getEmail()).isEqualTo("demo.analyst@zerotrust.com");
        assertThat(created.getRoles()).extracting(Role::getName).containsExactly("ROLE_SECURITY_ANALYST");
    }

    @Test
    @DisplayName("In demo profile with mutations-disabled, administrative customer deletion is rejected")
    void demoMutationsDisabledRejectsCustomerDeletion() {
        CustomerService customerService = new CustomerService(
            customerRepository, accountRepository, abacPolicyEnforcer, auditService
        );
        ReflectionTestUtils.setField(customerService, "demoMutationsDisabled", true);

        UUID customerId = UUID.randomUUID();
        SecuritySubject adminSubject = new SecuritySubject(UUID.randomUUID(), "admin@test.com", java.util.Set.of("ROLE_ADMIN"), java.util.Map.of());

        assertThatThrownBy(() -> customerService.deleteCustomer(customerId, adminSubject, SecurityContext.standard()))
            .isInstanceOf(AccessDeniedException.class)
            .hasMessageContaining("Administrative mutations (customer deletion) are disabled");

        verify(customerRepository, never()).delete(any(Customer.class));
    }

    @Test
    @DisplayName("In demo profile with mutations-disabled, user deactivation and role modification are rejected")
    void demoMutationsDisabledRejectsUserDeactivationAndRoleChanges() {
        UserService userService = new UserService(userRepository, roleRepository, passwordEncoder);
        ReflectionTestUtils.setField(userService, "demoMutationsDisabled", true);

        UUID userId = UUID.randomUUID();

        assertThatThrownBy(() -> userService.deactivate(userId))
            .isInstanceOf(AccessDeniedException.class)
            .hasMessageContaining("Administrative mutations (user deactivation) are disabled");

        assertThatThrownBy(() -> userService.updateRoles(userId, List.of("ROLE_ADMIN")))
            .isInstanceOf(AccessDeniedException.class)
            .hasMessageContaining("Administrative mutations (role modification) are disabled");

        verify(userRepository, never()).save(any());
    }

    @Test
    @DisplayName("In default/local profile, existing test accounts are preserved")
    void localProfilePreservesExistingTestAccounts() {
        when(environment.getActiveProfiles()).thenReturn(new String[]{"local"});
        Role adminRole = Role.builder().name("ROLE_ADMIN").build();
        Role analystRole = Role.builder().name("ROLE_SECURITY_ANALYST").build();
        Role auditorRole = Role.builder().name("ROLE_AUDITOR").build();
        Role employeeRole = Role.builder().name("ROLE_EMPLOYEE").build();

        when(roleRepository.findByName("ROLE_ADMIN")).thenReturn(Optional.of(adminRole));
        when(roleRepository.findByName("ROLE_SECURITY_ANALYST")).thenReturn(Optional.of(analystRole));
        when(roleRepository.findByName("ROLE_AUDITOR")).thenReturn(Optional.of(auditorRole));
        when(roleRepository.findByName("ROLE_EMPLOYEE")).thenReturn(Optional.of(employeeRole));
        when(userRepository.existsByEmail(anyString())).thenReturn(false);
        when(passwordEncoder.encode(any())).thenReturn("hashed-pwd");

        DataInitializer initializer = new DataInitializer(
            roleRepository, userRepository, customerRepository, accountRepository, passwordEncoder, environment
        );
        ReflectionTestUtils.setField(initializer, "seedDemoData", true);

        initializer.run(new DefaultApplicationArguments());

        // Verifies admin@zerotrust.com is seeded for local/test profile
        verify(userRepository, atLeastOnce()).save(argThat(user -> "admin@zerotrust.com".equals(user.getEmail())));
    }

    @Test
    @DisplayName("Public demo analyst cannot access sensitive customer data (ABAC denial)")
    void demoAnalystCannotAccessSensitiveCustomerData() {
        CustomerService customerService = new CustomerService(
            customerRepository, accountRepository, abacPolicyEnforcer, auditService
        );

        UUID customerId = UUID.randomUUID();
        SecuritySubject analystSubject = new SecuritySubject(
            UUID.randomUUID(), "demo.analyst@zerotrust.com", java.util.Set.of("ROLE_SECURITY_ANALYST"), java.util.Map.of()
        );

        Customer mockCustomer = Customer.builder()
            .id(customerId)
            .customerNumber("CUST-1001")
            .assignedEmployeeId(UUID.randomUUID())
            .riskTier(com.zerotrust.entity.enums.RiskTier.LOW)
            .build();
        when(customerRepository.findById(customerId)).thenReturn(Optional.of(mockCustomer));

        doThrow(new AccessDeniedException("ABAC Denial: Security Analyst denied non-read action VIEW_SENSITIVE"))
            .when(abacPolicyEnforcer).enforce(any(), any(), eq(com.zerotrust.security.abac.SecurityAction.VIEW_SENSITIVE), any());

        assertThatThrownBy(() -> customerService.getSensitiveCustomerData(customerId, analystSubject, SecurityContext.standard()))
            .isInstanceOf(AccessDeniedException.class)
            .hasMessageContaining("ABAC Denial");
    }
}
