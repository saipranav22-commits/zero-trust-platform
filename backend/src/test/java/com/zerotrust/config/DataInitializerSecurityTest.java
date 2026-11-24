package com.zerotrust.config;

import com.zerotrust.repository.AccountRepository;
import com.zerotrust.repository.CustomerRepository;
import com.zerotrust.repository.RoleRepository;
import com.zerotrust.repository.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.core.env.Environment;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class DataInitializerSecurityTest {

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

    @Test
    @DisplayName("Should fail fast with IllegalStateException if demo seeding is enabled in prod profile")
    void shouldFailFastIfDemoSeedingInProd() {
        when(environment.getActiveProfiles()).thenReturn(new String[]{"prod"});
        when(roleRepository.findByName(any())).thenReturn(Optional.empty());

        DataInitializer initializer = new DataInitializer(
            roleRepository, userRepository, customerRepository, accountRepository, passwordEncoder, environment
        );
        ReflectionTestUtils.setField(initializer, "seedDemoData", true);

        assertThatThrownBy(() -> initializer.run(new DefaultApplicationArguments()))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("strictly prohibited in the 'prod' profile");

        verify(userRepository, never()).save(any());
        verify(customerRepository, never()).save(any());
    }

    @Test
    @DisplayName("Should skip demo users and synthetic records when app.seed-demo-data is false")
    void shouldSkipDemoUsersWhenDisabledByDefault() {
        when(environment.getActiveProfiles()).thenReturn(new String[]{"default"});
        when(roleRepository.findByName(any())).thenReturn(Optional.empty());

        DataInitializer initializer = new DataInitializer(
            roleRepository, userRepository, customerRepository, accountRepository, passwordEncoder, environment
        );
        ReflectionTestUtils.setField(initializer, "seedDemoData", false);

        initializer.run(new DefaultApplicationArguments());

        // Roles must still be seeded
        verify(roleRepository, atLeastOnce()).save(any());

        // Users and customer portfolios must NOT be seeded
        verify(userRepository, never()).save(any());
        verify(customerRepository, never()).save(any());
        verify(accountRepository, never()).save(any());
    }
}
