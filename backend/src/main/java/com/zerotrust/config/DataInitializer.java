package com.zerotrust.config;

import com.zerotrust.entity.Role;
import com.zerotrust.entity.User;
import com.zerotrust.repository.RoleRepository;
import com.zerotrust.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

/**
 * Seeds the database with default roles and an admin user on startup.
 * Only runs if the data does not already exist.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class DataInitializer implements ApplicationRunner {

    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        seedRoles();
        seedAdminUser();
    }

    private void seedRoles() {
        String[] roles = {
            "ROLE_ADMIN",
            "ROLE_SECURITY_ANALYST",
            "ROLE_AUDITOR",
            "ROLE_EMPLOYEE"
        };

        String[] descriptions = {
            "Full system administrator with all privileges",
            "Can view and manage threat events and analytics",
            "Read-only access to audit logs and reports",
            "Standard employee with limited access"
        };

        for (int i = 0; i < roles.length; i++) {
            final String roleName = roles[i];
            final String roleDesc = descriptions[i];
            if (roleRepository.findByName(roleName).isEmpty()) {
                Role role = Role.builder()
                    .name(roleName)
                    .description(roleDesc)
                    .build();
                roleRepository.save(role);
                log.info("Created role: {}", roleName);
            }
        }
    }

    private void seedAdminUser() {
        if (userRepository.existsByEmail("admin@zerotrust.com")) {
            log.debug("Admin user already exists, skipping seed");
            return;
        }

        Role adminRole = roleRepository.findByName("ROLE_ADMIN")
            .orElseThrow(() -> new IllegalStateException("ROLE_ADMIN not found — roles must be seeded first"));

        User admin = User.builder()
            .email("admin@zerotrust.com")
            .passwordHash(passwordEncoder.encode("Admin@123"))
            .firstName("System")
            .lastName("Administrator")
            .isActive(true)
            .isLocked(false)
            .roles(Set.of(adminRole))
            .build();

        userRepository.save(admin);
        log.info("✅ Default admin user created: admin@zerotrust.com / Admin@123");

        // Also create a demo analyst user
        Role analystRole = roleRepository.findByName("ROLE_SECURITY_ANALYST")
            .orElse(adminRole);

        if (!userRepository.existsByEmail("analyst@zerotrust.com")) {
            User analyst = User.builder()
                .email("analyst@zerotrust.com")
                .passwordHash(passwordEncoder.encode("Analyst@123"))
                .firstName("Security")
                .lastName("Analyst")
                .isActive(true)
                .isLocked(false)
                .roles(Set.of(analystRole))
                .build();
            userRepository.save(analyst);
            log.info("✅ Demo analyst user created: analyst@zerotrust.com / Analyst@123");
        }
    }
}
