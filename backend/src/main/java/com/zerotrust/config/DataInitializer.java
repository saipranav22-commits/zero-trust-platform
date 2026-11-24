package com.zerotrust.config;

import com.zerotrust.entity.Account;
import com.zerotrust.entity.Customer;
import com.zerotrust.entity.Role;
import com.zerotrust.entity.User;
import com.zerotrust.entity.enums.AccountStatus;
import com.zerotrust.entity.enums.AccountType;
import com.zerotrust.entity.enums.KycStatus;
import com.zerotrust.entity.enums.RiskTier;
import com.zerotrust.repository.AccountRepository;
import com.zerotrust.repository.CustomerRepository;
import com.zerotrust.repository.RoleRepository;
import com.zerotrust.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.util.Arrays;
import java.util.Set;

/**
 * Seeds the database with default roles.
 * Synthetic demo users and banking records are DISABLED by default and strictly prohibited in production.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class DataInitializer implements ApplicationRunner {

    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final CustomerRepository customerRepository;
    private final AccountRepository accountRepository;
    private final PasswordEncoder passwordEncoder;
    private final Environment environment;

    @Value("${app.seed-demo-data:false}")
    private boolean seedDemoData;

    @Value("${app.demo.admin-password:}")
    private String demoAdminPassword;

    @Value("${app.demo.analyst-password:}")
    private String demoAnalystPassword;

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        seedRoles();

        boolean isProd = Arrays.asList(environment.getActiveProfiles()).contains("prod");
        if (isProd && seedDemoData) {
            throw new IllegalStateException(
                "CRITICAL SECURITY CONFIGURATION ERROR: Demo data seeding (app.seed-demo-data=true) " +
                "is strictly prohibited in the 'prod' profile. Application startup aborted."
            );
        }

        if (!seedDemoData) {
            log.info("Demo data seeding is disabled by default (app.seed-demo-data=false). Skipping demo user creation.");
            return;
        }

        boolean isDemo = Arrays.asList(environment.getActiveProfiles()).contains("demo");
        if (isDemo) {
            log.info("🌐 Initializing restricted public demo profile with safe credentials and synthetic data.");
            seedPublicDemoUsers();
            seedSyntheticBankingData();
            return;
        }

        log.warn("⚠️ Demo data seeding is ENABLED (app.seed-demo-data=true). Creating synthetic development accounts.");
        seedUsers();
        seedSyntheticBankingData();
    }

    private void seedPublicDemoUsers() {
        Role adminRole = roleRepository.findByName("ROLE_ADMIN")
            .orElseThrow(() -> new IllegalStateException("ROLE_ADMIN not found — roles must be seeded first"));
        Role analystRole = roleRepository.findByName("ROLE_SECURITY_ANALYST").orElse(adminRole);

        // 1. In public demo mode, NEVER create an admin account with default/hardcoded passwords.
        // An admin is only created if DEMO_ADMIN_PASSWORD is set by the platform administrator via environment variable.
        if (org.springframework.util.StringUtils.hasText(demoAdminPassword) && !userRepository.existsByEmail("admin@zerotrust.com")) {
            User admin = User.builder()
                .email("admin@zerotrust.com")
                .passwordHash(passwordEncoder.encode(demoAdminPassword))
                .firstName("System")
                .lastName("Administrator")
                .isActive(true)
                .isLocked(false)
                .roles(Set.of(adminRole))
                .build();
            userRepository.save(admin);
            log.info("🔐 Configured demo administrator account provisioned via environment secret.");
        } else if (!userRepository.existsByEmail("admin@zerotrust.com")) {
            log.info("🛡️ Public demo mode: Default admin account creation skipped (no DEMO_ADMIN_PASSWORD provided).");
        }

        // 2. Provision least-privilege demo analyst account (read-only monitoring & threat triage)
        String analystPassword = org.springframework.util.StringUtils.hasText(demoAnalystPassword)
            ? demoAnalystPassword : "DemoAnalyst@2026!";
        if (!userRepository.existsByEmail("demo.analyst@zerotrust.com")) {
            User demoAnalyst = User.builder()
                .email("demo.analyst@zerotrust.com")
                .passwordHash(passwordEncoder.encode(analystPassword))
                .firstName("Demo")
                .lastName("Analyst")
                .isActive(true)
                .isLocked(false)
                .roles(Set.of(analystRole))
                .build();
            userRepository.save(demoAnalyst);
            log.info("✅ Least-privilege public demo analyst provisioned: demo.analyst@zerotrust.com (ROLE_SECURITY_ANALYST)");
        }
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

    private void seedUsers() {
        Role adminRole = roleRepository.findByName("ROLE_ADMIN")
            .orElseThrow(() -> new IllegalStateException("ROLE_ADMIN not found — roles must be seeded first"));
        Role analystRole = roleRepository.findByName("ROLE_SECURITY_ANALYST").orElse(adminRole);
        Role auditorRole = roleRepository.findByName("ROLE_AUDITOR").orElse(adminRole);
        Role employeeRole = roleRepository.findByName("ROLE_EMPLOYEE").orElse(adminRole);

        if (!userRepository.existsByEmail("admin@zerotrust.com")) {
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
        }

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

        if (!userRepository.existsByEmail("auditor@zerotrust.com")) {
            User auditor = User.builder()
                .email("auditor@zerotrust.com")
                .passwordHash(passwordEncoder.encode("Auditor@123"))
                .firstName("Compliance")
                .lastName("Auditor")
                .isActive(true)
                .isLocked(false)
                .roles(Set.of(auditorRole))
                .build();
            userRepository.save(auditor);
            log.info("✅ Demo auditor user created: auditor@zerotrust.com / Auditor@123");
        }

        if (!userRepository.existsByEmail("employee@zerotrust.com")) {
            User employee = User.builder()
                .email("employee@zerotrust.com")
                .passwordHash(passwordEncoder.encode("Employee@123"))
                .firstName("Employee")
                .lastName("Primary")
                .isActive(true)
                .isLocked(false)
                .roles(Set.of(employeeRole))
                .build();
            userRepository.save(employee);
            log.info("✅ Demo employee user created: employee@zerotrust.com / Employee@123");
        }

        if (!userRepository.existsByEmail("employee2@zerotrust.com")) {
            User employee2 = User.builder()
                .email("employee2@zerotrust.com")
                .passwordHash(passwordEncoder.encode("Employee@123"))
                .firstName("Employee")
                .lastName("Secondary")
                .isActive(true)
                .isLocked(false)
                .roles(Set.of(employeeRole))
                .build();
            userRepository.save(employee2);
            log.info("✅ Demo employee2 user created: employee2@zerotrust.com / Employee@123");
        }
    }

    private void seedSyntheticBankingData() {
        if (customerRepository.count() > 0) {
            return;
        }

        User employee1 = userRepository.findByEmail("employee@zerotrust.com").orElse(null);
        User employee2 = userRepository.findByEmail("employee2@zerotrust.com").orElse(null);

        // Customer 1 assigned to Employee 1
        Customer cust1 = Customer.builder()
            .customerNumber("CUST-1001")
            .firstName("Client")
            .lastName("Alpha")
            .email("client.alpha@synthetic-domain.test")
            .phoneNumber("+1-555-0101")
            .kycStatus(KycStatus.VERIFIED)
            .riskTier(RiskTier.LOW)
            .assignedEmployeeId(employee1 != null ? employee1.getId() : null)
            .syntheticTaxId("SYN-991-8841")
            .annualIncome(new BigDecimal("125000.00"))
            .creditScore(780)
            .build();
        customerRepository.save(cust1);

        Account acc1 = Account.builder()
            .customer(cust1)
            .accountNumber("ACC-CHK-1001")
            .accountType(AccountType.CHECKING)
            .balance(new BigDecimal("24500.00"))
            .currency("USD")
            .status(AccountStatus.ACTIVE)
            .build();
        accountRepository.save(acc1);

        // Customer 2 assigned to Employee 2 (for BOLA testing)
        Customer cust2 = Customer.builder()
            .customerNumber("CUST-1002")
            .firstName("Client")
            .lastName("Beta")
            .email("client.beta@synthetic-domain.test")
            .phoneNumber("+1-555-0102")
            .kycStatus(KycStatus.VERIFIED)
            .riskTier(RiskTier.MEDIUM)
            .assignedEmployeeId(employee2 != null ? employee2.getId() : null)
            .syntheticTaxId("SYN-772-5512")
            .annualIncome(new BigDecimal("85000.00"))
            .creditScore(690)
            .build();
        customerRepository.save(cust2);

        Account acc2 = Account.builder()
            .customer(cust2)
            .accountNumber("ACC-SAV-2002")
            .accountType(AccountType.SAVINGS)
            .balance(new BigDecimal("50000.00"))
            .currency("USD")
            .status(AccountStatus.ACTIVE)
            .build();
        accountRepository.save(acc2);

        log.info("✅ Synthetic banking dataset initialized with 2 customer portfolios");
    }
}
