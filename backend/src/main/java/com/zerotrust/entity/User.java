package com.zerotrust.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Core User entity representing a platform user.
 * Handles authentication state, lockout tracking, and role associations.
 */
@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true, length = 255)
    private String email;

    @Column(nullable = false)
    private String passwordHash;

    @Column(nullable = false, length = 100)
    private String firstName;

    @Column(nullable = false, length = 100)
    private String lastName;

    @Column(nullable = false)
    @Builder.Default
    private boolean isActive = true;

    @Column(nullable = false)
    @Builder.Default
    private boolean isLocked = false;

    @Column(nullable = false)
    @Builder.Default
    private int failedLoginAttempts = 0;

    private Instant lockUntil;

    private Instant lastLoginAt;

    @Column(length = 45)
    private String lastLoginIp;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(nullable = false)
    private Instant updatedAt;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
        name = "user_roles",
        joinColumns = @JoinColumn(name = "user_id"),
        inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    @Builder.Default
    private Set<Role> roles = new HashSet<>();

    /**
     * Returns role names as a list of strings for JWT claims.
     */
    public List<String> getRoleNames() {
        return roles.stream()
            .map(Role::getName)
            .collect(Collectors.toList());
    }

    /**
     * Full name for display purposes.
     */
    public String getFullName() {
        return firstName + " " + lastName;
    }

    /**
     * Checks if account is currently locked, auto-unlocks if lock period has passed.
     */
    public boolean isAccountCurrentlyLocked() {
        if (!isLocked) return false;
        if (lockUntil != null && Instant.now().isAfter(lockUntil)) {
            this.isLocked = false;
            this.failedLoginAttempts = 0;
            this.lockUntil = null;
            return false;
        }
        return true;
    }

    /**
     * Increments failed login counter and locks account if threshold is reached.
     */
    public void incrementFailedLoginAttempts(int maxAttempts, long lockoutMinutes) {
        this.failedLoginAttempts++;
        if (this.failedLoginAttempts >= maxAttempts) {
            this.isLocked = true;
            this.lockUntil = Instant.now().plusSeconds(lockoutMinutes * 60);
        }
    }

    /**
     * Resets login failure tracking on successful authentication.
     */
    public void resetLoginFailures() {
        this.failedLoginAttempts = 0;
        this.isLocked = false;
        this.lockUntil = null;
    }
}
