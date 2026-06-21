package com.zerotrust.service;

import com.zerotrust.dto.request.LoginRequest;
import com.zerotrust.dto.request.RefreshTokenRequest;
import com.zerotrust.dto.request.RegisterRequest;
import com.zerotrust.dto.response.AuthResponse;
import com.zerotrust.entity.RefreshToken;
import com.zerotrust.entity.Role;
import com.zerotrust.entity.User;
import com.zerotrust.entity.enums.AuditStatus;
import com.zerotrust.exception.AccountLockedException;
import com.zerotrust.exception.ResourceNotFoundException;
import com.zerotrust.exception.UnauthorizedException;
import com.zerotrust.exception.ValidationException;
import com.zerotrust.repository.RefreshTokenRepository;
import com.zerotrust.repository.RoleRepository;
import com.zerotrust.repository.UserRepository;
import com.zerotrust.security.JwtTokenProvider;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

/**
 * Handles user registration, authentication, and token lifecycle.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository        userRepository;
    private final RoleRepository        roleRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtTokenProvider      jwtTokenProvider;
    private final PasswordEncoder       passwordEncoder;
    private final AuditService          auditService;

    @Value("${jwt.refresh-token-expiry-ms}")
    private long refreshTokenExpiryMs;

    @Value("${app.security.max-failed-logins}")
    private int maxFailedLogins;

    @Value("${app.security.lockout-duration-minutes}")
    private long lockoutDurationMinutes;

    // ─────────────────────────────────────────────
    // REGISTRATION
    // ─────────────────────────────────────────────

    @Transactional
    public AuthResponse register(RegisterRequest request, HttpServletRequest httpRequest) {
        if (userRepository.existsByEmail(request.email())) {
            throw new ValidationException("Email already registered: " + request.email());
        }

        Role defaultRole = roleRepository.findByName("ROLE_EMPLOYEE")
            .orElseThrow(() -> new IllegalStateException("Default role ROLE_EMPLOYEE not found"));

        User user = User.builder()
            .email(request.email())
            .passwordHash(passwordEncoder.encode(request.password()))
            .firstName(request.firstName())
            .lastName(request.lastName())
            .isActive(true)
            .isLocked(false)
            .roles(Set.of(defaultRole))
            .build();

        user = userRepository.save(user);
        log.info("New user registered: {}", user.getEmail());

        auditService.log(user.getId().toString(), user.getEmail(),
            "USER_REGISTER", "USER", user.getId().toString(),
            getClientIp(httpRequest), httpRequest.getHeader("User-Agent"),
            AuditStatus.SUCCESS, 0, "User registered successfully");

        return buildAuthResponse(user, httpRequest);
    }

    // ─────────────────────────────────────────────
    // LOGIN
    // ─────────────────────────────────────────────

    @Transactional
    public AuthResponse login(LoginRequest request, HttpServletRequest httpRequest) {
        String clientIp = getClientIp(httpRequest);

        User user = userRepository.findByEmail(request.email())
            .orElseThrow(() -> {
                log.warn("Login attempt for non-existent user: {}", request.email());
                return new UnauthorizedException("Invalid email or password");
            });

        // Check account lock
        if (user.isAccountCurrentlyLocked()) {
            auditService.log(user.getId().toString(), user.getEmail(),
                "USER_LOGIN_BLOCKED", "USER", user.getId().toString(),
                clientIp, httpRequest.getHeader("User-Agent"),
                AuditStatus.BLOCKED, 60, "Account locked");
            throw new AccountLockedException(
                "Account locked until " + user.getLockUntil() + ". Too many failed attempts.");
        }

        // Verify password
        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            user.incrementFailedLoginAttempts(maxFailedLogins, lockoutDurationMinutes);
            userRepository.save(user);

            String details = "Failed login attempt " + user.getFailedLoginAttempts() +
                             "/" + maxFailedLogins;
            auditService.log(user.getId().toString(), user.getEmail(),
                "USER_LOGIN_FAILED", "USER", user.getId().toString(),
                clientIp, httpRequest.getHeader("User-Agent"),
                AuditStatus.FAILURE, 40, details);

            log.warn("Failed login attempt {} for user: {}", user.getFailedLoginAttempts(), user.getEmail());
            throw new UnauthorizedException("Invalid email or password");
        }

        // Check if account is active
        if (!user.isActive()) {
            throw new UnauthorizedException("Account is deactivated. Contact your administrator.");
        }

        // Successful login — reset failure counter
        user.resetLoginFailures();
        user.setLastLoginAt(Instant.now());
        user.setLastLoginIp(clientIp);
        userRepository.save(user);

        auditService.log(user.getId().toString(), user.getEmail(),
            "USER_LOGIN", "USER", user.getId().toString(),
            clientIp, httpRequest.getHeader("User-Agent"),
            AuditStatus.SUCCESS, 0, "Successful login");

        log.info("User logged in successfully: {}", user.getEmail());
        return buildAuthResponse(user, httpRequest);
    }

    // ─────────────────────────────────────────────
    // REFRESH TOKEN
    // ─────────────────────────────────────────────

    @Transactional
    public AuthResponse refreshToken(RefreshTokenRequest request, HttpServletRequest httpRequest) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(request.refreshToken())
            .orElseThrow(() -> new UnauthorizedException("Invalid refresh token"));

        if (!refreshToken.isValid()) {
            throw new UnauthorizedException("Refresh token is expired or revoked");
        }

        User user = userRepository.findById(refreshToken.getUserId())
            .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        if (!user.isActive()) {
            throw new UnauthorizedException("Account is deactivated");
        }

        // Rotate: revoke old token
        refreshToken.setRevoked(true);
        refreshTokenRepository.save(refreshToken);

        log.debug("Refresh token rotated for user: {}", user.getEmail());
        return buildAuthResponse(user, httpRequest);
    }

    // ─────────────────────────────────────────────
    // LOGOUT
    // ─────────────────────────────────────────────

    @Transactional
    public void logout(String refreshTokenStr, String userId, HttpServletRequest httpRequest) {
        refreshTokenRepository.findByToken(refreshTokenStr).ifPresent(token -> {
            token.setRevoked(true);
            refreshTokenRepository.save(token);
        });

        auditService.log(userId, null,
            "USER_LOGOUT", "USER", userId,
            getClientIp(httpRequest), httpRequest.getHeader("User-Agent"),
            AuditStatus.SUCCESS, 0, "User logged out");
    }

    // ─────────────────────────────────────────────
    // HELPERS
    // ─────────────────────────────────────────────

    private AuthResponse buildAuthResponse(User user, HttpServletRequest httpRequest) {
        String accessToken  = jwtTokenProvider.generateAccessToken(
            user.getId(), user.getEmail(), user.getRoleNames());
        String refreshTokenStr = jwtTokenProvider.generateRefreshToken();

        RefreshToken refreshToken = RefreshToken.builder()
            .token(refreshTokenStr)
            .userId(user.getId())
            .expiresAt(Instant.now().plusMillis(refreshTokenExpiryMs))
            .revoked(false)
            .ipAddress(getClientIp(httpRequest))
            .userAgent(httpRequest.getHeader("User-Agent"))
            .build();
        refreshTokenRepository.save(refreshToken);

        return new AuthResponse(
            accessToken, refreshTokenStr, "Bearer",
            refreshTokenExpiryMs / 1000,
            new AuthResponse.UserSummary(
                user.getId(), user.getEmail(),
                user.getFirstName(), user.getLastName(),
                user.getRoleNames())
        );
    }

    private String getClientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        String realIp = request.getHeader("X-Real-IP");
        return realIp != null ? realIp : request.getRemoteAddr();
    }

    /** Periodically clean up expired refresh tokens */
    @Scheduled(fixedDelay = 3600000) // every hour
    @Transactional
    public void cleanupExpiredTokens() {
        int deleted = refreshTokenRepository.deleteExpiredTokens(Instant.now());
        if (deleted > 0) {
            log.info("Cleaned up {} expired refresh tokens", deleted);
        }
    }
}
