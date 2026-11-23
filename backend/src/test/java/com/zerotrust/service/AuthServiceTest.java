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
import com.zerotrust.exception.UnauthorizedException;
import com.zerotrust.exception.ValidationException;
import com.zerotrust.repository.RefreshTokenRepository;
import com.zerotrust.repository.RoleRepository;
import com.zerotrust.repository.UserRepository;
import com.zerotrust.security.JwtTokenProvider;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private JwtTokenProvider jwtTokenProvider;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private AuditService auditService;

    @Mock
    private HttpServletRequest httpRequest;

    @InjectMocks
    private AuthService authService;

    private Role employeeRole;
    private User activeUser;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(authService, "refreshTokenExpiryMs", 604800000L);
        ReflectionTestUtils.setField(authService, "maxFailedLogins", 5);
        ReflectionTestUtils.setField(authService, "lockoutDurationMinutes", 15L);

        employeeRole = Role.builder()
            .id(UUID.randomUUID())
            .name("ROLE_EMPLOYEE")
            .description("Standard employee")
            .build();

        activeUser = User.builder()
            .id(UUID.randomUUID())
            .email("user@zerotrust.com")
            .passwordHash("$2a$12$encodedHash")
            .firstName("Jane")
            .lastName("Doe")
            .isActive(true)
            .isLocked(false)
            .failedLoginAttempts(0)
            .roles(Set.of(employeeRole))
            .build();

        lenient().when(httpRequest.getRemoteAddr()).thenReturn("192.168.1.10");
        lenient().when(httpRequest.getHeader("User-Agent")).thenReturn("JUnit-Test-Agent");
    }

    @Test
    @DisplayName("Registration should create new user with ROLE_EMPLOYEE and return tokens")
    void shouldRegisterNewUser() {
        RegisterRequest req = new RegisterRequest("newuser@zerotrust.com", "Password@123", "Alice", "Smith");

        when(userRepository.existsByEmail("newuser@zerotrust.com")).thenReturn(false);
        when(roleRepository.findByName("ROLE_EMPLOYEE")).thenReturn(Optional.of(employeeRole));
        when(passwordEncoder.encode("Password@123")).thenReturn("$2a$12$hashed");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User u = invocation.getArgument(0);
            u.setId(UUID.randomUUID());
            return u;
        });
        when(jwtTokenProvider.generateAccessToken(any(), any(), any())).thenReturn("mock-access-token");
        when(jwtTokenProvider.generateRefreshToken()).thenReturn(UUID.randomUUID().toString());

        AuthResponse res = authService.register(req, httpRequest);

        assertThat(res).isNotNull();
        assertThat(res.accessToken()).isEqualTo("mock-access-token");
        assertThat(res.user().email()).isEqualTo("newuser@zerotrust.com");
        verify(userRepository).save(any(User.class));
        verify(auditService).log(anyString(), eq("newuser@zerotrust.com"), eq("USER_REGISTER"), any(), any(), any(), any(), eq(AuditStatus.SUCCESS), eq(0), anyString());
    }

    @Test
    @DisplayName("Registration with duplicate email must throw ValidationException")
    void shouldRejectDuplicateEmail() {
        RegisterRequest req = new RegisterRequest("existing@zerotrust.com", "Password@123", "Alice", "Smith");
        when(userRepository.existsByEmail("existing@zerotrust.com")).thenReturn(true);

        assertThatThrownBy(() -> authService.register(req, httpRequest))
            .isInstanceOf(ValidationException.class)
            .hasMessageContaining("Email already registered");

        verify(userRepository, never()).save(any());
    }

    @Test
    @DisplayName("Login with valid password should authenticate and reset failed attempts")
    void shouldAuthenticateValidLogin() {
        LoginRequest req = new LoginRequest("user@zerotrust.com", "CorrectPassword@123");

        when(userRepository.findByEmail("user@zerotrust.com")).thenReturn(Optional.of(activeUser));
        when(passwordEncoder.matches("CorrectPassword@123", activeUser.getPasswordHash())).thenReturn(true);
        when(jwtTokenProvider.generateAccessToken(any(), any(), any())).thenReturn("jwt-token-123");
        when(jwtTokenProvider.generateRefreshToken()).thenReturn(UUID.randomUUID().toString());

        AuthResponse res = authService.login(req, httpRequest);

        assertThat(res.accessToken()).isEqualTo("jwt-token-123");
        assertThat(activeUser.getFailedLoginAttempts()).isEqualTo(0);
        verify(userRepository).save(activeUser);
        verify(auditService).log(eq(activeUser.getId().toString()), eq("user@zerotrust.com"), eq("USER_LOGIN"), any(), any(), any(), any(), eq(AuditStatus.SUCCESS), eq(0), anyString());
    }

    @Test
    @DisplayName("Login with invalid password should increment failed attempts and throw UnauthorizedException")
    void shouldRejectInvalidPassword() {
        LoginRequest req = new LoginRequest("user@zerotrust.com", "WrongPassword");

        when(userRepository.findByEmail("user@zerotrust.com")).thenReturn(Optional.of(activeUser));
        when(passwordEncoder.matches("WrongPassword", activeUser.getPasswordHash())).thenReturn(false);

        assertThatThrownBy(() -> authService.login(req, httpRequest))
            .isInstanceOf(UnauthorizedException.class)
            .hasMessageContaining("Invalid email or password");

        assertThat(activeUser.getFailedLoginAttempts()).isEqualTo(1);
        verify(userRepository).save(activeUser);
        verify(auditService).log(anyString(), anyString(), eq("USER_LOGIN_FAILED"), any(), any(), any(), any(), eq(AuditStatus.FAILURE), anyInt(), anyString());
    }

    @Test
    @DisplayName("Login on locked account should throw AccountLockedException")
    void shouldBlockLockedAccount() {
        activeUser.setLocked(true);
        activeUser.setLockUntil(Instant.now().plusSeconds(900));

        LoginRequest req = new LoginRequest("user@zerotrust.com", "AnyPassword");
        when(userRepository.findByEmail("user@zerotrust.com")).thenReturn(Optional.of(activeUser));

        assertThatThrownBy(() -> authService.login(req, httpRequest))
            .isInstanceOf(AccountLockedException.class)
            .hasMessageContaining("Account locked");

        verify(auditService).log(anyString(), anyString(), eq("USER_LOGIN_BLOCKED"), any(), any(), any(), any(), eq(AuditStatus.BLOCKED), anyInt(), anyString());
        verify(passwordEncoder, never()).matches(any(), any());
    }

    @Test
    @DisplayName("Refresh token rotation should revoke old token and return new tokens")
    void shouldRotateRefreshToken() {
        String oldTokenStr = UUID.randomUUID().toString();
        RefreshToken oldToken = RefreshToken.builder()
            .token(oldTokenStr)
            .userId(activeUser.getId())
            .expiresAt(Instant.now().plusSeconds(3600))
            .revoked(false)
            .build();

        when(refreshTokenRepository.findByToken(oldTokenStr)).thenReturn(Optional.of(oldToken));
        when(userRepository.findById(activeUser.getId())).thenReturn(Optional.of(activeUser));
        when(jwtTokenProvider.generateAccessToken(any(), any(), any())).thenReturn("new-access-token");
        when(jwtTokenProvider.generateRefreshToken()).thenReturn(UUID.randomUUID().toString());

        AuthResponse res = authService.refreshToken(new RefreshTokenRequest(oldTokenStr), httpRequest);

        assertThat(res.accessToken()).isEqualTo("new-access-token");
        assertThat(oldToken.isRevoked()).isTrue();
        verify(refreshTokenRepository, times(2)).save(any(RefreshToken.class)); // 1 for revoking old, 1 for saving new
    }

    @Test
    @DisplayName("Refresh with revoked token should throw UnauthorizedException")
    void shouldRejectRevokedRefreshToken() {
        String tokenStr = "revoked-token";
        RefreshToken revokedToken = RefreshToken.builder()
            .token(tokenStr)
            .userId(activeUser.getId())
            .expiresAt(Instant.now().plusSeconds(3600))
            .revoked(true)
            .build();

        when(refreshTokenRepository.findByToken(tokenStr)).thenReturn(Optional.of(revokedToken));

        assertThatThrownBy(() -> authService.refreshToken(new RefreshTokenRequest(tokenStr), httpRequest))
            .isInstanceOf(UnauthorizedException.class)
            .hasMessageContaining("expired or revoked");
    }

    @Test
    @DisplayName("Logout should revoke the specified refresh token")
    void shouldRevokeTokenOnLogout() {
        String tokenStr = "active-token";
        RefreshToken token = RefreshToken.builder()
            .token(tokenStr)
            .userId(activeUser.getId())
            .expiresAt(Instant.now().plusSeconds(3600))
            .revoked(false)
            .build();

        when(refreshTokenRepository.findByToken(tokenStr)).thenReturn(Optional.of(token));

        authService.logout(tokenStr, activeUser.getId().toString(), httpRequest);

        assertThat(token.isRevoked()).isTrue();
        verify(refreshTokenRepository).save(token);
        verify(auditService).log(eq(activeUser.getId().toString()), isNull(), eq("USER_LOGOUT"), any(), any(), any(), any(), eq(AuditStatus.SUCCESS), eq(0), anyString());
    }
}
