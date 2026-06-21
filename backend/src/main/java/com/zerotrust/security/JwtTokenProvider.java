package com.zerotrust.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * JWT token provider for generating and validating access tokens.
 * Uses HMAC-SHA256 (HS256) signing algorithm.
 */
@Slf4j
@Component
public class JwtTokenProvider {

    private final SecretKey secretKey;
    private final long accessTokenExpiryMs;

    public JwtTokenProvider(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.access-token-expiry-ms}") long accessTokenExpiryMs) {
        byte[] keyBytes = Decoders.BASE64.decode(
            java.util.Base64.getEncoder().encodeToString(secret.getBytes())
        );
        this.secretKey = Keys.hmacShaKeyFor(keyBytes);
        this.accessTokenExpiryMs = accessTokenExpiryMs;
    }

    /**
     * Generates a signed JWT access token.
     */
    public String generateAccessToken(UUID userId, String email, List<String> roles) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + accessTokenExpiryMs);

        return Jwts.builder()
            .subject(userId.toString())
            .issuedAt(now)
            .expiration(expiry)
            .claims(Map.of(
                "email", email,
                "roles", roles,
                "userId", userId.toString()
            ))
            .signWith(secretKey, Jwts.SIG.HS256)
            .compact();
    }

    /**
     * Generates a refresh token (opaque UUID string).
     */
    public String generateRefreshToken() {
        return UUID.randomUUID().toString();
    }

    /**
     * Validates the JWT token and returns its claims.
     * @throws JwtException if token is invalid or expired
     */
    public Claims validateAndGetClaims(String token) {
        return Jwts.parser()
            .verifyWith(secretKey)
            .build()
            .parseSignedClaims(token)
            .getPayload();
    }

    /**
     * Extracts the user ID from a JWT token.
     */
    public String extractUserId(String token) {
        return validateAndGetClaims(token).getSubject();
    }

    /**
     * Extracts the email from a JWT token.
     */
    public String extractEmail(String token) {
        return validateAndGetClaims(token).get("email", String.class);
    }

    /**
     * Extracts roles list from a JWT token.
     */
    @SuppressWarnings("unchecked")
    public List<String> extractRoles(String token) {
        return validateAndGetClaims(token).get("roles", List.class);
    }

    /**
     * Checks if a token is expired without throwing.
     */
    public boolean isTokenExpired(String token) {
        try {
            return validateAndGetClaims(token).getExpiration().before(new Date());
        } catch (JwtException e) {
            return true;
        }
    }

    /**
     * Validates token without throwing — returns true if valid.
     */
    public boolean isTokenValid(String token) {
        try {
            validateAndGetClaims(token);
            return true;
        } catch (ExpiredJwtException e) {
            log.debug("JWT token expired: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            log.debug("JWT token malformed: {}", e.getMessage());
        } catch (SecurityException e) {
            log.debug("JWT signature invalid: {}", e.getMessage());
        } catch (JwtException e) {
            log.debug("JWT validation failed: {}", e.getMessage());
        }
        return false;
    }
}
