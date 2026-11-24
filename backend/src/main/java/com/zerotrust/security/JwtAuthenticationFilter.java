package com.zerotrust.security;

import com.zerotrust.service.RedisSecurityService;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

/**
 * JWT authentication filter that validates Bearer tokens on every request.
 * Checks Redis revocation denylist for immediate access termination.
 * Sets SecurityContext if token is valid so downstream can use @PreAuthorize.
 */
@Slf4j
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final RedisSecurityService redisSecurityService;

    public JwtAuthenticationFilter(
            JwtTokenProvider jwtTokenProvider,
            @Autowired(required = false) RedisSecurityService redisSecurityService) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.redisSecurityService = redisSecurityService;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        try {
            String token = extractBearerToken(request);

            if (StringUtils.hasText(token) && jwtTokenProvider.isTokenValid(token)) {
                // Check distributed revocation denylist
                if (redisSecurityService != null) {
                    try {
                        if (redisSecurityService.isTokenRevoked(token)) {
                            log.warn("Access attempt with revoked JWT token");
                            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                            response.setContentType("application/json");
                            response.getWriter().write("{\"success\":false,\"status\":401,\"message\":\"Access token has been revoked\"}");
                            return;
                        }
                    } catch (RedisSecurityService.RedisSecurityException ex) {
                        log.error("Mandatory Redis token revocation check unavailable for path {}: failing closed", request.getRequestURI());
                        response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
                        response.setContentType("application/json");
                        response.getWriter().write("{\"success\":false,\"status\":503,\"message\":\"Security state verification unavailable. Mandatory revocation check failed.\"}");
                        return;
                    }
                }

                String userId = jwtTokenProvider.extractUserId(token);
                String email  = jwtTokenProvider.extractEmail(token);
                List<String> roles = jwtTokenProvider.extractRoles(token);

                List<SimpleGrantedAuthority> authorities = roles.stream()
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());

                // Build authentication token — no password needed (already validated JWT)
                UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(email, null, authorities);
                authentication.setDetails(
                    new WebAuthenticationDetailsSource().buildDetails(request));

                // Store userId for controllers to access via MDC or request attribute
                request.setAttribute("userId", userId);
                request.setAttribute("userEmail", email);

                SecurityContextHolder.getContext().setAuthentication(authentication);
                log.debug("Set authentication for user: {}", email);
            }
        } catch (JwtException e) {
            log.debug("JWT validation failed: {}", e.getMessage());
            SecurityContextHolder.clearContext();
        } catch (Exception e) {
            log.error("Could not set user authentication in security context", e);
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }

    private String extractBearerToken(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }
}
