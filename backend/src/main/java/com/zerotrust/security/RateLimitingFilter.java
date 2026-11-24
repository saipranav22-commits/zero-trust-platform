package com.zerotrust.security;

import com.zerotrust.service.RedisSecurityService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Distributed Rate Limiting Filter positioned immediately after JwtAuthenticationFilter.
 * Enforces per-endpoint tier sliding-window limits backed by Redis Lua scripts.
 * Employs authenticated principal identity for authenticated requests and
 * trusted-proxy-validated client IP for unauthenticated requests.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class RateLimitingFilter extends OncePerRequestFilter {

    private final RedisSecurityService redisSecurityService;

    @Value("${app.rate-limit.enabled:true}")
    private boolean rateLimitEnabled;

    @Value("${app.security.trusted-proxies:127.0.0.1,::1}")
    private String trustedProxiesConfig;

    @Override
    protected boolean shouldNotFilter(@NonNull HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.startsWith("/actuator")
            || path.startsWith("/api-docs")
            || path.startsWith("/swagger-ui")
            || path.equals("/favicon.ico");
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        if (!rateLimitEnabled) {
            filterChain.doFilter(request, response);
            return;
        }

        RateLimitTier tier = resolveTier(request);
        String clientIp = resolveClientIp(request);
        String subjectId = resolveSubjectId(request, clientIp, tier);

        RateLimitResult result = redisSecurityService.checkRateLimit(subjectId, tier);

        if (result.allowed()) {
            response.setHeader("X-RateLimit-Remaining", String.valueOf(result.remaining()));
            filterChain.doFilter(request, response);
            return;
        }

        // Handle rejection or outage
        if (result.isOutage()) {
            if (tier.isFailClosedOnOutage()) {
                log.error("Rejecting request to {} due to Redis outage on fail-closed tier {}", request.getRequestURI(), tier);
                response.setStatus(HttpStatus.SERVICE_UNAVAILABLE.value());
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.getWriter().write("""
                    {"success":false,"status":503,"message":"Security enforcement service temporarily unavailable. Please retry later."}
                    """.trim());
                return;
            } else {
                log.warn("Allowing request to {} despite Redis outage (tier {} is fail-open)", request.getRequestURI(), tier);
                filterChain.doFilter(request, response);
                return;
            }
        }

        // Rate limit exceeded (429)
        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setHeader("Retry-After", String.valueOf(result.retryAfterSeconds()));
        response.setHeader("X-RateLimit-Remaining", "0");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        String body = String.format(
            "{\"success\":false,\"status\":429,\"message\":\"Rate limit exceeded. Try again in %d seconds.\",\"retryAfter\":%d}",
            result.retryAfterSeconds(), result.retryAfterSeconds()
        );
        response.getWriter().write(body);
    }

    private RateLimitTier resolveTier(HttpServletRequest request) {
        String path = request.getRequestURI();
        if (path.startsWith("/api/auth/")) {
            return RateLimitTier.AUTH;
        }
        if (path.startsWith("/api/transactions/")) {
            return RateLimitTier.TRANSACTIONS;
        }
        if (path.startsWith("/api/admin/")) {
            return RateLimitTier.ADMIN;
        }
        if (path.startsWith("/api/customers/") || path.startsWith("/api/accounts/")) {
            return RateLimitTier.BANKING;
        }
        return RateLimitTier.GENERAL;
    }

    private String resolveSubjectId(HttpServletRequest request, String clientIp, RateLimitTier tier) {
        // Pre-auth requests always keyed by IP to prevent credential brute-forcing
        if (tier == RateLimitTier.AUTH) {
            return "ip:" + clientIp;
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated() && !(authentication instanceof AnonymousAuthenticationToken)) {
            Object userId = request.getAttribute("userId");
            if (userId != null && StringUtils.hasText(userId.toString())) {
                return "user:" + userId.toString();
            }
            return "user:" + authentication.getName();
        }

        return "ip:" + clientIp;
    }

    public String resolveClientIp(HttpServletRequest request) {
        String remoteAddr = request.getRemoteAddr();
        if (remoteAddr == null || remoteAddr.isBlank()) {
            remoteAddr = "127.0.0.1";
        }

        Set<String> trusted = Arrays.stream(trustedProxiesConfig.split(","))
            .map(String::trim)
            .filter(StringUtils::hasText)
            .collect(Collectors.toSet());

        // If the immediate connection does not come from a trusted proxy, ignore all forwarding headers
        if (!trusted.contains(remoteAddr)) {
            return remoteAddr;
        }

        String forwarded = request.getHeader("X-Forwarded-For");
        if (!StringUtils.hasText(forwarded)) {
            return remoteAddr;
        }

        String[] hops = forwarded.split(",");
        // Walk right-to-left (from most recent hop to oldest)
        for (int i = hops.length - 1; i >= 0; i--) {
            String hop = hops[i].trim();
            if (StringUtils.hasText(hop) && !trusted.contains(hop)) {
                return hop; // Found the first non-trusted client IP
            }
        }

        // If all hops were trusted proxies, return remoteAddr
        return remoteAddr;
    }
}
