package com.zerotrust.integration;

import com.zerotrust.dto.request.LoginRequest;
import com.zerotrust.security.JwtTokenProvider;
import com.zerotrust.security.RateLimitResult;
import com.zerotrust.security.RateLimitTier;
import com.zerotrust.service.RedisSecurityService;
import com.zerotrust.service.SseTicketService;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.*;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.net.Socket;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class RedisSecurityIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private RedisSecurityService redisSecurityService;

    @Autowired
    private SseTicketService sseTicketService;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private StringRedisTemplate stringRedisTemplate;

    private static boolean redisAvailable = false;
    private static String redisHost = "127.0.0.1";
    private static int redisPort = 6379;

    @BeforeAll
    static void checkRedis() {
        String envHost = System.getenv("REDIS_HOST");
        if (envHost != null && !envHost.isBlank()) {
            redisHost = envHost;
        }
        String envPort = System.getenv("REDIS_PORT");
        if (envPort != null && !envPort.isBlank()) {
            try {
                redisPort = Integer.parseInt(envPort);
            } catch (NumberFormatException ignored) {
            }
        }

        try (Socket socket = new Socket(redisHost, redisPort)) {
            redisAvailable = true;
        } catch (Exception e) {
            redisAvailable = false;
        }
    }

    @BeforeEach
    void setUp() {
        boolean isCI = "true".equalsIgnoreCase(System.getenv("CI"))
                || "true".equalsIgnoreCase(System.getenv("GITHUB_ACTIONS"));
        if (isCI && !redisAvailable) {
            org.junit.jupiter.api.Assertions.fail(
                    "CRITICAL CI FAILURE: Redis 7 service container is required in CI but is not reachable at " +
                    redisHost + ":" + redisPort + ". Check GitHub Actions service container health.");
        }

        assumeTrue(redisAvailable, "Redis is not reachable on " + redisHost + ":" + redisPort + "; skipping Redis integration tests.");
        if (restTemplate.getRestTemplate()
                .getRequestFactory() instanceof org.springframework.http.client.SimpleClientHttpRequestFactory factory) {
            factory.setOutputStreaming(false);
        }
    }

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        checkRedis();
        registry.add("spring.data.redis.host", () -> redisHost);
        registry.add("spring.data.redis.port", () -> redisPort);
        registry.add("app.rate-limit.enabled", () -> "true");
        registry.add("app.rate-limit.tiers.auth.limit", () -> 10);
        registry.add("app.rate-limit.tiers.auth.window-seconds", () -> 60);
    }

    @Test
    @Order(1)
    @DisplayName("1. Distributed sliding-window rate limiting enforces quota and returns retry-after")
    void testSlidingWindowRateLimiting() {
        String testSubject = "ratelimit-subject-" + UUID.randomUUID();

        // 10 requests allowed
        for (int i = 0; i < 10; i++) {
            RateLimitResult result = redisSecurityService.checkRateLimit(testSubject, RateLimitTier.AUTH);
            assertThat(result.allowed()).isTrue();
            assertThat(result.remaining()).isEqualTo(9 - i);
        }

        // 11th request must be rejected
        RateLimitResult blocked = redisSecurityService.checkRateLimit(testSubject, RateLimitTier.AUTH);
        assertThat(blocked.allowed()).isFalse();
        assertThat(blocked.retryAfterSeconds()).isGreaterThan(0);
    }

    @Test
    @Order(2)
    @DisplayName("2. Concurrent burst rate limiting strictly enforces atomic limit with Lua")
    void testConcurrentBurstRateLimiting() throws Exception {
        String testSubject = "concurrent-subject-" + UUID.randomUUID();
        int totalRequests = 25;
        int limit = RateLimitTier.AUTH.getDefaultLimit(); // 10

        ExecutorService executor = Executors.newFixedThreadPool(totalRequests);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(totalRequests);

        AtomicInteger allowedCount = new AtomicInteger(0);
        AtomicInteger rejectedCount = new AtomicInteger(0);

        for (int i = 0; i < totalRequests; i++) {
            executor.submit(() -> {
                try {
                    startLatch.await();
                    RateLimitResult res = redisSecurityService.checkRateLimit(testSubject, RateLimitTier.AUTH);
                    if (res.allowed()) {
                        allowedCount.incrementAndGet();
                    } else {
                        rejectedCount.incrementAndGet();
                    }
                } catch (Exception ignored) {
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        startLatch.countDown();
        boolean finished = doneLatch.await(10, TimeUnit.SECONDS);
        executor.shutdown();

        assertThat(finished).isTrue();
        assertThat(allowedCount.get()).isEqualTo(limit);
        assertThat(rejectedCount.get()).isEqualTo(totalRequests - limit);
    }

    @Test
    @Order(3)
    @DisplayName("3. Distributed brute-force tracking blocks IP and throttles account without leaking user existence")
    void testDistributedBruteForceTracking() {
        String testIp = "198.51.100.42";
        String testEmail = "target-user-" + UUID.randomUUID() + "@zerotrust.com";

        assertThat(redisSecurityService.isIpBlocked(testIp)).isFalse();
        assertThat(redisSecurityService.isAccountThrottled(testEmail)).isFalse();

        // 5 failed auth attempts for account
        for (int i = 0; i < 5; i++) {
            redisSecurityService.recordFailedAuth("192.0.2." + i, testEmail);
        }
        assertThat(redisSecurityService.isAccountThrottled(testEmail)).isTrue();

        // 10 failed auth attempts for IP
        for (int i = 0; i < 10; i++) {
            redisSecurityService.recordFailedAuth(testIp, "other" + i + "@zerotrust.com");
        }
        assertThat(redisSecurityService.isIpBlocked(testIp)).isTrue();

        // Reset
        redisSecurityService.resetFailedAuth(testIp, testEmail);
        redisSecurityService.resetFailedAccountAuth(testEmail);
        redisSecurityService.resetFailedIpAuth(testIp);
        assertThat(redisSecurityService.isIpBlocked(testIp)).isFalse();
        assertThat(redisSecurityService.isAccountThrottled(testEmail)).isFalse();
    }

    @Test
    @Order(4)
    @DisplayName("4. Distributed JWT access token revocation denylist rejects revoked tokens immediately")
    void testJwtAccessTokenRevocation() {
        UUID userId = UUID.randomUUID();
        String email = "revoked-user@zerotrust.com";
        String token = jwtTokenProvider.generateAccessToken(userId, email, List.of("ROLE_ANALYST"));

        // Initially not revoked
        assertThat(redisSecurityService.isTokenRevoked(token)).isFalse();

        // Denylist token
        Instant expiry = Instant.now().plusSeconds(300);
        redisSecurityService.revokeAccessToken(token, expiry);

        // Immediately revoked
        assertThat(redisSecurityService.isTokenRevoked(token)).isTrue();

        // HTTP request with revoked token must return 401
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        HttpEntity<Void> request = new HttpEntity<>(headers);

        ResponseEntity<String> response = restTemplate.exchange(
                "/api/audit/logs",
                HttpMethod.GET,
                request,
                String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).contains("Access token has been revoked");
    }

    @Test
    @Order(5)
    @DisplayName("5. Distributed SSE tickets guarantee single-use consumption under concurrent race (atomic GETDEL)")
    void testConcurrentSseTicketConsumption() throws Exception {
        String userId = UUID.randomUUID().toString();
        String userEmail = "sse-user@zerotrust.com";
        Set<String> roles = Set.of("ROLE_ANALYST", "ROLE_SECURITY_ADMIN");

        String ticket = sseTicketService.createTicket(userId, userEmail, roles);
        assertThat(ticket).isNotBlank();

        int consumers = 4;
        ExecutorService executor = Executors.newFixedThreadPool(consumers);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(consumers);

        AtomicInteger successfulConsumes = new AtomicInteger(0);
        AtomicInteger rejectedConsumes = new AtomicInteger(0);

        for (int i = 0; i < consumers; i++) {
            executor.submit(() -> {
                try {
                    startLatch.await();
                    SseTicketService.TicketData data = sseTicketService.validateAndConsume(ticket);
                    if (data != null) {
                        successfulConsumes.incrementAndGet();
                    } else {
                        rejectedConsumes.incrementAndGet();
                    }
                } catch (Exception ignored) {
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        startLatch.countDown();
        boolean done = doneLatch.await(5, TimeUnit.SECONDS);
        executor.shutdown();

        assertThat(done).isTrue();
        // Exactly ONE consumer gets the ticket; all others get null!
        assertThat(successfulConsumes.get()).isEqualTo(1);
        assertThat(rejectedConsumes.get()).isEqualTo(consumers - 1);

        // Replay attempt must also fail
        assertThat(sseTicketService.validateAndConsume(ticket)).isNull();
    }

    @Test
    @Order(6)
    @DisplayName("6. Outage behavior enforces fail-closed on transactions and fail-open on general tiers")
    void testOutagePolicies() {
        // Test outage return values on tiers
        assertThat(RateLimitTier.TRANSACTIONS.isFailClosedOnOutage()).isTrue();
        assertThat(RateLimitTier.AUTH.isFailClosedOnOutage()).isTrue();
        assertThat(RateLimitTier.ADMIN.isFailClosedOnOutage()).isTrue();
        assertThat(RateLimitTier.BANKING.isFailClosedOnOutage()).isFalse();
        assertThat(RateLimitTier.GENERAL.isFailClosedOnOutage()).isFalse();

        RateLimitResult outageClosed = RateLimitResult.outageRejected();
        assertThat(outageClosed.isOutage()).isTrue();
        assertThat(outageClosed.allowed()).isFalse();

        RateLimitResult outageOpen = RateLimitResult.outageAllowed();
        assertThat(outageOpen.isOutage()).isTrue();
        assertThat(outageOpen.allowed()).isTrue();
    }

    @Test
    @Order(7)
    @DisplayName("7. HTTP Rate limiting returns 429 and Retry-After header when threshold exceeded")
    void testHttpRateLimitingReturns429() throws Exception {
        String testIp = "192.0.2." + (ThreadLocalRandom.current().nextInt(100, 250));
        java.net.http.HttpClient httpClient = java.net.http.HttpClient.newHttpClient();
        java.net.URI uri = java.net.URI.create("http://localhost:" + port + "/api/auth/login");
        String jsonPayload = "{\"email\":\"nobody@zerotrust.com\",\"password\":\"WrongPassword123!\"}";

        // First 10 requests should return 401 (invalid creds)
        for (int i = 0; i < 10; i++) {
            java.net.http.HttpRequest request = java.net.http.HttpRequest.newBuilder()
                    .uri(uri)
                    .header("Content-Type", "application/json")
                    .header("X-Forwarded-For", testIp)
                    .POST(java.net.http.HttpRequest.BodyPublishers.ofString(jsonPayload))
                    .build();
            java.net.http.HttpResponse<String> resp = httpClient.send(request,
                    java.net.http.HttpResponse.BodyHandlers.ofString());
            assertThat(resp.statusCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
        }

        // 11th request must be rate limited (429)
        java.net.http.HttpRequest rateLimitedReq = java.net.http.HttpRequest.newBuilder()
                .uri(uri)
                .header("Content-Type", "application/json")
                .header("X-Forwarded-For", testIp)
                .POST(java.net.http.HttpRequest.BodyPublishers.ofString(jsonPayload))
                .build();
        java.net.http.HttpResponse<String> rateLimitedResp = httpClient.send(rateLimitedReq,
                java.net.http.HttpResponse.BodyHandlers.ofString());
        assertThat(rateLimitedResp.statusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS.value());
        assertThat(rateLimitedResp.headers().firstValue("Retry-After")).isPresent();
        assertThat(rateLimitedResp.body()).contains("Rate limit exceeded");
    }

    @Test
    @Order(8)
    @DisplayName("8. IP spoofing prevention ignores X-Forwarded-For from untrusted remote clients")
    void testIpSpoofingPrevention() {
        com.zerotrust.security.RateLimitingFilter filter = new com.zerotrust.security.RateLimitingFilter(
                redisSecurityService);
        org.springframework.test.util.ReflectionTestUtils.setField(filter, "rateLimitEnabled", true);
        org.springframework.test.util.ReflectionTestUtils.setField(filter, "trustedProxiesConfig", "127.0.0.1,::1");

        // Case A: Untrusted remote IP attempts to spoof X-Forwarded-For
        org.springframework.mock.web.MockHttpServletRequest untrustedReq = new org.springframework.mock.web.MockHttpServletRequest();
        untrustedReq.setRemoteAddr("203.0.113.10"); // Untrusted external IP
        untrustedReq.addHeader("X-Forwarded-For", "192.168.1.100, 10.0.0.1"); // Forged header

        String resolvedIpUntrusted = org.springframework.test.util.ReflectionTestUtils.invokeMethod(filter,
                "resolveClientIp", untrustedReq);
        // Must use remoteAddr and IGNORE the spoofed header!
        assertThat(resolvedIpUntrusted).isEqualTo("203.0.113.10");

        // Case B: Trusted proxy passes real client in X-Forwarded-For
        org.springframework.mock.web.MockHttpServletRequest trustedReq = new org.springframework.mock.web.MockHttpServletRequest();
        trustedReq.setRemoteAddr("127.0.0.1"); // Trusted proxy
        trustedReq.addHeader("X-Forwarded-For", "198.51.100.77");

        String resolvedIpTrusted = org.springframework.test.util.ReflectionTestUtils.invokeMethod(filter,
                "resolveClientIp", trustedReq);
        // Must parse the real client IP!
        assertThat(resolvedIpTrusted).isEqualTo("198.51.100.77");
    }

    @Test
    @Order(9)
    @DisplayName("9. Source IP brute-force counter is preserved across valid account login (SEC-002)")
    void testIpBruteForceCounterPreservedAfterCanaryLogin() {
        String attackerIp = "198.51.100.99";
        String victimEmail = "victim-" + UUID.randomUUID() + "@zerotrust.com";
        String canaryEmail = "canary-" + UUID.randomUUID() + "@zerotrust.com";

        // Attacker fails 8 times against victim
        for (int i = 0; i < 8; i++) {
            redisSecurityService.recordFailedAuth(attackerIp, victimEmail);
        }
        assertThat(redisSecurityService.isAccountThrottled(victimEmail)).isTrue();
        assertThat(stringRedisTemplate.opsForValue().get("bruteforce:ip:" + attackerIp)).isEqualTo("8");

        // Attacker authenticates with their canary account ->
        // resetFailedAccountAuth(canaryEmail)
        redisSecurityService.resetFailedAccountAuth(canaryEmail);

        // IP counter MUST NOT be erased!
        assertThat(stringRedisTemplate.opsForValue().get("bruteforce:ip:" + attackerIp)).isEqualTo("8");

        // 2 more failed attempts from attacker IP push it over the IP threshold (10)
        redisSecurityService.recordFailedAuth(attackerIp, "another-" + UUID.randomUUID() + "@zerotrust.com");
        redisSecurityService.recordFailedAuth(attackerIp, "another-" + UUID.randomUUID() + "@zerotrust.com");
        assertThat(redisSecurityService.isIpBlocked(attackerIp)).isTrue();

        // Clean up
        redisSecurityService.resetFailedIpAuth(attackerIp);
    }

    @Test
    @Order(10)
    @DisplayName("10. Multi-hop trusted proxy traversal ignores spoofed leftmost IP (SEC-003)")
    void testMultiHopTrustedProxyResolution() {
        com.zerotrust.security.RateLimitingFilter filter = new com.zerotrust.security.RateLimitingFilter(
                redisSecurityService);
        org.springframework.test.util.ReflectionTestUtils.setField(filter, "rateLimitEnabled", true);
        org.springframework.test.util.ReflectionTestUtils.setField(filter, "trustedProxiesConfig",
                "127.0.0.1,10.0.0.1,10.0.0.2");

        // Client 198.51.100.22 sends spoofed header "1.1.1.1" -> proxy 10.0.0.2 ->
        // proxy 127.0.0.1 -> backend
        // Header received: "1.1.1.1, 198.51.100.22, 10.0.0.2" from remoteAddr 127.0.0.1
        org.springframework.mock.web.MockHttpServletRequest req = new org.springframework.mock.web.MockHttpServletRequest();
        req.setRemoteAddr("127.0.0.1"); // Trusted immediate proxy
        req.addHeader("X-Forwarded-For", "1.1.1.1, 198.51.100.22, 10.0.0.2");

        String resolved = org.springframework.test.util.ReflectionTestUtils.invokeMethod(filter, "resolveClientIp",
                req);
        // Rightmost non-trusted IP is 198.51.100.22; spoofed 1.1.1.1 must be ignored!
        assertThat(resolved).isEqualTo("198.51.100.22");
    }

    @Test
    @Order(11)
    @DisplayName("11. Mandatory Redis token revocation failure returns 503 fail-closed (SEC-001)")
    void testJwtOutageFailsClosedWith503() throws Exception {
        RedisSecurityService outageService = org.mockito.Mockito.mock(RedisSecurityService.class);
        org.mockito.Mockito.when(outageService.isTokenRevoked(org.mockito.ArgumentMatchers.anyString()))
                .thenThrow(
                        new RedisSecurityService.RedisSecurityException("Redis unreachable", new RuntimeException()));

        com.zerotrust.security.JwtAuthenticationFilter outageFilter = new com.zerotrust.security.JwtAuthenticationFilter(
                jwtTokenProvider, outageService);

        String validToken = jwtTokenProvider.generateAccessToken(UUID.randomUUID(), "user@zerotrust.com",
                List.of("ROLE_EMPLOYEE"));

        org.springframework.mock.web.MockHttpServletRequest request = new org.springframework.mock.web.MockHttpServletRequest();
        request.setRequestURI("/api/customers/me");
        request.addHeader("Authorization", "Bearer " + validToken);

        org.springframework.mock.web.MockHttpServletResponse response = new org.springframework.mock.web.MockHttpServletResponse();
        jakarta.servlet.FilterChain chain = org.mockito.Mockito.mock(jakarta.servlet.FilterChain.class);

        outageFilter.doFilter(request, response, chain);

        // Must return HTTP 503 Service Unavailable and NEVER forward down the chain
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE.value());
        assertThat(response.getContentAsString()).contains("503");
        assertThat(response.getContentAsString()).contains("Security state verification unavailable");
        org.mockito.Mockito.verifyNoInteractions(chain);
    }
}
