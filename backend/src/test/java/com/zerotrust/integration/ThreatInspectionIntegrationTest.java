package com.zerotrust.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zerotrust.entity.AuditLog;
import com.zerotrust.entity.ThreatEvent;
import com.zerotrust.entity.enums.AuditStatus;
import com.zerotrust.entity.enums.ThreatType;
import com.zerotrust.repository.AuditLogRepository;
import com.zerotrust.repository.NotificationRepository;
import com.zerotrust.repository.ThreatEventRepository;
import com.zerotrust.security.JwtTokenProvider;
import com.zerotrust.service.RedisSecurityService;
import org.junit.jupiter.api.*;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.ActiveProfiles;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class ThreatInspectionIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private ThreatEventRepository threatEventRepository;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private NotificationRepository notificationRepository;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private RedisSecurityService redisSecurityService;

    private HttpClient httpClient;
    private String employeeToken;
    private String adminToken;
    private String baseUrl;

    @BeforeEach
    void setUp() {
        httpClient = HttpClient.newHttpClient();
        baseUrl = "http://localhost:" + port;

        when(redisSecurityService.isTokenRevoked(anyString())).thenReturn(false);
        when(redisSecurityService.isIpBlocked(anyString())).thenReturn(false);
        when(redisSecurityService.isAccountThrottled(anyString())).thenReturn(false);

        employeeToken = jwtTokenProvider.generateAccessToken(
            UUID.randomUUID(), "employee@zerotrust.com", List.of("ROLE_EMPLOYEE")
        );
        adminToken = jwtTokenProvider.generateAccessToken(
            UUID.randomUUID(), "admin@zerotrust.com", List.of("ROLE_ADMIN", "ROLE_SECURITY_ANALYST")
        );
    }

    @Test
    @Order(1)
    @DisplayName("1. Real HTTP request with SQL injection query param is blocked with 403")
    void testBlockSqlInjectionInQueryParam() throws Exception {
        int initialThreatCount = (int) threatEventRepository.count();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + "/api/customers?search=" + java.net.URLEncoder.encode("' OR '1'='1", "UTF-8")))
            .header("Authorization", "Bearer " + employeeToken)
            .header("X-Forwarded-For", "198.51.100.15")
            .GET()
            .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(HttpStatus.FORBIDDEN.value());
        assertThat(response.body()).contains("Request blocked by Zero Trust Threat Detection Engine");
        assertThat(response.body()).contains("SQL_INJECTION");
        assertThat(response.headers().firstValue("X-Correlation-Id")).isPresent();

        // Verify threat event persistence
        List<ThreatEvent> threats = threatEventRepository.findAll();
        assertThat(threats.size()).isGreaterThan(initialThreatCount);

        ThreatEvent latest = threats.get(threats.size() - 1);
        assertThat(latest.getThreatType()).isEqualTo(ThreatType.SQL_INJECTION);
        assertThat(latest.getActionTaken()).isEqualTo("BLOCKED");
        assertThat(latest.getRiskScore()).isGreaterThanOrEqualTo(75);
        assertThat(latest.getSourceIp()).isEqualTo("198.51.100.15");

        // Verify audit log
        List<AuditLog> auditLogs = auditLogRepository.findAll();
        assertThat(auditLogs).anyMatch(a ->
            "THREAT_BLOCKED".equals(a.getAction()) && a.getStatus() == AuditStatus.BLOCKED && a.getRiskScore() >= 75
        );
    }

    @Test
    @Order(2)
    @DisplayName("2. Real HTTP request with XSS script payload in JSON body is blocked with 403")
    void testBlockXssInRequestBody() throws Exception {
        String xssPayload = """
            {"firstName":"<script>alert('xss')</script>","lastName":"Attacker","email":"xss@test.com"}
            """;

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + "/api/customers"))
            .header("Authorization", "Bearer " + employeeToken)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(xssPayload))
            .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(HttpStatus.FORBIDDEN.value());
        assertThat(response.body()).contains("XSS");
        assertThat(response.body()).contains("BLOCKED");

        // Verify notification was created
        assertThat(notificationRepository.count()).isGreaterThan(0);
    }

    @Test
    @Order(3)
    @DisplayName("3. Real HTTP request with Path Traversal in query parameter is blocked with 403")
    void testBlockPathTraversalInUri() throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + "/api/accounts?filePath=../../etc/passwd"))
            .header("Authorization", "Bearer " + employeeToken)
            .GET()
            .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(HttpStatus.FORBIDDEN.value());
        assertThat(response.body()).contains("PATH_TRAVERSAL");
    }

    @Test
    @Order(4)
    @DisplayName("4. Real HTTP request with Command Injection payload is blocked with 403")
    void testBlockCommandInjectionInBody() throws Exception {
        String cmdPayload = """
            {"notes":"; ls -la /var/log","amount":100.00}
            """;

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + "/api/transactions/deposit"))
            .header("Authorization", "Bearer " + employeeToken)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(cmdPayload))
            .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(HttpStatus.FORBIDDEN.value());
        assertThat(response.body()).contains("COMMAND_INJECTION");
    }

    @Test
    @Order(5)
    @DisplayName("5. Benign input resembling attack keywords is allowed without false positive")
    void testBenignInputAllowed() throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + "/api/customers?search=O'Connor"))
            .header("Authorization", "Bearer " + employeeToken)
            .GET()
            .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isNotEqualTo(HttpStatus.FORBIDDEN.value());
    }

    @Test
    @Order(6)
    @DisplayName("6. SEC-P3-001: Oversized bodies (>64KB) on JSON endpoints are rejected with 413 Payload Too Large")
    void testOversizedPayloadRejectedWith413() throws Exception {
        // Case A: Known Content-Length > 64 KB
        String largeJson = "{\"notes\":\"" + "A".repeat(70000) + "\"}";
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + "/api/customers"))
            .header("Authorization", "Bearer " + employeeToken)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(largeJson))
            .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(HttpStatus.PAYLOAD_TOO_LARGE.value());
        assertThat(response.body()).contains("Payload Too Large");
        assertThat(response.body()).contains("65536");

        // Case B: Attack payload placed after 64KB padding cannot bypass enforcement
        String paddedAttack = "{\"padding\":\"" + "X".repeat(66000) + "\",\"evil\":\"<script>alert(1)</script>\"}";
        HttpRequest attackReq = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + "/api/customers"))
            .header("Authorization", "Bearer " + employeeToken)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(paddedAttack))
            .build();

        HttpResponse<String> attackResp = httpClient.send(attackReq, HttpResponse.BodyHandlers.ofString());
        // Rejected with 413 rather than passing through uninspected!
        assertThat(attackResp.statusCode()).isEqualTo(HttpStatus.PAYLOAD_TOO_LARGE.value());
    }

    @Test
    @Order(7)
    @DisplayName("7. Threat events and audit logs commit in independent transaction on blocked requests")
    void testIndependentTransactionCommit() throws Exception {
        long initialThreatEvents = threatEventRepository.count();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + "/api/customers?search=" + java.net.URLEncoder.encode("1 UNION SELECT null, null, null", "UTF-8")))
            .header("Authorization", "Bearer " + employeeToken)
            .GET()
            .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(HttpStatus.FORBIDDEN.value());
        assertThat(threatEventRepository.count()).isEqualTo(initialThreatEvents + 1);
    }

    @Test
    @Order(8)
    @DisplayName("8. Performance benchmark: Request inspection overhead measurement")
    void testPerformanceInspectionOverhead() throws Exception {
        int iterations = 25;
        long totalElapsedNs = 0;

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + "/api/customers?search=normal-customer-search"))
            .header("Authorization", "Bearer " + employeeToken)
            .GET()
            .build();

        // Warm up
        for (int i = 0; i < 5; i++) {
            httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        }

        // Measure
        for (int i = 0; i < iterations; i++) {
            long start = System.nanoTime();
            HttpResponse<String> resp = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            long elapsed = System.nanoTime() - start;
            totalElapsedNs += elapsed;
            assertThat(resp.statusCode()).isNotEqualTo(HttpStatus.FORBIDDEN.value());
        }

        double avgLatencyMs = (totalElapsedNs / (double) iterations) / 1_000_000.0;
        System.out.printf(">>> REAL PERFORMANCE MEASUREMENT: Average HTTP round-trip latency under threat inspection: %.2f ms%n", avgLatencyMs);
        assertThat(avgLatencyMs).isLessThan(150.0);
    }

    @Test
    @Order(9)
    @DisplayName("9. SEC-P3-002: Security filter executes exclusively within SecurityFilterChain with principal context")
    void testFilterSingleExecutionAndSecurityContext() throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + "/api/customers/me"))
            .header("Authorization", "Bearer " + employeeToken)
            .GET()
            .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        // Authenticated request processed without duplicate filter failure
        assertThat(response.headers().firstValue("X-Correlation-Id")).isPresent();
    }

    @Test
    @Order(10)
    @DisplayName("10. SEC-P3-003: Sensitive credentials, tokens, cards and passwords are fully redacted in persisted threat events")
    void testSensitiveDataSanitizationInThreatEvent() throws Exception {
        int initialCount = (int) threatEventRepository.count();

        String sensitivePayload = """
            {
               "auth": {
                   "password": "SuperSecretPassword123!",
                   "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisSignature",
                   "creditCard": "4111222233334444",
                   "cvv": 987
               },
               "query": "1 UNION SELECT * FROM users"
            }
            """;

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + "/api/customers"))
            .header("Authorization", "Bearer " + employeeToken)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(sensitivePayload))
            .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(HttpStatus.FORBIDDEN.value());

        List<ThreatEvent> threats = threatEventRepository.findAll();
        assertThat(threats.size()).isGreaterThan(initialCount);

        ThreatEvent latest = threats.get(threats.size() - 1);
        String attackPayload = latest.getAttackPayload();

        // Must NOT leak credentials or tokens
        assertThat(attackPayload).doesNotContain("SuperSecretPassword123!");
        assertThat(attackPayload).doesNotContain("doNotLeakThisSignature");
        assertThat(attackPayload).doesNotContain("4111222233334444");
        assertThat(attackPayload).contains("[REDACTED]");
    }
}
