package com.zerotrust.threat;

import com.zerotrust.entity.enums.Severity;
import com.zerotrust.entity.enums.ThreatType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

/**
 * Core threat detection engine implementing rule-based detection for:
 * - SQL Injection
 * - Cross-Site Scripting (XSS)
 * - Path Traversal
 * - Command Injection
 * - Brute Force (IP-based rate limiting)
 */
@Slf4j
@Component
public class ThreatDetectionEngine {

    // ─────────────────────────────────────────────
    // COMPILED REGEX PATTERNS
    // ─────────────────────────────────────────────

    private static final List<PatternRule> SQL_INJECTION_RULES = List.of(
        new PatternRule(
            Pattern.compile("(?i)(\\bor\\b\\s+[\\w'\"]+\\s*=\\s*[\\w'\"]+)"),
            "SQL_OR_TAUTOLOGY", Severity.HIGH, 0.9),
        new PatternRule(
            Pattern.compile("(?i)union\\s+(all\\s+)?select"),
            "SQL_UNION_SELECT", Severity.CRITICAL, 1.0),
        new PatternRule(
            Pattern.compile("(?i)\\bdrop\\s+(table|database|schema)"),
            "SQL_DROP", Severity.CRITICAL, 1.0),
        new PatternRule(
            Pattern.compile("(?i)\\bexec\\s*\\(|xp_cmdshell|sp_executesql"),
            "SQL_EXEC", Severity.CRITICAL, 1.0),
        new PatternRule(
            Pattern.compile("(?i)insert\\s+into.+values\\s*\\("),
            "SQL_INSERT_INJECT", Severity.HIGH, 0.8),
        new PatternRule(
            Pattern.compile("(?i)(--|#|/\\*).*(\\bor\\b|\\band\\b|select|drop|update|insert|delete)"),
            "SQL_COMMENT_INJECT", Severity.HIGH, 0.85),
        new PatternRule(
            Pattern.compile("(?i)\\binformation_schema\\b|\\bpg_tables\\b|\\bsysobjects\\b"),
            "SQL_SCHEMA_ENUM", Severity.HIGH, 0.95),
        new PatternRule(
            Pattern.compile("(?i)\\bsleep\\s*\\(|\\bwaitfor\\s+delay\\b|\\bbenchmark\\s*\\("),
            "SQL_TIME_BASED_BLIND", Severity.HIGH, 0.9),
        new PatternRule(
            Pattern.compile("(?i)(into\\s+outfile|load_file\\s*\\()"),
            "SQL_FILE_OPERATION", Severity.CRITICAL, 1.0),
        new PatternRule(
            Pattern.compile("'\\s*;\\s*(drop|delete|update|insert|create|alter)"),
            "SQL_STACKED_QUERY", Severity.CRITICAL, 1.0)
    );

    private static final List<PatternRule> XSS_RULES = List.of(
        new PatternRule(
            Pattern.compile("(?i)<script[^>]*>[\\s\\S]*?</script>"),
            "XSS_SCRIPT_TAG", Severity.HIGH, 1.0),
        new PatternRule(
            Pattern.compile("(?i)javascript\\s*:"),
            "XSS_JAVASCRIPT_URI", Severity.HIGH, 0.95),
        new PatternRule(
            Pattern.compile("(?i)on(load|click|error|mouseover|submit|focus|blur|change|keyup|keydown|input)\\s*="),
            "XSS_EVENT_HANDLER", Severity.MEDIUM, 0.85),
        new PatternRule(
            Pattern.compile("(?i)<iframe[^>]*src"),
            "XSS_IFRAME", Severity.HIGH, 0.9),
        new PatternRule(
            Pattern.compile("(?i)document\\.(cookie|write|location|domain)"),
            "XSS_DOM_ACCESS", Severity.HIGH, 0.9),
        new PatternRule(
            Pattern.compile("(?i)eval\\s*\\([^)]+\\)"),
            "XSS_EVAL", Severity.HIGH, 0.9),
        new PatternRule(
            Pattern.compile("(?i)expression\\s*\\("),
            "XSS_CSS_EXPRESSION", Severity.MEDIUM, 0.8),
        new PatternRule(
            Pattern.compile("(?i)<img[^>]+src\\s*=\\s*[\"']?\\s*javascript:"),
            "XSS_IMG_JAVASCRIPT", Severity.HIGH, 0.95),
        new PatternRule(
            Pattern.compile("(?i)vbscript\\s*:"),
            "XSS_VBSCRIPT", Severity.MEDIUM, 0.85),
        new PatternRule(
            Pattern.compile("(?i)alert\\s*\\(|confirm\\s*\\(|prompt\\s*\\("),
            "XSS_DIALOG", Severity.MEDIUM, 0.7)
    );

    private static final List<PatternRule> PATH_TRAVERSAL_RULES = List.of(
        new PatternRule(
            Pattern.compile("(\\.\\./){2,}|(\\.\\.\\\\/){2,}"),
            "PATH_TRAVERSAL", Severity.HIGH, 0.95),
        new PatternRule(
            Pattern.compile("(?i)%2e%2e%2f|%2e%2e/|\\.%2f"),
            "PATH_TRAVERSAL_ENCODED", Severity.HIGH, 0.95),
        new PatternRule(
            Pattern.compile("(?i)(etc/passwd|etc/shadow|windows/system32|win.ini)"),
            "PATH_TRAVERSAL_SENSITIVE", Severity.CRITICAL, 1.0)
    );

    private static final List<PatternRule> COMMAND_INJECTION_RULES = List.of(
        new PatternRule(
            Pattern.compile("(?i)(;|\\||&&|`|\\$\\()\\s*(ls|cat|rm|wget|curl|nc|bash|sh|python|perl)\\b"),
            "CMD_INJECTION", Severity.CRITICAL, 1.0),
        new PatternRule(
            Pattern.compile("(?i)\\$\\{[^}]*\\}|#\\{[^}]*\\}"),
            "TEMPLATE_INJECTION", Severity.HIGH, 0.9)
    );

    // ─────────────────────────────────────────────
    // BRUTE FORCE TRACKING (in-memory, Phase 2 → Redis)
    // ─────────────────────────────────────────────

    private final ConcurrentHashMap<String, IpAttemptTracker> bruteForceTrackers
        = new ConcurrentHashMap<>();

    private static final int BRUTE_FORCE_THRESHOLD   = 10;
    private static final long BRUTE_FORCE_WINDOW_MS  = 5 * 60 * 1000L; // 5 minutes

    // ─────────────────────────────────────────────
    // PUBLIC API
    // ─────────────────────────────────────────────

    /**
     * Analyzes arbitrary string input for security threats.
     * Checks SQL injection, XSS, path traversal, and command injection.
     */
    public DetectionResult analyze(String input, String sourceIp) {
        if (input == null || input.isBlank()) return DetectionResult.clean();

        // Check SQL Injection (highest priority)
        DetectionResult sqli = checkPatterns(input, SQL_INJECTION_RULES, ThreatType.SQL_INJECTION);
        if (sqli.threatDetected()) return sqli;

        // Check XSS
        DetectionResult xss = checkPatterns(input, XSS_RULES, ThreatType.XSS);
        if (xss.threatDetected()) return xss;

        // Check Path Traversal
        DetectionResult path = checkPatterns(input, PATH_TRAVERSAL_RULES, ThreatType.PATH_TRAVERSAL);
        if (path.threatDetected()) return path;

        // Check Command Injection
        DetectionResult cmd = checkPatterns(input, COMMAND_INJECTION_RULES, ThreatType.COMMAND_INJECTION);
        if (cmd.threatDetected()) return cmd;

        return DetectionResult.clean();
    }

    /**
     * Records a failed authentication attempt for brute force detection.
     * @return DetectionResult indicating if brute force threshold has been exceeded
     */
    public DetectionResult recordFailedAuth(String sourceIp) {
        IpAttemptTracker tracker = bruteForceTrackers.computeIfAbsent(
            sourceIp, k -> new IpAttemptTracker());

        tracker.record();
        int count = tracker.getCount(BRUTE_FORCE_WINDOW_MS);

        if (count >= BRUTE_FORCE_THRESHOLD * 2) {
            return DetectionResult.threat(
                ThreatType.BRUTE_FORCE, Severity.CRITICAL,
                "BRUTE_FORCE_CRITICAL",
                "Brute force detected: " + count + " failed attempts from " + sourceIp,
                1.0);
        } else if (count >= BRUTE_FORCE_THRESHOLD) {
            return DetectionResult.threat(
                ThreatType.BRUTE_FORCE, Severity.HIGH,
                "BRUTE_FORCE_HIGH",
                "Brute force suspected: " + count + " failed attempts from " + sourceIp,
                0.9);
        }
        return DetectionResult.clean();
    }

    /**
     * Resets the brute force counter for a given IP (on successful login).
     */
    public void resetBruteForceCounter(String sourceIp) {
        bruteForceTrackers.remove(sourceIp);
    }

    // ─────────────────────────────────────────────
    // HELPERS
    // ─────────────────────────────────────────────

    private DetectionResult checkPatterns(String input, List<PatternRule> rules, ThreatType type) {
        for (PatternRule rule : rules) {
            if (rule.pattern().matcher(input).find()) {
                return DetectionResult.threat(
                    type, rule.severity(), rule.ruleName(),
                    "Pattern matched: " + rule.ruleName() + " in input",
                    rule.confidence());
            }
        }
        return DetectionResult.clean();
    }

    // ─────────────────────────────────────────────
    // INNER RECORDS / CLASSES
    // ─────────────────────────────────────────────

    private record PatternRule(
        Pattern pattern,
        String ruleName,
        Severity severity,
        double confidence
    ) {}

    private static class IpAttemptTracker {
        private final java.util.LinkedList<Long> timestamps = new java.util.LinkedList<>();

        synchronized void record() {
            timestamps.addLast(System.currentTimeMillis());
        }

        synchronized int getCount(long windowMs) {
            long cutoff = System.currentTimeMillis() - windowMs;
            timestamps.removeIf(t -> t < cutoff);
            return timestamps.size();
        }
    }
}
