package com.zerotrust;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Main entry point for the Zero Trust Security Platform.
 *
 * <p>This application provides:
 * <ul>
 *   <li>JWT-based authentication with RBAC</li>
 *   <li>Real-time threat detection (SQLi, XSS, Brute Force)</li>
 *   <li>Immutable audit logging with hash chaining</li>
 *   <li>Dynamic risk scoring per user</li>
 *   <li>Security analytics dashboard APIs</li>
 *   <li>Optional RAG-powered AI security assistant (Gemini)</li>
 * </ul>
 */
@SpringBootApplication
@EnableJpaAuditing
@EnableScheduling
public class ZeroTrustApplication {

    public static void main(String[] args) {
        SpringApplication.run(ZeroTrustApplication.class, args);
    }
}
