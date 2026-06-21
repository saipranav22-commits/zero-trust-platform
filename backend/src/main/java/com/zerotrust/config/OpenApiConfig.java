package com.zerotrust.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI openAPI() {
        return new OpenAPI()
            .info(new Info()
                .title("Zero Trust Security Platform API")
                .version("1.0.0")
                .description("""
                    **AI-Powered Zero Trust Data Protection Platform**
                    
                    Features:
                    - JWT Authentication with RBAC (Admin, Security Analyst, Auditor, Employee)
                    - Real-time threat detection (SQL Injection, XSS, Brute Force, Path Traversal)
                    - Immutable audit logging with SHA-256 hash chaining
                    - Security analytics dashboard
                    - RAG-powered AI security assistant (Gemini)
                    
                    **Default credentials:**
                    - Admin: `admin@zerotrust.com` / `Admin@123`
                    - Analyst: `analyst@zerotrust.com` / `Analyst@123`
                    """)
                .contact(new Contact()
                    .name("Zero Trust Platform")
                    .email("security@zerotrust.com"))
                .license(new License()
                    .name("MIT License")
                    .url("https://opensource.org/licenses/MIT")))
            .servers(List.of(
                new Server().url("http://localhost:8080").description("Local Development")))
            .addSecurityItem(new SecurityRequirement().addList("Bearer Authentication"))
            .components(new Components()
                .addSecuritySchemes("Bearer Authentication", new SecurityScheme()
                    .type(SecurityScheme.Type.HTTP)
                    .scheme("bearer")
                    .bearerFormat("JWT")
                    .description("Enter your JWT access token")));
    }
}
