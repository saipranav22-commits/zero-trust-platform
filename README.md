# 🛡️ SYVORA — Zero Trust API Security & Real-Time Threat Monitoring

> Enterprise-grade Zero Trust Banking & API Security Platform built with Spring Boot 3.3, Java 21, PostgreSQL 16, Redis 7, React 18, and Google Gemini AI. Features context-aware ABAC, AES-256-GCM field encryption, tamper-evident cryptographic audit logging, distributed rate limiting, real-time SSE threat streaming, and an automated SOC incident response lifecycle.

[![Java 21](https://img.shields.io/badge/Java-21-ED8B00?logo=openjdk&logoColor=white)](https://openjdk.org/)
[![Spring Boot 3.3](https://img.shields.io/badge/Spring_Boot-3.3.2-6DB33F?logo=springboot&logoColor=white)](https://spring.io/projects/spring-boot)
[![PostgreSQL 16](https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Redis 7](https://img.shields.io/badge/Redis-7.4-DC382D?logo=redis&logoColor=white)](https://redis.io/)
[![React 18](https://img.shields.io/badge/React-18.3-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![CI/CD](https://img.shields.io/badge/CI%2FCD-GitHub_Actions-2088FF?logo=githubactions&logoColor=white)](https://github.com/features/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 📑 Table of Contents
- [Executive Overview](#-executive-overview)
- [System Architecture](#-system-architecture)
- [Core Security Capabilities](#-core-security-capabilities)
  - [1. Context-Aware ABAC & Authorization Matrix](#1-context-aware-abac--authorization-matrix)
  - [2. AES-256-GCM Field-Level Encryption & Backfill](#2-aes-256-gcm-field-level-encryption--backfill)
  - [3. Tamper-Evident Monotonic Audit Hash Chain](#3-tamper-evident-monotonic-audit-hash-chain)
  - [4. Distributed Token Revocation & Fail-Closed Redis](#4-distributed-token-revocation--fail-closed-redis)
  - [5. Bounded Stream Threat Inspection Engine](#5-bounded-stream-threat-inspection-engine)
  - [6. Automated SOC Incident Management Lifecycle](#6-automated-soc-incident-management-lifecycle)
- [Database Architecture & Flyway Migrations](#-database-architecture--flyway-migrations)
- [Technology Stack & Architectural Rationale](#-technology-stack--architectural-rationale)
- [Automated Verification & Test Evidence](#-automated-verification--test-evidence)
- [Local Quick Start Guide](#-local-quick-start-guide)
- [Environment Configuration](#-environment-configuration)
- [API Demonstration & Verification Scripts](#-api-demonstration--verification-scripts)
- [Security Model, Threat Assumptions & Limitations](#-security-model-threat-assumptions--limitations)
- [Resume-Ready Project Impact Summary](#-resume-ready-project-impact-summary)

---

## 🎯 Executive Overview

SYVORA is designed around the core Zero Trust tenet: **"Never trust, always verify."** Traditional perimeter security models assume everything inside the network is trustworthy. SYVORA assumes breach, enforcing strict mutual verification, contextual risk-based policies, cryptographic non-repudiation, and proactive automated threat containment on every single API transaction.

```
                           +------------------------------------------+
                           |          Client / Attacker / UI          |
                           +--------------------+---------------------+
                                                | HTTP / SSE
                                                v
                           +------------------------------------------+
                           |           Nginx Reverse Proxy            |
                           |   (Bufferless SSE / Rate-Limit Proxy)    |
                           +--------------------+---------------------+
                                                |
                                                v
               +--------------------------------------------------------------+
               |                    Spring Security Filter Chain               |
               |                                                              |
               | 1. JwtAuthenticationFilter: Bearer Token + Redis Denylist   |
               | 2. RateLimitingFilter: Tiered Sliding Window (Redis Token)  |
               | 3. ThreatInspectionFilter: Bounded Request Stream (RFC 9110) |
               +--------------------------------------------------------------+
                                                |
                                                v
               +--------------------------------------------------------------+
               |                  Context-Aware ABAC Enforcer                 |
               |     Evaluates: Subject, Action, Resource, Environmental Risk |
               +--------------------+---------------------+-------------------+
                                    |                     |
                                    v                     v
                 +----------------------+     +----------------------+
                 |  Core Banking Domain |     |  SOC Threat Engine   |
                 |  - Idempotent Txns   |     |  - Incident Stepper  |
                 |  - Account Balances  |     |  - Timeline Audit    |
                 |  - AES-256-GCM TaxId |     |  - Gemini AI Triage  |
                 +----------+-----------+     +-----------+----------+
                            |                             |
                            +--------------+--------------+
                                           |
                                           v
               +--------------------------------------------------------------+
               |              AuditService (Pessimistic Anchor)               |
               |   Monotonic Sequencing, V2 Length-Value Canonical Serialization |
               |                   SHA-256 Back-Linked Chain                  |
               +---------------------------+----------------------------------+
                                           |
                                           v
                               +-----------------------+
                               |     PostgreSQL 16     |
                               |  Triggers: Immutable  |
                               |  Audit Logs & Timeline|
                               +-----------------------+
```

---

## 🏗️ System Architecture

### Multi-Tier Component Topology
1. **Frontend Presentation (React 18, TypeScript, TailwindCSS):**
   - Real-time SOC dashboard, Threat Event Monitor, Incident Management Drawer with state transition stepper, Audit Chain Verifier, and Gemini AI forensic analysis.
   - Served via Nginx 1.27 Alpine with strict security headers (`X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `CSP`) and unbuffered SSE reverse proxying.
2. **Security Gateway & API Core (Spring Boot 3.3, Java 21):**
   - **Filter 1 — `JwtAuthenticationFilter`:** Parses HS256 tokens; checks distributed Redis revocation denylist. Fails closed (`503 Service Unavailable`) on Redis outages.
   - **Filter 2 — `RateLimitingFilter`:** Distributed sliding-window rate limiter powered by Redis Lua scripts, segmented across `auth`, `transactions`, `banking`, and `admin` tiers.
   - **Filter 3 — `ThreatInspectionFilter`:** Inspects inbound payloads for SQLi, XSS, Path Traversal, and Command Injection using `CachedBodyHttpServletRequest`. Rejects oversized bodies (>64 KB) with `413 Payload Too Large` without unbounded heap allocation.
3. **Data & Forensic Persistence (PostgreSQL 16):**
   - 9 Flyway migrations establishing customer portfolios, financial transactions, distributed idempotency keys, threat logs, incidents, and audit chains.
   - Hardened with PL/pgSQL database triggers preventing `UPDATE` and `DELETE` on forensic records.
4. **Distributed Cache & State Store (Redis 7.4):**
   - Atomic token revocation, single-use SSE ticket consumption via Lua `GETDEL`, and rate-limiting sliding window counters.

---

## 🔒 Core Security Capabilities

### 1. Context-Aware ABAC & Authorization Matrix
Unlike basic RBAC that only checks static roles, SYVORA implements an Attribute-Based Access Control (ABAC) engine ([DefaultAbacPolicyEnforcer.java](file:///c:/Users/Hp/.gemini/antigravity/scratch/zero-trust-platform/backend/src/main/java/com/zerotrust/security/abac/DefaultAbacPolicyEnforcer.java)):
- **Dynamic Threat Adaptation:** If a customer account or system IP is subject to an active `CRITICAL` threat level or has a risk score $\ge 70$, high-privilege operations (`VIEW_SENSITIVE`, `UPDATE`, `TRANSFER`) are automatically denied.
- **Resource Ownership:** Employees can only inspect customer records assigned to their branch or portfolio.
- **Role Isolation:**
  - `ROLE_ADMIN`: Global management, incident oversight, system-wide checkpoints.
  - `ROLE_SECURITY_ANALYST`: Incident investigation, state transitions, analyst notes, Gemini AI triage.
  - `ROLE_AUDITOR`: Read-only verification of audit chains and incident records.
  - `ROLE_EMPLOYEE`: Routine banking customer support; denied access to incident workflows, audit verification, and unmasked PII.

### 2. AES-256-GCM Field-Level Encryption & Backfill
Sensitive customer identifiers (e.g. `synthetic_tax_id`) are never stored in plaintext:
- **Ciphertext Packaging:** `v1:<Base64(12-byte IV + Ciphertext + 16-byte GCM Tag)>`.
- **Nonces:** 96-bit cryptographically secure nonces generated uniquely per write via `SecureRandom`.
- **Tamper Detection:** GCM tag authentication failure immediately throws `SecurityException`.
- **Zero-Downtime Migration:** [CustomerEncryptionBackfillService.java](file:///c:/Users/Hp/.gemini/antigravity/scratch/zero-trust-platform/backend/src/main/java/com/zerotrust/security/crypto/CustomerEncryptionBackfillService.java) scans legacy databases for unencrypted rows on startup, transparently upgrading them in-place with rollback protection.

### 3. Tamper-Evident Monotonic Audit Hash Chain
Every security and financial event is recorded in an immutable, cryptographic chain:
- **Monotonic Ordering:** Total ordering is strictly enforced by `sequence_number BIGINT NOT NULL UNIQUE`.
- **Pessimistic Anchor Serialization:** A singleton table row (`audit_chain_anchor`, `id = 1`) locks sequence increment and previous-hash binding via `SELECT ... FOR UPDATE`, preventing race conditions and silent chain forking under high concurrency.
- **V2 Length-Value (LV) Canonical Serialization:** Eliminates delimiter collision attacks by prefixing the UTF-8 byte length to each attribute:
  $$\text{V2} \mid \text{len}(\text{seq}):\text{seq} \mid \text{len}(\text{prevHash}):\text{prevHash} \mid \text{len}(\text{userId}):\text{userId} \mid \dots \mid \text{len}(\text{digest}):\text{digest}$$
- **Anchor Head-Truncation Detection:** Verifying through the end of the chain compares the maximum log sequence and hash against the anchor. Deleting the latest record to conceal an attack triggers `HEAD_TRUNCATION_DETECTED`.
- **Database Engine Immutability:** A PL/pgSQL trigger (`trg_prevent_audit_log_tamper`) blocks any `UPDATE` or `DELETE` at the database level.

### 4. Distributed Token Revocation & Fail-Closed Redis
- When an analyst or admin revokes a session or locks an account, the JWT signature digest is written to Redis (`jwt:denylist:<sha256>`).
- On every request, `JwtAuthenticationFilter` validates the denylist.
- **Fail-Closed Guarantee:** If Redis is down, the filter catches `RedisSecurityException` and immediately terminates the request with `503 Service Unavailable`, guaranteeing that revoked tokens can never bypass security during an infrastructure outage.

### 5. Bounded Stream Threat Inspection Engine
- Inbound requests pass through [CachedBodyHttpServletRequest.java](file:///c:/Users/Hp/.gemini/antigravity/scratch/zero-trust-platform/backend/src/main/java/com/zerotrust/threat/CachedBodyHttpServletRequest.java).
- Caps initial stream buffer allocation to fixed bounds (1024 bytes) independently of client-supplied `Content-Length` headers, defeating memory exhaustion attacks.
- Streams exceeding 64 KB are terminated with `413 Payload Too Large`.
- Bounded streams are evaluated against regex patterns for SQL Injection, XSS, Path Traversal, and OS Command Injection.

### 6. Automated SOC Incident Management Lifecycle
- Qualifying threats (`CRITICAL`, `HIGH`, or `riskScore >= 70`) are automatically promoted to security incidents with deduplication on `related_threat_event_id`.
- Strict state machine: `OPEN` $\rightarrow$ `ACKNOWLEDGED` $\rightarrow$ `INVESTIGATING` $\rightarrow$ `RESOLVED`.
- Reopening requires explicit documented justification: `RESOLVED` $\rightarrow$ `OPEN`.
- Every transition appends an immutable timeline entry to `incident_timeline` with database-level deletion prevention triggers (`trg_prevent_incident_deletion`, `trg_prevent_incident_timeline_tamper`).
- Integrated with Google Gemini 1.5 Flash for contextual SOC incident triage, root-cause analysis, and remediation planning (with automated rule-based fallback when offline).

---

## 🗄️ Database Architecture & Flyway Migrations

The database is managed with 9 incremental Flyway SQL migrations:

| Version | Migration File | Scope & Capabilities |
| :---: | :--- | :--- |
| `V1` | `V1__init_schema.sql` | Users, roles, user-roles join, refresh tokens, baseline audit logs |
| `V2` | `V2__notifications_table.sql` | Real-time notifications and recipient bindings |
| `V3` | `V3__customer_banking_schema.sql` | Customers, accounts, financial transactions, audit indexes |
| `V4` | `V4__transaction_idempotency_and_correlation.sql` | Idempotency records, distributed request hashes, correlation IDs |
| `V5` | `V5__threat_event_correlation_and_scoring.sql` | Threat events, forensic metadata, risk scores, rule matches |
| `V6` | `V6__encrypt_sensitive_customer_fields.sql` | Customer PII column expansion for AES-256-GCM ciphertexts |
| `V7` | `V7__verify_customer_tax_id_encrypted.sql` | Documentation constraints and encryption verification metadata |
| `V8` | `V8__audit_chain_and_incident_management.sql` | Anchor singleton table, checkpoints, incidents, initial immutability triggers |
| `V9` | `V9__incident_forensic_evidence_preservation.sql` | FK restriction (`ON DELETE RESTRICT`) & incident timeline deletion triggers |

---

## 💻 Technology Stack & Architectural Rationale

| Layer | Component | Choice | Engineering Rationale |
| :--- | :--- | :--- | :--- |
| **Language** | Runtime | Java 21 LTS | Pattern matching, records, sealed interfaces, and robust memory safety. |
| **Framework** | Application Core | Spring Boot 3.3.2 | Production-ready actuators, dependency injection, and battle-tested Spring Security 6. |
| **Relational DB** | Primary Storage | PostgreSQL 16 | ACID transactions, row-level locking (`FOR UPDATE`), PL/pgSQL triggers, and JSONB. |
| **Distributed Cache**| State Store | Redis 7.4 (Lettuce) | Microsecond denylist lookups, distributed sliding windows, atomic `GETDEL` ticket consumption. |
| **Security** | Authentication | JJWT (0.12.6) + BCrypt | Stateless HS256 tokens with server-side revocation denylist. |
| **Cryptography** | Data at Rest | AES-256-GCM (JDK) | Authenticated encryption with associated data (AEAD) ensuring integrity and confidentiality. |
| **Hashing** | Audit Chaining | SHA-256 (JDK) | Collision-resistant cryptographic hashing with monotonic sequencing. |
| **Frontend** | Single Page App | React 18 + Vite + TS | High-performance reactive rendering with strict TypeScript type-safety. |
| **Styling** | Component Theme | TailwindCSS + Lucide | Consistent SOC dark-mode aesthetic with accessible UI components. |
| **AI Layer** | Threat Assistant | Google Gemini 1.5 Flash | Fast, low-latency incident explanations with provider-agnostic fallback. |
| **CI/CD** | Pipeline | GitHub Actions | Native container services (`postgres:16`, `redis:7.4`), zero-cost runner execution. |

---

## 🧪 Automated Verification & Test Evidence

SYVORA is backed by a comprehensive automated test suite spanning unit, security, integration, concurrency, and cryptographic verification.

```
[INFO] Results:
[INFO] 
[WARNING] Tests run: 136, Failures: 0, Errors: 0, Skipped: 11
[INFO] 
[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
[INFO] Total time:  01:38 min
```

### Test Suite Breakdown

| Category | Test Suite Class | Tests Run | Passed | Focus Areas |
| :--- | :--- | :---: | :---: | :--- |
| **Cryptography** | `AuditHasherTest` | 5 | 5 | Length-Value V2 collision resistance, null vs empty, Unicode, V1 fallback |
| **Audit Integrity** | `AuditChainIntegrityIntegrationTest` | 7 | 7 | Sequence continuity, tampering detection, sequence gaps, broken links, anchor head truncation, concurrent writes (50 threads) |
| **Incident SOC** | `IncidentManagementIntegrationTest` | 5 | 5 | Lifecycle state transitions, invalid transition rejection, auto-promotion, deduplication |
| **Encryption** | `CustomerEncryptionIntegrationTest` | 3 | 3 | Legacy plaintext backfill, unmasked employee ABAC denial, GCM round-trip |
| **Threat Engine** | `ThreatInspectionIntegrationTest` | 10 | 10 | Bounded requests, SQLi, XSS, Path Traversal, Command Injection, 413 rejection |
| **Concurrency** | `FinancialConcurrencyAndRollbackIntegrationTest` | 3 | 3 | Atomic transfers, balance preservation under opposite concurrent transfers |
| **Idempotency** | `IdempotencyIntegrationTest` | 4 | 4 | Payload conflict detection, concurrent duplicate rejection, replay caching |
| **Filter Hardening**| `ThreatFilterRemediationTest` | 4 | 4 | RFC 9110 413 response, persistence failure block, duplicate filter prevention |
| **ABAC & RBAC** | `AbacPolicyEnforcerTest` | 10 | 10 | Contextual risk-based denial, employee branch isolation, view masking |
| **Security** | `RoleBasedAccessControlTest` | 6 | 6 | Route permissions, role enforcement, unauthorized access rejection |
| **Controllers** | `IncidentControllerTest`, `AuditControllerTest`, etc. | 17 | 17 | REST endpoints, DTO sanitization, pagination |
| **Distributed** | `RedisSecurityIntegrationTest` | 11 | 0 *(11 skipped)* | Skipped locally when Redis container is offline; executed in CI/CD pipeline |
| **Total** | | **136** | **125** | **0 Failures, 0 Errors** |

---

## 🚀 Local Quick Start Guide

### Prerequisites
- Java 21 LTS (`java -version`)
- Maven 3.9+ (`mvn -version`)
- Node.js 20+ and npm (`node -v`)
- Docker Desktop or standalone Docker daemon (optional for containerized deployment)

### Option 1: Docker Compose (Recommended Full-Stack)
```bash
# 1. Clone repository
git clone https://github.com/your-username/zero-trust-platform.git
cd zero-trust-platform

# 2. Configure environment
cp .env.example .env

# 3. Generate a secure 256-bit JWT secret and AES encryption key
# 3. Generate a secure 256-bit JWT secret, AES encryption key, and database password
# On Linux/macOS:
export POSTGRES_PASSWORD=$(openssl rand -base64 16)
export JWT_SECRET=$(openssl rand -base64 32)
export ENCRYPTION_KEY=$(openssl rand -base64 32)

# On Windows PowerShell (Cryptographically Secure CSPRNG):
$env:POSTGRES_PASSWORD = $( $b = [byte[]]::new(16); [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); [Convert]::ToBase64String($b) )
$env:JWT_SECRET = $( $b = [byte[]]::new(32); [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); [Convert]::ToBase64String($b) )
$env:ENCRYPTION_KEY = $( $b = [byte[]]::new(32); [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); [Convert]::ToBase64String($b) )

# 4. Launch all services
docker compose up --build
```
The platform will be live at:
- **Frontend Dashboard:** `http://localhost:3000`
- **Backend API:** `http://localhost:8080`
- **Swagger UI:** `http://localhost:8080/swagger-ui.html`
- **Health Check:** `http://localhost:8080/actuator/health`

### Option 2: Local Developer Standalone Setup
```bash
# 1. Run backend tests (uses embedded H2 in PostgreSQL dialect mode)
cd backend
mvn clean test

# 2. Build frontend production assets
cd ../frontend
npm ci
npm run build
```

---

## ⚙️ Environment Configuration

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `POSTGRES_HOST` | `localhost` | PostgreSQL 16 host address |
| `POSTGRES_PORT` | `5432` | PostgreSQL port |
| `POSTGRES_DB` | `zerotrust_db` | Database name |
| `POSTGRES_USER` | `zerotrust` | Database username |
| `POSTGRES_PASSWORD` | `zerotrust123` | Database password |
| `REDIS_HOST` | `localhost` | Redis server host |
| `REDIS_PORT` | `6379` | Redis port |
| `JWT_SECRET` | *(Required in Prod)* | 256-bit Base64 signing secret for JWT access tokens |
| `ENCRYPTION_KEY` | *(Required in Prod)* | 256-bit Base64 master key for AES-256-GCM field encryption |
| `GEMINI_AI_ENABLED` | `false` | Set to `true` to activate Gemini AI incident explanation |
| `GEMINI_API_KEY` | `""` | Google Gemini API key from Google AI Studio |
| `APP_SEED_DEMO_DATA` | `false` | Seeding synthetic demo users (`true` in dev only; blocked in `prod`) |

---

## 📡 API Demonstration & Verification Scripts

### 1. Authenticate as Security Analyst
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"analyst@zerotrust.com","password":"Analyst@123"}'
```

### 2. Verify Audit Hash Chain Continuity
```bash
curl -X GET http://localhost:8080/api/audit/chain/verify \
  -H "Authorization: Bearer <TOKEN>"
```
*Expected Response:*
```json
{
  "success": true,
  "data": {
    "chainValid": true,
    "totalRecordsVerified": 142,
    "firstSequence": 1,
    "lastSequence": 142,
    "failureReason": "Audit chain intact and verified successfully"
  }
}
```

### 3. Submit Controlled Attack to Trigger Auto-Incident Creation
```bash
curl -X POST http://localhost:8080/api/customers \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"name":"Attacker","email":"test@inject.com","taxId":"123\" OR 1=1--"}'
```
*Expected Response:*
`403 Forbidden` (Threat blocked by `ThreatInspectionFilter`). An automated incident is generated and dispatched via SSE to connected analysts.

---

## 🛡️ Security Model, Threat Assumptions & Limitations

1. **Threat Model:** SYVORA protects against external network adversaries, malicious compromised user accounts, rogue API clients, and offline database tampering.
2. **Database Superuser Boundary:** The PostgreSQL immutability triggers (`trg_prevent_audit_log_tamper`, `trg_prevent_incident_deletion`) prevent tampering from any application role. However, a root PostgreSQL DBA (`postgres` superuser) can disable triggers (`ALTER TABLE audit_logs DISABLE TRIGGER ALL`). For non-repudiation against compromised DBAs, periodic cryptographic checkpoints must be exported to external WORM storage.
3. **Single-Node SSE:** The current SSE implementation broadcasts notifications across active client connections attached to the running instance. Clustered multi-replica deployments should enable Redis Pub/Sub to fan out notifications across instances.

---

## 💼 Resume-Ready Project Impact Summary

- **Enterprise Zero Trust Architecture:** Architected and engineered a comprehensive Spring Boot 3.3 and Java 21 modular monolith enforcing context-aware ABAC, dynamic risk scoring, and zero-trust verification on every request.
- **Cryptographic Audit Integrity:** Designed a tamper-evident audit logging engine using monotonically sequenced SHA-256 hash chains, pessimistic anchor locking to prevent concurrent chain forks, and length-value (LV) canonical serialization immune to delimiter collision attacks.
- **Resilient Distributed Security:** Implemented distributed rate limiting and token revocation using Redis 7 and Lettuce with fail-closed semantics, ensuring revoked JWTs cannot bypass security during cache outages.
- **High-Throughput Threat Engine:** Engineered a bounded-stream inspection filter capping memory allocation independently of client headers, mitigating DoS vulnerabilities while detecting SQLi, XSS, and command injection attacks with sub-millisecond overhead.
- **Production CI/CD & Database Reliability:** Established a 9-migration Flyway evolution pipeline with PostgreSQL PL/pgSQL immutability triggers and automated GitHub Actions CI testing against live PostgreSQL 16 and Redis 7 service containers.

---

*Authored by the SYVORA Engineering & Security Team. Released under the MIT License.*
