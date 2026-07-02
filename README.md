# 🛡️ Zero Trust Security Platform

> **AI-Powered Zero Trust Data Protection Platform** with real-time threat detection, RAG-based security intelligence, and secure database access control.

[![Java](https://img.shields.io/badge/Java-21-orange)](https://www.oracle.com/java/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.3.2-brightgreen)](https://spring.io/projects/spring-boot)
[![React](https://img.shields.io/badge/React-18.3-blue)](https://react.dev/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-blue)](https://www.postgresql.org/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED)](https://docs.docker.com/compose/)

---

## 🎯 Features

| Feature | Description |
|---------|-------------|
| **JWT Auth + RBAC** | HS256 tokens, refresh rotation, 4 roles |
| **Threat Detection** | SQL Injection, XSS, Brute Force, Path Traversal, Command Injection |
| **Audit Logging** | SHA-256 hash-chained immutable audit trail |
| **Risk Scoring** | Dynamic security score based on threat volume & severity |
| **Security Dashboard** | Real-time KPIs, charts, attack analytics |
| **AI Security Assistant** | Gemini AI + RAG for incident explanation |
| **Docker Support** | Full `docker-compose` setup (one command) |

---


---

# 🏗️ System Architecture

The Zero Trust Security Platform follows a layered architecture that separates authentication, threat detection, audit logging, AI-powered security intelligence, and secure data persistence into dedicated components.

<p align="center">
  <img src="Screenshot%202026-07-03%20004700.png" alt="System Architecture" width="1000"/>
</p>
---

## 📂 Project Structure

```text
zero-trust-platform/
├── backend/
│   ├── src/main/java/com/zerotrust/
│   │   ├── config/
│   │   ├── controller/
│   │   ├── entity/
│   │   ├── exception/
│   │   ├── repository/
│   │   ├── security/
│   │   ├── service/
│   │   └── threat/
│   └── src/main/resources/
│       ├── application.yml
│       └── db/migration/
├── frontend/
│   └── src/
│       ├── api/
│       ├── components/
│       ├── pages/
│       ├── store/
│       └── types/
├── docs/
├── docker-compose.yml
└── .env.example
```

---

## 🚀 Quick Start

### Option 1: Docker (Recommended)

```bash
# 1. Clone the repository
git clone <repo-url>
cd zero-trust-platform

# 2. Copy environment file
cp .env.example .env

# 3. (Optional) Enable Gemini AI
# Edit .env:  GEMINI_AI_ENABLED=true  GEMINI_API_KEY=your_key

# 4. Start everything
docker-compose up --build

# Platform will be available at:
# Frontend: http://localhost:3000
# Backend:  http://localhost:8080
# Swagger:  http://localhost:8080/swagger-ui.html
```

### Option 2: Manual Development

**Backend:**
```bash
# Prerequisites: Java 21, Maven 3.9+, PostgreSQL 16

# Start PostgreSQL (or use docker-compose up postgres)
docker run -d -e POSTGRES_DB=zerotrust_db -e POSTGRES_USER=zerotrust \
  -e POSTGRES_PASSWORD=zerotrust123 -p 5432:5432 postgres:16-alpine

cd backend
mvn spring-boot:run
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
# Runs at http://localhost:3000
```

---

## 🔑 Default Credentials

| Role | Email | Password |
|------|-------|----------|
| **Admin** | `admin@zerotrust.com` | `Admin@123` |
| **Security Analyst** | `analyst@zerotrust.com` | `Analyst@123` |

---

## 🤖 Enabling Gemini AI

1. Get a free API key from [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Edit `backend/src/main/resources/application.yml`:
   ```yaml
   app:
     ai:
       enabled: true
       gemini-api-key: "your_api_key_here"
   ```
3. Restart the backend — the AI assistant will now use Gemini for responses

The AI layer is **provider-agnostic** — `AiService.java` can be swapped for OpenAI or Ollama by changing the HTTP call.

---

## 📡 API Endpoints

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| POST | `/api/auth/register` | Register new user | Public |
| POST | `/api/auth/login` | Login (returns JWT) | Public |
| POST | `/api/auth/refresh` | Rotate refresh token | Public |
| POST | `/api/auth/logout` | Invalidate token | Auth |
| GET  | `/api/dashboard/overview` | Security KPIs | Auth |
| GET  | `/api/dashboard/threat-analytics` | Threat charts | Auth |
| GET  | `/api/threats` | List/search threats | Auth |
| PUT  | `/api/threats/{id}/status` | Update threat status | Analyst+ |
| GET  | `/api/audit/logs` | Audit log search | Auth |
| GET  | `/api/audit/logs/{id}/verify` | Verify hash integrity | Auth |
| GET  | `/api/users` | List users | Admin/Analyst |
| POST | `/api/ai/chat` | AI security assistant | Analyst+ |
| POST | `/api/ai/explain-threat` | AI threat explanation | Analyst+ |

Full Swagger UI: `http://localhost:8080/swagger-ui.html`

---

## 🔒 RBAC Roles

| Role | Permissions |
|------|-------------|
| `ROLE_ADMIN` | Full access — user management, all analytics, all operations |
| `ROLE_SECURITY_ANALYST` | Threat management, analytics, AI assistant |
| `ROLE_AUDITOR` | Read-only access to threats and audit logs |
| `ROLE_EMPLOYEE` | Login only (extensible for future features) |

---

## 🛡️ Threat Detection Rules

The `ThreatDetectionEngine` uses compiled regex patterns to detect:

- **SQL Injection**: OR tautologies, UNION SELECT, DROP, `information_schema`, time-based blind, file operations
- **XSS**: Script tags, javascript URIs, event handlers, iframe injection, DOM access, eval
- **Path Traversal**: `../` sequences, URL-encoded traversal, sensitive file paths
- **Command Injection**: Shell metacharacters with OS commands, template injection
- **Brute Force**: IP-based sliding window counter (10 attempts / 5 min)

---

## 📊 Resume-Worthy Technical Highlights

- **Java 21 features**: Records, pattern matching, sealed classes
- **Spring Boot 3.3**: Latest framework with virtual threads support
- **Zero Trust architecture**: Never trust, always verify design
- **SHA-256 hash chaining**: Tamper-proof audit logs (blockchain-inspired)
- **Provider-agnostic AI**: Gemini/OpenAI/Ollama interface abstraction
- **Flyway migrations**: Schema versioning and rollback
- **JWT refresh token rotation**: Security best practice
- **Specification pattern**: Dynamic JPA queries without custom SQL
- **Multi-stage Docker builds**: Minimal production images

---

*Built for showcasing Backend Engineering, System Design, Security Engineering, and AI integration skills.*
