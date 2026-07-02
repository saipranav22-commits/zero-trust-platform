# System Architecture

## Overview

The AI-Powered Zero Trust Data Protection Platform is designed as a modular full-stack application that secures sensitive enterprise data using modern backend engineering, security principles, and AI-assisted threat analysis.

The application consists of the following major components:

- React Frontend
- Spring Boot Backend
- PostgreSQL Database
- AI Security Assistant
- JWT Authentication
- Threat Detection Engine
- Audit Logging
- Docker Deployment

---

# High-Level Architecture

```
                User
                  │
                  ▼
        React Frontend (TypeScript)
                  │
                  ▼
      Spring Boot REST API (Java 21)
                  │
        ┌─────────┼──────────┐
        │         │          │
        ▼         ▼          ▼
 Authentication Threat Engine Audit Logs
        │         │          │
        └─────────┼──────────┘
                  │
                  ▼
            PostgreSQL
                  │
                  ▼
          AI Security Layer
```

---

# Main Components

## Frontend

- React
- TypeScript
- Tailwind CSS
- Axios
- Charts

Responsible for:

- Dashboard
- Threat Analytics
- User Management
- Audit Viewer

---

## Backend

Built using

- Java 21
- Spring Boot 3
- Spring Security
- JPA
- Hibernate

Responsible for

- Authentication
- Authorization
- Threat Detection
- Audit Logging
- AI Integration

---

## Database

PostgreSQL stores

- Users
- Roles
- Audit Logs
- Threat Events
- Refresh Tokens
- Security Policies

---

## Security Layer

Implements

- JWT Authentication
- Refresh Tokens
- RBAC
- BCrypt Password Hashing
- Secure REST APIs

---

## AI Layer

Provides

- Incident Explanation
- Threat Summary
- Security Recommendations
- Natural Language Security Queries

---

# Design Goals

- Security First
- Clean Architecture
- Scalable Design
- Production Ready
- Enterprise Standards
