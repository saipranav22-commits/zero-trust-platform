# Database Design

## Overview

The platform uses PostgreSQL as the primary relational database for storing authentication data, audit logs, threat information, user management, and security policies.

The database is normalized to reduce redundancy and maintain data integrity.

---

# Core Tables

## Users

Stores registered users.

Fields

- id
- name
- email
- password
- role
- account_status
- created_at

---

## Roles

Stores application roles.

Examples

- ADMIN
- SECURITY_ANALYST
- AUDITOR
- EMPLOYEE

---

## Refresh Tokens

Stores active refresh tokens.

Fields

- token
- user_id
- expiry
- revoked

---

## Audit Logs

Stores immutable security logs.

Fields

- id
- user_id
- action
- ip_address
- timestamp
- risk_score

---

## Threat Events

Stores detected attacks.

Examples

- SQL Injection
- XSS
- Brute Force
- Path Traversal
- Command Injection

---

## Security Policies

Stores configurable security rules.

Examples

- Password Policy
- Session Timeout
- Maximum Login Attempts
- Allowed Origins

---

# Relationships

User
│
├── Refresh Tokens

├── Audit Logs

└── Threat Events

---

# Design Principles

- Third Normal Form (3NF)
- Indexed foreign keys
- Secure password storage
- Immutable audit records
- Transaction consistency
