-- ============================================================
-- Zero Trust Platform - Database Schema
-- V1: Core tables (users, roles, tokens, audit, threats)
-- ============================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =====================
-- ROLES & PERMISSIONS
-- =====================
CREATE TABLE roles (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        VARCHAR(50)  NOT NULL UNIQUE,
    description VARCHAR(255),
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE permissions (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        VARCHAR(100) NOT NULL UNIQUE,
    description VARCHAR(255),
    resource    VARCHAR(100),
    action      VARCHAR(50),
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- =====================
-- USERS
-- =====================
CREATE TABLE users (
    id                    UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    email                 VARCHAR(255) NOT NULL UNIQUE,
    password_hash         VARCHAR(255) NOT NULL,
    first_name            VARCHAR(100) NOT NULL,
    last_name             VARCHAR(100) NOT NULL,
    is_active             BOOLEAN      NOT NULL DEFAULT TRUE,
    is_locked             BOOLEAN      NOT NULL DEFAULT FALSE,
    failed_login_attempts INT          NOT NULL DEFAULT 0,
    lock_until            TIMESTAMPTZ,
    last_login_at         TIMESTAMPTZ,
    last_login_ip         VARCHAR(45),
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- =====================
-- REFRESH TOKENS
-- =====================
CREATE TABLE refresh_tokens (
    id         UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    token      VARCHAR(255) NOT NULL UNIQUE,
    user_id    UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ  NOT NULL,
    revoked    BOOLEAN      NOT NULL DEFAULT FALSE,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- =====================
-- AUDIT LOGS (Immutable)
-- =====================
CREATE TABLE audit_logs (
    id            UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id       VARCHAR(255),
    user_email    VARCHAR(255),
    action        VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100),
    resource_id   VARCHAR(255),
    source_ip     VARCHAR(45),
    user_agent    TEXT,
    status        VARCHAR(20)  NOT NULL DEFAULT 'SUCCESS',
    risk_score    INT          NOT NULL DEFAULT 0,
    details       TEXT,
    previous_hash VARCHAR(64),
    current_hash  VARCHAR(64),
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- =====================
-- THREAT EVENTS
-- =====================
CREATE TABLE threat_events (
    id              UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id         VARCHAR(255),
    user_email      VARCHAR(255),
    threat_type     VARCHAR(50)  NOT NULL,
    severity        VARCHAR(20)  NOT NULL DEFAULT 'MEDIUM',
    source_ip       VARCHAR(45),
    target_resource VARCHAR(255),
    target_method   VARCHAR(10),
    attack_payload  TEXT,
    detection_rule  VARCHAR(255),
    status          VARCHAR(30)  NOT NULL DEFAULT 'DETECTED',
    resolved_by     VARCHAR(255),
    resolved_at     TIMESTAMPTZ,
    notes           TEXT,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- =====================
-- RISK SCORES
-- =====================
CREATE TABLE risk_scores (
    id                   UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id              VARCHAR(255) NOT NULL,
    user_email           VARCHAR(255),
    score                INT          NOT NULL DEFAULT 0,
    risk_level           VARCHAR(20)  NOT NULL DEFAULT 'LOW',
    failed_login_factor  INT          NOT NULL DEFAULT 0,
    threat_event_factor  INT          NOT NULL DEFAULT 0,
    unusual_access_factor INT         NOT NULL DEFAULT 0,
    details              TEXT,
    calculated_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- =====================
-- INDEXES FOR PERFORMANCE
-- =====================
CREATE INDEX idx_users_email          ON users(email);
CREATE INDEX idx_users_is_active      ON users(is_active);
CREATE INDEX idx_refresh_tokens_token ON refresh_tokens(token);
CREATE INDEX idx_refresh_tokens_uid   ON refresh_tokens(user_id);

CREATE INDEX idx_audit_logs_user_id   ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_action    ON audit_logs(action);
CREATE INDEX idx_audit_logs_created   ON audit_logs(created_at DESC);
CREATE INDEX idx_audit_logs_status    ON audit_logs(status);

CREATE INDEX idx_threat_events_type      ON threat_events(threat_type);
CREATE INDEX idx_threat_events_severity  ON threat_events(severity);
CREATE INDEX idx_threat_events_status    ON threat_events(status);
CREATE INDEX idx_threat_events_source_ip ON threat_events(source_ip);
CREATE INDEX idx_threat_events_created   ON threat_events(created_at DESC);
CREATE INDEX idx_threat_events_user_id   ON threat_events(user_id);

CREATE INDEX idx_risk_scores_user_id  ON risk_scores(user_id);
CREATE INDEX idx_risk_scores_level    ON risk_scores(risk_level);
CREATE INDEX idx_risk_scores_calc     ON risk_scores(calculated_at DESC);

-- =====================
-- SEED DEFAULT ROLES
-- =====================
INSERT INTO roles (id, name, description) VALUES
    (uuid_generate_v4(), 'ROLE_ADMIN',            'Full system administrator with all privileges'),
    (uuid_generate_v4(), 'ROLE_SECURITY_ANALYST', 'Can view and manage threat events and analytics'),
    (uuid_generate_v4(), 'ROLE_AUDITOR',          'Read-only access to audit logs and reports'),
    (uuid_generate_v4(), 'ROLE_EMPLOYEE',         'Standard employee with limited access');
