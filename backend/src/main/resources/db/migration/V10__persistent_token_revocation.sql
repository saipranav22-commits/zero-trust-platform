-- ============================================================
-- Zero Trust Platform - Database Schema
-- V10: Persistent Token Revocation Denylist
-- Guarantees access token revocation survives Redis restarts
-- ============================================================

CREATE TABLE IF NOT EXISTS revoked_tokens (
    token_digest VARCHAR(64) PRIMARY KEY,
    expires_at   TIMESTAMPTZ NOT NULL,
    revoked_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires_at ON revoked_tokens (expires_at);
