-- ============================================================
-- Zero Trust Platform - Phase 1R Migration
-- V4: Financial Transaction Correlation and Idempotency Records
-- ============================================================

-- Add correlation_id to transactions to link dual-entry debit and credit records
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS correlation_id UUID;
CREATE INDEX IF NOT EXISTS idx_transactions_correlation_id ON transactions (correlation_id);

-- Idempotency storage table for financial API state transitions
CREATE TABLE IF NOT EXISTS idempotency_records (
    idempotency_key VARCHAR(128) PRIMARY KEY,
    user_id         VARCHAR(64)  NOT NULL,
    request_hash    VARCHAR(64)  NOT NULL,
    status          VARCHAR(30)  NOT NULL,
    response_body   TEXT,
    status_code     INT,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ  NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_idempotency_user_id ON idempotency_records (user_id);
CREATE INDEX IF NOT EXISTS idx_idempotency_expires_at ON idempotency_records (expires_at);
