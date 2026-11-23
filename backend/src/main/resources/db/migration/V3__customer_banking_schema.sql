-- ============================================================
-- Zero Trust Platform - Phase 1 Migration
-- V3: Realistic Customer Financial & Banking Schema (Synthetic Data)
-- ============================================================

CREATE TABLE IF NOT EXISTS customers (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_number      VARCHAR(50)  NOT NULL UNIQUE,
    first_name           VARCHAR(100) NOT NULL,
    last_name            VARCHAR(100) NOT NULL,
    email                VARCHAR(255) NOT NULL UNIQUE,
    phone_number         VARCHAR(50),
    kyc_status           VARCHAR(30)  NOT NULL DEFAULT 'PENDING',
    risk_tier            VARCHAR(20)  NOT NULL DEFAULT 'LOW',
    assigned_employee_id UUID REFERENCES users(id) ON DELETE SET NULL,
    synthetic_tax_id     VARCHAR(50)  NOT NULL,
    annual_income        NUMERIC(15,2),
    credit_score         INT,
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_customers_assigned_employee ON customers(assigned_employee_id);
CREATE INDEX IF NOT EXISTS idx_customers_customer_number ON customers(customer_number);
CREATE INDEX IF NOT EXISTS idx_customers_risk_tier ON customers(risk_tier);

CREATE TABLE IF NOT EXISTS accounts (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id    UUID         NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    account_number VARCHAR(50)  NOT NULL UNIQUE,
    account_type   VARCHAR(30)  NOT NULL DEFAULT 'CHECKING',
    balance        NUMERIC(15,2) NOT NULL DEFAULT 0.00,
    currency       VARCHAR(10)  NOT NULL DEFAULT 'USD',
    status         VARCHAR(30)  NOT NULL DEFAULT 'ACTIVE',
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_accounts_customer_id ON accounts(customer_id);
CREATE INDEX IF NOT EXISTS idx_accounts_account_number ON accounts(account_number);

CREATE TABLE IF NOT EXISTS transactions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id          UUID         NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    reference_number    VARCHAR(64)  NOT NULL UNIQUE,
    amount              NUMERIC(15,2) NOT NULL,
    type                VARCHAR(30)  NOT NULL,
    status              VARCHAR(30)  NOT NULL DEFAULT 'COMPLETED',
    description         VARCHAR(255),
    source_account      VARCHAR(50),
    destination_account VARCHAR(50),
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_transactions_account_id ON transactions(account_id);
CREATE INDEX IF NOT EXISTS idx_transactions_reference ON transactions(reference_number);
CREATE INDEX IF NOT EXISTS idx_transactions_created_at ON transactions(created_at DESC);
