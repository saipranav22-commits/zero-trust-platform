-- ============================================================
-- Zero Trust Platform - Phase 5 Migration
-- V8: Tamper-Evident Audit Chain & Incident Management
-- ============================================================

-- 1. Audit chain anchor singleton table
CREATE TABLE IF NOT EXISTS audit_chain_anchor (
    id INT PRIMARY KEY,
    last_sequence BIGINT NOT NULL,
    last_hash VARCHAR(64) NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. Audit checkpoints table
CREATE TABLE IF NOT EXISTS audit_checkpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sequence_number BIGINT NOT NULL,
    checkpoint_hash VARCHAR(64) NOT NULL,
    record_count BIGINT NOT NULL,
    created_by VARCHAR(100) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_checkpoints_seq ON audit_checkpoints (sequence_number DESC);

-- 3. Update audit_logs with sequence_number
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS sequence_number BIGINT;

-- Backfill sequence_number for existing audit logs
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM audit_logs WHERE sequence_number IS NULL) THEN
        WITH numbered_logs AS (
            SELECT id, ROW_NUMBER() OVER (ORDER BY created_at ASC, id ASC) AS row_num
            FROM audit_logs
            WHERE sequence_number IS NULL
        )
        UPDATE audit_logs al
        SET sequence_number = nl.row_num
        FROM numbered_logs nl
        WHERE al.id = nl.id;
    END IF;
END $$;

-- Sequence for audit_logs
CREATE SEQUENCE IF NOT EXISTS audit_log_sequence_seq START WITH 1;
SELECT setval('audit_log_sequence_seq', COALESCE((SELECT MAX(sequence_number) FROM audit_logs), 0) + 1, false);

-- Set sequence_number not null and unique
ALTER TABLE audit_logs ALTER COLUMN sequence_number SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_logs_sequence_number ON audit_logs (sequence_number);

-- Initialize anchor row if not present
INSERT INTO audit_chain_anchor (id, last_sequence, last_hash, updated_at)
SELECT 1, COALESCE((SELECT MAX(sequence_number) FROM audit_logs), 0),
       COALESCE((SELECT current_hash FROM audit_logs ORDER BY sequence_number DESC LIMIT 1), 'GENESIS'),
       NOW()
WHERE NOT EXISTS (SELECT 1 FROM audit_chain_anchor WHERE id = 1);

-- 4. Incidents Table
CREATE TABLE IF NOT EXISTS incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_number VARCHAR(50) NOT NULL UNIQUE,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    status VARCHAR(30) NOT NULL DEFAULT 'OPEN',
    severity VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
    category VARCHAR(100),
    correlation_id VARCHAR(64),
    related_threat_event_id UUID UNIQUE,
    source_ip VARCHAR(45),
    target_resource VARCHAR(255),
    assigned_to VARCHAR(255),
    created_by VARCHAR(255),
    resolution_notes TEXT,
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents (severity);
CREATE INDEX IF NOT EXISTS idx_incidents_assigned_to ON incidents (assigned_to);
CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_correlation_id ON incidents (correlation_id);

-- 5. Incident Timeline Table
CREATE TABLE IF NOT EXISTS incident_timeline (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    action VARCHAR(100) NOT NULL,
    from_status VARCHAR(30),
    to_status VARCHAR(30),
    performed_by VARCHAR(255),
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_incident_timeline_incident_id ON incident_timeline (incident_id, created_at ASC);

-- 6. Immutability Protection for audit_logs (PostgreSQL trigger)
-- Prevents UPDATE or DELETE from ordinary application roles.
CREATE OR REPLACE FUNCTION prevent_audit_log_tamper()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Audit logs are immutable and cannot be updated or deleted. (Table: audit_logs)';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_prevent_audit_log_tamper ON audit_logs;
CREATE TRIGGER trg_prevent_audit_log_tamper
BEFORE UPDATE OR DELETE ON audit_logs
FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_tamper();
