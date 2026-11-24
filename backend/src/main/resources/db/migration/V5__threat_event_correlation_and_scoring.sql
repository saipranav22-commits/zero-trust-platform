-- ============================================================
-- Zero Trust Platform - Phase 3 Migration
-- V5: Threat Event Correlation, Risk Scoring, and Action Taken
-- ============================================================

ALTER TABLE threat_events ADD COLUMN IF NOT EXISTS correlation_id VARCHAR(64);
ALTER TABLE threat_events ADD COLUMN IF NOT EXISTS action_taken VARCHAR(20) DEFAULT 'DETECTED';
ALTER TABLE threat_events ADD COLUMN IF NOT EXISTS risk_score INT DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_threat_events_correlation_id ON threat_events (correlation_id);
CREATE INDEX IF NOT EXISTS idx_threat_events_action_taken ON threat_events (action_taken);
CREATE INDEX IF NOT EXISTS idx_threat_events_risk_score ON threat_events (risk_score);
