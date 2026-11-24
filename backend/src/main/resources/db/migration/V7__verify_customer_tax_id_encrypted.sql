-- ============================================================
-- Zero Trust Platform - Phase 4 Verification & Safety
-- V7: Add documentation comment and check constraint readiness
-- ============================================================

COMMENT ON COLUMN customers.synthetic_tax_id IS 'AES-256-GCM encrypted synthetic tax identifier with v1: prefix';
