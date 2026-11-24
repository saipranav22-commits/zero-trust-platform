-- ============================================================
-- Zero Trust Platform - Phase 4 Migration
-- V6: Expand synthetic_tax_id column length to support AES-256-GCM authenticated ciphertexts
-- ============================================================

ALTER TABLE customers ALTER COLUMN synthetic_tax_id TYPE VARCHAR(255);
