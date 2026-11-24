-- ============================================================
-- Zero Trust Platform - Phase 6 Migration
-- V9: Incident Forensic Evidence Preservation & Immutability Triggers
-- ============================================================

-- 1. Upgrade foreign key to ON DELETE RESTRICT to prevent cascading loss of evidence
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'incident_timeline_incident_id_fkey'
    ) THEN
        ALTER TABLE incident_timeline DROP CONSTRAINT incident_timeline_incident_id_fkey;
        ALTER TABLE incident_timeline
            ADD CONSTRAINT incident_timeline_incident_id_fkey
            FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE RESTRICT;
    END IF;
END $$;

-- 2. Forensic Evidence Preservation Triggers (PostgreSQL triggers)
-- Prevents deletion of incidents
CREATE OR REPLACE FUNCTION prevent_incident_deletion()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Incidents are permanent forensic records and cannot be deleted. (Table: incidents)';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_prevent_incident_deletion ON incidents;
CREATE TRIGGER trg_prevent_incident_deletion
BEFORE DELETE ON incidents
FOR EACH ROW EXECUTE FUNCTION prevent_incident_deletion();

-- Prevents updating or deleting incident timeline entries
CREATE OR REPLACE FUNCTION prevent_incident_timeline_tamper()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Incident timeline entries are immutable forensic evidence and cannot be updated or deleted. (Table: incident_timeline)';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_prevent_incident_timeline_tamper ON incident_timeline;
CREATE TRIGGER trg_prevent_incident_timeline_tamper
BEFORE UPDATE OR DELETE ON incident_timeline
FOR EACH ROW EXECUTE FUNCTION prevent_incident_timeline_tamper();
