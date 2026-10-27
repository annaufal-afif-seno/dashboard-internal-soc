-- ============================================================================
-- MIGRATION 010: Formal State Machine, Ingest Checkpoints, and Adapters Support
-- Version: v1.0 — Enterprise SOC Automation & 100/100 Standards
-- ============================================================================

BEGIN;

-- 1. Expand triage_status CHECK constraint
ALTER TABLE soc_ops.soc_triage_queue 
    DROP CONSTRAINT IF EXISTS soc_triage_queue_triage_status_check;

ALTER TABLE soc_ops.soc_triage_queue 
    ADD CONSTRAINT soc_triage_queue_triage_status_check 
    CHECK ((triage_status)::text = ANY (ARRAY[
        'NEW'::character varying, 
        'ASSIGNED'::character varying, 
        'INVESTIGATING'::character varying, 
        'PENDING_ACTION'::character varying, 
        'PENDING_SOC_AUDIT'::character varying,
        'ESCALATED_TO_IRIS'::character varying,
        'AUTO_CLOSED'::character varying,
        'RESOLVED'::character varying, 
        'CLOSED'::character varying, 
        'FP REJECT'::character varying, 
        'FP_REJECT'::character varying
    ]::text[]));

-- 2. Add threat_intel_status column to soc_ops.soc_triage_queue if not exists
ALTER TABLE soc_ops.soc_triage_queue
    ADD COLUMN IF NOT EXISTS threat_intel_status VARCHAR(32) DEFAULT 'AVAILABLE';

-- 3. Add expires_at column to enrichment.threat_intelligence_iocs if not exists
ALTER TABLE enrichment.threat_intelligence_iocs
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ DEFAULT (CURRENT_TIMESTAMP + INTERVAL '7 days');

-- 4. Create Ingestion Checkpoints Table for Idempotent Stream Pulling
CREATE TABLE IF NOT EXISTS telemetry.ingest_checkpoints (
    tenant_id VARCHAR(64) PRIMARY KEY,
    last_event_id VARCHAR(128),
    last_timestamp TIMESTAMPTZ NOT NULL,
    cursor_offset BIGINT DEFAULT 0,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_ingest_checkpoints_ts ON telemetry.ingest_checkpoints(last_timestamp);

-- Record migration in schema_migrations
INSERT INTO public.schema_migrations (version, applied_at)
VALUES ('010_formal_state_machine_and_checkpoints.sql', CURRENT_TIMESTAMP)
ON CONFLICT (version) DO NOTHING;

COMMIT;
