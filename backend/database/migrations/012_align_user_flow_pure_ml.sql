-- ==============================================================================
-- Migration 012: Align User Flow 100% & Pure ML State Machine
-- ==============================================================================
-- 1. Updates soc_ops.soc_triage_queue to enforce strictly valid flow statuses:
--    'OPEN', 'INVESTIGATE', 'CLOSE', 'WAITING', 'APPROVE', 'REJECT', 'FP Reject'
-- 2. Migrates existing legacy statuses to the user's flow
-- 3. Adds ground truth approval workflow columns
-- ==============================================================================

BEGIN;

-- 1. Add new columns for Ground Truth Workflow & Manager Review
ALTER TABLE soc_ops.soc_triage_queue
    ADD COLUMN IF NOT EXISTS is_verified_true_positive BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS ground_truth_verdict VARCHAR(30) DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS analyst_notes TEXT DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS manager_review_notes TEXT DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS manager_reviewer VARCHAR(100) DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS manager_reviewed_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS reject_count INTEGER DEFAULT 0,
    ADD COLUMN IF NOT EXISTS parent_triage_id VARCHAR(64) DEFAULT NULL;

-- 2. Drop legacy status constraint if exists
ALTER TABLE soc_ops.soc_triage_queue 
    DROP CONSTRAINT IF EXISTS chk_triage_status_valid,
    DROP CONSTRAINT IF EXISTS soc_triage_queue_triage_status_check;

-- 3. Normalize legacy statuses to User's Official Flow
UPDATE soc_ops.soc_triage_queue
SET triage_status = 'OPEN'
WHERE triage_status IN ('NEW', 'ASSIGNED');

UPDATE soc_ops.soc_triage_queue
SET triage_status = 'INVESTIGATE'
WHERE triage_status IN ('INVESTIGATING', 'PENDING_ACTION');

UPDATE soc_ops.soc_triage_queue
SET triage_status = 'CLOSE'
WHERE triage_status IN ('RESOLVED', 'CLOSED');

UPDATE soc_ops.soc_triage_queue
SET triage_status = 'CLOSE',
    is_verified_true_positive = TRUE,
    ground_truth_verdict = 'THREAT'
WHERE triage_status = 'ESCALATED_TO_IRIS';

-- Default fallback if any unexpected string remains
UPDATE soc_ops.soc_triage_queue
SET triage_status = 'OPEN'
WHERE triage_status NOT IN ('OPEN', 'INVESTIGATE', 'CLOSE', 'WAITING', 'APPROVE', 'REJECT', 'FP Reject');

-- 4. Apply strict constraint matching user's official flow 100%
ALTER TABLE soc_ops.soc_triage_queue
    ADD CONSTRAINT chk_triage_status_user_flow_100pct
    CHECK (triage_status IN (
        'OPEN',
        'INVESTIGATE',
        'CLOSE',
        'WAITING',
        'APPROVE',
        'REJECT',
        'FP Reject'
    ));

-- 5. Record schema migration
INSERT INTO public.schema_migrations (version, applied_at)
VALUES ('012_align_user_flow_pure_ml.sql', CURRENT_TIMESTAMP)
ON CONFLICT DO NOTHING;

COMMIT;
