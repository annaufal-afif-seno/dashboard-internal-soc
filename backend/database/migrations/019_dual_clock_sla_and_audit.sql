-- ============================================================================
-- MIGRATION 019: DUAL-CLOCK SLA AND AUDIT TIMESTAMPS
-- Non-destructive • Idempotent • Production-Grade
-- ============================================================================
-- Implementation:
-- 1. first_detected_at: Permanent, immutable incident genesis timestamp for MTTA/MTTR
-- 2. priority_changed_at: Timestamp updated whenever priority elevates
-- 3. sla_deadline: Explicit calculated deadline for real-time SLA tracking
-- ============================================================================

BEGIN;

ALTER TABLE soc_ops.soc_triage_queue
    ADD COLUMN IF NOT EXISTS first_detected_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    ADD COLUMN IF NOT EXISTS priority_changed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    ADD COLUMN IF NOT EXISTS sla_deadline TIMESTAMPTZ;

-- Backfill first_detected_at with earliest available creation / lookback time
UPDATE soc_ops.soc_triage_queue q
SET first_detected_at = COALESCE(q.first_detected_at, i.first_seen_at, q.priority_established_at, q.created_at, CURRENT_TIMESTAMP),
    priority_changed_at = COALESCE(q.priority_changed_at, q.priority_established_at, q.created_at, CURRENT_TIMESTAMP)
FROM correlation.correlated_incidents i
WHERE q.incident_id = i.incident_id;

-- Ensure standalone tickets also backfilled
UPDATE soc_ops.soc_triage_queue
SET first_detected_at = COALESCE(first_detected_at, priority_established_at, created_at, CURRENT_TIMESTAMP),
    priority_changed_at = COALESCE(priority_changed_at, priority_established_at, created_at, CURRENT_TIMESTAMP)
WHERE first_detected_at IS NULL OR priority_changed_at IS NULL;

-- Compute sla_deadline based on priority_changed_at
UPDATE soc_ops.soc_triage_queue
SET sla_deadline = CASE
    WHEN priority = 'P0' THEN priority_changed_at + INTERVAL '15 minutes'
    WHEN priority = 'P1' THEN priority_changed_at + INTERVAL '60 minutes'
    WHEN priority = 'P2' THEN priority_changed_at + INTERVAL '4 hours'
    WHEN priority = 'P3' THEN priority_changed_at + INTERVAL '24 hours'
    ELSE priority_changed_at + INTERVAL '7 days'
END
WHERE sla_deadline IS NULL;

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_soc_queue_first_detected_at
    ON soc_ops.soc_triage_queue (first_detected_at);

CREATE INDEX IF NOT EXISTS idx_soc_queue_priority_changed_at
    ON soc_ops.soc_triage_queue (priority_changed_at);

CREATE INDEX IF NOT EXISTS idx_soc_queue_sla_deadline_active
    ON soc_ops.soc_triage_queue (sla_deadline, triage_status);

COMMIT;
