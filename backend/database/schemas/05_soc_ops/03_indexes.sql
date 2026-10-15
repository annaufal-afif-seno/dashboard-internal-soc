-- ==============================================================================
-- SCHEMA: SOC_OPS (INDEXES)
-- ==============================================================================

-- Partial Composite Index for Sub-second Triage Queue Queries (Migration 016 Optimization)
CREATE INDEX IF NOT EXISTS idx_soc_queue_active_prio 
    ON soc_ops.soc_triage_queue (priority, created_at DESC) 
    WHERE triage_status IN ('OPEN', 'INVESTIGATE', 'WAITING', 'NEW', 'ASSIGNED', 'INVESTIGATING', 'HOLDING_P4');

CREATE INDEX IF NOT EXISTS idx_soc_queue_incident_id ON soc_ops.soc_triage_queue (incident_id);
CREATE INDEX IF NOT EXISTS idx_soc_queue_status ON soc_ops.soc_triage_queue (triage_status);
CREATE INDEX IF NOT EXISTS idx_soc_queue_analyst ON soc_ops.soc_triage_queue (assigned_analyst);

CREATE INDEX IF NOT EXISTS idx_ground_truth_incident ON soc_ops.ground_truth_dataset (incident_id);
