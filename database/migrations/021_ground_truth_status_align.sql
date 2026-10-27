BEGIN;
ALTER TABLE soc_ops.soc_triage_queue ADD COLUMN IF NOT EXISTS ground_truth_status VARCHAR(50) DEFAULT 'ACT NEED';
ALTER TABLE soc_ops.soc_triage_queue DROP CONSTRAINT IF EXISTS chk_triage_status_user_flow_100pct;
ALTER TABLE soc_ops.soc_triage_queue ADD CONSTRAINT chk_triage_status_user_flow_100pct CHECK (triage_status::text = ANY (ARRAY['OPEN', 'INVESTIGATE', 'CLOSE', 'GROUNDTRUTH', 'WAITING', 'APPROVE', 'REJECT', 'FP Reject']));
COMMIT;
