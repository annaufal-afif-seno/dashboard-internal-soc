-- ============================================================================
-- MIGRATION 011: Block Simulated LLM Verdicts from Ground Truth Contamination
-- Version: v1.0 — Simulation Guard for ML Retraining & Confusion Matrix Integrity
-- Compatible: PostgreSQL 14+ | Non-Destructive | Zero Downtime
-- ============================================================================
-- PURPOSE:
-- When Cloud LLM API key is missing, the system returns deterministic fake
-- verdicts via _simulate_cloud_reasoning(). Similarly, Local LLM fallback
-- returns hardcoded heuristic verdicts when the model server is offline.
-- These create circular dependencies and contaminate ML retraining data.
-- ============================================================================

BEGIN;

-- 1. ADD SIMULATION FLAG COLUMN
ALTER TABLE soc_ops.ground_truth_dataset
    ADD COLUMN IF NOT EXISTS is_llm_simulated BOOLEAN DEFAULT FALSE;

COMMENT ON COLUMN soc_ops.ground_truth_dataset.is_llm_simulated IS
    'TRUE if LLM verdicts came from heuristic fallback or offline simulation. '
    'Excluded from ML retraining and confusion matrix views.';

CREATE INDEX IF NOT EXISTS idx_gt_not_simulated
    ON soc_ops.ground_truth_dataset (is_llm_simulated)
    WHERE is_llm_simulated = FALSE;

CREATE INDEX IF NOT EXISTS idx_gt_simulated_audit
    ON soc_ops.ground_truth_dataset (is_llm_simulated, created_at)
    WHERE is_llm_simulated = TRUE;

-- 2. UPDATE CONFUSION MATRIX VIEW (exclude simulated rows)
CREATE OR REPLACE VIEW soc_ops.v_ai_model_confusion_matrix AS
SELECT
    'Local LLM' AS model_tier,
    COUNT(*) AS total_samples,
    SUM(CASE WHEN local_llm_verdict = 'TRUE_POSITIVE' AND ground_truth_label = 1 THEN 1 ELSE 0 END) AS true_positives,
    SUM(CASE WHEN local_llm_verdict = 'FALSE_POSITIVE' AND ground_truth_label = 0 THEN 1 ELSE 0 END) AS true_negatives,
    SUM(CASE WHEN local_llm_verdict = 'TRUE_POSITIVE' AND ground_truth_label = 0 THEN 1 ELSE 0 END) AS false_positives,
    SUM(CASE WHEN local_llm_verdict = 'FALSE_POSITIVE' AND ground_truth_label = 1 THEN 1 ELSE 0 END) AS false_negatives,
    ROUND(
        (SUM(CASE WHEN (local_llm_verdict = 'TRUE_POSITIVE' AND ground_truth_label = 1)
                    OR (local_llm_verdict = 'FALSE_POSITIVE' AND ground_truth_label = 0) THEN 1 ELSE 0 END)::NUMERIC
        / NULLIF(COUNT(*), 0)) * 100, 2
    ) AS accuracy_pct
FROM soc_ops.ground_truth_dataset
WHERE local_llm_verdict IS NOT NULL AND is_llm_simulated = FALSE
UNION ALL
SELECT
    'Cloud LLM' AS model_tier,
    COUNT(*) AS total_samples,
    SUM(CASE WHEN cloud_llm_verdict = 'TRUE_POSITIVE' AND ground_truth_label = 1 THEN 1 ELSE 0 END) AS true_positives,
    SUM(CASE WHEN cloud_llm_verdict = 'FALSE_POSITIVE' AND ground_truth_label = 0 THEN 1 ELSE 0 END) AS true_negatives,
    SUM(CASE WHEN cloud_llm_verdict = 'TRUE_POSITIVE' AND ground_truth_label = 0 THEN 1 ELSE 0 END) AS false_positives,
    SUM(CASE WHEN cloud_llm_verdict = 'FALSE_POSITIVE' AND ground_truth_label = 1 THEN 1 ELSE 0 END) AS false_negatives,
    ROUND(
        (SUM(CASE WHEN (cloud_llm_verdict = 'TRUE_POSITIVE' AND ground_truth_label = 1)
                    OR (cloud_llm_verdict = 'FALSE_POSITIVE' AND ground_truth_label = 0) THEN 1 ELSE 0 END)::NUMERIC
        / NULLIF(COUNT(*), 0)) * 100, 2
    ) AS accuracy_pct
FROM soc_ops.ground_truth_dataset
WHERE cloud_llm_verdict IS NOT NULL AND is_llm_simulated = FALSE
UNION ALL
SELECT
    'ML Tier-1 (LightGBM)' AS model_tier,
    COUNT(*) AS total_samples,
    SUM(CASE WHEN ml_tier1_prediction = 1 AND ground_truth_label = 1 THEN 1 ELSE 0 END) AS true_positives,
    SUM(CASE WHEN ml_tier1_prediction = 0 AND ground_truth_label = 0 THEN 1 ELSE 0 END) AS true_negatives,
    SUM(CASE WHEN ml_tier1_prediction = 1 AND ground_truth_label = 0 THEN 1 ELSE 0 END) AS false_positives,
    SUM(CASE WHEN ml_tier1_prediction = 0 AND ground_truth_label = 1 THEN 1 ELSE 0 END) AS false_negatives,
    ROUND(
        (SUM(CASE WHEN ml_tier1_prediction = ground_truth_label THEN 1 ELSE 0 END)::NUMERIC
        / NULLIF(COUNT(*), 0)) * 100, 2
    ) AS accuracy_pct
FROM soc_ops.ground_truth_dataset
WHERE ml_tier1_prediction IS NOT NULL AND is_llm_simulated = FALSE;



-- 3. SIMULATION MONITORING VIEW
CREATE OR REPLACE VIEW soc_ops.v_simulation_frequency AS
SELECT
    DATE_TRUNC('day', created_at) AS report_date,
    tenant_id,
    COUNT(*) FILTER (WHERE is_llm_simulated = TRUE)  AS simulated_count,
    COUNT(*) FILTER (WHERE is_llm_simulated = FALSE) AS real_count,
    COUNT(*) AS total_count,
    ROUND(
        (COUNT(*) FILTER (WHERE is_llm_simulated = TRUE))::NUMERIC
        / NULLIF(COUNT(*), 0) * 100, 2
    ) AS simulation_pct
FROM soc_ops.ground_truth_dataset
GROUP BY DATE_TRUNC('day', created_at), tenant_id
ORDER BY report_date DESC, tenant_id;


-- 4. RETRAINING-SAFE VIEW (excludes simulated, already-trained, unconfirmed)
CREATE OR REPLACE VIEW soc_ops.v_retraining_candidates AS
SELECT
    id, incident_id, triage_id, tenant_id,
    rule_code, category, rule_level, event_count,
    max_inline_risk_score, total_risk_score, priority,
    target_host, host_criticality,
    is_internet_exposed, is_privileged_user, is_service_account,
    threat_intel_match, mitre_tactics, mitre_attack_ids,
    ioa_summary, log_source, extracted_features,
    ml_tier1_prediction, ml_tier1_confidence,
    ground_truth_label, resolution_outcome,
    analyst_id, analyst_notes, created_at
FROM soc_ops.ground_truth_dataset
WHERE is_llm_simulated = FALSE
  AND is_used_in_training = FALSE
  AND analyst_id IS NOT NULL
ORDER BY created_at ASC;


-- 5. SCHEMA MIGRATION RECORD
INSERT INTO public.schema_migrations (version, applied_at)
VALUES ('011_block_simulated_ground_truth.sql', CURRENT_TIMESTAMP)
ON CONFLICT (version) DO NOTHING;

COMMIT;

