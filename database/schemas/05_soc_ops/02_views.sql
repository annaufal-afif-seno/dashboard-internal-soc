-- ==============================================================================
-- SCHEMA: SOC_OPS (VIEWS)
-- ==============================================================================

-- 1. Earliest Deadline First (EDF) SLA-Aware Actionable Triage Queue
CREATE OR REPLACE VIEW soc_ops.v_actionable_triage_queue AS
SELECT 
    t.triage_id,
    t.priority,
    i.title AS judul_insiden,
    i.target_host,
    i.attacker_source_ip,
    t.triage_status,
    t.assigned_analyst,
    COALESCE(t.priority_established_at, t.created_at) AS waktu_muncul,
    CASE
        WHEN t.priority = 'P0' THEN COALESCE(t.priority_established_at, t.created_at) + INTERVAL '15 minutes'
        WHEN t.priority = 'P1' THEN COALESCE(t.priority_established_at, t.created_at) + INTERVAL '1 hour'
        WHEN t.priority = 'P2' THEN COALESCE(t.priority_established_at, t.created_at) + INTERVAL '4 hours'
        WHEN t.priority = 'P3' THEN COALESCE(t.priority_established_at, t.created_at) + INTERVAL '24 hours'
        ELSE COALESCE(t.priority_established_at, t.created_at) + INTERVAL '7 days'
    END AS batas_deadline_sla,
    CASE
        WHEN t.priority = 'P0' THEN 'DARURAT TERTINGGI (< 15m)'
        WHEN t.priority = 'P1' THEN 'MENDESAK (< 60m)'
        WHEN t.priority = 'P2' THEN 'REVIEW SHIFT (< 4 Jam)'
        WHEN t.priority = 'P3' THEN 'REVIEW HARIAN (< 24 Jam)'
        ELSE 'REVIEW MINGGUAN (< 7 Hari)'
    END AS target_sla,
    CASE
        WHEN (
            CASE
                WHEN t.priority = 'P0' THEN COALESCE(t.priority_established_at, t.created_at) + INTERVAL '15 minutes'
                WHEN t.priority = 'P1' THEN COALESCE(t.priority_established_at, t.created_at) + INTERVAL '1 hour'
                WHEN t.priority = 'P2' THEN COALESCE(t.priority_established_at, t.created_at) + INTERVAL '4 hours'
                WHEN t.priority = 'P3' THEN COALESCE(t.priority_established_at, t.created_at) + INTERVAL '24 hours'
                ELSE COALESCE(t.priority_established_at, t.created_at) + INTERVAL '7 days'
            END < CURRENT_TIMESTAMP
        ) THEN 'SLA BREACH (LEWAT BATAS)'
        ELSE 'AKTIF DALAM SLA'
    END AS status_kepatuhan_sla
FROM soc_ops.soc_triage_queue t
JOIN correlation.correlated_incidents i ON t.incident_id = i.incident_id
WHERE t.triage_status IN ('OPEN', 'INVESTIGATE', 'WAITING', 'NEW', 'ASSIGNED', 'INVESTIGATING', 'HOLDING_P4')
ORDER BY
    batas_deadline_sla,
    CASE t.priority
        WHEN 'P0' THEN 1
        WHEN 'P1' THEN 2
        WHEN 'P2' THEN 3
        WHEN 'P3' THEN 4
        ELSE 5
    END,
    COALESCE(t.priority_established_at, t.created_at);

-- 2. AI Model Confusion Matrix & Accuracy Analytics View
CREATE OR REPLACE VIEW soc_ops.v_ai_model_confusion_matrix AS
SELECT 
    'Local LLM' AS model_tier,
    count(*) AS total_samples,
    sum(CASE WHEN local_llm_verdict = 'TRUE_POSITIVE' AND ground_truth_label = 1 THEN 1 ELSE 0 END) AS true_positives,
    sum(CASE WHEN local_llm_verdict = 'FALSE_POSITIVE' AND ground_truth_label = 0 THEN 1 ELSE 0 END) AS true_negatives,
    sum(CASE WHEN local_llm_verdict = 'TRUE_POSITIVE' AND ground_truth_label = 0 THEN 1 ELSE 0 END) AS false_positives,
    sum(CASE WHEN local_llm_verdict = 'FALSE_POSITIVE' AND ground_truth_label = 1 THEN 1 ELSE 0 END) AS false_negatives,
    round((sum(CASE WHEN (local_llm_verdict = 'TRUE_POSITIVE' AND ground_truth_label = 1) OR (local_llm_verdict = 'FALSE_POSITIVE' AND ground_truth_label = 0) THEN 1 ELSE 0 END)::numeric / NULLIF(count(*), 0)::numeric * 100), 2) AS accuracy_pct
FROM soc_ops.ground_truth_dataset
WHERE local_llm_verdict IS NOT NULL
UNION ALL
SELECT 
    'Cloud LLM' AS model_tier,
    count(*) AS total_samples,
    sum(CASE WHEN cloud_llm_verdict = 'TRUE_POSITIVE' AND ground_truth_label = 1 THEN 1 ELSE 0 END) AS true_positives,
    sum(CASE WHEN cloud_llm_verdict = 'FALSE_POSITIVE' AND ground_truth_label = 0 THEN 1 ELSE 0 END) AS true_negatives,
    sum(CASE WHEN cloud_llm_verdict = 'TRUE_POSITIVE' AND ground_truth_label = 0 THEN 1 ELSE 0 END) AS false_positives,
    sum(CASE WHEN cloud_llm_verdict = 'FALSE_POSITIVE' AND ground_truth_label = 1 THEN 1 ELSE 0 END) AS false_negatives,
    round((sum(CASE WHEN (cloud_llm_verdict = 'TRUE_POSITIVE' AND ground_truth_label = 1) OR (cloud_llm_verdict = 'FALSE_POSITIVE' AND ground_truth_label = 0) THEN 1 ELSE 0 END)::numeric / NULLIF(count(*), 0)::numeric * 100), 2) AS accuracy_pct
FROM soc_ops.ground_truth_dataset
WHERE cloud_llm_verdict IS NOT NULL;
