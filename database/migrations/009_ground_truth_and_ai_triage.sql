-- ============================================================================
-- MIGRATION 009: Ground Truth Dataset & Tri-Tier AI Triage Benchmark
-- Version: v1.0 — Active Learning Ground Truth Store & Confusion Matrix Views
-- Compatible: PostgreSQL 14+ | Non-Destructive | Zero Downtime
-- ============================================================================

BEGIN;

-- 1. TABLE: soc_ops.ground_truth_dataset
-- Penampung fitur insiden dan label definitif dari Analis SOC (Ground Truth)
-- untuk keperluan Active Learning re-training Machine Learning & evaluasi LLM.
CREATE TABLE IF NOT EXISTS soc_ops.ground_truth_dataset (
    id BIGSERIAL PRIMARY KEY,
    incident_id VARCHAR(64) NOT NULL,
    triage_id VARCHAR(64) NOT NULL,
    tenant_id VARCHAR(64) DEFAULT 'DEFAULT',

    -- [Features X: Telemetry & Ingestion]
    rule_code VARCHAR(64),
    category VARCHAR(64),
    rule_level INT,
    event_count INT,
    max_inline_risk_score INT DEFAULT 0,
    total_risk_score INT DEFAULT 0,
    priority VARCHAR(4),
    target_host VARCHAR(128),
    host_criticality VARCHAR(32) DEFAULT 'STANDARD',
    is_internet_exposed BOOLEAN DEFAULT FALSE,
    is_privileged_user BOOLEAN DEFAULT FALSE,
    is_service_account BOOLEAN DEFAULT FALSE,
    threat_intel_match BOOLEAN DEFAULT FALSE,
    mitre_tactics JSONB DEFAULT '[]'::jsonb,
    mitre_attack_ids JSONB DEFAULT '[]'::jsonb,
    ioa_summary TEXT,
    log_source TEXT,
    extracted_features JSONB DEFAULT '{}'::jsonb,

    -- [Predictions: AI Model Outputs for Benchmarking]
    ml_tier1_prediction INT,                       -- 0=Benign, 1=Threat
    ml_tier1_confidence NUMERIC(5,2),             -- 0.00 - 100.00 %
    local_llm_verdict VARCHAR(32),                -- 'FALSE_POSITIVE', 'TRUE_POSITIVE', 'UNCERTAIN'
    local_llm_confidence NUMERIC(5,2),            -- 0.00 - 100.00 %
    cloud_llm_verdict VARCHAR(32),                -- 'FALSE_POSITIVE', 'TRUE_POSITIVE', 'UNCERTAIN'
    cloud_llm_confidence NUMERIC(5,2),            -- 0.00 - 100.00 %
    voting_score NUMERIC(5,2),                    -- Soft voting score 0.00 - 100.00
    decision_path VARCHAR(32),                    -- 'AUTO_CLOSE', 'ESCALATE', 'HITL_GROUND_TRUTH'

    -- [Ground Truth Target Y: Verified by Human Analyst]
    ground_truth_label INT NOT NULL CHECK (ground_truth_label IN (0, 1)), -- 0=Benign/FP, 1=True Threat/TP
    resolution_outcome VARCHAR(64) NOT NULL,
    analyst_id VARCHAR(128),
    analyst_notes TEXT,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    -- [Model Retraining Lifecycle]
    is_used_in_training BOOLEAN DEFAULT FALSE,
    trained_at TIMESTAMPTZ,

    CONSTRAINT uq_ground_truth_incident UNIQUE (incident_id)
);

CREATE INDEX IF NOT EXISTS idx_gt_label ON soc_ops.ground_truth_dataset (ground_truth_label);
CREATE INDEX IF NOT EXISTS idx_gt_untrained ON soc_ops.ground_truth_dataset (is_used_in_training) WHERE is_used_in_training = FALSE;
CREATE INDEX IF NOT EXISTS idx_gt_tenant ON soc_ops.ground_truth_dataset (tenant_id);

-- 2. TRIGGER FUNCTION: Otomatis rekam Ground Truth saat tiket di-RESOLVE / di-CLOSE oleh Analis
CREATE OR REPLACE FUNCTION soc_ops.capture_ground_truth_on_triage()
RETURNS TRIGGER AS $$
DECLARE
    v_inc RECORD;
    v_score RECORD;
    v_asset RECORD;
    v_gt_label INT;
BEGIN
    -- Hanya rekam jika ada keputusan resolusi definitif
    IF NEW.resolution_outcome IS NOT NULL AND (
        OLD.resolution_outcome IS DISTINCT FROM NEW.resolution_outcome OR
        OLD.triage_status IS DISTINCT FROM NEW.triage_status
    ) THEN
        -- Tentukan Label Biner: 0 = Benign/Noise (Auto-Dismiss), 1 = True Threat/Actionable Incident
        IF NEW.resolution_outcome IN ('FALSE_POSITIVE_TUNING_REQ', 'OPERATIONAL_NOISE', 'BENIGN_AUTHORIZED', 'TRUE_POSITIVE_NO_ACTION') THEN
            v_gt_label := 0;
        ELSIF NEW.resolution_outcome IN ('TRUE_POSITIVE_ACTIONABLE') THEN
            v_gt_label := 1;
        ELSE
            -- Status lain seperti REJECTED atau CUSTOM tidak dijadikan training data otomatis
            RETURN NEW;
        END IF;

        -- Ambil data insiden
        SELECT * INTO v_inc 
        FROM correlation.correlated_incidents 
        WHERE incident_id = NEW.incident_id;

        -- Ambil data calculated score
        SELECT * INTO v_score 
        FROM risk_engine.calculated_risk_scores 
        WHERE incident_id = NEW.incident_id;

        -- Ambil data aset
        SELECT * INTO v_asset 
        FROM enrichment.asset_inventory_context 
        WHERE hostname = v_inc.target_host OR ip_address = v_inc.target_host
        LIMIT 1;

        -- Upsert record ke tabel ground_truth_dataset
        INSERT INTO soc_ops.ground_truth_dataset (
            incident_id,
            triage_id,
            tenant_id,
            rule_code,
            rule_level,
            event_count,
            max_inline_risk_score,
            total_risk_score,
            priority,
            target_host,
            host_criticality,
            is_internet_exposed,
            is_privileged_user,
            threat_intel_match,
            ioa_summary,
            ground_truth_label,
            resolution_outcome,
            analyst_id,
            analyst_notes,
            created_at
        ) VALUES (
            NEW.incident_id,
            NEW.triage_id,
            COALESCE(v_inc.tenant_id, 'DEFAULT'),
            COALESCE(v_inc.correlation_rule_id, 'UNKNOWN'),
            ROUND(COALESCE(v_score.total_score, 50) / 7.0)::INT,
            COALESCE((SELECT COUNT(*) FROM correlation.incident_stages WHERE incident_id = NEW.incident_id), 1),
            COALESCE(v_score.total_score, 50),
            COALESCE(v_score.total_score, 50),
            NEW.priority,
            v_inc.target_host,
            COALESCE(v_asset.criticality_tier, 'STANDARD'),
            COALESCE(v_asset.is_internet_exposed, FALSE),
            (v_inc.compromised_account ILIKE '%root%' OR v_inc.compromised_account ILIKE '%admin%'),
            (v_inc.attacker_source_ip IS NOT NULL AND v_inc.attacker_source_ip != 'unknown'),
            v_inc.narrative,
            v_gt_label,
            NEW.resolution_outcome,
            NEW.assigned_analyst,
            NEW.false_positive_reason,
            CURRENT_TIMESTAMP
        )
        ON CONFLICT (incident_id) DO UPDATE SET
            ground_truth_label = EXCLUDED.ground_truth_label,
            resolution_outcome = EXCLUDED.resolution_outcome,
            analyst_id = EXCLUDED.analyst_id,
            analyst_notes = EXCLUDED.analyst_notes,
            created_at = CURRENT_TIMESTAMP;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_capture_ground_truth ON soc_ops.soc_triage_queue;
CREATE TRIGGER trg_capture_ground_truth
AFTER UPDATE ON soc_ops.soc_triage_queue
FOR EACH ROW EXECUTE FUNCTION soc_ops.capture_ground_truth_on_triage();

-- 3. VIEW: Confusion Matrix & Model Benchmark Comparison
-- Membandingkan akurasi dan False Positive rate Local LLM vs Cloud LLM terhadap Ground Truth Analis
CREATE OR REPLACE VIEW soc_ops.v_ai_model_confusion_matrix AS
SELECT 
    'Local LLM' AS model_tier,
    COUNT(*) AS total_samples,
    SUM(CASE WHEN local_llm_verdict = 'TRUE_POSITIVE' AND ground_truth_label = 1 THEN 1 ELSE 0 END) AS true_positives,
    SUM(CASE WHEN local_llm_verdict = 'FALSE_POSITIVE' AND ground_truth_label = 0 THEN 1 ELSE 0 END) AS true_negatives,
    SUM(CASE WHEN local_llm_verdict = 'TRUE_POSITIVE' AND ground_truth_label = 0 THEN 1 ELSE 0 END) AS false_positives,
    SUM(CASE WHEN local_llm_verdict = 'FALSE_POSITIVE' AND ground_truth_label = 1 THEN 1 ELSE 0 END) AS false_negatives,
    ROUND(
        (SUM(CASE WHEN (local_llm_verdict = 'TRUE_POSITIVE' AND ground_truth_label = 1) OR (local_llm_verdict = 'FALSE_POSITIVE' AND ground_truth_label = 0) THEN 1 ELSE 0 END)::NUMERIC 
        / NULLIF(COUNT(*), 0)) * 100, 2
    ) AS accuracy_pct
FROM soc_ops.ground_truth_dataset
WHERE local_llm_verdict IS NOT NULL
UNION ALL
SELECT 
    'Cloud LLM' AS model_tier,
    COUNT(*) AS total_samples,
    SUM(CASE WHEN cloud_llm_verdict = 'TRUE_POSITIVE' AND ground_truth_label = 1 THEN 1 ELSE 0 END) AS true_positives,
    SUM(CASE WHEN cloud_llm_verdict = 'FALSE_POSITIVE' AND ground_truth_label = 0 THEN 1 ELSE 0 END) AS true_negatives,
    SUM(CASE WHEN cloud_llm_verdict = 'TRUE_POSITIVE' AND ground_truth_label = 0 THEN 1 ELSE 0 END) AS false_positives,
    SUM(CASE WHEN cloud_llm_verdict = 'FALSE_POSITIVE' AND ground_truth_label = 1 THEN 1 ELSE 0 END) AS false_negatives,
    ROUND(
        (SUM(CASE WHEN (cloud_llm_verdict = 'TRUE_POSITIVE' AND ground_truth_label = 1) OR (cloud_llm_verdict = 'FALSE_POSITIVE' AND ground_truth_label = 0) THEN 1 ELSE 0 END)::NUMERIC 
        / NULLIF(COUNT(*), 0)) * 100, 2
    ) AS accuracy_pct
FROM soc_ops.ground_truth_dataset
WHERE cloud_llm_verdict IS NOT NULL;

COMMIT;
