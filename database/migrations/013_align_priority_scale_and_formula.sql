-- ============================================================================
-- Migration 013: Align Priority Scale & Risk Formula (P0: 80-100, P1: 60-79, P2: 40-59, P3: 20-39, P4: <20)
-- 100% Compliant with User Formula Specification & Floor Clamp Safety
-- ============================================================================

BEGIN;

-- 1. Drop old constraint on risk_engine.calculated_risk_scores
ALTER TABLE risk_engine.calculated_risk_scores
    DROP CONSTRAINT IF EXISTS chk_score_priority_alignment;

-- 2. Update existing scores at boundary points (80 -> P0, 60 -> P1, 40 -> P2)
UPDATE risk_engine.calculated_risk_scores
SET soc_priority = 'P0'
WHERE total_score >= 80;

UPDATE risk_engine.calculated_risk_scores
SET soc_priority = 'P1'
WHERE total_score >= 60 AND total_score < 80;

UPDATE risk_engine.calculated_risk_scores
SET soc_priority = 'P2'
WHERE total_score >= 40 AND total_score < 60;

UPDATE risk_engine.calculated_risk_scores
SET soc_priority = 'P3'
WHERE total_score >= 20 AND total_score < 40;

UPDATE risk_engine.calculated_risk_scores
SET soc_priority = 'P4'
WHERE total_score < 20;

-- 3. Add aligned constraint on risk_engine.calculated_risk_scores
ALTER TABLE risk_engine.calculated_risk_scores
    ADD CONSTRAINT chk_score_priority_alignment CHECK (
        (((total_score >= 0) AND (total_score < 20)) AND (soc_priority = 'P4')) OR
        (((total_score >= 20) AND (total_score < 40)) AND (soc_priority = 'P3')) OR
        (((total_score >= 40) AND (total_score < 60)) AND (soc_priority = 'P2')) OR
        (((total_score >= 60) AND (total_score < 80)) AND (soc_priority = 'P1')) OR
        (((total_score >= 80) AND (total_score <= 100)) AND (soc_priority = 'P0'))
    );

-- 4. Sync priority in soc_ops.soc_triage_queue
UPDATE soc_ops.soc_triage_queue q
SET priority = s.soc_priority
FROM risk_engine.calculated_risk_scores s
WHERE q.incident_id = s.incident_id AND q.priority != s.soc_priority;

COMMIT;
