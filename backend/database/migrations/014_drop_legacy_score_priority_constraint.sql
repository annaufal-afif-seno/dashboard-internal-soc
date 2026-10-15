-- ============================================================================
-- Migration 014: Drop Legacy Score-to-Priority Check Constraint
-- Decouples continuous risk score (0-100) from discrete priority (P0-P4)
-- ============================================================================

BEGIN;

ALTER TABLE risk_engine.calculated_risk_scores
    DROP CONSTRAINT IF EXISTS chk_score_priority_alignment;

COMMIT;
