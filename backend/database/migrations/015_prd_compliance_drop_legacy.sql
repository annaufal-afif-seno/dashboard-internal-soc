-- ============================================================================
-- Migration 015: PRD Compliance - Drop Legacy Score-Based Systems
-- PRD Section 8: Komponen lama yang harus dihapus atau diubah
-- ============================================================================

BEGIN;

-- PRD Section 8 #2: Risk score formula dihapus
-- Drop constraint that ties score ranges to priority
ALTER TABLE risk_engine.calculated_risk_scores
    DROP CONSTRAINT IF EXISTS chk_score_priority_alignment;

-- PRD Section 8 #9: Mapping P0-P4 berbasis skor sudah tidak ada
-- Priority now determined by aggregate category, not score

-- PRD Section 3: Aggregate status hanya OPEN dan CLOSED
-- Update any lingering ACTIONABLE/SUPPRESSED/PENDING_REVIEW to CLOSED
UPDATE suppression.aggregated_alerts
SET status = 'CLOSED'
WHERE status NOT IN ('OPEN', 'CLOSED');

-- PRD Section 5: Triage status update - remove legacy HOLDING_P4 references
-- HOLDING_P4 is still used for P4 tickets waiting for SLA expiry

COMMIT;
