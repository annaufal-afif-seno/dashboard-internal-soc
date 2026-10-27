-- ============================================================================
-- MIGRATION 004: Suppression Taxonomy Alignment & MISP-Readiness Upgrade
-- Version: v2.1 — Standardize S1–S5, add MISP fields, fix factor_type CHECK
-- Compatible: PostgreSQL 14+ | Non-Destructive | Safe on existing data
-- ============================================================================

BEGIN;

-- 1. STANDARDIZE SUPPRESSION CLASS TAXONOMY (S1–S5)
-- Old: S2_DEDUPLICATION, S3_AGGREGATION, S4_MAINTENANCE (operational stages)
-- New: S2_FALSE_POSITIVE, S3_MAINTENANCE, S4_EXCEPTION (policy decisions)
UPDATE suppression.suppression_rules
SET suppression_class = 'S1_KNOWN_GOOD'
WHERE suppression_class IN ('S2_DEDUPLICATION', 'S3_AGGREGATION');

UPDATE suppression.suppression_rules
SET suppression_class = 'S3_MAINTENANCE'
WHERE suppression_class = 'S4_MAINTENANCE';

ALTER TABLE suppression.suppression_rules
    DROP CONSTRAINT IF EXISTS suppression_rules_suppression_class_check;

ALTER TABLE suppression.suppression_rules
    ADD CONSTRAINT suppression_rules_suppression_class_check
        CHECK (suppression_class IN (
            'S1_KNOWN_GOOD', 'S2_FALSE_POSITIVE',
            'S3_MAINTENANCE', 'S4_EXCEPTION', 'S5_CONDITIONAL'
        ));

-- 2. FIX risk_scoring_factors CHECK (add KNOWN_GOOD_OFFSET, CONFIDENCE_DEPTH)
ALTER TABLE risk_engine.risk_scoring_factors
    DROP CONSTRAINT IF EXISTS risk_scoring_factors_factor_type_check;

ALTER TABLE risk_engine.risk_scoring_factors
    ADD CONSTRAINT risk_scoring_factors_factor_type_check
        CHECK (factor_type IN (
            'DETECTION_SEVERITY', 'ASSET_CRITICALITY', 'IDENTITY_RISK',
            'THREAT_INTELLIGENCE', 'BEHAVIORAL_ANOMALY', 'CORRELATION_CHAIN',
            'KNOWN_GOOD_OFFSET', 'CONFIDENCE_DEPTH'
        ));

-- 3. ADD MISP-CRITICAL FIELDS TO CUMULATIVE_ALERTS
ALTER TABLE suppression.cumulative_alerts
    ADD COLUMN IF NOT EXISTS tlp_level VARCHAR(12) DEFAULT 'TLP:AMBER',
    ADD COLUMN IF NOT EXISTS sighting_count INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS source_feed VARCHAR(64) DEFAULT 'wazuh-pipeline',
    ADD COLUMN IF NOT EXISTS stix_indicator_id VARCHAR(128),
    ADD COLUMN IF NOT EXISTS mitre_technique_id VARCHAR(32);

ALTER TABLE suppression.aggregated_alerts
    ADD COLUMN IF NOT EXISTS tlp_level VARCHAR(12) DEFAULT 'TLP:AMBER',
    ADD COLUMN IF NOT EXISTS mitre_technique_id VARCHAR(32);

-- 4. INDEXES FOR MISP EXPORT
CREATE INDEX IF NOT EXISTS idx_cumulative_misp_export
    ON suppression.cumulative_alerts (source_feed, tlp_level, last_seen_at DESC)
    WHERE sighting_count > 0;

CREATE INDEX IF NOT EXISTS idx_cumulative_mitre_technique
    ON suppression.cumulative_alerts (mitre_technique_id)
    WHERE mitre_technique_id IS NOT NULL;

COMMIT;
