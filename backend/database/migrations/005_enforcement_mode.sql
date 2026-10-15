-- ============================================================================
-- MIGRATION 005: Enforcement Mode & Wazuh Two-Tier Lifecycle Support
-- Adds enforcement_mode column and expands status check constraint
-- ============================================================================

BEGIN;

-- 1. Add enforcement_mode column to suppression_rules if not exists
ALTER TABLE suppression.suppression_rules
    ADD COLUMN IF NOT EXISTS enforcement_mode VARCHAR(32) DEFAULT 'PIPELINE_MUTE';

-- 2. Alter column status to VARCHAR(32) and update CHECK constraint
ALTER TABLE suppression.suppression_rules
    ALTER COLUMN status TYPE VARCHAR(32);

ALTER TABLE suppression.suppression_rules
    DROP CONSTRAINT IF EXISTS suppression_rules_status_check;

ALTER TABLE suppression.suppression_rules
    ADD CONSTRAINT suppression_rules_status_check
        CHECK (status IN (
            'ACTIVE', 'EXPIRED', 'REVOKED', 'PENDING_REVIEW',
            'PENDING_WAZUH_DEPLOY', 'TUNED_IN_WAZUH_XML'
        ));

COMMIT;
