-- ============================================================================
-- MIGRATION 006: Sweet Spot 21-Category Architecture & OS Platform Dimension
-- Compatible: PostgreSQL 14+ | Non-Destructive | Safe on existing data
-- ============================================================================
BEGIN;

-- 1. AGGREGATED_ALERTS: Add os_platform column
ALTER TABLE suppression.aggregated_alerts
    ADD COLUMN IF NOT EXISTS os_platform VARCHAR(16) NOT NULL DEFAULT 'unknown';

ALTER TABLE suppression.aggregated_alerts
    DROP CONSTRAINT IF EXISTS aggregated_alerts_category_check;

UPDATE suppression.aggregated_alerts SET category='AUTH_FAILURE' WHERE category='AUTHENTICATION';
UPDATE suppression.aggregated_alerts SET category='WEB_OPERATIONAL' WHERE category='NETWORK_WEB';
UPDATE suppression.aggregated_alerts SET category='EXECUTION' WHERE category='ENDPOINT_PROCESS';
UPDATE suppression.aggregated_alerts SET category='SYSTEM_HEALTH'
    WHERE category NOT IN ('RANSOMWARE','MALWARE','COMMAND_AND_CONTROL','EXFILTRATION',
        'LATERAL_MOVEMENT','PRIVILEGE_ESCALATION','CREDENTIAL_ACCESS','DEFENSE_EVASION',
        'EXECUTION','PERSISTENCE','DISCOVERY','INITIAL_ACCESS','AUTH_FAILURE','AUTH_SUCCESS',
        'WEB_ATTACK','WEB_OPERATIONAL','FILE_INTEGRITY','VULNERABILITY','COMPLIANCE',
        'CLOUD_CONTAINER','SYSTEM_HEALTH','TELEMETRY','UNKNOWN');

ALTER TABLE suppression.aggregated_alerts
    ADD CONSTRAINT aggregated_alerts_category_check CHECK (category IN (
        'RANSOMWARE','MALWARE','COMMAND_AND_CONTROL','EXFILTRATION',
        'LATERAL_MOVEMENT','PRIVILEGE_ESCALATION','CREDENTIAL_ACCESS',
        'DEFENSE_EVASION','EXECUTION','PERSISTENCE','DISCOVERY',
        'INITIAL_ACCESS','AUTH_FAILURE','AUTH_SUCCESS',
        'WEB_ATTACK','WEB_OPERATIONAL','FILE_INTEGRITY',
        'VULNERABILITY','COMPLIANCE','CLOUD_CONTAINER','SYSTEM_HEALTH','TELEMETRY','UNKNOWN'));

ALTER TABLE suppression.aggregated_alerts
    ADD CONSTRAINT chk_agg_os_platform CHECK (os_platform IN ('linux','windows','macos','unknown'));

-- 2. CUMULATIVE_ALERTS: Add os_platform column and update category CHECK
ALTER TABLE suppression.cumulative_alerts
    ADD COLUMN IF NOT EXISTS os_platform VARCHAR(16) NOT NULL DEFAULT 'unknown';

ALTER TABLE suppression.cumulative_alerts
    DROP CONSTRAINT IF EXISTS cumulative_alerts_category_check;

UPDATE suppression.cumulative_alerts SET category='AUTH_FAILURE' WHERE category='AUTHENTICATION';
UPDATE suppression.cumulative_alerts SET category='WEB_OPERATIONAL' WHERE category='NETWORK_WEB';
UPDATE suppression.cumulative_alerts SET category='EXECUTION' WHERE category='ENDPOINT_PROCESS';
UPDATE suppression.cumulative_alerts SET category='SYSTEM_HEALTH'
    WHERE category NOT IN ('RANSOMWARE','MALWARE','COMMAND_AND_CONTROL','EXFILTRATION',
        'LATERAL_MOVEMENT','PRIVILEGE_ESCALATION','CREDENTIAL_ACCESS','DEFENSE_EVASION',
        'EXECUTION','PERSISTENCE','DISCOVERY','INITIAL_ACCESS','AUTH_FAILURE','AUTH_SUCCESS',
        'WEB_ATTACK','WEB_OPERATIONAL','FILE_INTEGRITY','VULNERABILITY','COMPLIANCE',
        'CLOUD_CONTAINER','SYSTEM_HEALTH','TELEMETRY','UNKNOWN');

ALTER TABLE suppression.cumulative_alerts
    ADD CONSTRAINT cumulative_alerts_category_check CHECK (category IN (
        'RANSOMWARE','MALWARE','COMMAND_AND_CONTROL','EXFILTRATION',
        'LATERAL_MOVEMENT','PRIVILEGE_ESCALATION','CREDENTIAL_ACCESS',
        'DEFENSE_EVASION','EXECUTION','PERSISTENCE','DISCOVERY',
        'INITIAL_ACCESS','AUTH_FAILURE','AUTH_SUCCESS',
        'WEB_ATTACK','WEB_OPERATIONAL','FILE_INTEGRITY',
        'VULNERABILITY','COMPLIANCE','CLOUD_CONTAINER','SYSTEM_HEALTH','TELEMETRY','UNKNOWN'));

ALTER TABLE suppression.cumulative_alerts
    ADD CONSTRAINT chk_cum_os_platform CHECK (os_platform IN ('linux','windows','macos','unknown'));

COMMIT;

-- VERIFICATION
DO $$
DECLARE v_ok BOOLEAN;
BEGIN
    SELECT EXISTS (SELECT FROM information_schema.columns
        WHERE table_schema='suppression' AND table_name='aggregated_alerts' AND column_name='os_platform')
    INTO v_ok;
    RAISE NOTICE 'Migration 006: os_platform in aggregated_alerts = %', v_ok;
    SELECT EXISTS (SELECT FROM information_schema.columns
        WHERE table_schema='suppression' AND table_name='cumulative_alerts' AND column_name='os_platform')
    INTO v_ok;
    RAISE NOTICE 'Migration 006: os_platform in cumulative_alerts = %', v_ok;
END $$;

CREATE INDEX IF NOT EXISTS idx_agg_alerts_os ON suppression.aggregated_alerts(os_platform);
CREATE INDEX IF NOT EXISTS idx_cum_alerts_os ON suppression.cumulative_alerts(os_platform);
CREATE INDEX IF NOT EXISTS idx_agg_alerts_category ON suppression.aggregated_alerts(category);
CREATE INDEX IF NOT EXISTS idx_cum_alerts_category ON suppression.cumulative_alerts(category);
CREATE INDEX IF NOT EXISTS idx_agg_alerts_cat_os ON suppression.aggregated_alerts(category, os_platform);
CREATE INDEX IF NOT EXISTS idx_cum_alerts_cat_os ON suppression.cumulative_alerts(category, os_platform);
CREATE INDEX IF NOT EXISTS idx_agg_alerts_window_start ON suppression.aggregated_alerts(window_start DESC);
CREATE INDEX IF NOT EXISTS idx_cum_alerts_total_events ON suppression.cumulative_alerts(total_event_count DESC);

