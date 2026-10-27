-- ============================================================================
-- MIGRATION 007: Audit Fixes, 22 Sweet Spot Category Alignment, and Metadata Persistence
-- Compatible: PostgreSQL 14+ | Non-Destructive | Zero Downtime
-- ============================================================================
BEGIN;

-- 1. DROP EXISTING OLD CONSTRAINTS FIRST (Allows updating values without constraint violation)
ALTER TABLE suppression.aggregated_alerts
    DROP CONSTRAINT IF EXISTS aggregated_alerts_category_check;

ALTER TABLE suppression.cumulative_alerts
    DROP CONSTRAINT IF EXISTS cumulative_alerts_category_check;

-- 2. MIGRATE EXISTING CATEGORY VALUES IN AGGREGATED & CUMULATIVE ALERTS
UPDATE suppression.aggregated_alerts
    SET category = 'CONFIGURATION_ASSESSMENT'
    WHERE category = 'COMPLIANCE';

UPDATE suppression.cumulative_alerts
    SET category = 'CONFIGURATION_ASSESSMENT'
    WHERE category = 'COMPLIANCE';

UPDATE suppression.aggregated_alerts
    SET category = 'SYSTEM_HEALTH'
    WHERE category = 'TELEMETRY';

UPDATE suppression.cumulative_alerts
    SET category = 'SYSTEM_HEALTH'
    WHERE category = 'TELEMETRY';

UPDATE suppression.aggregated_alerts
    SET category = 'OTHER'
    WHERE category = 'UNKNOWN';

UPDATE suppression.cumulative_alerts
    SET category = 'OTHER'
    WHERE category = 'UNKNOWN';

-- Catch-all migration for any unmapped category
UPDATE suppression.aggregated_alerts
    SET category = 'OTHER'
    WHERE category NOT IN (
        'RANSOMWARE','MALWARE','COMMAND_AND_CONTROL','EXFILTRATION',
        'LATERAL_MOVEMENT','PRIVILEGE_ESCALATION','CREDENTIAL_ACCESS',
        'DEFENSE_EVASION','EXECUTION','PERSISTENCE','DISCOVERY',
        'INITIAL_ACCESS','AUTH_FAILURE','AUTH_SUCCESS',
        'WEB_ATTACK','WEB_OPERATIONAL','FILE_INTEGRITY',
        'VULNERABILITY','CONFIGURATION_ASSESSMENT','CLOUD_CONTAINER',
        'SYSTEM_HEALTH','OTHER'
    );

UPDATE suppression.cumulative_alerts
    SET category = 'OTHER'
    WHERE category NOT IN (
        'RANSOMWARE','MALWARE','COMMAND_AND_CONTROL','EXFILTRATION',
        'LATERAL_MOVEMENT','PRIVILEGE_ESCALATION','CREDENTIAL_ACCESS',
        'DEFENSE_EVASION','EXECUTION','PERSISTENCE','DISCOVERY',
        'INITIAL_ACCESS','AUTH_FAILURE','AUTH_SUCCESS',
        'WEB_ATTACK','WEB_OPERATIONAL','FILE_INTEGRITY',
        'VULNERABILITY','CONFIGURATION_ASSESSMENT','CLOUD_CONTAINER',
        'SYSTEM_HEALTH','OTHER'
    );

-- 3. RE-ESTABLISH EXACT 22 SWEET SPOT CATEGORY CHECK CONSTRAINTS
ALTER TABLE suppression.aggregated_alerts
    ADD CONSTRAINT aggregated_alerts_category_check CHECK (category IN (
        'RANSOMWARE','MALWARE','COMMAND_AND_CONTROL','EXFILTRATION',
        'LATERAL_MOVEMENT','PRIVILEGE_ESCALATION','CREDENTIAL_ACCESS',
        'DEFENSE_EVASION','EXECUTION','PERSISTENCE','DISCOVERY',
        'INITIAL_ACCESS','AUTH_FAILURE','AUTH_SUCCESS',
        'WEB_ATTACK','WEB_OPERATIONAL','FILE_INTEGRITY',
        'VULNERABILITY','CONFIGURATION_ASSESSMENT','CLOUD_CONTAINER',
        'SYSTEM_HEALTH','OTHER'
    ));

ALTER TABLE suppression.cumulative_alerts
    ADD CONSTRAINT cumulative_alerts_category_check CHECK (category IN (
        'RANSOMWARE','MALWARE','COMMAND_AND_CONTROL','EXFILTRATION',
        'LATERAL_MOVEMENT','PRIVILEGE_ESCALATION','CREDENTIAL_ACCESS',
        'DEFENSE_EVASION','EXECUTION','PERSISTENCE','DISCOVERY',
        'INITIAL_ACCESS','AUTH_FAILURE','AUTH_SUCCESS',
        'WEB_ATTACK','WEB_OPERATIONAL','FILE_INTEGRITY',
        'VULNERABILITY','CONFIGURATION_ASSESSMENT','CLOUD_CONTAINER',
        'SYSTEM_HEALTH','OTHER'
    ));

-- 4. PERSIST METADATA IN AGGREGATED_ALERTS (JSONB COLUMNS FOR GROUPS & MITRE TACTICS)
ALTER TABLE suppression.aggregated_alerts
    ADD COLUMN IF NOT EXISTS mitre_tactics JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE suppression.aggregated_alerts
    ADD COLUMN IF NOT EXISTS classification_groups JSONB NOT NULL DEFAULT '[]'::jsonb;

-- 5. RECREATE V_ACTIONABLE_AGGREGATES VIEW WITH FULL SCHEMA COMPATIBILITY
DROP VIEW IF EXISTS suppression.v_actionable_aggregates;

CREATE VIEW suppression.v_actionable_aggregates AS
SELECT
    aa.aggregation_id,
    aa.rule_id,
    aa.deduplication_key,
    aa.tenant_id,
    aa.agent_id,
    aa.source_ip,
    aa.destination_ip,
    aa.username,
    aa.category,
    aa.actor,
    aa.target,
    aa.event_count,
    aa.window_start,
    aa.window_end,
    aa.window_duration_seconds,
    aa.max_inline_risk_score,
    aa.ocsf_severity_id,
    aa.ioa_summary,
    aa.rule_description,
    aa.os_platform,
    aa.tlp_level,
    aa.mitre_technique_id,
    aa.mitre_tactics,
    aa.classification_groups,
    aa.created_at,
    ca.total_event_count   AS cumulative_total_events,
    ca.total_burst_windows AS cumulative_burst_windows,
    ca.first_seen_at       AS entity_first_seen,
    ca.last_seen_at        AS entity_last_seen,
    ca.peak_risk_score     AS entity_peak_risk,
    ca.status              AS entity_status
FROM suppression.aggregated_alerts aa
LEFT JOIN suppression.cumulative_alerts ca
    ON aa.deduplication_key = ca.deduplication_key
WHERE
    aa.status = 'ACTIONABLE'
    AND aa.is_suppressed = FALSE;

COMMIT;
