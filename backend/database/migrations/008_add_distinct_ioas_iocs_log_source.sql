-- ============================================================================
-- MIGRATION 008: Add log_source, distinct_ioas, and distinct_iocs to aggregated_alerts
-- Compatible: PostgreSQL 14+ | Non-Destructive | Zero Downtime
-- ============================================================================
BEGIN;

ALTER TABLE suppression.aggregated_alerts
    ADD COLUMN IF NOT EXISTS log_source TEXT,
    ADD COLUMN IF NOT EXISTS distinct_ioas JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS distinct_iocs JSONB NOT NULL DEFAULT '[]'::jsonb;

-- Recreate view v_actionable_aggregates with new columns
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
    aa.log_source,
    aa.ioa_summary,
    aa.distinct_ioas,
    aa.distinct_iocs,
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
LEFT JOIN suppression.cumulative_alerts ca ON aa.deduplication_key = ca.deduplication_key
WHERE aa.status = 'ACTIONABLE';

COMMIT;
