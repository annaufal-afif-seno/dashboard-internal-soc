-- Migration 025: Cluster v1 Architecture (Smart Sampling, Deterministic Keys, Bypass & Metrics)
-- Adds storage for Smart Evidence Sampling (max 50), Cluster Summary Metrics,
-- Preserved Exact IPs, High-Value Bypass Context, and Wazuh Query Pointers.

ALTER TABLE suppression.aggregated_alerts
    ADD COLUMN IF NOT EXISTS smart_evidence JSONB DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS cluster_metrics JSONB DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS exact_source_ip VARCHAR(64),
    ADD COLUMN IF NOT EXISTS distinct_src_ips JSONB DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS wazuh_query_pointer JSONB DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS is_high_value BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS bypass_reason VARCHAR(64),
    ADD COLUMN IF NOT EXISTS success_indicator VARCHAR(32) DEFAULT 'none',
    ADD COLUMN IF NOT EXISTS external_auth_success BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS pkg_activity_nearby BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS parent_cluster_id VARCHAR(128),
    ADD COLUMN IF NOT EXISTS first_seen_event_time TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_seen_event_time TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS is_backfill BOOLEAN DEFAULT FALSE;

-- Performance Indexes
CREATE INDEX IF NOT EXISTS idx_agg_alerts_is_high_value
    ON suppression.aggregated_alerts (is_high_value);

CREATE INDEX IF NOT EXISTS idx_agg_alerts_parent_cluster
    ON suppression.aggregated_alerts (parent_cluster_id);

CREATE INDEX IF NOT EXISTS idx_agg_alerts_comp_key
    ON suppression.aggregated_alerts (composite_cluster_key);
