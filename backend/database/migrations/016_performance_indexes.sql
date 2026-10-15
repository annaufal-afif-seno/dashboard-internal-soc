-- ====================================================================
-- MIGRATION 016: High-Performance Database Indexes for Telemetry & Triage
-- Optimizes:
-- 1. telemetry.normalized_events (raw_event_id) -> Eliminates 10s Seq Scan on 4.5M rows
-- 2. correlation.correlated_incidents (first_seen_at) -> Eliminates Seq Scan on 116k rows
-- 3. soc_ops.soc_triage_queue partial index for active tickets
-- 4. pg_trgm GIN Trigram indexes on suppression.aggregated_alerts & cumulative_alerts
-- ====================================================================

-- 1. Install pg_trgm extension for ILIKE wildcard search acceleration
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- 2. B-Tree index on normalized_events (raw_event_id)
-- Note: Creating on partitioned parent automatically propagates to all partition tables
CREATE INDEX IF NOT EXISTS idx_norm_events_raw_event_id 
ON telemetry.normalized_events (raw_event_id);

-- Also ensure explicit indexes on each existing partition if needed
CREATE INDEX IF NOT EXISTS idx_norm_events_2026_07_raw_event_id 
ON telemetry.normalized_events_2026_07 (raw_event_id);

CREATE INDEX IF NOT EXISTS idx_norm_events_2026_08_raw_event_id 
ON telemetry.normalized_events_2026_08 (raw_event_id);

CREATE INDEX IF NOT EXISTS idx_norm_events_2026_09_raw_event_id 
ON telemetry.normalized_events_2026_09 (raw_event_id);

CREATE INDEX IF NOT EXISTS idx_norm_events_2026_10_raw_event_id 
ON telemetry.normalized_events_2026_10 (raw_event_id);

CREATE INDEX IF NOT EXISTS idx_norm_events_default_raw_event_id 
ON telemetry.normalized_events_default (raw_event_id);

-- 3. B-Tree index on correlation.correlated_incidents (first_seen_at)
CREATE INDEX IF NOT EXISTS idx_corr_incidents_first_seen_at 
ON correlation.correlated_incidents (first_seen_at DESC);

-- 4. Partial index on soc_ops.soc_triage_queue for active tickets
CREATE INDEX IF NOT EXISTS idx_soc_queue_active_lookup
ON soc_ops.soc_triage_queue (priority, created_at DESC)
WHERE UPPER(triage_status) NOT IN ('CLOSED', 'CLOSE', 'RESOLVED');

-- 5. Trigram GIN Indexes on suppression.aggregated_alerts for search acceleration
CREATE INDEX IF NOT EXISTS idx_agg_alerts_actor_trgm 
ON suppression.aggregated_alerts USING gin (actor gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_agg_alerts_target_trgm 
ON suppression.aggregated_alerts USING gin (target gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_agg_alerts_rule_desc_trgm 
ON suppression.aggregated_alerts USING gin (rule_description gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_agg_alerts_ioa_summary_trgm 
ON suppression.aggregated_alerts USING gin (ioa_summary gin_trgm_ops);

-- 6. Trigram GIN Indexes on suppression.cumulative_alerts
CREATE INDEX IF NOT EXISTS idx_cum_alerts_actor_trgm 
ON suppression.cumulative_alerts USING gin (actor gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_cum_alerts_target_trgm 
ON suppression.cumulative_alerts USING gin (target gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_cum_alerts_rule_desc_trgm 
ON suppression.cumulative_alerts USING gin (rule_description gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_cum_alerts_ioa_summary_trgm 
ON suppression.cumulative_alerts USING gin (ioa_summary gin_trgm_ops);
