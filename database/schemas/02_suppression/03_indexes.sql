-- ==============================================================================
-- SCHEMA: SUPPRESSION (INDEXES & GIN TRIGRAM SEARCH)
-- ==============================================================================

-- 1. B-Tree Indexes for Operational Lookups
CREATE INDEX IF NOT EXISTS idx_agg_alerts_dedup_key ON suppression.aggregated_alerts (deduplication_key);
CREATE INDEX IF NOT EXISTS idx_agg_alerts_window_end ON suppression.aggregated_alerts (window_end DESC);
CREATE INDEX IF NOT EXISTS idx_agg_alerts_status ON suppression.aggregated_alerts (status);
CREATE INDEX IF NOT EXISTS idx_agg_alerts_rule ON suppression.aggregated_alerts (rule_id);
CREATE INDEX IF NOT EXISTS idx_agg_alerts_tenant ON suppression.aggregated_alerts (tenant_id);

CREATE INDEX IF NOT EXISTS idx_cum_alerts_last_seen ON suppression.cumulative_alerts (last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_cum_alerts_status ON suppression.cumulative_alerts (status);

CREATE INDEX IF NOT EXISTS idx_evidence_agg_id ON suppression.aggregate_evidence_mapping (aggregation_id);
CREATE INDEX IF NOT EXISTS idx_evidence_raw_id ON suppression.aggregate_evidence_mapping (raw_event_id);

-- 2. GIN Trigram Search Indexes (Migration 016 Optimization: Sub-second ILIKE queries)
CREATE INDEX IF NOT EXISTS idx_agg_alerts_actor_trgm ON suppression.aggregated_alerts USING gin (actor gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_agg_alerts_target_trgm ON suppression.aggregated_alerts USING gin (target gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_agg_alerts_rule_desc_trgm ON suppression.aggregated_alerts USING gin (rule_description gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_agg_alerts_ioa_summary_trgm ON suppression.aggregated_alerts USING gin (ioa_summary gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_cum_alerts_actor_trgm ON suppression.cumulative_alerts USING gin (actor gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_cum_alerts_target_trgm ON suppression.cumulative_alerts USING gin (target gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_cum_alerts_rule_desc_trgm ON suppression.cumulative_alerts USING gin (rule_description gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_cum_alerts_ioa_summary_trgm ON suppression.cumulative_alerts USING gin (ioa_summary gin_trgm_ops);
