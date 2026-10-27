-- ==============================================================================
-- SCHEMA: TELEMETRY (PERFORMANCE & SEARCH INDEXES)
-- ==============================================================================

-- 1. Indexes on telemetry.events (Unified Lean Table)
CREATE INDEX IF NOT EXISTS idx_telemetry_events_ts ON telemetry.events (event_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_telemetry_events_rule ON telemetry.events (rule_id, rule_level);
CREATE INDEX IF NOT EXISTS idx_telemetry_events_agent ON telemetry.events (agent_id, tenant_id);
CREATE INDEX IF NOT EXISTS idx_telemetry_events_src_ip ON telemetry.events (source_ip) WHERE source_ip IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_telemetry_events_username ON telemetry.events (username) WHERE username IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_telemetry_events_payload_gin ON telemetry.events USING gin (raw_payload jsonb_path_ops);

-- 2. Indexes on telemetry.raw_events
CREATE INDEX IF NOT EXISTS idx_raw_events_timestamp ON telemetry.raw_events (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_raw_events_agent ON telemetry.raw_events (agent_id);
CREATE INDEX IF NOT EXISTS idx_raw_events_src_ip ON telemetry.raw_events (source_ip);
CREATE INDEX IF NOT EXISTS idx_raw_events_dst_ip ON telemetry.raw_events (destination_ip);

-- 3. Indexes on telemetry.normalized_events (Including Migration 016 Optimization)
CREATE INDEX IF NOT EXISTS idx_norm_raw_event_id ON telemetry.normalized_events (raw_event_id);
CREATE INDEX IF NOT EXISTS idx_norm_events_event_timestamp ON telemetry.normalized_events (event_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_norm_events_rule_id ON telemetry.normalized_events (rule_id);
CREATE INDEX IF NOT EXISTS idx_norm_events_rule_level ON telemetry.normalized_events (rule_level);
CREATE INDEX IF NOT EXISTS idx_norm_events_processed_at ON telemetry.normalized_events (processed_at DESC);
