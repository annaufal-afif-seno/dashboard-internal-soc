-- ==============================================================================
-- SCHEMA: CORRELATION (INDEXES)
-- ==============================================================================

CREATE INDEX IF NOT EXISTS idx_corr_incidents_first_seen ON correlation.correlated_incidents (first_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_corr_incidents_last_seen ON correlation.correlated_incidents (last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_corr_incidents_status ON correlation.correlated_incidents (status);
CREATE INDEX IF NOT EXISTS idx_corr_incidents_target ON correlation.correlated_incidents (target_host);

CREATE INDEX IF NOT EXISTS idx_incident_stages_inc_id ON correlation.incident_stages (incident_id);
CREATE INDEX IF NOT EXISTS idx_incident_stages_agg_id ON correlation.incident_stages (aggregation_id);
