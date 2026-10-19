-- ============================================================================
-- MIGRATION 020: THREAT CAMPAIGN & MULTI-LAYER ATTACK GRAPH CLUSTERING
-- Date: 2026-10-17 | Non-Destructive • Idempotent • Production-Grade
-- ============================================================================
-- Implementation:
-- 1. correlation.threat_campaign_clusters: Holds consolidated multi-IP attack campaigns
-- 2. correlation.cluster_members: Links multi-layer forensic evidence & unmasked precursors
-- 3. correlation.cluster_causality_edges: Directed causality graph connections
-- ============================================================================

BEGIN;

-- ----------------------------------------------------------------------------
-- 1. CREATE TABLE: correlation.threat_campaign_clusters
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS correlation.threat_campaign_clusters (
    cluster_id VARCHAR(64) PRIMARY KEY,
    pivot_incident_id VARCHAR(64) NOT NULL
        REFERENCES correlation.correlated_incidents(incident_id) ON DELETE CASCADE,
    pivot_triage_id VARCHAR(64)
        REFERENCES soc_ops.soc_triage_queue(triage_id) ON DELETE SET NULL,
    tenant_id VARCHAR(64) NOT NULL DEFAULT 'DEFAULT',
    target_host VARCHAR(128) NOT NULL,
    compromised_account VARCHAR(128),
    campaign_title VARCHAR(255) NOT NULL,
    campaign_risk_score INT NOT NULL DEFAULT 50 CHECK (campaign_risk_score BETWEEN 0 AND 100),
    priority VARCHAR(10) NOT NULL DEFAULT 'P1',
    mitre_tactics_chain TEXT[] NOT NULL DEFAULT '{}',
    first_activity_at TIMESTAMPTZ NOT NULL,
    last_activity_at TIMESTAMPTZ NOT NULL,
    total_distinct_actors INT DEFAULT 1,
    total_aggregates_count INT DEFAULT 1,
    total_raw_events_count INT DEFAULT 1,
    causality_dag JSONB NOT NULL DEFAULT '{}'::jsonb,
    cluster_status VARCHAR(32) DEFAULT 'CONFIRMED_THREAT'
        CHECK (cluster_status IN ('CONFIRMED_THREAT', 'UNDER_INVESTIGATION', 'FALSE_CORRELATION', 'CLOSED_RESOLVED')),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_campaign_clusters_target
    ON correlation.threat_campaign_clusters (tenant_id, target_host, last_activity_at DESC);

CREATE INDEX IF NOT EXISTS idx_campaign_clusters_pivot
    ON correlation.threat_campaign_clusters (pivot_incident_id);


-- ----------------------------------------------------------------------------
-- 2. CREATE TABLE: correlation.cluster_members
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS correlation.cluster_members (
    member_id BIGSERIAL PRIMARY KEY,
    cluster_id VARCHAR(64) NOT NULL
        REFERENCES correlation.threat_campaign_clusters(cluster_id) ON DELETE CASCADE,
    aggregation_id VARCHAR(64)
        REFERENCES suppression.aggregated_alerts(aggregation_id) ON DELETE SET NULL,
    raw_event_id VARCHAR(64),
    layer_stage INT NOT NULL DEFAULT 1 CHECK (layer_stage IN (1, 2, 3)),
    entity_role VARCHAR(64) NOT NULL DEFAULT 'GENERAL_ACTIVITY'
        CHECK (entity_role IN (
            'PRECURSOR_RECON', 'BRUTE_FORCE_SPRAY', 'SUCCESSFUL_ENTRY',
            'PIVOT_COMPROMISE', 'LATERAL_MOVE', 'PERSISTENCE', 'C2_EXFIL',
            'GENERAL_ACTIVITY'
        )),
    actor_entity VARCHAR(128) NOT NULL,
    target_entity VARCHAR(128) NOT NULL,
    rule_id INT,
    event_timestamp TIMESTAMPTZ NOT NULL,
    temporal_offset_seconds BIGINT NOT NULL DEFAULT 0,
    confidence_weight NUMERIC(4,3) DEFAULT 1.000,
    prior_status VARCHAR(32) DEFAULT 'OPEN',
    evidence_summary TEXT
);

CREATE INDEX IF NOT EXISTS idx_cluster_members_cluster
    ON correlation.cluster_members (cluster_id, event_timestamp ASC);

CREATE INDEX IF NOT EXISTS idx_cluster_members_actor
    ON correlation.cluster_members (actor_entity);

CREATE INDEX IF NOT EXISTS idx_cluster_members_agg
    ON correlation.cluster_members (aggregation_id);


-- ----------------------------------------------------------------------------
-- 3. CREATE TABLE: correlation.cluster_causality_edges
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS correlation.cluster_causality_edges (
    edge_id BIGSERIAL PRIMARY KEY,
    cluster_id VARCHAR(64) NOT NULL
        REFERENCES correlation.threat_campaign_clusters(cluster_id) ON DELETE CASCADE,
    source_node VARCHAR(128) NOT NULL,
    target_node VARCHAR(128) NOT NULL,
    relation_type VARCHAR(64) NOT NULL,
    weight NUMERIC(4,3) DEFAULT 1.000,
    evidence_timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_cluster_edges_cluster
    ON correlation.cluster_causality_edges (cluster_id);

COMMIT;
