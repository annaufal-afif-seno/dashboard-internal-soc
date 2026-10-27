-- ============================================================================
-- WAZUH ALERT FATIGUE REDUCTION & GROUPING PIPELINE
-- MULTI-SCHEMA ENTERPRISE ARCHITECTURE (PostgreSQL 14+)
-- Terpisah Rapi Berdasarkan 7 Tahapan Pipeline Fungsional
-- ============================================================================

-- Aktifkan Ekstensi Global
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "btree_gin";

-- ----------------------------------------------------------------------------
-- PEMBUATAN 7 DEDICATED SCHEMAS
-- ----------------------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS telemetry;     -- Stage 1: Ingestion Log Mentah & Normalisasi
CREATE SCHEMA IF NOT EXISTS enrichment;    -- Stage 3: Asset, Identity & Threat Intel
CREATE SCHEMA IF NOT EXISTS suppression;   -- Stage 2: Noise Control, Allowlist & Agregasi
CREATE SCHEMA IF NOT EXISTS correlation;   -- Stage 4: Attack Chain & Multistage Incidents
CREATE SCHEMA IF NOT EXISTS risk_engine;   -- Stage 5: Dynamic Scoring & Priority Invariant
CREATE SCHEMA IF NOT EXISTS soc_ops;       -- Stage 6: Triage Queue, Notes & Active Response
CREATE SCHEMA IF NOT EXISTS metrics;       -- Stage 7: KPI Rollup & Suppression Escape Rate

-- ----------------------------------------------------------------------------
-- GLOBAL TRIGGER FUNCTION (UNTUK updated_at)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.trigger_set_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;


-- ----------------------------------------------------------------------------
-- 1. SCHEMA: telemetry (STAGE 1 LOG TELEMETRY)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS telemetry.raw_events (
    event_id VARCHAR(64) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    agent_id VARCHAR(32) NOT NULL,
    tenant_id VARCHAR(64) DEFAULT 'DEFAULT',
    agent_name VARCHAR(128),
    agent_ip VARCHAR(45),
    source_ip VARCHAR(45),
    destination_ip VARCHAR(45),
    source_port INT,
    destination_port INT,
    protocol VARCHAR(16),
    username VARCHAR(128),
    location VARCHAR(255),
    decoder_name VARCHAR(64),
    raw_payload TEXT NOT NULL,
    ingested_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_raw_events PRIMARY KEY (event_id, timestamp)
) PARTITION BY RANGE (timestamp);

CREATE TABLE IF NOT EXISTS telemetry.raw_events_2026_07 PARTITION OF telemetry.raw_events
    FOR VALUES FROM ('2026-07-01 00:00:00+00') TO ('2026-08-01 00:00:00+00');

CREATE TABLE IF NOT EXISTS telemetry.raw_events_2026_08 PARTITION OF telemetry.raw_events
    FOR VALUES FROM ('2026-08-01 00:00:00+00') TO ('2026-09-01 00:00:00+00');

CREATE TABLE IF NOT EXISTS telemetry.raw_events_default PARTITION OF telemetry.raw_events DEFAULT;

CREATE TABLE IF NOT EXISTS telemetry.normalized_events (
    normalized_event_id VARCHAR(64) NOT NULL,
    raw_event_id VARCHAR(64) NOT NULL,
    event_timestamp TIMESTAMPTZ NOT NULL,
    rule_id INT NOT NULL,
    rule_level INT NOT NULL CHECK (rule_level BETWEEN 0 AND 16),
    rule_description TEXT NOT NULL,
    classification_groups TEXT[] NOT NULL DEFAULT '{}',
    mitre_attack_ids VARCHAR(16)[] DEFAULT '{}',
    mitre_tactics TEXT[] DEFAULT '{}',
    mitre_techniques TEXT[] DEFAULT '{}',
    compliance_frameworks JSONB DEFAULT '{}',
    -- Enriched Context Fields
    asset_criticality_tier VARCHAR(16) DEFAULT 'STANDARD',
    is_asset_internet_exposed BOOLEAN DEFAULT FALSE,
    is_privileged_user BOOLEAN DEFAULT FALSE,
    is_service_account BOOLEAN DEFAULT FALSE,
    threat_intel_match BOOLEAN DEFAULT FALSE,
    threat_intel_confidence INT DEFAULT 0,
    processed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_normalized_events PRIMARY KEY (normalized_event_id, processed_at),
    CONSTRAINT fk_norm_to_raw FOREIGN KEY (raw_event_id, event_timestamp) 
        REFERENCES telemetry.raw_events(event_id, timestamp) ON DELETE CASCADE
) PARTITION BY RANGE (processed_at);

CREATE TABLE IF NOT EXISTS telemetry.normalized_events_2026_07 PARTITION OF telemetry.normalized_events
    FOR VALUES FROM ('2026-07-01 00:00:00+00') TO ('2026-08-01 00:00:00+00');

CREATE TABLE IF NOT EXISTS telemetry.normalized_events_2026_08 PARTITION OF telemetry.normalized_events
    FOR VALUES FROM ('2026-08-01 00:00:00+00') TO ('2026-09-01 00:00:00+00');

CREATE TABLE IF NOT EXISTS telemetry.normalized_events_default PARTITION OF telemetry.normalized_events DEFAULT;


-- ----------------------------------------------------------------------------
-- 2. SCHEMA: enrichment (STAGE 3 CONTEXT ENRICHMENT)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS enrichment.asset_inventory_context (
    asset_id VARCHAR(64) PRIMARY KEY,
    hostname VARCHAR(128) NOT NULL UNIQUE,
    ip_address VARCHAR(45),
    asset_type VARCHAR(32) NOT NULL,
    criticality_tier VARCHAR(16) NOT NULL CHECK (
        criticality_tier IN ('CROWN_JEWEL', 'CRITICAL', 'HIGH', 'STANDARD', 'LAB')
    ),
    criticality_score INT NOT NULL CHECK (criticality_score IN (0, 5, 15, 20, 25)),
    environment VARCHAR(32) DEFAULT 'PRODUCTION' CHECK (environment IN ('PRODUCTION', 'STAGING', 'DEVELOPMENT', 'LAB')),
    is_internet_exposed BOOLEAN DEFAULT FALSE,
    owner_department VARCHAR(128),
    last_synced_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

DROP TRIGGER IF EXISTS trg_asset_updated_at ON enrichment.asset_inventory_context;
CREATE TRIGGER trg_asset_updated_at
BEFORE UPDATE ON enrichment.asset_inventory_context
FOR EACH ROW EXECUTE FUNCTION public.trigger_set_timestamp();

CREATE TABLE IF NOT EXISTS enrichment.identity_context (
    identity_id VARCHAR(64) PRIMARY KEY,
    username VARCHAR(128) NOT NULL UNIQUE,
    account_type VARCHAR(32) NOT NULL CHECK (
        account_type IN ('STANDARD_USER', 'PRIVILEGED_ADMIN', 'SERVICE_ACCOUNT', 'SYSTEM', 'EXTERNAL_VENDOR')
    ),
    is_privileged BOOLEAN DEFAULT FALSE,
    department VARCHAR(128),
    expected_hosts TEXT[] DEFAULT '{}',
    risk_baseline_score INT DEFAULT 0 CHECK (risk_baseline_score BETWEEN 0 AND 100),
    last_synced_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

DROP TRIGGER IF EXISTS trg_identity_updated_at ON enrichment.identity_context;
CREATE TRIGGER trg_identity_updated_at
BEFORE UPDATE ON enrichment.identity_context
FOR EACH ROW EXECUTE FUNCTION public.trigger_set_timestamp();

CREATE TABLE IF NOT EXISTS enrichment.threat_intelligence_iocs (
    ioc_id BIGSERIAL PRIMARY KEY,
    indicator_value VARCHAR(255) NOT NULL,
    indicator_type VARCHAR(16) NOT NULL CHECK (
        indicator_type IN ('IPV4', 'IPV6', 'DOMAIN', 'MD5', 'SHA256', 'URL')
    ),
    threat_actor VARCHAR(128),
    malware_family VARCHAR(128),
    confidence_score INT NOT NULL CHECK (confidence_score BETWEEN 0 AND 100),
    source_feed VARCHAR(64) NOT NULL,
    description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    first_seen TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ,
    CONSTRAINT uq_ioc_indicator UNIQUE (indicator_value, indicator_type)
);


-- ----------------------------------------------------------------------------
-- 3. SCHEMA: suppression (STAGE 2 NOISE REDUCTION & AGGREGATION)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS suppression.maintenance_windows (
    window_id VARCHAR(64) PRIMARY KEY,
    title VARCHAR(128) NOT NULL,
    target_hostname VARCHAR(128) NOT NULL,
    target_ip VARCHAR(45),
    ticket_id VARCHAR(64) NOT NULL,
    approved_by VARCHAR(128) NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    window_end TIMESTAMPTZ NOT NULL,
    status VARCHAR(16) DEFAULT 'SCHEDULED' CHECK (status IN ('SCHEDULED', 'ACTIVE', 'COMPLETED', 'CANCELLED')),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_maint_window_time CHECK (window_end > window_start)
);

CREATE TABLE IF NOT EXISTS suppression.suppression_rules (
    suppression_id VARCHAR(32) PRIMARY KEY,
    rule_name VARCHAR(128) NOT NULL,
    suppression_class VARCHAR(20) NOT NULL CHECK (
        suppression_class IN ('S1_KNOWN_GOOD', 'S2_DEDUPLICATION', 'S3_AGGREGATION', 'S4_MAINTENANCE', 'S5_CONDITIONAL')
    ),
    target_rule_ids INT[] NOT NULL,
    author VARCHAR(128) NOT NULL,
    approver VARCHAR(128) NOT NULL,
    ticket_id VARCHAR(64) NOT NULL,
    business_reason TEXT NOT NULL,
    scope_definition JSONB NOT NULL,
    status VARCHAR(16) DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'EXPIRED', 'REVOKED', 'PENDING_REVIEW')),
    created_date DATE NOT NULL DEFAULT CURRENT_DATE,
    expires_date DATE NOT NULL,
    review_cycle VARCHAR(16) DEFAULT 'MONTHLY' CHECK (review_cycle IN ('WEEKLY', 'MONTHLY', 'QUARTERLY')),
    drift_baseline_count INT DEFAULT 0,
    current_drift_sigma NUMERIC(8,2) DEFAULT 0.00,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_suppression_dates CHECK (expires_date >= created_date),
    CONSTRAINT chk_separation_of_duties CHECK (author <> approver)
);

DROP TRIGGER IF EXISTS trg_suppression_updated_at ON suppression.suppression_rules;
CREATE TRIGGER trg_suppression_updated_at
BEFORE UPDATE ON suppression.suppression_rules
FOR EACH ROW EXECUTE FUNCTION public.trigger_set_timestamp();

CREATE TABLE IF NOT EXISTS suppression.suppression_audit_log (
    log_id BIGSERIAL PRIMARY KEY,
    suppression_id VARCHAR(64) NOT NULL,
    action VARCHAR(32) NOT NULL CHECK (action IN ('CREATED', 'APPROVED', 'REJECTED', 'REVOKED', 'MODIFIED', 'REVIEWED', 'EXTENDED', 'EXPIRED')),
    performed_by VARCHAR(128) NOT NULL,
    notes TEXT,
    recorded_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS suppression.aggregated_alerts (
    aggregation_id VARCHAR(64) PRIMARY KEY,
    rule_id INT NOT NULL,
    deduplication_key VARCHAR(128) NOT NULL,
    tenant_id VARCHAR(64) DEFAULT 'DEFAULT',
    agent_id VARCHAR(32) NOT NULL,
    source_ip VARCHAR(45),
    destination_ip VARCHAR(45),
    username VARCHAR(128),
    event_count INT NOT NULL DEFAULT 1 CHECK (event_count >= 1),
    window_start TIMESTAMPTZ NOT NULL,
    window_end TIMESTAMPTZ NOT NULL,
    status VARCHAR(32) DEFAULT 'CLOSED' CHECK (status = 'CLOSED'),
    category VARCHAR(32) DEFAULT 'HOST',
    rule_description TEXT,
    actor VARCHAR(128),
    target VARCHAR(128),
    window_duration_seconds INT DEFAULT 900,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_window_time CHECK (window_end >= window_start),
    CONSTRAINT uq_dedup_window UNIQUE (deduplication_key, window_end)
);

CREATE TABLE IF NOT EXISTS suppression.cumulative_alerts (
    cumulative_id VARCHAR(64) PRIMARY KEY,
    deduplication_key VARCHAR(128) UNIQUE NOT NULL,
    category VARCHAR(32) DEFAULT 'HOST',
    rule_id INT NOT NULL,
    rule_description TEXT,
    actor VARCHAR(128),
    target VARCHAR(128),
    agent_id VARCHAR(32) NOT NULL,
    tenant_id VARCHAR(64) DEFAULT 'DEFAULT',
    total_event_count BIGINT NOT NULL DEFAULT 1,
    total_burst_windows INT NOT NULL DEFAULT 1,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    status VARCHAR(32) DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'DORMANT')),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS suppression.aggregate_evidence_mapping (
    aggregation_id VARCHAR(64) NOT NULL REFERENCES suppression.aggregated_alerts(aggregation_id) ON DELETE CASCADE,
    raw_event_id VARCHAR(64) NOT NULL,
    event_timestamp TIMESTAMPTZ NOT NULL,
    mapped_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_aggregate_evidence PRIMARY KEY (aggregation_id, raw_event_id),
    CONSTRAINT fk_evidence_to_raw FOREIGN KEY (raw_event_id, event_timestamp)
        REFERENCES telemetry.raw_events(event_id, timestamp) ON DELETE CASCADE
);


-- ----------------------------------------------------------------------------
-- 4. SCHEMA: correlation (STAGE 4 ATTACK CHAINS & CORRELATION)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS correlation.correlation_rules (
    correlation_rule_id VARCHAR(32) PRIMARY KEY,
    rule_code VARCHAR(64) UNIQUE NOT NULL,
    rule_name VARCHAR(128) NOT NULL,
    description TEXT NOT NULL,
    timeframe_seconds INT NOT NULL CHECK (timeframe_seconds > 0),
    target_severity VARCHAR(8) NOT NULL CHECK (target_severity IN ('P0', 'P1', 'P2', 'P3')),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS correlation.correlated_incidents (
    incident_id VARCHAR(64) PRIMARY KEY,
    correlation_rule_id VARCHAR(32) NOT NULL REFERENCES correlation.correlation_rules(correlation_rule_id),
    tenant_id VARCHAR(64) DEFAULT 'DEFAULT',
    title VARCHAR(255) NOT NULL,
    narrative TEXT NOT NULL,
    initial_access_vector VARCHAR(128),
    attacker_source_ip VARCHAR(45),
    compromised_account VARCHAR(128),
    target_host VARCHAR(128),
    incident_status VARCHAR(32) DEFAULT 'DETECTED' CHECK (
        incident_status IN ('DETECTED', 'IN_TRIAGE', 'ESCALATED', 'CONTAINED', 'RESOLVED', 'CLOSED_FP')
    ),
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    related_incident_ids TEXT[] DEFAULT '{}',
    detected_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS correlation.incident_stages (
    stage_id BIGSERIAL PRIMARY KEY,
    incident_id VARCHAR(64) NOT NULL REFERENCES correlation.correlated_incidents(incident_id) ON DELETE CASCADE,
    sequence_order INT NOT NULL CHECK (sequence_order >= 1),
    stage_name VARCHAR(64) NOT NULL,
    reference_id VARCHAR(64) NOT NULL,
    evidence_type VARCHAR(32) NOT NULL CHECK (evidence_type IN ('AGGREGATED_ALERT', 'NORMALIZED_EVENT', 'CUMULATIVE_PROFILE')),
    stage_description TEXT,
    recorded_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_stage_order UNIQUE (incident_id, sequence_order)
);


-- ----------------------------------------------------------------------------
-- 5. SCHEMA: risk_engine (STAGE 5 DYNAMIC RISK SCORING)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS risk_engine.risk_scoring_factors (
    factor_id BIGSERIAL PRIMARY KEY,
    incident_id VARCHAR(64) NOT NULL REFERENCES correlation.correlated_incidents(incident_id) ON DELETE CASCADE,
    factor_type VARCHAR(64) NOT NULL CHECK (
        factor_type IN ('DETECTION_SEVERITY', 'ASSET_CRITICALITY', 'IDENTITY_RISK', 'THREAT_INTELLIGENCE', 'BEHAVIORAL_ANOMALY', 'CORRELATION_CHAIN')
    ),
    weight_added INT NOT NULL CHECK (weight_added BETWEEN -100 AND 100),
    justification TEXT,
    evaluated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS risk_engine.calculated_risk_scores (
    score_id BIGSERIAL PRIMARY KEY,
    incident_id VARCHAR(64) UNIQUE NOT NULL REFERENCES correlation.correlated_incidents(incident_id) ON DELETE CASCADE,
    total_score INT NOT NULL CHECK (total_score BETWEEN 0 AND 100),
    soc_priority VARCHAR(4) NOT NULL CHECK (soc_priority IN ('P0', 'P1', 'P2', 'P3', 'P4')),
    scoring_version VARCHAR(16) DEFAULT 'v1.0',
    calculated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_score_priority_alignment CHECK (
        (total_score BETWEEN 0 AND 20   AND soc_priority = 'P4') OR
        (total_score BETWEEN 21 AND 40  AND soc_priority = 'P3') OR
        (total_score BETWEEN 41 AND 60  AND soc_priority = 'P2') OR
        (total_score BETWEEN 61 AND 80  AND soc_priority = 'P1') OR
        (total_score BETWEEN 81 AND 100 AND soc_priority = 'P0')
    )
);


-- ----------------------------------------------------------------------------
-- 6. SCHEMA: soc_ops (STAGE 6 SOC WORKFLOW & ACTIVE RESPONSE)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS soc_ops.soc_triage_queue (
    triage_id VARCHAR(64) PRIMARY KEY,
    incident_id VARCHAR(64) NOT NULL REFERENCES correlation.correlated_incidents(incident_id) ON DELETE CASCADE,
    assigned_analyst VARCHAR(128),
    priority VARCHAR(4) NOT NULL CHECK (priority IN ('P0', 'P1', 'P2', 'P3', 'P4')),
    triage_status VARCHAR(32) DEFAULT 'NEW' CHECK (
        triage_status IN ('NEW', 'ASSIGNED', 'INVESTIGATING', 'PENDING_ACTION', 'RESOLVED', 'CLOSED', 'FP REJECT', 'FP_REJECT')
    ),
    resolution_outcome VARCHAR(32) CHECK (
        resolution_outcome IN ('TRUE_POSITIVE_ACTIONABLE', 'TRUE_POSITIVE_NO_ACTION', 'FALSE_POSITIVE_TUNING_REQ', 'OPERATIONAL_NOISE', 'BENIGN_AUTHORIZED')
    ),
    false_positive_reason TEXT,
    mean_time_to_triage_seconds INT,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMPTZ,
    cooldown_until TIMESTAMPTZ
);

DROP TRIGGER IF EXISTS trg_soc_triage_updated_at ON soc_ops.soc_triage_queue;
CREATE TRIGGER trg_soc_triage_updated_at
BEFORE UPDATE ON soc_ops.soc_triage_queue
FOR EACH ROW EXECUTE FUNCTION public.trigger_set_timestamp();

CREATE OR REPLACE FUNCTION soc_ops.trigger_triage_resolved()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.triage_status = 'RESOLVED' AND (OLD.triage_status IS DISTINCT FROM 'RESOLVED') THEN
        IF NEW.resolved_at IS NULL THEN
            NEW.resolved_at := CURRENT_TIMESTAMP;
        END IF;
        NEW.mean_time_to_triage_seconds := ROUND(EXTRACT(EPOCH FROM (NEW.resolved_at - NEW.created_at)))::INT;
    END IF;

    -- Automatically set 24h cooldown for P2 & P3 when status changes to CLOSED
    IF NEW.triage_status = 'CLOSED' AND (OLD.triage_status IS DISTINCT FROM 'CLOSED') THEN
        IF NEW.resolved_at IS NULL THEN
            NEW.resolved_at := CURRENT_TIMESTAMP;
        END IF;
        IF NEW.priority IN ('P2', 'P3') AND NEW.cooldown_until IS NULL THEN
            NEW.cooldown_until := CURRENT_TIMESTAMP + INTERVAL '24 hours';
        END IF;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_soc_triage_resolved ON soc_ops.soc_triage_queue;
CREATE TRIGGER trg_soc_triage_resolved
BEFORE UPDATE ON soc_ops.soc_triage_queue
FOR EACH ROW EXECUTE FUNCTION soc_ops.trigger_triage_resolved();

CREATE INDEX IF NOT EXISTS idx_soc_queue_cooldown ON soc_ops.soc_triage_queue (priority, triage_status, cooldown_until);

-- Earliest Deadline First (EDF) Dynamic SLA Triage View based on incident first_seen_at
CREATE OR REPLACE VIEW soc_ops.v_actionable_triage_queue AS
SELECT 
    t.triage_id,
    t.priority,
    s.total_score AS skor_risiko,
    i.title AS judul_insiden,
    i.target_host,
    i.attacker_source_ip,
    t.triage_status,
    t.assigned_analyst,
    COALESCE(i.first_seen_at, t.created_at) AS waktu_muncul,
    CASE 
        WHEN t.priority = 'P0' THEN COALESCE(i.first_seen_at, t.created_at) + INTERVAL '15 minutes'
        WHEN t.priority = 'P1' THEN COALESCE(i.first_seen_at, t.created_at) + INTERVAL '30 minutes'
        WHEN t.priority = 'P2' THEN COALESCE(i.first_seen_at, t.created_at) + INTERVAL '4 hours'
        WHEN t.priority = 'P3' THEN COALESCE(i.first_seen_at, t.created_at) + INTERVAL '24 hours'
        WHEN t.priority = 'P4' THEN COALESCE(i.first_seen_at, t.created_at) + INTERVAL '7 days'
        ELSE COALESCE(i.first_seen_at, t.created_at) + INTERVAL '7 days'
    END AS batas_deadline_sla,
    CASE 
        WHEN t.priority = 'P0' THEN 'DARURAT TERTINGGI (< 15m)'
        WHEN t.priority = 'P1' THEN 'MENDESAK (< 30m)'
        WHEN t.priority = 'P2' THEN 'REVIEW SHIFT (< 4 Jam)'
        WHEN t.priority = 'P3' THEN 'REVIEW HARIAN (< 24 Jam)'
        WHEN t.priority = 'P4' THEN 'REVIEW MINGGUAN (< 7 Hari)'
        ELSE 'REVIEW MINGGUAN (< 7 Hari)'
    END AS target_sla,
    CASE 
        WHEN (CASE 
                WHEN t.priority = 'P0' THEN COALESCE(i.first_seen_at, t.created_at) + INTERVAL '15 minutes'
                WHEN t.priority = 'P1' THEN COALESCE(i.first_seen_at, t.created_at) + INTERVAL '30 minutes'
                WHEN t.priority = 'P2' THEN COALESCE(i.first_seen_at, t.created_at) + INTERVAL '4 hours'
                WHEN t.priority = 'P3' THEN COALESCE(i.first_seen_at, t.created_at) + INTERVAL '24 hours'
                WHEN t.priority = 'P4' THEN COALESCE(i.first_seen_at, t.created_at) + INTERVAL '7 days'
                ELSE COALESCE(i.first_seen_at, t.created_at) + INTERVAL '7 days'
              END) < CURRENT_TIMESTAMP THEN 'SLA BREACH (LEWAT BATAS)'
        ELSE 'AKTIF DALAM SLA'
    END AS status_kepatuhan_sla
FROM soc_ops.soc_triage_queue t
JOIN correlation.correlated_incidents i ON t.incident_id = i.incident_id
JOIN risk_engine.calculated_risk_scores s ON t.incident_id = s.incident_id
WHERE t.triage_status IN ('NEW', 'ASSIGNED', 'INVESTIGATING')
ORDER BY 
    CASE 
        WHEN t.priority = 'P0' THEN COALESCE(i.first_seen_at, t.created_at) + INTERVAL '15 minutes'
        WHEN t.priority = 'P1' THEN COALESCE(i.first_seen_at, t.created_at) + INTERVAL '30 minutes'
        WHEN t.priority = 'P2' THEN COALESCE(i.first_seen_at, t.created_at) + INTERVAL '4 hours'
        WHEN t.priority = 'P3' THEN COALESCE(i.first_seen_at, t.created_at) + INTERVAL '24 hours'
        ELSE COALESCE(i.first_seen_at, t.created_at) + INTERVAL '7 days'
    END ASC,
    CASE t.priority 
        WHEN 'P0' THEN 1 
        WHEN 'P1' THEN 2 
        WHEN 'P2' THEN 3 
        WHEN 'P3' THEN 4 
        ELSE 5 
    END ASC,
    s.total_score DESC;

CREATE TABLE IF NOT EXISTS soc_ops.incident_investigation_notes (
    note_id BIGSERIAL PRIMARY KEY,
    incident_id VARCHAR(64) NOT NULL REFERENCES correlation.correlated_incidents(incident_id) ON DELETE CASCADE,
    analyst_name VARCHAR(128) NOT NULL,
    note_text TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS soc_ops.incident_response_actions (
    action_id BIGSERIAL PRIMARY KEY,
    incident_id VARCHAR(64) NOT NULL REFERENCES correlation.correlated_incidents(incident_id) ON DELETE CASCADE,
    action_type VARCHAR(32) NOT NULL CHECK (
        action_type IN ('HOST_ISOLATION', 'IP_BLOCK_FIREWALL', 'USER_ACCOUNT_DISABLE', 'PROCESS_TERMINATION', 'ENABLE_AUDIT_MODE', 'CUSTOM_SCRIPT')
    ),
    target_entity VARCHAR(128) NOT NULL,
    initiated_by VARCHAR(128) NOT NULL,
    execution_status VARCHAR(16) DEFAULT 'PENDING' CHECK (
        execution_status IN ('PENDING', 'SUCCESS', 'FAILED', 'ROLLED_BACK')
    ),
    execution_output TEXT,
    executed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);


-- ----------------------------------------------------------------------------
-- 7. SCHEMA: metrics (STAGE 7 METRICS & GOVERNANCE KPIS)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS metrics.operational_metrics_daily (
    metric_date DATE PRIMARY KEY,
    raw_events_count BIGINT DEFAULT 0,
    wazuh_alerts_count BIGINT DEFAULT 0,
    suppressed_events_count BIGINT DEFAULT 0,
    aggregated_alerts_count BIGINT DEFAULT 0,
    correlated_incidents_count BIGINT DEFAULT 0,
    analyst_reviewed_count BIGINT DEFAULT 0,
    true_positives_count BIGINT DEFAULT 0,
    actionable_incidents_count BIGINT DEFAULT 0,
    suppression_escapes_count BIGINT DEFAULT 0,
    avg_mean_time_to_triage_sec FLOAT DEFAULT 0.0,
    alert_reduction_percentage NUMERIC(5,2) GENERATED ALWAYS AS (
        CASE WHEN raw_events_count > 0 
             THEN ROUND(((raw_events_count - (aggregated_alerts_count + correlated_incidents_count))::NUMERIC / raw_events_count::NUMERIC) * 100.0, 2)
             ELSE 0.00 END
    ) STORED,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);


-- ----------------------------------------------------------------------------
-- INDEXING STRATEGY (ACROSS DEDICATED SCHEMAS)
-- ----------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_asset_criticality ON enrichment.asset_inventory_context (criticality_tier, ip_address);
CREATE INDEX IF NOT EXISTS idx_identity_username ON enrichment.identity_context (username, account_type);
CREATE INDEX IF NOT EXISTS idx_threat_intel_lookup ON enrichment.threat_intelligence_iocs (indicator_value, indicator_type) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_maint_target_window ON suppression.maintenance_windows (target_hostname, window_start, window_end) WHERE status = 'ACTIVE';

CREATE INDEX IF NOT EXISTS idx_raw_events_tenant_time ON telemetry.raw_events (tenant_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_raw_events_src_ip ON telemetry.raw_events (source_ip) WHERE source_ip IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_norm_events_rule_level ON telemetry.normalized_events (rule_level, rule_id);
CREATE INDEX IF NOT EXISTS idx_norm_events_mitre ON telemetry.normalized_events USING GIN (mitre_attack_ids);
CREATE INDEX IF NOT EXISTS idx_norm_events_tactics ON telemetry.normalized_events USING GIN (mitre_tactics);
CREATE INDEX IF NOT EXISTS idx_norm_events_groups ON telemetry.normalized_events USING GIN (classification_groups);

CREATE INDEX IF NOT EXISTS idx_aggregated_alerts_dedup ON suppression.aggregated_alerts (deduplication_key, status, window_end);
CREATE INDEX IF NOT EXISTS idx_evidence_mapping_raw ON suppression.aggregate_evidence_mapping (raw_event_id, event_timestamp);
CREATE INDEX IF NOT EXISTS idx_suppression_rules_scope ON suppression.suppression_rules USING GIN (scope_definition);
CREATE INDEX IF NOT EXISTS idx_suppression_active ON suppression.suppression_rules (status, expires_date) WHERE status = 'ACTIVE';

CREATE INDEX IF NOT EXISTS idx_soc_queue_status_prio ON soc_ops.soc_triage_queue (triage_status, priority, created_at);
CREATE INDEX IF NOT EXISTS idx_soc_queue_analyst ON soc_ops.soc_triage_queue (assigned_analyst) WHERE assigned_analyst IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_investigation_notes_inc ON soc_ops.incident_investigation_notes (incident_id, created_at);
CREATE INDEX IF NOT EXISTS idx_response_actions_inc ON soc_ops.incident_response_actions (incident_id, executed_at);

-- ----------------------------------------------------------------------------
-- PARTITION MANAGEMENT STORED PROCEDURES
-- ----------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE create_monthly_partitions(target_date DATE)
AS $$
DECLARE
    start_time TIMESTAMPTZ;
    end_time TIMESTAMPTZ;
    raw_part_name TEXT;
    norm_part_name TEXT;
BEGIN
    start_time := DATE_TRUNC('month', target_date);
    end_time   := start_time + INTERVAL '1 month';
    
    raw_part_name  := 'raw_events_' || TO_CHAR(start_time, 'YYYY_MM');
    norm_part_name := 'normalized_events_' || TO_CHAR(start_time, 'YYYY_MM');
    
    EXECUTE FORMAT(
        'CREATE TABLE IF NOT EXISTS telemetry.%I PARTITION OF telemetry.raw_events FOR VALUES FROM (%L) TO (%L);', 
        raw_part_name, start_time, end_time
    );
    EXECUTE FORMAT(
        'CREATE TABLE IF NOT EXISTS telemetry.%I PARTITION OF telemetry.normalized_events FOR VALUES FROM (%L) TO (%L);', 
        norm_part_name, start_time, end_time
    );
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE PROCEDURE purge_expired_partitions(retention_days INT)
AS $$
DECLARE
    part_record RECORD;
    cutoff_date DATE;
    part_date DATE;
    tbl_name TEXT;
    parent_tbl TEXT;
BEGIN
    cutoff_date := CURRENT_DATE - (retention_days || ' days')::INTERVAL;
    
    FOR parent_tbl IN VALUES ('normalized_events'), ('raw_events')
    LOOP
        FOR part_record IN 
            SELECT c.relname AS child_table
            FROM pg_inherits i
            JOIN pg_class c ON i.inhrelid = c.oid
            JOIN pg_class p ON i.inhparent = p.oid
            JOIN pg_namespace n ON p.relnamespace = n.oid
            WHERE p.relname = parent_tbl AND n.nspname = 'telemetry'
        LOOP
            tbl_name := part_record.child_table;
            BEGIN
                part_date := TO_DATE(SUBSTRING(tbl_name FROM '_([0-9]{4}_[0-9]{2})$'), 'YYYY_MM');
                
                IF part_date < DATE_TRUNC('month', cutoff_date) THEN
                    EXECUTE FORMAT('ALTER TABLE telemetry.%I DETACH PARTITION telemetry.%I;', parent_tbl, tbl_name);
                    EXECUTE FORMAT('DROP TABLE telemetry.%I;', tbl_name);
                END IF;
            EXCEPTION WHEN OTHERS THEN
                CONTINUE;
            END;
        END LOOP;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

