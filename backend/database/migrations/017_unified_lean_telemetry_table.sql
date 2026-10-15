-- ==============================================================================
-- MIGRATION 017: UNIFIED LEAN TELEMETRY TABLE (INDUSTRY GOLD STANDARD)
-- ==============================================================================
-- Eliminates dual-write I/O amplification between raw_events and normalized_events.
-- Stores indexed fast-query metadata alongside 100% full raw payload in JSONB.
-- Zero foreign-key locking overhead on ingestion bulk inserts.

CREATE SCHEMA IF NOT EXISTS telemetry;

-- 1. Create Parent Partitioned Table
CREATE TABLE IF NOT EXISTS telemetry.events (
    event_id VARCHAR(64) NOT NULL,
    event_timestamp TIMESTAMPTZ NOT NULL,
    agent_id VARCHAR(32) NOT NULL DEFAULT '000',
    tenant_id VARCHAR(64) NOT NULL DEFAULT 'DEFAULT',
    agent_name VARCHAR(128),
    rule_id INT NOT NULL,
    rule_level INT NOT NULL DEFAULT 0,
    rule_description TEXT,
    source_ip INET,
    destination_ip INET,
    source_port INT,
    destination_port INT,
    protocol VARCHAR(16),
    username VARCHAR(128),
    classification_groups TEXT[],
    mitre_attack_ids TEXT[],
    mitre_tactics TEXT[],
    mitre_techniques TEXT[],
    compliance_frameworks JSONB DEFAULT '{}'::jsonb,
    asset_criticality_tier VARCHAR(16) DEFAULT 'STANDARD',
    is_asset_internet_exposed BOOLEAN DEFAULT FALSE,
    is_privileged_user BOOLEAN DEFAULT FALSE,
    is_service_account BOOLEAN DEFAULT FALSE,
    threat_intel_match BOOLEAN DEFAULT FALSE,
    threat_intel_confidence INT DEFAULT 0,
    -- 100% original forensic evidence compressed natively in PostgreSQL JSONB
    raw_payload JSONB NOT NULL,
    ingested_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_telemetry_events PRIMARY KEY (event_id, event_timestamp)
) PARTITION BY RANGE (event_timestamp);

-- 2. Create Monthly Partitions
CREATE TABLE IF NOT EXISTS telemetry.events_2026_07 PARTITION OF telemetry.events
    FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');

CREATE TABLE IF NOT EXISTS telemetry.events_2026_08 PARTITION OF telemetry.events
    FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');

CREATE TABLE IF NOT EXISTS telemetry.events_2026_09 PARTITION OF telemetry.events
    FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');

CREATE TABLE IF NOT EXISTS telemetry.events_2026_10 PARTITION OF telemetry.events
    FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');

CREATE TABLE IF NOT EXISTS telemetry.events_2026_11 PARTITION OF telemetry.events
    FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');

CREATE TABLE IF NOT EXISTS telemetry.events_2026_12 PARTITION OF telemetry.events
    FOR VALUES FROM ('2026-12-01') TO ('2027-01-01');

CREATE TABLE IF NOT EXISTS telemetry.events_2027_01 PARTITION OF telemetry.events
    FOR VALUES FROM ('2027-01-01') TO ('2027-02-01');

CREATE TABLE IF NOT EXISTS telemetry.events_default PARTITION OF telemetry.events
    DEFAULT;

-- 3. High-Performance Indexing on Unified Events
CREATE INDEX IF NOT EXISTS idx_telemetry_events_ts 
    ON telemetry.events (event_timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_telemetry_events_rule 
    ON telemetry.events (rule_id, rule_level);

CREATE INDEX IF NOT EXISTS idx_telemetry_events_agent 
    ON telemetry.events (agent_id, tenant_id);

CREATE INDEX IF NOT EXISTS idx_telemetry_events_src_ip 
    ON telemetry.events (source_ip) WHERE source_ip IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_telemetry_events_username 
    ON telemetry.events (username) WHERE username IS NOT NULL;

-- GIN Index on JSONB for sub-millisecond dynamic field queries
CREATE INDEX IF NOT EXISTS idx_telemetry_events_payload_gin 
    ON telemetry.events USING gin (raw_payload jsonb_path_ops);
