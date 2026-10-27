-- ==============================================================================
-- SCHEMA: TELEMETRY (TABLES & PARTITIONS)
-- ==============================================================================

-- 1. UNIFIED LEAN EVENTS (Modern Gold Standard: 1 Event = 1 Row, Zero Dual-Write)
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
    raw_payload JSONB NOT NULL,
    ingested_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_telemetry_events PRIMARY KEY (event_id, event_timestamp)
) PARTITION BY RANGE (event_timestamp);

-- Monthly Partitions for telemetry.events
CREATE TABLE IF NOT EXISTS telemetry.events_2026_07 PARTITION OF telemetry.events FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');
CREATE TABLE IF NOT EXISTS telemetry.events_2026_08 PARTITION OF telemetry.events FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');
CREATE TABLE IF NOT EXISTS telemetry.events_2026_09 PARTITION OF telemetry.events FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');
CREATE TABLE IF NOT EXISTS telemetry.events_2026_10 PARTITION OF telemetry.events FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');
CREATE TABLE IF NOT EXISTS telemetry.events_2026_11 PARTITION OF telemetry.events FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');
CREATE TABLE IF NOT EXISTS telemetry.events_2026_12 PARTITION OF telemetry.events FOR VALUES FROM ('2026-12-01') TO ('2027-01-01');
CREATE TABLE IF NOT EXISTS telemetry.events_2027_01 PARTITION OF telemetry.events FOR VALUES FROM ('2027-01-01') TO ('2027-02-01');
CREATE TABLE IF NOT EXISTS telemetry.events_default PARTITION OF telemetry.events DEFAULT;


-- 2. RAW EVENTS (Legacy Dual-Table Raw Storage)
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

-- Monthly Partitions for telemetry.raw_events
CREATE TABLE IF NOT EXISTS telemetry.raw_events_2026_07 PARTITION OF telemetry.raw_events FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');
CREATE TABLE IF NOT EXISTS telemetry.raw_events_2026_08 PARTITION OF telemetry.raw_events FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');
CREATE TABLE IF NOT EXISTS telemetry.raw_events_2026_09 PARTITION OF telemetry.raw_events FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');
CREATE TABLE IF NOT EXISTS telemetry.raw_events_2026_10 PARTITION OF telemetry.raw_events FOR VALUES FROM ('2026-10-01') TO ('2026-12-01');
CREATE TABLE IF NOT EXISTS telemetry.raw_events_2026_12 PARTITION OF telemetry.raw_events FOR VALUES FROM ('2026-12-01') TO ('2027-01-01');
CREATE TABLE IF NOT EXISTS telemetry.raw_events_2027_01 PARTITION OF telemetry.raw_events FOR VALUES FROM ('2027-01-01') TO ('2027-02-01');
CREATE TABLE IF NOT EXISTS telemetry.raw_events_default PARTITION OF telemetry.raw_events DEFAULT;


-- 3. NORMALIZED EVENTS (Extracted Common Event Model - CEM)
CREATE TABLE IF NOT EXISTS telemetry.normalized_events (
    normalized_event_id VARCHAR(80) NOT NULL,
    raw_event_id VARCHAR(64) NOT NULL,
    event_timestamp TIMESTAMPTZ NOT NULL,
    rule_id INT NOT NULL,
    rule_level INT NOT NULL,
    rule_description TEXT,
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
    processed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_normalized_events PRIMARY KEY (normalized_event_id, processed_at)
) PARTITION BY RANGE (processed_at);

-- Monthly Partitions for telemetry.normalized_events
CREATE TABLE IF NOT EXISTS telemetry.normalized_events_2026_07 PARTITION OF telemetry.normalized_events FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');
CREATE TABLE IF NOT EXISTS telemetry.normalized_events_2026_08 PARTITION OF telemetry.normalized_events FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');
CREATE TABLE IF NOT EXISTS telemetry.normalized_events_2026_09 PARTITION OF telemetry.normalized_events FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');
CREATE TABLE IF NOT EXISTS telemetry.normalized_events_2026_10 PARTITION OF telemetry.normalized_events FOR VALUES FROM ('2026-10-01') TO ('2026-12-01');
CREATE TABLE IF NOT EXISTS telemetry.normalized_events_2026_12 PARTITION OF telemetry.normalized_events FOR VALUES FROM ('2026-12-01') TO ('2027-01-01');
CREATE TABLE IF NOT EXISTS telemetry.normalized_events_2027_01 PARTITION OF telemetry.normalized_events FOR VALUES FROM ('2027-01-01') TO ('2027-02-01');
CREATE TABLE IF NOT EXISTS telemetry.normalized_events_default PARTITION OF telemetry.normalized_events DEFAULT;


-- 4. INGESTION CHECKPOINTS (High-Water Mark Tracking)
CREATE TABLE IF NOT EXISTS telemetry.ingest_checkpoints (
    source_name VARCHAR(128) PRIMARY KEY,
    last_processed_timestamp TIMESTAMPTZ NOT NULL,
    last_processed_event_id VARCHAR(64),
    records_processed_total BIGINT DEFAULT 0,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
