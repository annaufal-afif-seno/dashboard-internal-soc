-- ==============================================================================
-- JALUR 2 APEX ENTERPRISE DUAL-TRACK ISOLATION SCHEMA
-- ==============================================================================
-- Menjamin 100% isolasi dari Jalur 1 (Zero-Touch Guarantee).
-- Seluruh tabel dibuat dengan klausa IF NOT EXISTS tanpa mengubah struktur
-- tabel atau indeks eksisting Jalur 1.

CREATE TABLE IF NOT EXISTS telemetry.alert_activity_groups (
    group_id VARCHAR(128) PRIMARY KEY,
    policy_version INT NOT NULL DEFAULT 8,
    category_code VARCHAR(64) NOT NULL,
    category_domain VARCHAR(64) NOT NULL,
    fingerprint VARCHAR(128) NOT NULL,
    fingerprint_quality VARCHAR(32) NOT NULL DEFAULT 'exact',
    status VARCHAR(32) NOT NULL DEFAULT 'open',
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    window_duration_sec INT NOT NULL DEFAULT 600,
    max_duration_sec INT NOT NULL DEFAULT 86400,
    alert_count INT NOT NULL DEFAULT 1,
    continuation_of_id VARCHAR(128),
    root_campaign_id VARCHAR(128),
    tenant_id VARCHAR(64) NOT NULL DEFAULT 'DEFAULT',
    agent_name VARCHAR(128),
    source_ip VARCHAR(64),
    target VARCHAR(128),
    fingerprint_input JSONB,
    tracked_samples JSONB,
    tracked_counts JSONB,
    is_spike BOOLEAN DEFAULT FALSE,
    peak_rate_per_min FLOAT DEFAULT 1.0,
    is_pinned BOOLEAN DEFAULT FALSE,
    is_tainted BOOLEAN DEFAULT FALSE,
    triage_status VARCHAR(32) DEFAULT 'OPEN',
    assigned_analyst VARCHAR(128),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alert_activity_groups_fp ON telemetry.alert_activity_groups(tenant_id, fingerprint, status);
CREATE INDEX IF NOT EXISTS idx_alert_activity_groups_last_seen ON telemetry.alert_activity_groups(last_seen DESC);

CREATE TABLE IF NOT EXISTS telemetry.activity_group_alerts (
    group_id VARCHAR(128) NOT NULL,
    alert_id VARCHAR(128) NOT NULL,
    event_time TIMESTAMPTZ NOT NULL,
    is_late BOOLEAN DEFAULT FALSE,
    added_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (group_id, alert_id)
);

CREATE INDEX IF NOT EXISTS idx_activity_group_alerts_time ON telemetry.activity_group_alerts(event_time DESC);

CREATE TABLE IF NOT EXISTS telemetry.activity_group_events (
    event_seq BIGSERIAL PRIMARY KEY,
    group_id VARCHAR(128) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    reason VARCHAR(128),
    details JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_activity_group_events_gid ON telemetry.activity_group_events(group_id);

CREATE TABLE IF NOT EXISTS telemetry.apex_activity_groups (
    group_id VARCHAR(128) PRIMARY KEY,
    fingerprint_hash VARCHAR(128) NOT NULL,
    tenant_id VARCHAR(64) NOT NULL DEFAULT 'DEFAULT',
    category_code VARCHAR(64) NOT NULL,
    category_domain VARCHAR(64) NOT NULL,
    quality VARCHAR(32) NOT NULL DEFAULT 'exact',
    event_count INT NOT NULL DEFAULT 1,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    window_duration_seconds INT NOT NULL DEFAULT 600,
    agent_name VARCHAR(128),
    source_ip VARCHAR(64),
    target VARCHAR(128),
    fingerprint_body JSONB,
    tracked_samples JSONB,
    tracked_counts JSONB,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_apex_activity_groups_hash ON telemetry.apex_activity_groups(tenant_id, fingerprint_hash);
