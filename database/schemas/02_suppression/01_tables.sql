-- ==============================================================================
-- SCHEMA: SUPPRESSION (TABLES & GOVERNANCE)
-- ==============================================================================

-- 1. AGGREGATED ALERTS (15-Minute Sliding-Window Deduplicated Burst Objects)
CREATE TABLE IF NOT EXISTS suppression.aggregated_alerts (
    aggregation_id VARCHAR(64) PRIMARY KEY,
    rule_id INT NOT NULL,
    deduplication_key VARCHAR(64) NOT NULL,
    tenant_id VARCHAR(64) DEFAULT 'DEFAULT',
    agent_id VARCHAR(32),
    source_ip VARCHAR(45),
    destination_ip VARCHAR(45),
    username VARCHAR(128),
    category VARCHAR(64) DEFAULT 'UNCATEGORIZED',
    actor VARCHAR(128),
    target VARCHAR(128),
    event_count INT NOT NULL DEFAULT 1,
    window_start TIMESTAMPTZ NOT NULL,
    window_end TIMESTAMPTZ NOT NULL,
    window_duration_seconds INT NOT NULL DEFAULT 900,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIONABLE',
    is_suppressed BOOLEAN DEFAULT FALSE,
    suppression_rule_id VARCHAR(64),
    suppression_reason TEXT,
    max_inline_risk_score INT DEFAULT 0,
    ocsf_severity_id INT DEFAULT 1,
    log_source VARCHAR(64) DEFAULT 'wazuh',
    ioa_summary TEXT,
    distinct_ioas TEXT[],
    distinct_iocs TEXT[],
    rule_description TEXT,
    os_platform VARCHAR(32) DEFAULT 'linux',
    tlp_level VARCHAR(16) DEFAULT 'WHITE',
    mitre_technique_id VARCHAR(32),
    mitre_tactics TEXT[],
    classification_groups TEXT[],
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 2. CUMULATIVE ALERTS (Long-Term Low-and-Slow Attack Tracking Baseline)
CREATE TABLE IF NOT EXISTS suppression.cumulative_alerts (
    deduplication_key VARCHAR(64) PRIMARY KEY,
    total_event_count BIGINT DEFAULT 0,
    total_burst_windows INT DEFAULT 0,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    peak_risk_score INT DEFAULT 0,
    status VARCHAR(32) DEFAULT 'ACTIVE',
    rule_id INT,
    actor VARCHAR(128),
    target VARCHAR(128),
    rule_description TEXT,
    ioa_summary TEXT,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 3. AGGREGATE EVIDENCE MAPPING (Link between Aggregates and Raw Events)
CREATE TABLE IF NOT EXISTS suppression.aggregate_evidence_mapping (
    mapping_id BIGSERIAL PRIMARY KEY,
    aggregation_id VARCHAR(64) NOT NULL,
    raw_event_id VARCHAR(64) NOT NULL,
    event_timestamp TIMESTAMPTZ NOT NULL,
    linked_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 4. SUPPRESSION RULES (Deterministic Filtering Rules)
CREATE TABLE IF NOT EXISTS suppression.suppression_rules (
    rule_id VARCHAR(64) PRIMARY KEY,
    rule_name VARCHAR(128) NOT NULL,
    description TEXT,
    category VARCHAR(64),
    target_rule_ids INT[],
    target_actors TEXT[],
    target_targets TEXT[],
    target_ips INET[],
    is_active BOOLEAN DEFAULT TRUE,
    enforcement_mode VARCHAR(32) DEFAULT 'AUTO_DISMISS',
    created_by VARCHAR(128) DEFAULT 'SYSTEM',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 5. SUPPRESSION GROUPS (Hierarchical Policy Packaging)
CREATE TABLE IF NOT EXISTS suppression.suppression_groups (
    group_id VARCHAR(64) PRIMARY KEY,
    group_name VARCHAR(128) NOT NULL,
    description TEXT,
    category VARCHAR(64),
    is_enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 6. SHARED VALUE LISTS (Reusable Whitelists/Blacklists)
CREATE TABLE IF NOT EXISTS suppression.shared_value_lists (
    list_id VARCHAR(64) PRIMARY KEY,
    list_name VARCHAR(128) NOT NULL,
    list_type VARCHAR(32) NOT NULL, -- IP, USER, DOMAIN, HASH
    items TEXT[] NOT NULL DEFAULT '{}',
    description TEXT,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 7. MAINTENANCE WINDOWS (Temporary Scheduled Suppression)
CREATE TABLE IF NOT EXISTS suppression.maintenance_windows (
    window_id VARCHAR(64) PRIMARY KEY,
    title VARCHAR(128) NOT NULL,
    target_entities TEXT[] NOT NULL DEFAULT '{}',
    start_time TIMESTAMPTZ NOT NULL,
    end_time TIMESTAMPTZ NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_by VARCHAR(128) DEFAULT 'SYSTEM'
);

-- 8. SUPPRESSION AUDIT LOG (Immutable Compliance Log)
CREATE TABLE IF NOT EXISTS suppression.suppression_audit_log (
    audit_id BIGSERIAL PRIMARY KEY,
    aggregation_id VARCHAR(64) NOT NULL,
    suppression_rule_id VARCHAR(64),
    action_taken VARCHAR(64) NOT NULL,
    reason TEXT,
    executed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
