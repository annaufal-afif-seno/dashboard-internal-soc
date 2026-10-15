-- ==============================================================================
-- SCHEMA: CORRELATION (MULTI-STAGE ATTACK CORRELATION)
-- ==============================================================================

-- 1. CORRELATED INCIDENTS (Grouped Stages forming Multi-Step Attack Campaign)
CREATE TABLE IF NOT EXISTS correlation.correlated_incidents (
    incident_id VARCHAR(64) PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    correlation_rule_id VARCHAR(64),
    target_host VARCHAR(128),
    attacker_source_ip VARCHAR(45),
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    total_stages INT NOT NULL DEFAULT 1,
    severity VARCHAR(32) DEFAULT 'MEDIUM',
    status VARCHAR(32) DEFAULT 'ACTIVE',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 2. INCIDENT STAGES (Individual Tactics/Steps within an Incident)
CREATE TABLE IF NOT EXISTS correlation.incident_stages (
    stage_id BIGSERIAL PRIMARY KEY,
    incident_id VARCHAR(64) NOT NULL REFERENCES correlation.correlated_incidents(incident_id) ON DELETE CASCADE,
    aggregation_id VARCHAR(64) NOT NULL,
    stage_order INT NOT NULL DEFAULT 1,
    mitre_tactic VARCHAR(64),
    mitre_technique VARCHAR(64),
    observed_at TIMESTAMPTZ NOT NULL
);

-- 3. CORRELATION RULES (State-Machine Definition for Multi-Step Detection)
CREATE TABLE IF NOT EXISTS correlation.correlation_rules (
    rule_id VARCHAR(64) PRIMARY KEY,
    rule_name VARCHAR(128) NOT NULL,
    description TEXT,
    stage_sequence TEXT[] NOT NULL,
    time_window_seconds INT NOT NULL DEFAULT 1800,
    minimum_stages INT NOT NULL DEFAULT 2,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
