-- ==============================================================================
-- SCHEMA: SOC_OPS (TRIAGE, USERS, & GROUND TRUTH)
-- ==============================================================================

-- 1. SOC TRIAGE QUEUE (Operational Workload & Ticket Routing)
CREATE TABLE IF NOT EXISTS soc_ops.soc_triage_queue (
    triage_id VARCHAR(64) PRIMARY KEY,
    incident_id VARCHAR(64) NOT NULL,
    priority VARCHAR(8) NOT NULL DEFAULT 'P3', -- P0, P1, P2, P3, P4
    triage_status VARCHAR(32) NOT NULL DEFAULT 'OPEN',
    assigned_analyst VARCHAR(128),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    priority_established_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMPTZ,
    resolution_notes TEXT
);

-- 2. SOC USERS & ANALYSTS
CREATE TABLE IF NOT EXISTS soc_ops.soc_users (
    user_id VARCHAR(64) PRIMARY KEY,
    username VARCHAR(128) UNIQUE NOT NULL,
    full_name VARCHAR(255),
    role VARCHAR(32) DEFAULT 'SOC_ANALYST',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 3. GROUND TRUTH DATASET (Machine Learning & AI Evaluation Ground Truth)
CREATE TABLE IF NOT EXISTS soc_ops.ground_truth_dataset (
    sample_id BIGSERIAL PRIMARY KEY,
    incident_id VARCHAR(64) NOT NULL,
    ground_truth_label INT NOT NULL, -- 1: TRUE_POSITIVE, 0: FALSE_POSITIVE
    local_llm_verdict VARCHAR(32),
    cloud_llm_verdict VARCHAR(32),
    lightgbm_verdict VARCHAR(32),
    confidence_score NUMERIC(4,3),
    validated_by_analyst VARCHAR(128),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 4. INVESTIGATION NOTES
CREATE TABLE IF NOT EXISTS soc_ops.incident_investigation_notes (
    note_id BIGSERIAL PRIMARY KEY,
    incident_id VARCHAR(64) NOT NULL,
    analyst_id VARCHAR(64),
    content TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 5. INCIDENT RESPONSE ACTIONS (Containment & Remediation)
CREATE TABLE IF NOT EXISTS soc_ops.incident_response_actions (
    action_id BIGSERIAL PRIMARY KEY,
    incident_id VARCHAR(64) NOT NULL,
    action_type VARCHAR(64) NOT NULL, -- BLOCK_IP, ISOLATE_HOST, DISABLE_USER
    target_entity VARCHAR(128) NOT NULL,
    status VARCHAR(32) DEFAULT 'PENDING',
    executed_by VARCHAR(128),
    executed_at TIMESTAMPTZ
);
