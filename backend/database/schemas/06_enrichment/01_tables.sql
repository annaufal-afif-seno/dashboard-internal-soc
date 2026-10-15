-- ==============================================================================
-- SCHEMA: ENRICHMENT (ASSETS, IDENTITY, & THREAT INTEL)
-- ==============================================================================

-- 1. ASSET INVENTORY CONTEXT (Criticality & Network Exposure)
CREATE TABLE IF NOT EXISTS enrichment.asset_inventory_context (
    asset_id VARCHAR(64) PRIMARY KEY,
    hostname VARCHAR(128) NOT NULL,
    ip_addresses INET[] NOT NULL DEFAULT '{}',
    criticality_tier VARCHAR(16) NOT NULL DEFAULT 'STANDARD', -- CRITICAL, HIGH, STANDARD, LOW
    is_internet_exposed BOOLEAN DEFAULT FALSE,
    business_unit VARCHAR(128),
    owner_email VARCHAR(128),
    os_info VARCHAR(128),
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 2. IDENTITY CONTEXT (User Privileges & Service Accounts)
CREATE TABLE IF NOT EXISTS enrichment.identity_context (
    identity_id VARCHAR(64) PRIMARY KEY,
    username VARCHAR(128) UNIQUE NOT NULL,
    full_name VARCHAR(255),
    department VARCHAR(128),
    is_privileged BOOLEAN DEFAULT FALSE,
    is_service_account BOOLEAN DEFAULT FALSE,
    mfa_enabled BOOLEAN DEFAULT TRUE,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 3. THREAT INTELLIGENCE IOCs (MISP / AlienVault OTX Threat Intelligence)
CREATE TABLE IF NOT EXISTS enrichment.threat_intelligence_iocs (
    ioc_id BIGSERIAL PRIMARY KEY,
    ioc_value VARCHAR(255) NOT NULL,
    ioc_type VARCHAR(32) NOT NULL, -- IP, DOMAIN, HASH, URL
    threat_actor VARCHAR(128),
    confidence_score INT DEFAULT 75,
    severity VARCHAR(32) DEFAULT 'HIGH',
    source_feed VARCHAR(64) DEFAULT 'MISP',
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_threat_ioc_lookup ON enrichment.threat_intelligence_iocs (ioc_value, ioc_type);
CREATE INDEX IF NOT EXISTS idx_asset_hostname ON enrichment.asset_inventory_context (hostname);
