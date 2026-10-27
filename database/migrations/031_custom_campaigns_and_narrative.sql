-- Migration 031: Custom threat campaigns and narrative summary
ALTER TABLE correlation.threat_campaign_clusters 
ADD COLUMN IF NOT EXISTS narrative_summary TEXT;

CREATE TABLE IF NOT EXISTS correlation.custom_threat_campaigns (
    id VARCHAR(64) PRIMARY KEY,
    folder_name VARCHAR(128) NOT NULL,
    file_name VARCHAR(255) NOT NULL,
    victim_target VARCHAR(128) NOT NULL,
    time_range VARCHAR(64),
    custom_start TIMESTAMPTZ,
    custom_end TIMESTAMPTZ,
    tenant_id VARCHAR(64) DEFAULT 'DEFAULT',
    total_alerts INT DEFAULT 0,
    description TEXT,
    created_by VARCHAR(128) DEFAULT 'analyst',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_custom_campaigns_folder 
ON correlation.custom_threat_campaigns (folder_name, created_at DESC);
