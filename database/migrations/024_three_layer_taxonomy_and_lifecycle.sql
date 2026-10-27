-- Migration 024: Three-Layer Taxonomy and Stateful Lifecycle Attributes
-- Aligns with 3-Layer Architecture:
-- Layer 1: domain (ATTACK, VULNERABILITY, SYSTEM)
-- Layer 2: target_category (Web_Network_Attack, Identity_Access, Endpoint_Threat, Software_CVE, Security_Posture, Host_Telemetry, User_Management, Service_Network)
-- Layer 3: action_ttp (Granular TTP / Event Action)
-- Lifecycle: lifecycle_role (STATELESS, OPEN_STATE, CLOSE_STATE)
-- Disposition: SAFE, REVIEW, ACTIONABLE, PENDING_PAIR

ALTER TABLE telemetry.normalized_events
    ADD COLUMN IF NOT EXISTS domain VARCHAR(32) DEFAULT 'SYSTEM',
    ADD COLUMN IF NOT EXISTS target_category VARCHAR(64) DEFAULT 'Host_Telemetry',
    ADD COLUMN IF NOT EXISTS action_ttp VARCHAR(128) DEFAULT 'General',
    ADD COLUMN IF NOT EXISTS lifecycle_role VARCHAR(32) DEFAULT 'STATELESS';

-- Also add to aggregated_alerts
ALTER TABLE suppression.aggregated_alerts
    ADD COLUMN IF NOT EXISTS domain VARCHAR(32) DEFAULT 'SYSTEM',
    ADD COLUMN IF NOT EXISTS target_category VARCHAR(64) DEFAULT 'Host_Telemetry',
    ADD COLUMN IF NOT EXISTS action_ttp VARCHAR(128) DEFAULT 'General',
    ADD COLUMN IF NOT EXISTS lifecycle_role VARCHAR(32) DEFAULT 'STATELESS';

-- Performance Index for 3-Layer filtering
CREATE INDEX IF NOT EXISTS idx_norm_events_domain_target_disp
    ON telemetry.normalized_events (domain, target_category, disposition);

CREATE INDEX IF NOT EXISTS idx_norm_events_lifecycle_role
    ON telemetry.normalized_events (lifecycle_role);
