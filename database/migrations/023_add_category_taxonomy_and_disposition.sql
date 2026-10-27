-- Migration 023: Add 7 Primary Categories Taxonomy, Subcategory, and 3-State Disposition
-- Compatible: PostgreSQL 14+ | Non-Destructive

BEGIN;

-- 1. Update suppression.aggregated_alerts
ALTER TABLE suppression.aggregated_alerts 
    ADD COLUMN IF NOT EXISTS primary_category VARCHAR(64) DEFAULT 'Informational',
    ADD COLUMN IF NOT EXISTS subcategory VARCHAR(64) DEFAULT 'General',
    ADD COLUMN IF NOT EXISTS disposition VARCHAR(32) DEFAULT 'SAFE',
    ADD COLUMN IF NOT EXISTS confidence_score INTEGER DEFAULT 50,
    ADD COLUMN IF NOT EXISTS composite_cluster_key VARCHAR(512),
    ADD COLUMN IF NOT EXISTS who_cluster VARCHAR(256),
    ADD COLUMN IF NOT EXISTS what_cluster VARCHAR(256);

CREATE INDEX IF NOT EXISTS idx_aggregated_alerts_primary_category ON suppression.aggregated_alerts(primary_category);
CREATE INDEX IF NOT EXISTS idx_aggregated_alerts_disposition ON suppression.aggregated_alerts(disposition);
CREATE INDEX IF NOT EXISTS idx_aggregated_alerts_subcategory ON suppression.aggregated_alerts(subcategory);

-- 2. Update telemetry.normalized_events
ALTER TABLE telemetry.normalized_events 
    ADD COLUMN IF NOT EXISTS primary_category VARCHAR(64) DEFAULT 'Informational',
    ADD COLUMN IF NOT EXISTS subcategory VARCHAR(64) DEFAULT 'General',
    ADD COLUMN IF NOT EXISTS disposition VARCHAR(32) DEFAULT 'SAFE',
    ADD COLUMN IF NOT EXISTS confidence_score INTEGER DEFAULT 50,
    ADD COLUMN IF NOT EXISTS composite_cluster_key VARCHAR(512),
    ADD COLUMN IF NOT EXISTS who_cluster VARCHAR(256),
    ADD COLUMN IF NOT EXISTS what_cluster VARCHAR(256);

-- 3. Record migration in schema_migrations
INSERT INTO public.schema_migrations (version) VALUES ('023_add_category_taxonomy_and_disposition.sql')
ON CONFLICT (version) DO NOTHING;

COMMIT;
