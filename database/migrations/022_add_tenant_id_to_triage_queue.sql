-- Migration 022: Add tenant_id to soc_ops.soc_triage_queue for Multi-Tenant Support
ALTER TABLE soc_ops.soc_triage_queue ADD COLUMN IF NOT EXISTS tenant_id character varying(64);
UPDATE soc_ops.soc_triage_queue q
SET tenant_id = COALESCE(i.tenant_id, 'DEFAULT')
FROM correlation.correlated_incidents i
WHERE q.incident_id = i.incident_id;
CREATE INDEX IF NOT EXISTS idx_soc_triage_queue_tenant_id ON soc_ops.soc_triage_queue(tenant_id);
