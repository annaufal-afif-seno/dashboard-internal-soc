-- ============================================================================
-- MIGRATION 018: ALIGN ASOC NEW WORKFLOW (100% SPECIFICATION COMPLIANCE)
-- Date: 2026-10-15 | Author: @ansen / ASOC Core Engineering
-- Compatible: PostgreSQL 14+ | Non-Destructive | Zero Downtime
-- ============================================================================
-- Implementation:
-- 1. Multi-Aggregate Ticket Membership (1 Induk + Correlated Aggregates in 24h)
-- 2. Direct Ticket Entity Tracking (Actor + Target + Tenant) & Dynamic SLA Deadlines
-- 3. Window Buffer Grace Period for In-Flight Aggregate Windows
-- 4. External Case Linkage (DFIR-IRIS & MISP)
-- 5. Human SOC Governance (Policy Bundles & Wazuh CDB/XML Suppression Proposals)
-- 6. Simplification of Aggregate Status (OPEN / CLOSED)
-- ============================================================================

BEGIN;

-- ----------------------------------------------------------------------------
-- 1. AGGREGATED ALERTS STATUS & INDEXING OPTIMIZATION
-- ----------------------------------------------------------------------------
-- Ensure status is simplified to OPEN and CLOSED while remaining safe on legacy data
ALTER TABLE suppression.aggregated_alerts
    DROP CONSTRAINT IF EXISTS aggregated_alerts_status_check;

ALTER TABLE suppression.aggregated_alerts
    ADD CONSTRAINT aggregated_alerts_status_check
        CHECK (status IN ('OPEN', 'CLOSED', 'ACTIONABLE', 'SUPPRESSED', 'PENDING_REVIEW'));

-- Index for sub-millisecond 24h entity correlation lookup: Actor + Korban + Tenant
CREATE INDEX IF NOT EXISTS idx_agg_alerts_corr_24h
    ON suppression.aggregated_alerts (tenant_id, actor, target, window_end DESC);


-- ----------------------------------------------------------------------------
-- 2. ENHANCE SOC TRIAGE QUEUE (TICKET TABLE) WITH ASOC NEW WORKFLOW COLUMNS
-- ----------------------------------------------------------------------------
ALTER TABLE soc_ops.soc_triage_queue
    ADD COLUMN IF NOT EXISTS actor VARCHAR(128),
    ADD COLUMN IF NOT EXISTS target VARCHAR(128),
    ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(64) DEFAULT 'DEFAULT',
    ADD COLUMN IF NOT EXISTS os_platform VARCHAR(64) DEFAULT 'unknown',
    ADD COLUMN IF NOT EXISTS induk_aggregation_id VARCHAR(64)
        REFERENCES suppression.aggregated_alerts(aggregation_id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS sla_deadline TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS window_buffer_until TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS iris_case_id INT,
    ADD COLUMN IF NOT EXISTS iris_case_url TEXT,
    ADD COLUMN IF NOT EXISTS misp_event_id INT,
    ADD COLUMN IF NOT EXISTS misp_sync_status VARCHAR(32) DEFAULT 'NOT_SYNCED';

-- Backfill existing tickets with entity info from correlated_incidents if available
UPDATE soc_ops.soc_triage_queue q
SET 
    actor = COALESCE(q.actor, i.attacker_source_ip, 'unknown'),
    target = COALESCE(q.target, i.target_host, 'unknown'),
    tenant_id = COALESCE(q.tenant_id, i.tenant_id, 'DEFAULT')
FROM correlation.correlated_incidents i
WHERE q.incident_id = i.incident_id
  AND (q.actor IS NULL OR q.target IS NULL);

-- Compute default sla_deadline for active tickets based on priority_established_at
UPDATE soc_ops.soc_triage_queue
SET sla_deadline = CASE
    WHEN priority = 'P0' THEN COALESCE(priority_established_at, created_at) + INTERVAL '15 minutes'
    WHEN priority = 'P1' THEN COALESCE(priority_established_at, created_at) + INTERVAL '60 minutes'
    WHEN priority = 'P2' THEN COALESCE(priority_established_at, created_at) + INTERVAL '4 hours'
    WHEN priority = 'P3' THEN COALESCE(priority_established_at, created_at) + INTERVAL '24 hours'
    ELSE COALESCE(priority_established_at, created_at) + INTERVAL '7 days'
END
WHERE sla_deadline IS NULL;

-- Expand triage_status CHECK constraint to accommodate all automated & human workflow steps
ALTER TABLE soc_ops.soc_triage_queue
    DROP CONSTRAINT IF EXISTS chk_triage_status_user_flow_100pct;

ALTER TABLE soc_ops.soc_triage_queue
    ADD CONSTRAINT chk_triage_status_user_flow_100pct
        CHECK (triage_status IN (
            'OPEN', 'INVESTIGATE', 'CLOSE', 'WAITING', 'APPROVE', 'REJECT', 
            'FP Reject', 'FP_REJECT', 'AUTO_CLOSED', 'ESCALATED_IRIS', 
            'WAITING_SLA', 'ENRICHING', 'AI_TRIAGING', 'RESOLVED', 'CLOSED'
        ));

-- Index on SLA deadline and active state for real-time monitoring & scheduler workers
CREATE INDEX IF NOT EXISTS idx_soc_queue_sla_deadline
    ON soc_ops.soc_triage_queue (sla_deadline, triage_status);

CREATE INDEX IF NOT EXISTS idx_soc_queue_entity_lookup
    ON soc_ops.soc_triage_queue (tenant_id, actor, target, triage_status);


-- ----------------------------------------------------------------------------
-- 3. CREATE MULTI-AGGREGATE TICKET MEMBERSHIP TABLE
-- ----------------------------------------------------------------------------
-- Holds the 1 Induk + Correlated Aggregates that comprise a forensic incident ticket
CREATE TABLE IF NOT EXISTS soc_ops.ticket_aggregates (
    ticket_id VARCHAR(64) NOT NULL REFERENCES soc_ops.soc_triage_queue(triage_id) ON DELETE CASCADE,
    aggregation_id VARCHAR(64) NOT NULL REFERENCES suppression.aggregated_alerts(aggregation_id) ON DELETE CASCADE,
    is_induk BOOLEAN DEFAULT FALSE,
    is_escalation_trigger BOOLEAN DEFAULT FALSE,
    added_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_ticket_aggregates PRIMARY KEY (ticket_id, aggregation_id)
);

CREATE INDEX IF NOT EXISTS idx_ticket_aggs_ticket ON soc_ops.ticket_aggregates(ticket_id);
CREATE INDEX IF NOT EXISTS idx_ticket_aggs_agg ON soc_ops.ticket_aggregates(aggregation_id);


-- ----------------------------------------------------------------------------
-- 4. CREATE HUMAN SOC WORKFLOW: POLICY BUNDLES TABLE
-- ----------------------------------------------------------------------------
-- Holds confirmed benign incident clusters per tenant ready for SOC Developer audit
CREATE TABLE IF NOT EXISTS suppression.policy_bundles (
    bundle_id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    ticket_id VARCHAR(64) REFERENCES soc_ops.soc_triage_queue(triage_id) ON DELETE SET NULL,
    actor VARCHAR(128) NOT NULL,
    target VARCHAR(128) NOT NULL,
    wazuh_rule_ids INT[] NOT NULL DEFAULT '{}',
    bundle_status VARCHAR(32) DEFAULT 'PENDING_DEV_AUDIT' CHECK (
        bundle_status IN ('PENDING_DEV_AUDIT', 'IN_REVIEW', 'PROPOSAL_CREATED', 'REJECTED', 'ARCHIVED')
    ),
    developer_notes TEXT,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_policy_bundles_tenant ON suppression.policy_bundles(tenant_id, bundle_status);


-- ----------------------------------------------------------------------------
-- 5. CREATE HUMAN SOC WORKFLOW: WAZUH SUPPRESSION PROPOSALS TABLE
-- ----------------------------------------------------------------------------
-- Enforces Separation of Duties: SOC Developer creates & tests with logtest,
-- SOC Manager approves or rejects with mandatory justification notes.
CREATE TABLE IF NOT EXISTS suppression.wazuh_rule_proposals (
    proposal_id VARCHAR(64) PRIMARY KEY,
    bundle_id VARCHAR(64) REFERENCES suppression.policy_bundles(bundle_id) ON DELETE CASCADE,
    tenant_id VARCHAR(64) NOT NULL,
    proposal_type VARCHAR(16) NOT NULL CHECK (proposal_type IN ('CDB_LIST', 'XML_RULE')),
    rule_content TEXT NOT NULL,
    business_reason TEXT NOT NULL,
    logtest_status VARCHAR(16) DEFAULT 'NOT_TESTED' CHECK (logtest_status IN ('PASSED', 'FAILED', 'NOT_TESTED')),
    logtest_output TEXT,
    developer_author VARCHAR(128) NOT NULL,
    manager_approver VARCHAR(128),
    manager_rejection_reason TEXT,
    approval_status VARCHAR(20) DEFAULT 'PENDING_APPROVAL' CHECK (
        approval_status IN ('PENDING_APPROVAL', 'APPROVED', 'REJECTED')
    ),
    expires_date DATE NOT NULL,
    is_deployed_to_wazuh BOOLEAN DEFAULT FALSE,
    deployed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_author_approver_proposal CHECK (developer_author <> manager_approver)
);

CREATE INDEX IF NOT EXISTS idx_wazuh_proposals_status ON suppression.wazuh_rule_proposals(approval_status, tenant_id);
CREATE INDEX IF NOT EXISTS idx_wazuh_proposals_expiry ON suppression.wazuh_rule_proposals(expires_date);


-- ----------------------------------------------------------------------------
-- 6. RECREATE DYNAMIC SLA & TRIAGE QUEUE VIEW (ALIGNED WITH NEW WORKFLOW)
-- ----------------------------------------------------------------------------
-- Uses absolute sla_deadline (calculated from induk aggregate arrival / escalation reset)
DROP VIEW IF EXISTS soc_ops.v_actionable_triage_queue CASCADE;

CREATE VIEW soc_ops.v_actionable_triage_queue AS
SELECT 
    t.triage_id,
    t.priority,
    COALESCE(s.total_score, 0) AS skor_risiko,
    COALESCE(i.title, 'ASOC Correlated Incident: ' || t.actor || ' -> ' || t.target) AS judul_insiden,
    t.target AS target_host,
    t.actor AS attacker_source_ip,
    t.tenant_id,
    t.triage_status,
    t.assigned_analyst,
    COALESCE(t.priority_established_at, t.created_at) AS waktu_prioritas_dimulai,
    t.sla_deadline AS batas_deadline_sla,
    t.window_buffer_until,
    t.iris_case_id,
    t.misp_event_id,
    CASE 
        WHEN t.priority = 'P0' THEN 'DARURAT TERTINGGI (< 15m)'
        WHEN t.priority = 'P1' THEN 'MENDESAK (< 60m)'
        WHEN t.priority = 'P2' THEN 'REVIEW SHIFT (< 4 Jam)'
        WHEN t.priority = 'P3' THEN 'REVIEW HARIAN (< 24 Jam)'
        WHEN t.priority = 'P4' THEN 'OBSERVASI MINGGUAN (< 7 Hari)'
        ELSE 'OBSERVASI MINGGUAN (< 7 Hari)'
    END AS target_sla,
    CASE 
        WHEN t.sla_deadline < CURRENT_TIMESTAMP THEN 'SLA BREACH (LEWAT BATAS)'
        ELSE 'AKTIF DALAM SLA'
    END AS status_kepatuhan_sla
FROM soc_ops.soc_triage_queue t
LEFT JOIN correlation.correlated_incidents i ON t.incident_id = i.incident_id
LEFT JOIN risk_engine.calculated_risk_scores s ON t.incident_id = s.incident_id
WHERE t.triage_status IN ('OPEN', 'INVESTIGATE', 'WAITING', 'WAITING_SLA', 'ENRICHING', 'AI_TRIAGING')
ORDER BY 
    t.sla_deadline ASC,
    CASE t.priority 
        WHEN 'P0' THEN 1 
        WHEN 'P1' THEN 2 
        WHEN 'P2' THEN 3 
        WHEN 'P3' THEN 4 
        ELSE 5 
    END ASC;


-- ----------------------------------------------------------------------------
-- 7. RECORD MIGRATION IN SCHEMA_MIGRATIONS
-- ----------------------------------------------------------------------------
INSERT INTO public.schema_migrations (version, applied_at)
VALUES ('018_align_asoc_new_workflow.sql', CURRENT_TIMESTAMP)
ON CONFLICT (version) DO NOTHING;

COMMIT;
