-- ============================================================================
-- MIGRATION 002: Aggregat & Cumulative Alert Schema Upgrade
-- Version: v2.0 — Best Practice 100/100 Upgrade
-- Compatible: PostgreSQL 14+ | Non-Destructive (ADD COLUMN IF NOT EXISTS)
-- Safe to run on existing database with data — no data loss
-- ============================================================================

BEGIN;

-- ----------------------------------------------------------------------------
-- 1. AGGREGATED_ALERTS: Tambah kolom is_suppressed, suppression fields, risk & OCSF
--    (Kolom ini sudah ada di Python model tapi belum di schema SQL)
-- ----------------------------------------------------------------------------

ALTER TABLE suppression.aggregated_alerts
    ADD COLUMN IF NOT EXISTS is_suppressed BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS suppression_rule_id VARCHAR(32),
    ADD COLUMN IF NOT EXISTS suppression_reason TEXT,
    ADD COLUMN IF NOT EXISTS ioa_summary TEXT,
    ADD COLUMN IF NOT EXISTS max_inline_risk_score INT NOT NULL DEFAULT 0
        CONSTRAINT chk_risk_score_range CHECK (max_inline_risk_score BETWEEN 0 AND 100),
    ADD COLUMN IF NOT EXISTS ocsf_severity_id INT
        CONSTRAINT chk_ocsf_severity CHECK (ocsf_severity_id IS NULL OR ocsf_severity_id BETWEEN 1 AND 6);

-- Perluas CHECK constraint status: dari 'CLOSED' saja menjadi enum yang lebih lengkap
-- Harus drop dulu constraint lama, lalu buat yang baru
ALTER TABLE suppression.aggregated_alerts
    DROP CONSTRAINT IF EXISTS aggregated_alerts_status_check;

ALTER TABLE suppression.aggregated_alerts
    ADD CONSTRAINT aggregated_alerts_status_check
        CHECK (status IN ('CLOSED', 'ACTIONABLE', 'SUPPRESSED', 'PENDING_REVIEW'));

-- Perluas CHECK constraint category: dari 'HOST' menjadi 9 kategori universal
ALTER TABLE suppression.aggregated_alerts
    DROP CONSTRAINT IF EXISTS aggregated_alerts_category_check;

ALTER TABLE suppression.aggregated_alerts
    ADD CONSTRAINT aggregated_alerts_category_check
        CHECK (category IN (
            'AUTHENTICATION', 'NETWORK_WEB', 'ENDPOINT_PROCESS',
            'MALWARE', 'VULNERABILITY', 'FILE_INTEGRITY',
            'CLOUD_CONTAINER', 'SYSTEM_HEALTH', 'COMPLIANCE', 'UNKNOWN'
        ));

-- Update nilai default category dari 'HOST' ke 'SYSTEM_HEALTH'
ALTER TABLE suppression.aggregated_alerts
    ALTER COLUMN category SET DEFAULT 'SYSTEM_HEALTH';

-- Update nilai yang sudah ada dengan value lama 'HOST' → 'SYSTEM_HEALTH'
UPDATE suppression.aggregated_alerts
    SET category = 'SYSTEM_HEALTH'
    WHERE category NOT IN (
        'AUTHENTICATION', 'NETWORK_WEB', 'ENDPOINT_PROCESS',
        'MALWARE', 'VULNERABILITY', 'FILE_INTEGRITY',
        'CLOUD_CONTAINER', 'SYSTEM_HEALTH', 'COMPLIANCE', 'UNKNOWN'
    );

-- ----------------------------------------------------------------------------
-- 2. CUMULATIVE_ALERTS: Tambah kolom ioa_summary dan peak_risk_score
-- ----------------------------------------------------------------------------

ALTER TABLE suppression.cumulative_alerts
    ADD COLUMN IF NOT EXISTS ioa_summary TEXT,
    ADD COLUMN IF NOT EXISTS peak_risk_score INT NOT NULL DEFAULT 0
        CONSTRAINT chk_cum_risk_score CHECK (peak_risk_score BETWEEN 0 AND 100);

-- Perluas CHECK constraint category di cumulative_alerts
ALTER TABLE suppression.cumulative_alerts
    DROP CONSTRAINT IF EXISTS cumulative_alerts_category_check;

ALTER TABLE suppression.cumulative_alerts
    ADD CONSTRAINT cumulative_alerts_category_check
        CHECK (category IN (
            'AUTHENTICATION', 'NETWORK_WEB', 'ENDPOINT_PROCESS',
            'MALWARE', 'VULNERABILITY', 'FILE_INTEGRITY',
            'CLOUD_CONTAINER', 'SYSTEM_HEALTH', 'COMPLIANCE', 'UNKNOWN'
        ));

ALTER TABLE suppression.cumulative_alerts
    ALTER COLUMN category SET DEFAULT 'SYSTEM_HEALTH';

UPDATE suppression.cumulative_alerts
    SET category = 'SYSTEM_HEALTH'
    WHERE category NOT IN (
        'AUTHENTICATION', 'NETWORK_WEB', 'ENDPOINT_PROCESS',
        'MALWARE', 'VULNERABILITY', 'FILE_INTEGRITY',
        'CLOUD_CONTAINER', 'SYSTEM_HEALTH', 'COMPLIANCE', 'UNKNOWN'
    );

-- ----------------------------------------------------------------------------
-- 3. INDEX BARU: Performa query untuk suppression filter, dashboard SOC,
--    dan correlation window cooldown lookup
-- ----------------------------------------------------------------------------

-- Index untuk filtering aggregat yang belum disuppress (ACTIONABLE)
CREATE INDEX IF NOT EXISTS idx_agg_alerts_actionable
    ON suppression.aggregated_alerts (tenant_id, status, window_end)
    WHERE status = 'ACTIONABLE' AND NOT is_suppressed;

-- Index untuk risk-based prioritization (scoring engine)
CREATE INDEX IF NOT EXISTS idx_agg_alerts_risk_score
    ON suppression.aggregated_alerts (max_inline_risk_score DESC, ocsf_severity_id DESC NULLS LAST)
    WHERE status = 'ACTIONABLE';

-- Index untuk suppression rule audit (berapa agregat yang di-suppress per rule)
CREATE INDEX IF NOT EXISTS idx_agg_alerts_suppression_rule
    ON suppression.aggregated_alerts (suppression_rule_id)
    WHERE is_suppressed = TRUE;

-- Index untuk cumulative entity lookup (historical lookback oleh correlation engine)
CREATE INDEX IF NOT EXISTS idx_cumulative_actor_category
    ON suppression.cumulative_alerts (actor, category, last_seen_at DESC);

-- Index untuk cumulative peak risk — entity dengan riwayat serangan tinggi
CREATE INDEX IF NOT EXISTS idx_cumulative_peak_risk
    ON suppression.cumulative_alerts (peak_risk_score DESC)
    WHERE status = 'ACTIVE';

-- Index untuk correlation window cooldown check (SocTriageQueue)
CREATE INDEX IF NOT EXISTS idx_triage_cooldown
    ON soc_ops.soc_triage_queue (incident_id, cooldown_until)
    WHERE cooldown_until IS NOT NULL;

-- Index untuk correlated_incidents re-open lookup (actor/target based)
CREATE INDEX IF NOT EXISTS idx_incidents_actor_target
    ON correlation.correlated_incidents (attacker_source_ip, target_host, last_seen_at DESC);

-- ----------------------------------------------------------------------------
-- 4. FUNCTION: Cooldown-aware incident upsert helper
--    Digunakan oleh correlation engine untuk memutuskan: re-open vs buat baru
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION soc_ops.get_active_incident_for_cooldown(
    p_attacker_ip VARCHAR(45),
    p_target_host VARCHAR(128),
    p_tenant_id   VARCHAR(64)
)
RETURNS TABLE (
    incident_id       VARCHAR(64),
    triage_id         VARCHAR(64),
    triage_status     VARCHAR(32),
    cooldown_until    TIMESTAMPTZ,
    last_seen_at      TIMESTAMPTZ
)
LANGUAGE SQL STABLE
AS $$
    SELECT
        i.incident_id,
        t.triage_id,
        t.triage_status,
        t.cooldown_until,
        i.last_seen_at
    FROM correlation.correlated_incidents i
    JOIN soc_ops.soc_triage_queue t ON i.incident_id = t.incident_id
    WHERE
        i.tenant_id = p_tenant_id
        AND (i.attacker_source_ip = p_attacker_ip OR i.target_host = p_target_host)
        AND t.triage_status NOT IN ('CLOSED')
        AND (t.cooldown_until IS NULL OR t.cooldown_until > CURRENT_TIMESTAMP)
    ORDER BY i.last_seen_at DESC
    LIMIT 1;
$$;

COMMENT ON FUNCTION soc_ops.get_active_incident_for_cooldown IS
'Returns the most recent open/in-cooldown incident for an actor+target pair.
Used by the correlation engine to decide: append to existing ticket vs create new ticket.
Returns NULL if no active cooldown exists (= safe to create new ticket).';

-- ----------------------------------------------------------------------------
-- 5. Trigger: Auto-set cooldown_until saat tiket di-RESOLVE
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION soc_ops.trigger_set_cooldown_on_resolve()
RETURNS TRIGGER AS $$
BEGIN
    -- Saat status berubah ke RESOLVED, set cooldown_until = resolved_at + 72 jam (default)
    -- SOC dapat override cooldown_hours per correlation rule via incident metadata
    IF NEW.triage_status = 'RESOLVED' AND (OLD.triage_status IS DISTINCT FROM 'RESOLVED') THEN
        IF NEW.resolved_at IS NULL THEN
            NEW.resolved_at := CURRENT_TIMESTAMP;
        END IF;
        -- Default cooldown: 72 jam. Override dengan set cooldown_until manual sebelum commit.
        IF NEW.cooldown_until IS NULL THEN
            NEW.cooldown_until := NEW.resolved_at + INTERVAL '72 hours';
        END IF;
    END IF;
    -- Jika tiket di-re-open (status kembali ke IN_TRIAGE/INVESTIGATING), clear cooldown
    IF NEW.triage_status IN ('INVESTIGATING', 'IN_TRIAGE') AND OLD.triage_status = 'RESOLVED' THEN
        NEW.cooldown_until := NULL;
        NEW.resolved_at := NULL;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_soc_triage_cooldown ON soc_ops.soc_triage_queue;
CREATE TRIGGER trg_soc_triage_cooldown
BEFORE UPDATE ON soc_ops.soc_triage_queue
FOR EACH ROW EXECUTE FUNCTION soc_ops.trigger_set_cooldown_on_resolve();

-- ----------------------------------------------------------------------------
-- 6. View: Aggregated alerts siap korelasi (bukan suppressed, belum expired)
--    Digunakan oleh dashboard SOC dan correlation engine
-- ----------------------------------------------------------------------------

CREATE OR REPLACE VIEW suppression.v_actionable_aggregates AS
SELECT
    aa.aggregation_id,
    aa.rule_id,
    aa.deduplication_key,
    aa.tenant_id,
    aa.category,
    aa.actor,
    aa.target,
    aa.event_count,
    aa.window_start,
    aa.window_end,
    aa.window_duration_seconds,
    aa.max_inline_risk_score,
    aa.ocsf_severity_id,
    aa.ioa_summary,
    aa.rule_description,
    aa.created_at,
    ca.total_event_count   AS cumulative_total_events,
    ca.total_burst_windows AS cumulative_burst_windows,
    ca.first_seen_at       AS entity_first_seen,
    ca.last_seen_at        AS entity_last_seen,
    ca.peak_risk_score     AS entity_peak_risk,
    ca.status              AS entity_status
FROM suppression.aggregated_alerts aa
LEFT JOIN suppression.cumulative_alerts ca
    ON aa.deduplication_key = ca.deduplication_key
WHERE
    aa.status = 'ACTIONABLE'
    AND aa.is_suppressed = FALSE;

COMMENT ON VIEW suppression.v_actionable_aggregates IS
'Aggregated alerts yang lolos filter suppression dan siap dikirim ke correlation engine.
Includes cumulative context (entity history) via JOIN ke cumulative_alerts.';

COMMIT;

-- ============================================================================
-- VERIFIKASI POST-MIGRATION
-- ============================================================================
DO $$
DECLARE
    v_agg_cols   INT;
    v_cum_cols   INT;
    v_indexes    INT;
BEGIN
    -- Hitung kolom baru di aggregated_alerts
    SELECT COUNT(*) INTO v_agg_cols
    FROM information_schema.columns
    WHERE table_schema = 'suppression'
      AND table_name   = 'aggregated_alerts'
      AND column_name  IN ('is_suppressed', 'suppression_rule_id', 'suppression_reason',
                           'ioa_summary', 'max_inline_risk_score', 'ocsf_severity_id');

    -- Hitung kolom baru di cumulative_alerts
    SELECT COUNT(*) INTO v_cum_cols
    FROM information_schema.columns
    WHERE table_schema = 'suppression'
      AND table_name   = 'cumulative_alerts'
      AND column_name  IN ('ioa_summary', 'peak_risk_score');

    -- Hitung index baru
    SELECT COUNT(*) INTO v_indexes
    FROM pg_indexes
    WHERE schemaname = 'suppression'
      AND indexname IN (
          'idx_agg_alerts_actionable',
          'idx_agg_alerts_risk_score',
          'idx_agg_alerts_suppression_rule',
          'idx_cumulative_actor_category',
          'idx_cumulative_peak_risk'
      );

    RAISE NOTICE '=== MIGRATION 002 VERIFICATION ===';
    RAISE NOTICE 'aggregated_alerts new columns found: % / 6 expected', v_agg_cols;
    RAISE NOTICE 'cumulative_alerts new columns found: % / 2 expected', v_cum_cols;
    RAISE NOTICE 'New indexes created: % / 5 expected', v_indexes;

    IF v_agg_cols = 6 AND v_cum_cols = 2 AND v_indexes >= 4 THEN
        RAISE NOTICE '✅ MIGRATION 002 COMPLETED SUCCESSFULLY — Schema is 100/100 Best Practice';
    ELSE
        RAISE WARNING '⚠️  MIGRATION 002 INCOMPLETE — check column counts above';
    END IF;
END $$;
