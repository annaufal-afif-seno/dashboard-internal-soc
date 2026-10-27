-- =============================================================================
-- Migration 030: Unified 6-Category Taxonomy
-- Adds primary_category, subcategory, disposition, confidence_score columns
-- to normalized_events, aggregated_alerts, and correlated_incidents tables.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 1. ADD COLUMNS TO public.normalized_events
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'normalized_events'
          AND column_name = 'primary_category'
    ) THEN
        ALTER TABLE public.normalized_events
            ADD COLUMN primary_category VARCHAR(32) DEFAULT 'INFORMATIONAL';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'normalized_events'
          AND column_name = 'subcategory'
    ) THEN
        ALTER TABLE public.normalized_events
            ADD COLUMN subcategory VARCHAR(64) DEFAULT 'General';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'normalized_events'
          AND column_name = 'disposition'
    ) THEN
        ALTER TABLE public.normalized_events
            ADD COLUMN disposition VARCHAR(16) DEFAULT 'NEEDS_REVIEW';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'normalized_events'
          AND column_name = 'confidence_score'
    ) THEN
        ALTER TABLE public.normalized_events
            ADD COLUMN confidence_score INTEGER DEFAULT 50;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 2. ADD COLUMNS TO public.aggregated_alerts
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'aggregated_alerts'
          AND column_name = 'primary_category'
    ) THEN
        ALTER TABLE public.aggregated_alerts
            ADD COLUMN primary_category VARCHAR(32) DEFAULT 'INFORMATIONAL';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'aggregated_alerts'
          AND column_name = 'subcategory'
    ) THEN
        ALTER TABLE public.aggregated_alerts
            ADD COLUMN subcategory VARCHAR(64) DEFAULT 'General';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'aggregated_alerts'
          AND column_name = 'disposition'
    ) THEN
        ALTER TABLE public.aggregated_alerts
            ADD COLUMN disposition VARCHAR(16) DEFAULT 'NEEDS_REVIEW';
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 3. ADD COLUMNS TO public.correlated_incidents
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'correlated_incidents'
          AND column_name = 'primary_category'
    ) THEN
        ALTER TABLE public.correlated_incidents
            ADD COLUMN primary_category VARCHAR(32) DEFAULT 'INFORMATIONAL';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'correlated_incidents'
          AND column_name = 'severity_score'
    ) THEN
        ALTER TABLE public.correlated_incidents
            ADD COLUMN severity_score INTEGER DEFAULT 0;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'correlated_incidents'
          AND column_name = 'attack_subcategory'
    ) THEN
        ALTER TABLE public.correlated_incidents
            ADD COLUMN attack_subcategory VARCHAR(64);
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 4. CREATE INDEXES ON NEW COLUMNS
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_normalized_events_primary_category
    ON public.normalized_events (primary_category);

CREATE INDEX IF NOT EXISTS idx_normalized_events_disposition
    ON public.normalized_events (disposition);

CREATE INDEX IF NOT EXISTS idx_aggregated_alerts_primary_category
    ON public.aggregated_alerts (primary_category);

CREATE INDEX IF NOT EXISTS idx_aggregated_alerts_disposition
    ON public.aggregated_alerts (disposition);

CREATE INDEX IF NOT EXISTS idx_correlated_incidents_primary_category
    ON public.correlated_incidents (primary_category);

-- ---------------------------------------------------------------------------
-- 5. BACKFILL primary_category IN normalized_events FROM classification_groups
-- ---------------------------------------------------------------------------

-- ATTACK: attack, web_attack, sqli, xss, recon, web_scan
UPDATE public.normalized_events
SET primary_category = 'ATTACK'
WHERE classification_groups && ARRAY[
    'attack', 'web_attack', 'sqli', 'xss', 'recon', 'web_scan'
]::text[];

-- VULNERABILITY: vulnerability-detector, vulnerability, cve
UPDATE public.normalized_events
SET primary_category = 'VULNERABILITY'
WHERE primary_category = 'INFORMATIONAL'
  AND classification_groups && ARRAY[
    'vulnerability-detector', 'vulnerability', 'cve'
]::text[];

-- CONFIGURATION: syscheck, sca, config_changed, dpkg
UPDATE public.normalized_events
SET primary_category = 'CONFIGURATION'
WHERE primary_category = 'INFORMATIONAL'
  AND classification_groups && ARRAY[
    'syscheck', 'sca', 'config_changed', 'dpkg'
]::text[];

-- IDENTITY_ACCESS: authentication_failed, authentication_success, sudo, pam, sshd
UPDATE public.normalized_events
SET primary_category = 'IDENTITY_ACCESS'
WHERE primary_category = 'INFORMATIONAL'
  AND classification_groups && ARRAY[
    'authentication_failed', 'authentication_success', 'sudo', 'pam', 'sshd'
]::text[];

-- SYSTEM_HEALTH: apparmor, systemd, docker, nginx, apache, agent_flooding, ossec
UPDATE public.normalized_events
SET primary_category = 'SYSTEM_HEALTH'
WHERE primary_category = 'INFORMATIONAL'
  AND classification_groups && ARRAY[
    'apparmor', 'systemd', 'docker', 'nginx', 'apache', 'agent_flooding', 'ossec'
]::text[];

-- INFORMATIONAL: everything else already has the default 'INFORMATIONAL'

-- ---------------------------------------------------------------------------
-- 6. BACKFILL disposition IN normalized_events
-- ---------------------------------------------------------------------------

-- THREAT: attack/vulnerability categories with confidence >= 50
UPDATE public.normalized_events
SET disposition = 'THREAT'
WHERE primary_category IN ('ATTACK', 'VULNERABILITY')
  AND confidence_score >= 50;

-- NOISE: SYSTEM_HEALTH
UPDATE public.normalized_events
SET disposition = 'NOISE'
WHERE primary_category = 'SYSTEM_HEALTH';

-- NOISE: INFORMATIONAL
UPDATE public.normalized_events
SET disposition = 'NOISE'
WHERE primary_category = 'INFORMATIONAL';

-- NEEDS_REVIEW: everything else (already default, but be explicit for rows
-- that are ATTACK/VULNERABILITY with confidence < 50, or CONFIGURATION, or IDENTITY_ACCESS)
UPDATE public.normalized_events
SET disposition = 'NEEDS_REVIEW'
WHERE disposition = 'NEEDS_REVIEW'
  AND primary_category NOT IN ('ATTACK', 'VULNERABILITY', 'SYSTEM_HEALTH', 'INFORMATIONAL');

-- ---------------------------------------------------------------------------
-- 7. RECORD MIGRATION IN schema_migrations
-- ---------------------------------------------------------------------------
INSERT INTO public.schema_migrations (version, description, applied_at)
VALUES (30, 'Unified 6-category taxonomy: primary_category, subcategory, disposition, confidence_score', NOW())
ON CONFLICT (version) DO NOTHING;
