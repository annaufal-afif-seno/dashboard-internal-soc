-- ============================================================================
-- MIGRATION 003: Suppression Groups Schema Upgrade
-- ============================================================================

BEGIN;

-- ----------------------------------------------------------------------------
-- 1. Create suppression.suppression_groups table
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS suppression.suppression_groups (
    group_id VARCHAR(32) PRIMARY KEY,
    group_name VARCHAR(256) NOT NULL,
    group_type VARCHAR(32) NOT NULL CHECK (group_type IN ('TENANT', 'USE_CASE', 'ASSET_GROUP', 'ACTOR', 'MITRE_TACTIC', 'MAINTENANCE')),
    tenant_id VARCHAR(64) DEFAULT 'ALL',
    description TEXT,
    mitre_tactics TEXT[],
    mitre_techniques TEXT[],
    shared_scope JSONB DEFAULT '{}',
    auto_merge BOOLEAN DEFAULT FALSE,
    priority VARCHAR(4) DEFAULT 'P2',
    owner VARCHAR(128) NOT NULL,
    status VARCHAR(16) DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'DRAFT', 'ARCHIVED', 'UNDER_REVIEW')),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- ----------------------------------------------------------------------------
-- 2. Create suppression.shared_value_lists table
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS suppression.shared_value_lists (
    list_id VARCHAR(32) PRIMARY KEY,
    list_name VARCHAR(128) NOT NULL,
    list_type VARCHAR(32) NOT NULL CHECK (list_type IN ('IP', 'HOSTNAME', 'USERNAME', 'CIDR', 'AGENT_GROUP', 'RULE_SID')),
    values JSONB NOT NULL DEFAULT '[]',
    description TEXT,
    referenced_by VARCHAR(32)[] DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- ----------------------------------------------------------------------------
-- 3. Add group_id FK to suppression.suppression_rules
-- ----------------------------------------------------------------------------
ALTER TABLE suppression.suppression_rules
    ADD COLUMN IF NOT EXISTS group_id VARCHAR(32) REFERENCES suppression.suppression_groups(group_id) ON DELETE SET NULL;

-- ----------------------------------------------------------------------------
-- 4. Create necessary indexes
-- ----------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_sup_groups_tenant ON suppression.suppression_groups(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_sup_groups_type ON suppression.suppression_groups(group_type, status);
CREATE INDEX IF NOT EXISTS idx_sup_rules_group ON suppression.suppression_rules(group_id) WHERE group_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_shared_lists_type ON suppression.shared_value_lists(list_type);

-- ----------------------------------------------------------------------------
-- 5. Create triggers for updated_at
-- ----------------------------------------------------------------------------
DROP TRIGGER IF EXISTS trg_suppression_groups_updated_at ON suppression.suppression_groups;
CREATE TRIGGER trg_suppression_groups_updated_at
BEFORE UPDATE ON suppression.suppression_groups
FOR EACH ROW EXECUTE FUNCTION public.trigger_set_timestamp();

DROP TRIGGER IF EXISTS trg_shared_value_lists_updated_at ON suppression.shared_value_lists;
CREATE TRIGGER trg_shared_value_lists_updated_at
BEFORE UPDATE ON suppression.shared_value_lists
FOR EACH ROW EXECUTE FUNCTION public.trigger_set_timestamp();

-- ----------------------------------------------------------------------------
-- 6. Add seed data for existing suppression groups
-- ----------------------------------------------------------------------------
INSERT INTO suppression.suppression_groups (group_id, group_name, group_type, tenant_id, owner, shared_scope)
VALUES
    ('GRP-2026-001', 'Container Security Baseline', 'USE_CASE', 'TenantC', 'Deployment Automation Engine', '{}'),
    ('GRP-2026-002', 'System Provisioning Auth', 'USE_CASE', 'TenantC', 'Deployment Automation Engine', '{}'),
    ('GRP-2026-003', 'hportal-prod-159 Tuning', 'ASSET_GROUP', 'TenantC', 'admin_secops', '{"hostname": "hportal-prod-159"}')
ON CONFLICT (group_id) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 7. Update existing suppression_rules to assign group_ids
-- ----------------------------------------------------------------------------
UPDATE suppression.suppression_rules
SET group_id = 'GRP-2026-001'
WHERE target_rule_ids && ARRAY[52004, 86003, 52002];

UPDATE suppression.suppression_rules
SET group_id = 'GRP-2026-002'
WHERE target_rule_ids && ARRAY[5482, 5901, 5902];

COMMIT;

-- ============================================================================
-- 8. VERIFICATION POST-MIGRATION
-- ============================================================================
DO $$
DECLARE
    v_groups_exists BOOLEAN;
    v_lists_exists BOOLEAN;
    v_group_col_exists BOOLEAN;
    v_seed_count INT;
BEGIN
    SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_schema = 'suppression' AND table_name = 'suppression_groups'
    ) INTO v_groups_exists;

    SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_schema = 'suppression' AND table_name = 'shared_value_lists'
    ) INTO v_lists_exists;

    SELECT EXISTS (
        SELECT FROM information_schema.columns 
        WHERE table_schema = 'suppression' AND table_name = 'suppression_rules' AND column_name = 'group_id'
    ) INTO v_group_col_exists;

    SELECT COUNT(*) INTO v_seed_count
    FROM suppression.suppression_groups
    WHERE group_id IN ('GRP-2026-001', 'GRP-2026-002', 'GRP-2026-003');

    RAISE NOTICE '=== MIGRATION 003 VERIFICATION ===';
    RAISE NOTICE 'suppression_groups table exists: %', v_groups_exists;
    RAISE NOTICE 'shared_value_lists table exists: %', v_lists_exists;
    RAISE NOTICE 'group_id column in suppression_rules exists: %', v_group_col_exists;
    RAISE NOTICE 'Seed groups created: % / 3', v_seed_count;

    IF v_groups_exists AND v_lists_exists AND v_group_col_exists AND v_seed_count >= 3 THEN
        RAISE NOTICE '✅ MIGRATION 003 COMPLETED SUCCESSFULLY';
    ELSE
        RAISE WARNING '⚠️  MIGRATION 003 INCOMPLETE';
    END IF;
END $$;
