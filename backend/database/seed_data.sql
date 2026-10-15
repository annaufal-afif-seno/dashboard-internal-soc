-- ============================================================================
-- WAZUH ALERT FATIGUE REDUCTION & GROUPING PIPELINE
-- INITIAL MASTER REFERENCE & SEED DATA (STAGE 2 & 3)
-- ============================================================================
SET search_path TO telemetry, enrichment, suppression, correlation, risk_engine, soc_ops, metrics, public;


-- 1. Master Asset Inventory Seed Data
INSERT INTO asset_inventory_context (asset_id, hostname, ip_address, asset_type, criticality_tier, criticality_score, environment, is_internet_exposed, owner_department)
VALUES
    ('AST-001', 'dc-01.prod.local', '10.0.0.10', 'DOMAIN_CONTROLLER', 'CROWN_JEWEL', 25, 'PRODUCTION', FALSE, 'IT Infrastructure'),
    ('AST-002', 'db-primary-01.prod.local', '10.0.0.11', 'DB_SERVER', 'CROWN_JEWEL', 25, 'PRODUCTION', FALSE, 'Database Ops'),
    ('AST-003', 'api-gateway-01.prod.local', '10.0.0.12', 'WEB_SERVER', 'CRITICAL', 20, 'PRODUCTION', TRUE, 'Core Platform'),
    ('AST-004', 'hportal-prod-159', '192.168.1.159', 'WEB_SERVER', 'HIGH', 15, 'PRODUCTION', TRUE, 'Portal Operations'),
    ('AST-005', 'leaning-sgu-dimas-124', '192.168.1.124', 'WORKSTATION', 'STANDARD', 5, 'PRODUCTION', FALSE, 'Internal Staff'),
    ('AST-006', 'Learning-acadcsirt-dimas-123', '192.168.1.123', 'WORKSTATION', 'STANDARD', 5, 'PRODUCTION', FALSE, 'Internal Staff')
ON CONFLICT (hostname) DO NOTHING;

-- 2. Master Identity Context Seed Data
INSERT INTO identity_context (identity_id, username, account_type, is_privileged, department, expected_hosts, risk_baseline_score)
VALUES
    ('ID-001', 'root', 'PRIVILEGED_ADMIN', TRUE, 'Security & Systems', ARRAY['dc-01.prod.local', 'db-primary-01.prod.local'], 40),
    ('ID-002', 'administrator', 'PRIVILEGED_ADMIN', TRUE, 'Windows Domain Ops', ARRAY['dc-01.prod.local'], 40),
    ('ID-003', 'svc_backup', 'SERVICE_ACCOUNT', FALSE, 'Backup Operations', ARRAY['backup-01.prod.local', 'backup-02.prod.local'], 10),
    ('ID-004', 'svc_deploy', 'SERVICE_ACCOUNT', FALSE, 'DevOps CI/CD', ARRAY['api-gateway-01.prod.local', 'hportal-prod-159'], 10),
    ('ID-005', 'dimas_analyst', 'STANDARD_USER', FALSE, 'SOC Security Operations', ARRAY['leaning-sgu-dimas-124'], 0)
ON CONFLICT (username) DO NOTHING;

-- 3. Master Threat Intelligence IoCs Seed Data
INSERT INTO threat_intelligence_iocs (indicator_value, indicator_type, threat_actor, malware_family, confidence_score, source_feed, description, is_active)
VALUES
    ('198.51.100.23', 'IPV4', 'APT29', 'CobaltStrike', 95, 'AbuseIPDB / AlienVault OTX', 'Known C2 Beacon IP', TRUE),
    ('203.0.113.45', 'IPV4', 'FIN7', 'Carbanak', 90, 'Emerging Threats', 'Web Scanner & Exploitation Source', TRUE),
    ('malicious-c2-tunnel.onion', 'DOMAIN', 'Unknown Threat', 'DNS_Tunneling', 85, 'ThreatConnect', 'Suspicious Fast-Flux DNS Tunnel', TRUE),
    ('d41d8cd98f00b204e9800998ecf8427e', 'MD5', 'Commodity', 'Webshell_c99', 99, 'Internal YARA Repo', 'Known PHP webshell MD5 hash', TRUE)
ON CONFLICT (indicator_value, indicator_type) DO NOTHING;

-- 4. Master Maintenance Windows (S4)
INSERT INTO maintenance_windows (window_id, title, target_hostname, target_ip, ticket_id, approved_by, window_start, window_end, status)
VALUES
    ('MW-2026-0701', 'Monthly Security Patching Window', 'hportal-prod-159', '192.168.1.159', 'CRQ-2026-8801', 'security_manager_alice', '2026-07-01 00:00:00+00', '2026-07-01 04:00:00+00', 'COMPLETED'),
    ('MW-2026-0715', 'Database Kernel Upgrade', 'db-primary-01.prod.local', '10.0.0.11', 'CRQ-2026-8802', 'security_manager_alice', '2026-07-15 01:00:00+00', '2026-07-15 03:00:00+00', 'COMPLETED')
ON CONFLICT (window_id) DO NOTHING;

-- 5. Master Suppression Rules (S1 - S5)
INSERT INTO suppression_rules (suppression_id, rule_name, suppression_class, target_rule_ids, author, approver, ticket_id, business_reason, scope_definition, status, created_date, expires_date, review_cycle)
VALUES
    ('SUP-2026-001', 'Nessus Primary Vulnerability Scanner', 'S1_KNOWN_GOOD', ARRAY[5710, 31101, 100300], 'sec_eng_john', 'soc_lead_alice', 'CRQ-2026-9001', 'Approved monthly internal and external vulnerability scanning by security team', '{"source_ips": ["10.10.50.20", "10.10.50.21"]}'::jsonb, 'ACTIVE', '2026-07-01', '2026-12-31', 'MONTHLY'),
    ('SUP-2026-002', 'Routine Non-Critical AppArmor Noise', 'S1_KNOWN_GOOD', ARRAY[52002], 'sec_eng_john', 'soc_lead_alice', 'CRQ-2026-9002', 'Filter routine getattr/open benign AppArmor denials on container workloads', '{"operations": ["getattr", "open"]}'::jsonb, 'ACTIVE', '2026-07-01', '2026-10-01', 'MONTHLY'),
    ('SUP-2026-003', 'Web Server 400 Bot Burst — Known-Good Internet Noise', 'S1_KNOWN_GOOD', ARRAY[31101, 31533], 'sec_eng_john', 'soc_lead_alice', 'CRQ-2026-9003', 'Collapse high frequency 400 errors from internet scanners into single summary object', '{"window_minutes": 15}'::jsonb, 'ACTIVE', '2026-07-01', '2027-01-01', 'QUARTERLY')
ON CONFLICT (suppression_id) DO NOTHING;

-- 6. Master Correlation Rules (Stage 4)
INSERT INTO correlation_rules (correlation_rule_id, rule_code, rule_name, description, timeframe_seconds, target_severity, is_active)
VALUES
    ('CORR-001', 'AUTH_BRUTE_FORCE_SUCCESS', 'Brute Force Followed by Successful Login', 'Multiple failed logins followed by authentication success from same source IP within 10 minutes', 600, 'P1', TRUE),
    ('CORR-002', 'LOGIN_PRIVESC_PERSIST', 'Intrusion Chain: Login -> Sudo -> Persistence', 'Successful authentication followed by privilege escalation and cron/registry persistence within 30 minutes', 1800, 'P0', TRUE),
    ('CORR-003', 'SUSPICIOUS_POWERSHELL_CHAIN', 'PowerShell Encoded Command & Ingress Tool Transfer', 'Encoded PowerShell execution accompanied by LOLBAS download or external network connection', 600, 'P0', TRUE),
    ('CORR-004', 'LATERAL_MOVEMENT_SWEEP', 'Cross-Host Remote Execution Sweep', 'Single user or source accessing administrative shares or executing WMI/WinRM across multiple internal endpoints', 900, 'P1', TRUE),
    ('CORR-005', 'MALWARE_C2_BURST', 'Malware Execution with C2 Network Connection', 'YARA/Webshell signature detection followed by active outbound network connection', 300, 'P0', TRUE),
    ('CORR-006', 'DISTRIBUTED_PASSWORD_SPRAY', 'Distributed Multi-IP Password Spraying Attack', 'Multiple authentication failures originating from rotating IPs targeting a single endpoint', 900, 'P1', TRUE),
    ('CORR-007', 'RANSOMWARE_TAMPER_AND_IMPACT', 'Ransomware Defense Evasion and Mass File Impact', 'Backup tampering or shadow copy deletion followed by mass file modification/encryption on same endpoint', 900, 'P0', TRUE),
    ('CORR-008', 'GENERIC_HOST_MULTI_TACTIC_CHAIN', 'Generic Host Multi-Stage Intrusion Chain', 'Cross-tactic attack progression (Penetration/Evasion followed by Execution/Impact) on the same host within 15 minutes', 900, 'P0', TRUE),
    ('CORR-SA', 'STANDALONE_BURST_TRACKER', 'Recurring Standalone Alert Burst Consolidation', 'Consolidation of recurring standalone alerts', 86400, 'P3', TRUE),
    ('CORR-ENTITY', 'ENTITY_CENTRIC_TRACKER', 'Entity-Centric Behavior & Multi-Stage Attack Correlation', 'Dynamic multi-stage entity-centric correlation', 86400, 'P2', TRUE),
    ('CORR-OPP', 'OPPORTUNISTIC_CROSS_CATEGORY', 'Opportunistic Cross-Category Attack Progression', 'Multi-stage cross-category attack progression across observed categories', 86400, 'P1', TRUE)
ON CONFLICT (correlation_rule_id) DO NOTHING;
