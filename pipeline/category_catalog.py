"""
========================================================================================
APEX CATEGORY CATALOG & CLASSIFIER REGISTRY (VERSION 3.4 / APEX GOLD STANDARD)
========================================================================================
Implements the 32-category taxonomy across 8 security domains with Layered Specificity
Hierarchy (Exploit/Attack > Credential > Recon > FIM/System > Policy > Generic).

Complies with NIST SP 800-61 Rev. 3, MITRE ATT&CK v15, and OCSF v1.3 standards.
100% Deterministic, O(1) set-intersection lookups, zero black-box drift.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Set, Tuple

# ── Specificity Hierarchy Weights ─────────────────────────────────────────────
WEIGHT_ACTIVE_EXPLOIT_MALWARE = 100
WEIGHT_CREDENTIAL_ACCESS_AUTH = 80
WEIGHT_RECONNAISSANCE_SCAN    = 60
WEIGHT_SYSTEM_INTEGRITY       = 50
WEIGHT_COMPLIANCE_POLICY      = 30
WEIGHT_GENERIC_FALLBACK       = 10

@dataclass
class RollupPolicy:
    label: str
    fingerprint_specs: List[str]
    min_leaves: int

@dataclass
class CategoryPolicy:
    code: str
    domain: str
    title: str
    specificity_weight: int
    match_criteria: Dict[str, Any]
    fingerprint_specs: List[str]
    track_fields: List[str] = field(default_factory=list)
    window: str = "10m"
    max_duration: str = "1h"
    max_alerts: int = 5000
    pin_level: Optional[int] = 12
    baseline_per_min: int = 3
    is_state_type: bool = False
    rollups: List[RollupPolicy] = field(default_factory=list)

# ── 32 Categories Registry Definition ───────────────────────────────────────────
APEX_32_CATEGORIES: List[CategoryPolicy] = [
    # ── 1. DOMAIN: IDENTITY & ACCESS ──────────────────────────────────────────
    CategoryPolicy(
        code="priv_escalation",
        domain="Identity & access",
        title="Privilege escalation",
        specificity_weight=WEIGHT_ACTIVE_EXPLOIT_MALWARE,
        match_criteria={
            "rule_groups_any": ["privilege_escalation"],
            "rule_id_any": [5402, 4672, 4673, 4674],
            "mitre_tactics_any": ["Privilege Escalation"]
        },
        fingerprint_specs=["agent", "src_user:clean", "dst_user:clean", "cmd:cmd?"],
        track_fields=[],
        window="10m",
        max_duration="1h",
        pin_level=10
    ),
    CategoryPolicy(
        code="credential_access",
        domain="Identity & access",
        title="Credential Access / Dumping / Kerberoasting",
        specificity_weight=WEIGHT_CREDENTIAL_ACCESS_AUTH,
        match_criteria={
            "mitre_techniques_any": ["T1003", "T1558", "T1558.003"],
            "rule_groups_any": ["credential_dumping", "kerberoasting"],
            "rule_id_any": [4768, 4769, 4771]
        },
        fingerprint_specs=["agent", "src_user:clean?", "target_service"],
        track_fields=["src_ip"],
        window="15m",
        max_duration="2h",
        pin_level=10,
        rollups=[
            RollupPolicy(label="Kerberoasting Spray", fingerprint_specs=["agent", "target_service"], min_leaves=5)
        ]
    ),
    CategoryPolicy(
        code="auth_anomaly_success",
        domain="Identity & access",
        title="Anomalous / Suspicious Successful Authentication",
        specificity_weight=WEIGHT_CREDENTIAL_ACCESS_AUTH,
        match_criteria={
            "rule_groups_any": ["authentication_success", "win_authentication_success", "pam_success"],
            "level_gte": 7
        },
        fingerprint_specs=["agent", "src_ip?", "dst_user:clean"],
        track_fields=["dst_port"],
        window="15m",
        max_duration="2h",
        pin_level=10
    ),
    CategoryPolicy(
        code="auth_bruteforce",
        domain="Identity & access",
        title="Failed login / Brute force",
        specificity_weight=WEIGHT_CREDENTIAL_ACCESS_AUTH,
        match_criteria={
            "rule_groups_any": [
                "authentication_failed", "authentication_failures",
                "win_authentication_failed", "sshd_failed_login", "pam_failed"
            ],
            "rule_id_any": [5503, 5710, 5716, 5720, 2501, 2502]
        },
        fingerprint_specs=["agent", "src_ip?", "dst_user:clean"],
        track_fields=["dst_port"],
        window="10m",
        max_duration="1h",
        max_alerts=5000,
        baseline_per_min=3,
        rollups=[
            RollupPolicy(label="Password spraying", fingerprint_specs=["agent", "src_ip"], min_leaves=6),
            RollupPolicy(label="Distributed brute force", fingerprint_specs=["agent", "dst_user:clean"], min_leaves=6),
            RollupPolicy(label="Distributed Host Stuffing", fingerprint_specs=["agent"], min_leaves=20)
        ]
    ),
    CategoryPolicy(
        code="account_change",
        domain="Identity & access",
        title="Account or group change",
        specificity_weight=WEIGHT_CREDENTIAL_ACCESS_AUTH,
        match_criteria={
            "rule_groups_any": ["account_changed", "user_management", "group_management"],
            "rule_id_any": [4720, 4722, 4724, 4726, 4738, 4740, 5902]
        },
        fingerprint_specs=["agent", "operation", "dst_user:clean"],
        track_fields=[],
        window="1h",
        max_duration="4h",
        pin_level=12
    ),

    # ── 2. DOMAIN: WEB ────────────────────────────────────────────────────────
    CategoryPolicy(
        code="web_attack",
        domain="Web",
        title="Web attack (SQLi, XSS, Path Traversal, RCE)",
        specificity_weight=WEIGHT_ACTIVE_EXPLOIT_MALWARE,
        match_criteria={
            "rule_groups_any": ["web_attack", "attack", "sqli", "xss", "traversal", "cmd_injection"],
            "rule_id_range": [31101, 31110]
        },
        fingerprint_specs=["agent", "src_ip:true_client", "attack_type"],
        track_fields=["url_path:tmpl"],
        window="10m",
        max_duration="1h",
        pin_level=12,
        rollups=[
            RollupPolicy(label="Multi-Vector Web Attack", fingerprint_specs=["agent", "src_ip:true_client"], min_leaves=5)
        ]
    ),
    CategoryPolicy(
        code="web_error_flood",
        domain="Web",
        title="HTTP 4xx / 5xx burst / Web Reconnaissance Fuzzing",
        specificity_weight=WEIGHT_RECONNAISSANCE_SCAN,
        match_criteria={
            "rule_groups_any": ["web", "accesslog", "web_scan"],
            "rule_id_any": [31151, 31152, 31153, 31154],
            "http_status_class": ["4xx", "5xx"]
        },
        fingerprint_specs=["agent", "src_ip:true_client", "status_class"],
        track_fields=["url_path:tmpl"],
        window="5m",
        max_duration="1h",
        pin_level=12,
        rollups=[
            RollupPolicy(label="Web Resource Fuzzing", fingerprint_specs=["agent", "src_ip:true_client"], min_leaves=10)
        ]
    ),

    # ── 3. DOMAIN: NETWORK ────────────────────────────────────────────────────
    CategoryPolicy(
        code="c2_beacon_session",
        domain="Network",
        title="Command & Control (C2) / Reverse Shell Session",
        specificity_weight=WEIGHT_ACTIVE_EXPLOIT_MALWARE,
        match_criteria={
            "mitre_tactics_any": ["Command and Control"],
            "rule_groups_any": ["reverse_shell", "c2_traffic", "c2_beacon"]
        },
        fingerprint_specs=["agent", "src_ip", "dst_ip", "dst_port"],
        track_fields=[],
        window="15m",
        max_duration="4h",
        pin_level=10,
        rollups=[
            RollupPolicy(label="C2 Beacon Drift", fingerprint_specs=["agent", "dst_ip"], min_leaves=4)
        ]
    ),
    CategoryPolicy(
        code="data_exfiltration",
        domain="Network",
        title="Data Exfiltration / Excessive Outbound Traffic",
        specificity_weight=WEIGHT_ACTIVE_EXPLOIT_MALWARE,
        match_criteria={
            "mitre_tactics_any": ["Exfiltration"],
            "rule_groups_any": ["data_loss", "exfiltration", "large_outbound"]
        },
        fingerprint_specs=["agent", "src_ip", "dst_ip"],
        track_fields=["bytes_out"],
        window="15m",
        max_duration="2h",
        pin_level=10
    ),
    CategoryPolicy(
        code="ioc_match",
        domain="Network",
        title="Threat-intel (IOC) match (MISP / AbuseIPDB / VT)",
        specificity_weight=WEIGHT_ACTIVE_EXPLOIT_MALWARE,
        match_criteria={
            "rule_groups_any": ["threat_intel", "misp_hit", "abuseipdb_hit", "ioc_detected"]
        },
        fingerprint_specs=["agent", "ioc"],
        track_fields=[],
        window="1h",
        max_duration="1d",
        pin_level=12
    ),
    CategoryPolicy(
        code="ids_signature",
        domain="Network",
        title="IDS / IPS signature (Suricata, Snort)",
        specificity_weight=WEIGHT_ACTIVE_EXPLOIT_MALWARE,
        match_criteria={
            "has_field": ["data.alert.signature_id", "network.signature_id"],
            "rule_groups_any": ["ids", "suricata", "snort"]
        },
        fingerprint_specs=["sig_id", "src_ip", "dst_ip"],
        track_fields=["dst_port"],
        window="5m",
        max_duration="1h",
        pin_level=12,
        rollups=[
            RollupPolicy(label="Many sources, one target", fingerprint_specs=["sig_id", "dst_ip"], min_leaves=6)
        ]
    ),
    CategoryPolicy(
        code="dos_flood",
        domain="Network",
        title="Flood / DoS / Volumetric Traffic",
        specificity_weight=WEIGHT_RECONNAISSANCE_SCAN,
        match_criteria={
            "rule_groups_any": ["flood", "dos", "ddos", "connection_rate"]
        },
        fingerprint_specs=["dst_ip", "dst_port", "proto?"],
        track_fields=["src_ip"],
        window="2m",
        max_duration="30m",
        pin_level=12
    ),
    CategoryPolicy(
        code="dns_suspicious",
        domain="Network",
        title="Suspicious DNS / DGA Query",
        specificity_weight=WEIGHT_RECONNAISSANCE_SCAN,
        match_criteria={
            "rule_groups_any": ["dns", "dga", "dns_threat"],
            "rule_id_any": [22, 100022]
        },
        fingerprint_specs=["agent", "domain:d2ld"],
        track_fields=["domain"],
        window="15m",
        max_duration="2h",
        pin_level=12
    ),
    CategoryPolicy(
        code="scan_vertical",
        domain="Network",
        title="Port scan / Network sweep",
        specificity_weight=WEIGHT_RECONNAISSANCE_SCAN,
        match_criteria={
            "rule_groups_any": ["recon", "scan", "portscan"],
            "exclude_groups_any": ["web"]
        },
        fingerprint_specs=["src_ip", "dst_ip"],
        track_fields=["dst_port"],
        window="5m",
        max_duration="1h",
        pin_level=12,
        rollups=[
            RollupPolicy(label="Network sweep (many targets)", fingerprint_specs=["src_ip"], min_leaves=4)
        ]
    ),
    CategoryPolicy(
        code="firewall_deny",
        domain="Network",
        title="Firewall deny / drop",
        specificity_weight=WEIGHT_RECONNAISSANCE_SCAN,
        match_criteria={
            "rule_groups_any": ["firewall_drop", "firewall_deny", "iptables_drop"]
        },
        fingerprint_specs=["src_ip", "dst_ip", "dst_port", "proto?"],
        track_fields=[],
        window="5m",
        max_duration="30m",
        pin_level=12,
        rollups=[
            RollupPolicy(label="Source probing many ports or hosts", fingerprint_specs=["src_ip"], min_leaves=8)
        ]
    ),

    # ── 4. DOMAIN: ENDPOINT ───────────────────────────────────────────────────
    CategoryPolicy(
        code="malware",
        domain="Endpoint",
        title="Malware detection (AV / YARA / Rootkit)",
        specificity_weight=WEIGHT_ACTIVE_EXPLOIT_MALWARE,
        match_criteria={
            "rule_groups_any": ["malware", "virustotal", "yara", "clamav", "rootkit"]
        },
        fingerprint_specs=["agent", "file_hash"],
        track_fields=["file_path"],
        window="15m",
        max_duration="4h",
        pin_level=12
    ),
    CategoryPolicy(
        code="lolbin_script",
        domain="Endpoint",
        title="Script / LOLBin execution (PowerShell, certutil, mshta)",
        specificity_weight=WEIGHT_ACTIVE_EXPLOIT_MALWARE,
        match_criteria={
            "rule_groups_any": ["encoded_powershell", "lolbin", "certutil", "mshta", "rundll32"],
            "mitre_techniques_any": ["T1059.001", "T1218"]
        },
        fingerprint_specs=["agent", "process", "cmd:cmd", "src_user:clean?"],
        track_fields=[],
        window="10m",
        max_duration="2h",
        pin_level=12
    ),
    CategoryPolicy(
        code="suspicious_process",
        domain="Endpoint",
        title="Suspicious process creation (Sysmon 1 / Auditd)",
        specificity_weight=WEIGHT_SYSTEM_INTEGRITY,
        match_criteria={
            "rule_groups_any": ["sysmon_event1", "process_creation", "execve"],
            "level_gte": 7
        },
        fingerprint_specs=["agent", "process_hash", "src_user:clean"],
        track_fields=["cmd:cmd"],
        window="10m",
        max_duration="2h",
        pin_level=12
    ),
    CategoryPolicy(
        code="persistence",
        domain="Endpoint",
        title="Persistence change (cron, systemd, run key)",
        specificity_weight=WEIGHT_SYSTEM_INTEGRITY,
        match_criteria={
            "rule_groups_any": ["persistence", "run_key", "cron_modified", "systemd_unit"],
            "mitre_tactics_any": ["Persistence"]
        },
        fingerprint_specs=["agent", "ptype", "object"],
        track_fields=[],
        window="1h",
        max_duration="8h",
        pin_level=12
    ),
    CategoryPolicy(
        code="fim_change",
        domain="Endpoint",
        title="File integrity change (Syscheck)",
        specificity_weight=WEIGHT_SYSTEM_INTEGRITY,
        match_criteria={
            "rule_groups_any": ["syscheck"]
        },
        fingerprint_specs=["agent", "file_path", "fim_event"],
        track_fields=["file_path"],
        window="10m",
        max_duration="2h",
        pin_level=12,
        rollups=[
            RollupPolicy(label="Bulk change in directory", fingerprint_specs=["agent", "file_path:dir"], min_leaves=10)
        ]
    ),
    CategoryPolicy(
        code="rootcheck",
        domain="Endpoint",
        title="Rootcheck anomaly (Scan cycle finding)",
        specificity_weight=WEIGHT_SYSTEM_INTEGRITY,
        match_criteria={
            "rule_groups_any": ["rootcheck"]
        },
        fingerprint_specs=["agent", "title"],
        track_fields=[],
        window="12h",
        max_duration="2d",
        pin_level=12,
        is_state_type=True
    ),
    CategoryPolicy(
        code="log_tamper",
        domain="Endpoint",
        title="Log cleared / Audit service stopped",
        specificity_weight=WEIGHT_SYSTEM_INTEGRITY,
        match_criteria={
            "rule_groups_any": ["auditd_stopped", "syslog_stopped", "log_cleared"],
            "rule_id_any": [1102]
        },
        fingerprint_specs=["agent", "log_source", "operation"],
        track_fields=[],
        window="1h",
        max_duration="4h",
        pin_level=10
    ),
    CategoryPolicy(
        code="agent_health",
        domain="Endpoint",
        title="Agent disconnected / stopped",
        specificity_weight=WEIGHT_COMPLIANCE_POLICY,
        match_criteria={
            "rule_groups_any": ["ossec", "agent_status", "agent_disconnected"]
        },
        fingerprint_specs=["agent", "health_event"],
        track_fields=[],
        window="30m",
        max_duration="1d",
        pin_level=12
    ),

    # ── 5. DOMAIN: POSTURE ────────────────────────────────────────────────────
    CategoryPolicy(
        code="vuln_detected",
        domain="Posture",
        title="Vulnerability detected (CVE Scan)",
        specificity_weight=WEIGHT_COMPLIANCE_POLICY,
        match_criteria={
            "rule_groups_any": ["vulnerability-detector"]
        },
        fingerprint_specs=["agent", "cve", "package"],
        track_fields=[],
        window="36h",
        max_duration="14d",
        pin_level=12,
        is_state_type=True
    ),
    CategoryPolicy(
        code="sca_failed",
        domain="Posture",
        title="Benchmark check failed (SCA / CIS Benchmark)",
        specificity_weight=WEIGHT_COMPLIANCE_POLICY,
        match_criteria={
            "rule_groups_any": ["sca"],
            "sca_result": "failed"
        },
        fingerprint_specs=["agent", "policy", "check_id"],
        track_fields=[],
        window="36h",
        max_duration="14d",
        pin_level=12,
        is_state_type=True,
        rollups=[
            RollupPolicy(label="Benchmark drift (many checks)", fingerprint_specs=["agent", "policy"], min_leaves=5)
        ]
    ),
    CategoryPolicy(
        code="policy_violation",
        domain="Posture",
        title="Policy violation (Compliance PCI DSS / GDPR)",
        specificity_weight=WEIGHT_COMPLIANCE_POLICY,
        match_criteria={
            "rule_groups_any": ["pci_dss", "gdpr", "hipaa", "nist_800_53", "compliance"]
        },
        fingerprint_specs=["agent", "policy_group", "src_user:clean?"],
        track_fields=[],
        window="30m",
        max_duration="4h",
        pin_level=12
    ),

    # ── 6. DOMAIN: CLOUD & SAAS ───────────────────────────────────────────────
    CategoryPolicy(
        code="cloud_api_denied",
        domain="Cloud & SaaS",
        title="Cloud API denied / Unauthorized access",
        specificity_weight=WEIGHT_CREDENTIAL_ACCESS_AUTH,
        match_criteria={
            "rule_groups_any": ["cloudtrail", "gcp_audit", "azure_audit"],
            "error_code_any": ["AccessDenied", "Unauthorized", "Forbidden"]
        },
        fingerprint_specs=["principal", "service", "api", "err"],
        track_fields=["src_ip"],
        window="15m",
        max_duration="2h",
        pin_level=12,
        rollups=[
            RollupPolicy(label="API enumeration", fingerprint_specs=["principal"], min_leaves=6)
        ]
    ),
    CategoryPolicy(
        code="cloud_iam_change",
        domain="Cloud & SaaS",
        title="Cloud IAM / Config change",
        specificity_weight=WEIGHT_SYSTEM_INTEGRITY,
        match_criteria={
            "rule_groups_any": ["cloud_iam", "role_modified", "policy_attached"]
        },
        fingerprint_specs=["principal", "api", "resource"],
        track_fields=[],
        window="30m",
        max_duration="4h",
        pin_level=10
    ),
    CategoryPolicy(
        code="cloud_login_failed",
        domain="Cloud & SaaS",
        title="Console / SaaS login failure (AWS Console / Okta / O365)",
        specificity_weight=WEIGHT_CREDENTIAL_ACCESS_AUTH,
        match_criteria={
            "rule_groups_any": ["console_login_failed", "okta_auth_failed", "o365_login_failed"]
        },
        fingerprint_specs=["principal", "src_ip"],
        track_fields=[],
        window="15m",
        max_duration="2h",
        pin_level=12
    ),
    CategoryPolicy(
        code="saas_audit",
        domain="Cloud & SaaS",
        title="SaaS admin activity audit",
        specificity_weight=WEIGHT_COMPLIANCE_POLICY,
        match_criteria={
            "rule_groups_any": ["saas_audit", "o365_admin", "github_audit"]
        },
        fingerprint_specs=["actor", "operation", "src_ip?"],
        track_fields=[],
        window="30m",
        max_duration="4h",
        pin_level=12
    ),

    # ── 7. DOMAIN: CONTAINERS ─────────────────────────────────────────────────
    CategoryPolicy(
        code="container_runtime",
        domain="Containers",
        title="Container runtime event (Docker / K8s)",
        specificity_weight=WEIGHT_SYSTEM_INTEGRITY,
        match_criteria={
            "rule_groups_any": ["docker", "k8s_audit", "container_security", "container_exec"]
        },
        fingerprint_specs=["agent", "container", "action"],
        track_fields=[],
        window="10m",
        max_duration="2h",
        pin_level=12
    ),

    # ── 8. DOMAIN: FALLBACK ───────────────────────────────────────────────────
    CategoryPolicy(
        code="generic_rule",
        domain="Fallback",
        title="Unclassified (Fallback)",
        specificity_weight=WEIGHT_GENERIC_FALLBACK,
        match_criteria={},
        fingerprint_specs=["rule_id", "agent"],
        track_fields=[],
        window="10m",
        max_duration="1h",
        pin_level=12
    )
]

# ── Evaluator Helper: Predicate Matching ───────────────────────────────────────
def match_alert_against_criteria(alert: Dict[str, Any], criteria: Dict[str, Any]) -> bool:
    """
    Evaluates an alert against structured criteria using O(1) set intersections.
    All criteria defined in the dict must evaluate to True (Logical AND).
    """
    if not criteria:
        return True

    # Rule groups match (case-insensitive)
    rule_groups_raw = alert.get("rule", {}).get("groups") or alert.get("rule_groups") or []
    alert_groups = {str(g).lower().strip() for g in rule_groups_raw}

    if "exclude_groups_any" in criteria:
        excluded = {str(g).lower().strip() for g in criteria["exclude_groups_any"]}
        if alert_groups.intersection(excluded):
            return False

    if "rule_groups_any" in criteria:
        required = {str(g).lower().strip() for g in criteria["rule_groups_any"]}
        if not alert_groups.intersection(required):
            return False

    # Rule ID match
    rule_id_raw = alert.get("rule", {}).get("id") or alert.get("rule_id")
    rule_id = int(rule_id_raw) if rule_id_raw is not None and str(rule_id_raw).isdigit() else 0

    if "rule_id_any" in criteria:
        if rule_id not in criteria["rule_id_any"]:
            return False

    if "rule_id_range" in criteria:
        r_min, r_max = criteria["rule_id_range"]
        if not (r_min <= rule_id <= r_max):
            return False

    # MITRE Tactics match
    mitre_tactics_raw = alert.get("rule", {}).get("mitre", {}).get("tactics") or alert.get("mitre_tactics") or []
    alert_tactics = {str(t).lower().strip() for t in mitre_tactics_raw}
    if "mitre_tactics_any" in criteria:
        required_tactics = {str(t).lower().strip() for t in criteria["mitre_tactics_any"]}
        if not alert_tactics.intersection(required_tactics):
            return False

    # MITRE Techniques match
    mitre_tech_raw = alert.get("rule", {}).get("mitre", {}).get("techniques") or alert.get("mitre_techniques") or []
    alert_tech = {str(t).upper().strip() for t in mitre_tech_raw}
    if "mitre_techniques_any" in criteria:
        required_tech = {str(t).upper().strip() for t in criteria["mitre_techniques_any"]}
        if not alert_tech.intersection(required_tech):
            return False

    # Severity Level
    rule_level = alert.get("rule", {}).get("level") or alert.get("rule_level") or 0
    if "level_gte" in criteria:
        if rule_level < criteria["level_gte"]:
            return False
    if "level_lte" in criteria:
        if rule_level > criteria["level_lte"]:
            return False

    # HTTP Status Class (e.g. 4xx, 5xx)
    if "http_status_class" in criteria:
        status_code = alert.get("http", {}).get("status_code") or alert.get("http_status")
        if status_code is not None:
            sc_prefix = f"{str(status_code)[0]}xx"
            if sc_prefix not in criteria["http_status_class"]:
                return False
        else:
            return False

    # Field Existence
    if "has_field" in criteria:
        fields = criteria["has_field"]
        if isinstance(fields, str):
            fields = [fields]
        for f in fields:
            parts = f.split(".")
            curr = alert
            found = True
            for p in parts:
                if isinstance(curr, dict) and p in curr:
                    curr = curr[p]
                else:
                    found = False
                    break
            if not found or curr in (None, "", []):
                return False

    return True


# ── Classifier Function (Layered Specificity First Match Wins) ────────────────
def classify_alert(alert: Dict[str, Any]) -> CategoryPolicy:
    """
    Classifies a normalized alert into exactly one CategoryPolicy.
    Evaluates categories sorted by specificity_weight descending.
    First match wins on the highest tier.
    """
    # Sort categories by specificity_weight descending
    sorted_catalog = sorted(APEX_32_CATEGORIES, key=lambda c: c.specificity_weight, reverse=True)

    for policy in sorted_catalog:
        if policy.code == "generic_rule":
            continue
        if match_alert_against_criteria(alert, policy.match_criteria):
            return policy

    # Fallback policy
    return next(c for c in APEX_32_CATEGORIES if c.code == "generic_rule")
