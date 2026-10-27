"""
Stage 1: Cluster v1 Architecture (Smart Sampling, Deterministic Keys, High-Value Bypass, Forensics)
Collapses High-Frequency Repetitive Burst Events into Actionable Aggregated Objects (Clusters)
Preserving 100% Relational Links via Smart Evidence Sampling (max 50) and Wazuh Query Pointers.
Deterministic, Idempotent, Linux-focused SIEM Clustering Layer.
"""
import os
import hashlib
import uuid
import json
import ipaddress
import re
from typing import Dict, Any, List, Optional, Tuple, Set
from datetime import datetime, timezone, timedelta
from dateutil import parser as dt_parser
from collections import defaultdict, Counter

from pipeline.models import CommonEventModel, AggregatedAlertDB, AggregateEvidenceMappingDB
from config.settings import BASE_DIR, PERSISTENCE_DIR

# ── Load Centralized Cluster v1 Configuration ──────────────────────────────────
CLUSTER_CONFIG_PATH = BASE_DIR / "config" / "cluster_config.json"
_DEFAULT_CLUSTER_CONFIG = {
    "window_size_seconds": 900,
    "grace_period_seconds": 120,
    "late_arriving_cutoff_hours": 24,
    "max_distinct_paths_per_prefix": 20,
    "max_keys_per_actor_window": 200,
    "rate_limit_routine_seconds": 60,
    "max_material_updates_per_min": 5,
    "unparsed_threshold_pct": 5.0,
    "pkg_context_window_seconds": 300,
    "evidence_sample_cap": 50,
    "cold_snapshot_enabled": True,
    "os_target": "linux",
    "trusted_proxies_by_tenant": {
        "DEFAULT": ["127.0.0.1", "::1"]
    },
    "privileged_accounts_by_tenant": {
        "DEFAULT": ["root", "admin", "administrator", "ubuntu", "wheel", "domain_admins", "svc-*"]
    },
    "known_admin_ips_by_tenant": {
        "DEFAULT": []
    },
    "exploit_threat_categories": [
        "SQLI", "TRAVERSAL", "WEBSHELL", "COMMAND_INJECTION", "CVE_EXPLOIT"
    ],
    "critical_fim_paths": [
        "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/etc/shadow", "/etc/passwd",
        "/etc/sudoers", "/etc/ssh/sshd_config", "/etc/crontab", "/etc/cron.", "/etc/systemd/system"
    ]
}

def load_cluster_config() -> Dict[str, Any]:
    if os.path.exists(CLUSTER_CONFIG_PATH):
        try:
            with open(CLUSTER_CONFIG_PATH, "r", encoding="utf-8") as f:
                cfg = json.load(f)
                merged = dict(_DEFAULT_CLUSTER_CONFIG)
                merged.update(cfg)
                return merged
        except Exception:
            pass
    return dict(_DEFAULT_CLUSTER_CONFIG)

CLUSTER_CONFIG = load_cluster_config()




def generate_deterministic_alert_id(
    manager_node: str,
    wazuh_alert_id: str,
    event_timestamp_raw: str
) -> str:
    raw_str = f"{manager_node or 'mgr_default'}|{wazuh_alert_id or 'none'}|{event_timestamp_raw or '0'}"
    return hashlib.sha256(raw_str.encode("utf-8")).hexdigest()


# ── Network & Actor Subnet Aggregation ─────────────────────────────────────────
def normalize_actor_subnet(ip_str: Optional[str], is_external_auth_success: bool = False) -> str:
    if not ip_str or not isinstance(ip_str, str):
        return "none"
    ip_clean = ip_str.strip()
    if is_external_auth_success:
        return ip_clean

    try:
        ip = ipaddress.ip_address(ip_clean)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return str(ip)
        if isinstance(ip, ipaddress.IPv4Address):
            net = ipaddress.ip_network(f"{ip}/24", strict=False)
            return str(net)
        elif isinstance(ip, ipaddress.IPv6Address):
            net = ipaddress.ip_network(f"{ip}/64", strict=False)
            return str(net)
        return str(ip)
    except Exception:
        return ip_clean


def extract_client_ip_anti_spoofing(
    remote_addr: str,
    xff_header: Optional[str],
    trusted_proxies: List[str]
) -> str:
    if not remote_addr:
        return "none"
    remote_addr_clean = remote_addr.strip()
    
    is_trusted = False
    for p in trusted_proxies:
        p_clean = p.strip()
        if "/" in p_clean:
            try:
                if ipaddress.ip_address(remote_addr_clean) in ipaddress.ip_network(p_clean, strict=False):
                    is_trusted = True
                    break
            except Exception:
                pass
        elif remote_addr_clean == p_clean:
            is_trusted = True
            break

    if not is_trusted or not xff_header:
        return remote_addr_clean

    parts = [x.strip() for x in xff_header.split(",") if x.strip()]
    for candidate in reversed(parts):
        cand_trusted = False
        for p in trusted_proxies:
            p_clean = p.strip()
            if "/" in p_clean:
                try:
                    if ipaddress.ip_address(candidate) in ipaddress.ip_network(p_clean, strict=False):
                        cand_trusted = True
                        break
                except Exception:
                    pass
            elif candidate == p_clean:
                cand_trusted = True
                break
        if not cand_trusted:
            return candidate

    return remote_addr_clean


def extract_ua_family(ua_str: Optional[str]) -> str:
    """Classify User-Agent string into families for actor campaign clustering."""
    if not ua_str or not isinstance(ua_str, str):
        return "none"
    ua = ua_str.lower()
    if "curl" in ua: return "Curl"
    if "python-requests" in ua: return "Python-Requests"
    if "sqlmap" in ua: return "Sqlmap"
    if "nikto" in ua: return "Nikto"
    if "nmap" in ua: return "Nmap"
    if "gobuster" in ua: return "Gobuster"
    if "dirbuster" in ua: return "Dirbuster"
    if "wpscan" in ua: return "WPScan"
    if "chrome" in ua and "safari" in ua: return "Chrome"
    if "firefox" in ua: return "Firefox"
    if "safari" in ua and "chrome" not in ua: return "Safari"
    if "edge" in ua: return "Edge"
    return "Other"

# ── High-Value Deterministic Rule Evaluator ───────────────────────────────────
_RE_EXPLOIT_SIGNATURE = re.compile(
    r'(?i)(\.\./|\.\.\\|union\s+select|select\s+.*\s+from|base64_decode|<script|eval\(|\bcmd=\b|/etc/passwd|/cgi-bin/|\.env|\bphpinfo\b)',
    re.IGNORECASE
)

def evaluate_source_type(event: Any) -> str:
    """
    Classify telemetry origin into explicit first-class source_type:
    ('web', 'auth', 'fim', 'sca', 'vuln', 'system', 'malware')
    Eliminates guesswork in downstream Category and Correlation stages.
    """
    rule_id = str(getattr(event, "rule_id", "0"))
    groups = getattr(event, "classification_groups", []) or []
    groups_lower = [str(g).lower() for g in groups]
    desc = str(getattr(event, "rule_description", "")).lower()
    full_log = str(getattr(event, "raw_payload", "") or getattr(event, "full_log", "")).lower()

    if any(g in ("vulnerability-detector", "vulnerability") for g in groups_lower) or "cve-" in desc:
        return "vuln"
    if "sca" in groups_lower or "compliance" in groups_lower:
        return "sca"
    if "syscheck" in groups_lower or "integrity" in groups_lower or rule_id in ("550", "554"):
        return "fim"
    if any(g in ("malware", "rootcheck", "yara") for g in groups_lower) or any(k in desc for k in ("trojan", "ransomware", "backdoor", "rootkit")):
        return "malware"
    if any(g in ("web", "accesslog", "apache", "nginx") for g in groups_lower) or "http/" in full_log:
        return "web"
    if any(g in ("authentication_failed", "authentication_success", "sshd", "pam", "login") for g in groups_lower) or rule_id in ("5710", "5715", "5716", "5501", "100020"):
        return "auth"
    return "system"

def evaluate_high_value_event(
    event: Any,
    tenant_config: Optional[Dict[str, Any]] = None,
    recent_pkg_activity: bool = False
) -> Tuple[bool, Optional[str], str, bool]:
    """
    Determines if an event is High-Value with Linux-hardened deterministic checks.
    IMPORTANT: Cluster ONLY produces success_indicator = 'none' or 'possible'.
    Status 'confirmed' is strictly reserved for the Correlation Stage!
    Returns (is_high_value, bypass_reason, success_indicator, pkg_activity_nearby)
    """
    tenant_id = getattr(event, "tenant_id", "DEFAULT") or "DEFAULT"
    rule_id = str(getattr(event, "rule_id", "0"))
    rule_level = int(getattr(event, "rule_level", 0) or 0)
    groups = getattr(event, "classification_groups", []) or []
    groups_lower = [str(g).lower() for g in groups]
    rule_desc = str(getattr(event, "rule_description", "") or "").lower()
    full_log = str(getattr(event, "raw_payload", "") or getattr(event, "full_log", "") or "").lower()
    username = str(getattr(event, "username", "") or "").lower()
    src_ip = getattr(event, "source_ip", None) or ""
    http_status = getattr(event, "http_status", None)

    priv_list = CLUSTER_CONFIG["privileged_accounts_by_tenant"].get(
        tenant_id, CLUSTER_CONFIG["privileged_accounts_by_tenant"]["DEFAULT"]
    )
    admin_ips = CLUSTER_CONFIG["known_admin_ips_by_tenant"].get(
        tenant_id, CLUSTER_CONFIG["known_admin_ips_by_tenant"]["DEFAULT"]
    )

    is_external_ip = False
    if src_ip:
        try:
            ip = ipaddress.ip_address(src_ip)
            is_external_ip = not (ip.is_private or ip.is_loopback or ip.is_link_local) and (src_ip not in admin_ips)
        except Exception:
            is_external_ip = True

    # 1. Privileged Auth Success from External IP
    is_auth_success = (
        rule_id in ("5715", "5501", "100020", "5716") or
        "accepted password" in full_log or "session opened" in full_log or "authentication succeeded" in rule_desc
    )
    is_priv_user = any(
        username == p or (p.endswith("*") and username.startswith(p[:-1]))
        for p in priv_list
    )
    if is_auth_success and is_priv_user and is_external_ip:
        return True, "privileged_external_auth_success", "possible", False

    # 2. Malware Signature / YARA Hit
    is_malware = any(g in ("malware", "rootcheck", "syscheck_integrity", "yara") for g in groups_lower) or \
                 any(k in rule_desc for k in ("trojan", "ransomware", "backdoor", "yara", "rootkit"))
    if is_malware and ("yara" in rule_desc or "trojan" in rule_desc or "ransomware" in rule_desc or "backdoor" in rule_desc):
        return True, "malware_signature_hit", "possible", False

    # 3. Wazuh Rootcheck
    if "rootcheck" in groups_lower or "rootcheck" in str(getattr(event, "location", "")).lower():
        return True, "rootcheck_kernel_tamper", "possible", False

    # 4. Critical FIM Path
    file_path = str(getattr(event, "clean_path", "") or getattr(event, "url_path", "") or "")
    if not file_path:
        for cp in CLUSTER_CONFIG["critical_fim_paths"]:
            if cp in full_log:
                file_path = cp
                break

    is_fim = "syscheck" in groups_lower or "integrity" in groups_lower or rule_id in ("550", "554")
    if is_fim and file_path:
        for crit in CLUSTER_CONFIG["critical_fim_paths"]:
            if file_path.startswith(crit) or crit in file_path:
                return True, "critical_fim_modification", "possible", recent_pkg_activity

    # 5. Exploit Attempt Evaluation
    is_exploit = any(cat in str(getattr(event, "action_ttp", "")).upper() for cat in CLUSTER_CONFIG["exploit_threat_categories"]) or \
                 _RE_EXPLOIT_SIGNATURE.search(full_log) is not None or \
                 _RE_EXPLOIT_SIGNATURE.search(file_path) is not None or \
                 rule_id in ("31104", "31106", "31514", "31430")

    if is_exploit:
        if http_status == 200:
            return False, "exploit_attempt_http_200", "possible", False
        else:
            return False, "exploit_attempt_blocked", "none", False

    return False, None, "none", False


# ── Composite Cluster Key Generator (SHA-256 + Window Bucket) ─────────────────
def calculate_composite_cluster_key(event: Any, window_bucket_epoch: Optional[int] = None) -> Tuple[str, str, str, str]:
    """
    Standard Composite Key Layer (SHA-256, Zero-Collision):
    Formula: Tenant + Rule_ID + Agent + [Who] + [What] + [Window_Bucket]
    Target is excluded from key (tracked as distinct_targets[]) to avoid key explosion.
    For CVE, SCA, and FIM: Who is explicitly set to 'NO_ACTOR'.
    """
    tenant = getattr(event, "tenant_id", "DEFAULT") or "DEFAULT"
    rule_id = str(getattr(event, "rule_id", "0"))
    agent = getattr(event, "agent_name", None) or getattr(event, "agent_id", "none") or "none"
    src_type = evaluate_source_type(event)

    # Who Dimension
    if src_type in ("vuln", "sca", "fim"):
        who = "NO_ACTOR"
    else:
        who_raw = getattr(event, "who_cluster", None) or getattr(event, "who_subnet", None) or getattr(event, "source_ip", None) or agent
        who = normalize_actor_subnet(str(who_raw))
    
    # What Dimension
    what_raw = getattr(event, "what_cluster", None) or getattr(event, "clean_path", None) or getattr(event, "event_type", None) or rule_id
    what = str(what_raw).strip() or rule_id

    # Stateful session preservation: incorporate username for auth & user session lifecycle
    username = getattr(event, "username", None)
    if username and (src_type == "auth" or getattr(event, "target_category", None) == "User_Management"):
        what = f"{what}:user={username}"
    
    win_part = str(window_bucket_epoch) if window_bucket_epoch is not None else "0"
    raw_key = f"{tenant}|{rule_id}|{agent}|{who}|{what}|{win_part}"
    sha256_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
    return raw_key, sha256_hash, str(who), str(what)


# ── Smart Evidence Tracker (Max 50 Samples) ───────────────────────────────────
class SmartEvidenceTracker:
    def __init__(self, capacity: int = 50):
        self.capacity = capacity
        self.head_samples: List[Dict[str, Any]] = []
        self.tail_samples: List[Dict[str, Any]] = []
        self.highest_severity_samples: List[Dict[str, Any]] = []
        self.distinct_path_samples: List[Dict[str, Any]] = []
        self.seen_paths: Set[str] = set()

    def add_sample(
        self,
        event_id: str,
        event_time: datetime,
        rule_id: int,
        rule_level: int,
        source_ip: Optional[str],
        clean_path: Optional[str],
        http_status: Optional[int]
    ):
        entry = {
            "event_id": event_id,
            "timestamp": event_time.isoformat(),
            "rule_id": rule_id,
            "rule_level": rule_level,
            "source_ip": source_ip or "none",
            "clean_path": clean_path or "/",
            "http_status": http_status
        }
        if len(self.head_samples) < 15:
            self.head_samples.append(entry)

        self.tail_samples.append(entry)
        if len(self.tail_samples) > 15:
            self.tail_samples.pop(0)

        if rule_level >= 5:
            self.highest_severity_samples.append(entry)
            self.highest_severity_samples.sort(key=lambda x: x["rule_level"], reverse=True)
            if len(self.highest_severity_samples) > 10:
                self.highest_severity_samples.pop()

        p = clean_path or "/"
        if p not in self.seen_paths and len(self.distinct_path_samples) < 10:
            self.seen_paths.add(p)
            self.distinct_path_samples.append(entry)

    def get_combined_samples(self) -> List[Dict[str, Any]]:
        combined: Dict[str, Dict[str, Any]] = {}
        for item in self.head_samples + self.tail_samples + self.highest_severity_samples + self.distinct_path_samples:
            eid = item["event_id"]
            if eid not in combined:
                combined[eid] = item
                if len(combined) >= self.capacity:
                    break
        return list(combined.values())


# ── Aggregated Window (Cluster Object) ─────────────────────────────────────────
class AggregatedWindow:
    def __init__(
        self,
        aggregation_id: str,
        dedup_key: str,
        rule_id: int,
        agent_id: str,
        source_ip: Optional[str],
        destination_ip: Optional[str],
        username: Optional[str],
        start_time: datetime,
        window_duration: timedelta,
        tenant_id: str = "DEFAULT",
        category: str = "SYSTEM_HEALTH",
        actor: Optional[str] = None,
        target: Optional[str] = None,
        rule_description: Optional[str] = None,
        ioa_summary: Optional[str] = None,
        os_platform: str = "unknown",
        log_source: Optional[str] = None,
        extracted_iocs: Optional[Dict[str, Any]] = None,
        composite_key: Optional[str] = None,
        who: Optional[str] = None,
        what: Optional[str] = None,
        primary_category: Optional[str] = None,
        subcategory: Optional[str] = None,
        disposition: Optional[str] = None,
        confidence_score: Optional[int] = None,
        domain: Optional[str] = None,
        target_category: Optional[str] = None,
        action_ttp: Optional[str] = None,
        lifecycle_role: Optional[str] = None,
        is_high_value: bool = False,
        bypass_reason: Optional[str] = None,
        success_indicator: str = "none",
        external_auth_success: bool = False,
        pkg_activity_nearby: bool = False,
        parent_cluster_id: Optional[str] = None,
        is_backfill: bool = False,
        source_type: str = "system",
        suppression_class: Optional[str] = "S2_DEDUPLICATION",
    ):
        self.aggregation_id = aggregation_id
        self.dedup_key = dedup_key
        self.rule_id = rule_id
        self.rule_description = rule_description
        self.agent_id = agent_id
        self.source_ip = source_ip
        self.exact_source_ip = source_ip
        self.destination_ip = destination_ip
        self.username = username
        self.tenant_id = tenant_id
        self.category = category
        self.actor = actor or source_ip or f"agent:{agent_id}"
        self.target = target or username or destination_ip or f"agent:{agent_id}"
        self.source_type = source_type
        self.suppression_class = suppression_class or "S2_DEDUPLICATION"
        self.target_counter: Counter = Counter()
        if self.target:
            self.target_counter[self.target] += 1
        self.user_agent_counter: Counter = Counter()
        self.ioa_summary = ioa_summary
        self.os_platform = os_platform
        self.composite_key = composite_key or dedup_key
        self.who = who or actor or source_ip or f"agent:{agent_id}"
        self.what = what or str(rule_id)
        self.domain = domain or primary_category or "SYSTEM"
        self.target_category = target_category or "Host_Telemetry"
        self.action_ttp = action_ttp or subcategory or "General"
        self.lifecycle_role = lifecycle_role or "STATELESS"
        self.primary_category = self.domain
        self.subcategory = self.action_ttp
        self.disposition = disposition or "SAFE"
        self.confidence_score = confidence_score or 50
        self.log_source = log_source

        self.is_high_value = is_high_value
        self.bypass_reason = bypass_reason
        self.success_indicator = success_indicator
        self.external_auth_success = external_auth_success
        self.pkg_activity_nearby = pkg_activity_nearby
        self.parent_cluster_id = parent_cluster_id
        self.is_backfill = is_backfill

        self.has_emitted_open: bool = False
        self.last_routine_forward_time: Optional[datetime] = None
        self.material_updates_count_minute: int = 0
        self.new_ip_updates_count_minute: int = 0
        self.current_minute_bucket: Optional[str] = None

        self.smart_tracker = SmartEvidenceTracker(capacity=CLUSTER_CONFIG["evidence_sample_cap"])
        self.distinct_src_ips: Set[str] = set()
        if source_ip:
            self.distinct_src_ips.add(source_ip)

        self.distinct_ioas: Set[str] = set()
        if ioa_summary:
            self.distinct_ioas.add(ioa_summary)
        self.distinct_iocs: Set[str] = set()
        if source_ip and not source_ip.startswith(('10.', '172.16.', '192.168.', '127.')):
            self.distinct_iocs.add(f"ipv4:{source_ip}")

        self.window_start = start_time
        self.window_duration = window_duration
        self.window_duration_seconds = int(window_duration.total_seconds())
        self.window_end = start_time + window_duration
        self.first_seen_event_time = start_time
        self.last_seen_event_time = start_time
        self.event_count = 1
        self.max_inline_risk_score: int = 0
        self.max_rule_level: int = 0
        self.ocsf_severity_id: Optional[int] = None
        self.raw_evidence: List[Tuple[str, datetime]] = []
        self.status = "ACTIVE_EMITTED" if is_high_value else "OPEN"

        self.http_statuses: Counter = Counter()
        self.path_counter: Counter = Counter()
        self.rule_id_counter: Counter = Counter([rule_id])
        self.scanner_ua_detected: bool = False
        self.classification_groups: List[str] = []
        self.mitre_tactics: List[str] = []

    def add_event(
        self,
        event_id: str,
        event_time: datetime,
        rule_level: int = 0,
        rule_id: int = 0,
        ioa_summary: Optional[str] = None,
        inline_risk_score: Optional[int] = None,
        ocsf_severity_id: Optional[int] = None,
        extracted_iocs: Optional[Dict[str, Any]] = None,
        log_source: Optional[str] = None,
        http_status: Optional[int] = None,
        is_scanner_ua: bool = False,
        source_ip: Optional[str] = None,
        clean_path: Optional[str] = None,
        mitre_tactics: Optional[List[str]] = None,
        target: Optional[str] = None,
        user_agent: Optional[str] = None,
        is_material_update: bool = False
    ) -> bool:
        self.event_count += 1
        self.last_seen_event_time = max(self.last_seen_event_time, event_time)
        if event_time < self.first_seen_event_time:
            self.first_seen_event_time = event_time

        if target:
            self.target_counter[target] += 1
        if user_agent:
            self.user_agent_counter[extract_ua_family(user_agent)] += 1
        if http_status is not None:
            self.http_statuses[http_status] += 1
        if clean_path:
            self.path_counter[clean_path] += 1
        if rule_id:
            self.rule_id_counter[rule_id] += 1
        if is_scanner_ua:
            self.scanner_ua_detected = True

        if source_ip:
            self.distinct_src_ips.add(source_ip)

        self.smart_tracker.add_sample(
            event_id=event_id,
            event_time=event_time,
            rule_id=rule_id or self.rule_id,
            rule_level=rule_level,
            source_ip=source_ip or self.source_ip,
            clean_path=clean_path,
            http_status=http_status
        )

        if mitre_tactics:
            for t in mitre_tactics:
                if t and t not in self.mitre_tactics:
                    self.mitre_tactics.append(t)

        if rule_level > self.max_rule_level:
            self.max_rule_level = rule_level

        if inline_risk_score is not None and inline_risk_score > self.max_inline_risk_score:
            self.max_inline_risk_score = inline_risk_score
        if ocsf_severity_id is not None:
            if self.ocsf_severity_id is None or ocsf_severity_id > self.ocsf_severity_id:
                self.ocsf_severity_id = ocsf_severity_id

        self.raw_evidence.append((event_id, event_time))
        return is_material_update

    def is_expired(self, current_time: datetime, grace_seconds: int = 120) -> bool:
        # Standard forward expiration past window end + grace
        if current_time > (self.window_end + timedelta(seconds=grace_seconds)):
            return True
        # Anti-Time-Travel Guard: If event is older than window start minus grace, close active window
        if current_time < (self.window_start - timedelta(seconds=grace_seconds)):
            return True
        return False

    def is_stale_for_eviction(self, current_time: datetime) -> bool:
        if current_time > (self.window_end + self.window_duration):
            return True
        if current_time < (self.window_start - self.window_duration):
            return True
        return False

    def should_forward_bypass(
        self,
        current_time: datetime,
        is_material: bool = False,
        is_priority_material: bool = False,
        is_new_ip: bool = False
    ) -> bool:
        if not self.has_emitted_open:
            self.has_emitted_open = True
            self.last_routine_forward_time = current_time
            return True

        # Priority Material Updates (severity jump, external auth success, exploit possible, high-value upgrade)
        # MUST be forwarded immediately (seketika)!
        if is_priority_material:
            return True

        # New IP additions are rate-limited to 5/min to throttle botnet/DDoS flood without stalling priority updates
        if is_new_ip:
            min_bucket = current_time.strftime("%Y-%m-%d %H:%M")
            if min_bucket != self.current_minute_bucket:
                self.current_minute_bucket = min_bucket
                self.new_ip_updates_count_minute = 0

            max_new_ips = CLUSTER_CONFIG.get("max_new_ip_updates_per_min", CLUSTER_CONFIG.get("max_material_updates_per_min", 5))
            if self.new_ip_updates_count_minute < max_new_ips:
                self.new_ip_updates_count_minute += 1
                return True

        # Fallback material update check if called with legacy is_material flag
        if is_material and not is_new_ip and not is_priority_material:
            return True
            
        routine_sec = CLUSTER_CONFIG.get("rate_limit_routine_seconds", 60)
        if self.last_routine_forward_time is None or (current_time - self.last_routine_forward_time).total_seconds() >= routine_sec:
            self.last_routine_forward_time = current_time
            return True

        return False


# ── Sliding Window Aggregator Engine ──────────────────────────────────────────
class SlidingWindowAggregator:
    def __init__(self, config_path: Optional[str] = None):
        self.rules_config: Dict[str, Any] = {}
        if config_path is None:
            config_path = str(BASE_DIR / "config" / "aggregation_rules.json")

        self.cluster_config = CLUSTER_CONFIG
        self.default_window_seconds = self.cluster_config.get("window_size_seconds", 900)
        self.grace_period_seconds = self.cluster_config.get("grace_period_seconds", 120)

        if os.path.exists(config_path):
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.default_window_seconds = data.get("default_window_seconds", self.default_window_seconds)
                    self.rules_config = data.get("rules", {})
            except Exception:
                pass

        self.active_windows: Dict[str, AggregatedWindow] = {}
        self.completed_aggregates: List[Dict[str, Any]] = []
        
        # Cardinality Guards:
        self.prefix_path_tracker: Dict[str, Set[str]] = defaultdict(set)
        # Actor hard cap: (tenant, actor_subnet, window_id) -> set(distinct_dedup_keys)
        self.actor_window_distinct_keys: Dict[str, Set[str]] = defaultdict(set)

        self.total_events_in = 0
        self.total_aggregates_out = 0
        self.total_evidence_links = 0
        self._gc_interval = 25000
        self.last_valid_timestamp: Optional[datetime] = None
        self.recent_dpkg_timestamps: Dict[str, datetime] = {}
        self.opened_clusters: List[Dict[str, Any]] = []

    def parse_iso_timestamp(self, ts_str: str) -> datetime:
        try:
            dt = dt_parser.parse(ts_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            self.last_valid_timestamp = dt
            return dt
        except Exception:
            return self.last_valid_timestamp or datetime.now(timezone.utc)

    def get_window_duration(self, rule_id: str, event: Optional[Any] = None) -> timedelta:
        """
        In Cluster v1 Architecture, all standard aggregations use the centralized uniform
        window (default 900s / 15 minutes) loaded from cluster_config.json.
        High-Value events bypass the window buffer immediately (0s).
        Legacy variable windows (300s/600s/1800s/3600s) have been completely removed.
        """
        return timedelta(seconds=self.default_window_seconds)

    def process_event(self, event: CommonEventModel) -> Optional[Dict[str, Any]]:
        self.total_events_in += 1
        event_time = self.parse_iso_timestamp(event.timestamp)
        rule_id_str = str(event.rule_id)
        rule_id_int = int(event.rule_id) if event.rule_id.isdigit() else 0
        agent_id = str(getattr(event, "agent_id", "000"))
        tenant_id = getattr(event, "tenant_id", "DEFAULT") or "DEFAULT"

        is_pkg_event = rule_id_str in ("2832", "2902", "2904") or "dpkg" in str(getattr(event, "location", "")).lower() or "apt" in str(getattr(event, "location", "")).lower()
        if is_pkg_event:
            self.recent_dpkg_timestamps[agent_id] = event_time

        recent_pkg_activity = False
        if agent_id in self.recent_dpkg_timestamps:
            delta_pkg = abs((event_time - self.recent_dpkg_timestamps[agent_id]).total_seconds())
            if delta_pkg <= CLUSTER_CONFIG["pkg_context_window_seconds"]:
                recent_pkg_activity = True

        if self.total_events_in % self._gc_interval == 0:
            evicted = self._cleanup_stale_windows(event_time)
            self.completed_aggregates.extend(evicted)

        is_high_val, bypass_reason, success_ind, pkg_ctx = evaluate_high_value_event(
            event,
            recent_pkg_activity=recent_pkg_activity
        )
        is_external_auth = (bypass_reason == "privileged_external_auth_success") or \
                           (rule_id_str in ("5715", "5501", "100020") and not getattr(event, "is_privileged_user", False))

        window_duration = self.get_window_duration(rule_id_str, event=event)
        window_seconds = int(window_duration.total_seconds())

        rule_cfg = self.rules_config.get(rule_id_str, {})
        norm_groups = sorted(event.classification_groups) if event.classification_groups else []
        event_type_str = norm_groups[0] if norm_groups else None

        # Cluster v1 Deterministic Window Bucket & Composite Key (SHA-256)
        # Formula: SHA256(tenant_id | rule_id | agent_id | who | what | window_bucket_epoch)
        # All legacy per-rule keys and variable override paths are decommissioned.
        window_bucket_epoch = int(event_time.timestamp() // window_seconds) * window_seconds
        composite_raw, composite_hash, who_val, what_val = calculate_composite_cluster_key(
            event, window_bucket_epoch=window_bucket_epoch
        )
        prefix_key = f"{tenant_id}|{rule_id_str}|{agent_id}|{who_val}|{window_bucket_epoch}"
        current_paths = self.prefix_path_tracker[prefix_key]

        is_exploit_signature = any(cat in str(getattr(event, "action_ttp", "")).upper() for cat in CLUSTER_CONFIG["exploit_threat_categories"]) or \
                               _RE_EXPLOIT_SIGNATURE.search(what_val) is not None

        if not is_exploit_signature:
            if len(current_paths) >= CLUSTER_CONFIG["max_distinct_paths_per_prefix"] and what_val not in current_paths:
                what_val = "OTHER"
            else:
                current_paths.add(what_val)

        actor_window_key = f"{tenant_id}|{who_val}|{window_bucket_epoch}"
        distinct_keys_for_actor = self.actor_window_distinct_keys[actor_window_key]
        
        # Check if this exact what_val is already known or if cap reached
        if len(distinct_keys_for_actor) >= CLUSTER_CONFIG["max_keys_per_actor_window"] and what_val not in distinct_keys_for_actor:
            what_val = "OTHER_SIGNATURE"
        else:
            distinct_keys_for_actor.add(what_val)

        # Cluster v1 Canonical Composite Cluster Key (Zero-Collision, SHA-256)
        dedup_raw = f"{tenant_id}|{rule_id_str}|{agent_id}|{who_val}|{what_val}|{window_bucket_epoch}"
        dedup_key = hashlib.sha256(dedup_raw.encode("utf-8")).hexdigest()

        now_utc = datetime.now(timezone.utc)
        is_backfill = abs((now_utc - event_time).total_seconds()) > (CLUSTER_CONFIG["late_arriving_cutoff_hours"] * 3600)

        closed_alert = None
        target_name = getattr(event, "dedup_target", None) or getattr(event, "destination_host", None) or getattr(event, "destination_ip", None) or getattr(event, "username", None) or f"agent:{agent_id}"

        if dedup_key in self.active_windows:
            window = self.active_windows[dedup_key]
            if window.is_expired(event_time, grace_seconds=self.grace_period_seconds):
                closed_alert = self._finalize_window(window)

                parent_id = window.aggregation_id if window.is_high_value else None
                new_agg_id = f"agg_{uuid.uuid4().hex}"
                new_window = self._create_window_instance(
                    new_agg_id=new_agg_id,
                    dedup_key=dedup_key,
                    rule_id_int=rule_id_int,
                    event=event,
                    event_time=event_time,
                    window_duration=window_duration,
                    tenant_id=tenant_id,
                    composite_raw=composite_raw,
                    who_val=who_val,
                    what_val=what_val,
                    is_high_val=is_high_val,
                    bypass_reason=bypass_reason,
                    success_ind=success_ind,
                    is_external_auth=is_external_auth,
                    pkg_ctx=pkg_ctx,
                    parent_cluster_id=parent_id,
                    is_backfill=is_backfill
                )
                self.active_windows[dedup_key] = new_window
            else:
                is_new_ip = bool(event.source_ip and event.source_ip not in window.distinct_src_ips)
                is_priority_material = (
                    int(getattr(event, "rule_level", 0) or 0) > window.max_rule_level or
                    (success_ind != "none" and success_ind != window.success_indicator) or
                    (is_high_val and not window.is_high_value) or
                    (is_external_auth and not window.external_auth_success)
                )
                is_material = is_priority_material or is_new_ip
                window.add_event(
                    event_id=event.event_id,
                    event_time=event_time,
                    rule_level=int(getattr(event, "rule_level", 0) or 0),
                    rule_id=rule_id_int,
                    ioa_summary=getattr(event, "ioa_summary", None),
                    inline_risk_score=getattr(event, "inline_risk_score", None),
                    ocsf_severity_id=getattr(event, "ocsf_severity_id", None),
                    extracted_iocs=getattr(event, "extracted_iocs", None),
                    log_source=getattr(event, "location", None),
                    http_status=getattr(event, "http_status", None),
                    is_scanner_ua=getattr(event, "is_scanner_ua", False),
                    source_ip=event.source_ip,
                    clean_path=getattr(event, "clean_path", None),
                    mitre_tactics=getattr(event, "mitre_tactics", None),
                    target=target_name,
                    user_agent=getattr(event, "user_agent", None),
                    is_material_update=is_material
                )
                if window.is_high_value and window.should_forward_bypass(
                    event_time,
                    is_material=is_material,
                    is_priority_material=is_priority_material,
                    is_new_ip=is_new_ip
                ):
                    window.status = "ACTIVE_EMITTED"
        else:
            new_agg_id = f"agg_{uuid.uuid4().hex}"
            new_window = self._create_window_instance(
                new_agg_id=new_agg_id,
                dedup_key=dedup_key,
                rule_id_int=rule_id_int,
                event=event,
                event_time=event_time,
                window_duration=window_duration,
                tenant_id=tenant_id,
                composite_raw=composite_raw,
                who_val=who_val,
                what_val=what_val,
                is_high_val=is_high_val,
                bypass_reason=bypass_reason,
                success_ind=success_ind,
                is_external_auth=is_external_auth,
                pkg_ctx=pkg_ctx,
                parent_cluster_id=None,
                is_backfill=is_backfill
            )
            self.active_windows[dedup_key] = new_window

        return closed_alert

    def _create_window_instance(
        self,
        new_agg_id: str,
        dedup_key: str,
        rule_id_int: int,
        event: CommonEventModel,
        event_time: datetime,
        window_duration: timedelta,
        tenant_id: str,
        composite_raw: str,
        who_val: str,
        what_val: str,
        is_high_val: bool,
        bypass_reason: Optional[str],
        success_ind: str,
        is_external_auth: bool,
        pkg_ctx: bool,
        parent_cluster_id: Optional[str],
        is_backfill: bool
    ) -> AggregatedWindow:
        category = getattr(event, "event_category", "SYSTEM_HEALTH") or "SYSTEM_HEALTH"
        supp_class = self.rules_config.get(str(rule_id_int), {}).get("suppression_class", "S2_DEDUPLICATION")
        win = AggregatedWindow(
            aggregation_id=new_agg_id,
            dedup_key=dedup_key,
            rule_id=rule_id_int,
            agent_id=event.agent_id,
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            username=event.username,
            start_time=event_time,
            window_duration=window_duration,
            tenant_id=tenant_id,
            category=category,
            suppression_class=supp_class,
            actor=getattr(event, "dedup_actor", None),
            target=getattr(event, "dedup_target", None) or getattr(event, "destination_host", None),
            rule_description=getattr(event, "rule_description", None),
            ioa_summary=getattr(event, "ioa_summary", None),
            os_platform=getattr(event, "os_platform", "unknown"),
            log_source=getattr(event, "location", None),
            extracted_iocs=getattr(event, "extracted_iocs", None),
            composite_key=composite_raw,
            who=who_val,
            what=what_val,
            domain=getattr(event, "domain", getattr(event, "primary_category", "SYSTEM")),
            target_category=getattr(event, "target_category", "Host_Telemetry"),
            action_ttp=getattr(event, "action_ttp", getattr(event, "subcategory", "General")),
            lifecycle_role=getattr(event, "lifecycle_role", "STATELESS"),
            primary_category=getattr(event, "domain", getattr(event, "primary_category", "SYSTEM")),
            subcategory=getattr(event, "action_ttp", getattr(event, "subcategory", "General")),
            disposition=getattr(event, "disposition", "SAFE"),
            confidence_score=getattr(event, "confidence_score", 50),
            is_high_value=is_high_val,
            bypass_reason=bypass_reason,
            success_indicator=success_ind,
            external_auth_success=is_external_auth,
            pkg_activity_nearby=pkg_ctx,
            parent_cluster_id=parent_cluster_id,
            is_backfill=is_backfill,
            source_type=evaluate_source_type(event),
        )
        win.raw_evidence.append((event.event_id, event_time))
        win.max_inline_risk_score = getattr(event, "inline_risk_score", None) or 0
        win.max_rule_level = int(getattr(event, "rule_level", 0) or 0)
        win.ocsf_severity_id = getattr(event, "ocsf_severity_id", None)
        win.classification_groups = list(getattr(event, "classification_groups", None) or [])
        win.mitre_tactics = list(getattr(event, "mitre_tactics", None) or [])
        if getattr(event, "http_status", None) is not None:
            win.http_statuses[event.http_status] += 1
        if getattr(event, "clean_path", None):
            win.path_counter[getattr(event, "clean_path")] += 1
        if getattr(event, "is_scanner_ua", False):
            win.scanner_ua_detected = True

        ua_val = getattr(event, "user_agent", None)
        if ua_val:
            win.user_agent_counter[extract_ua_family(ua_val)] += 1

        win.smart_tracker.add_sample(
            event_id=event.event_id,
            event_time=event_time,
            rule_id=rule_id_int,
            rule_level=win.max_rule_level,
            source_ip=event.source_ip,
            clean_path=getattr(event, "clean_path", None),
            http_status=getattr(event, "http_status", None)
        )

        # Emit cluster_opened signal for ALL newly opened clusters
        self.opened_clusters.append({
            "event": "cluster_opened",
            "aggregation_id": win.aggregation_id,
            "dedup_key": win.dedup_key,
            "tenant_id": win.tenant_id,
            "rule_id": win.rule_id,
            "source_type": win.source_type,
            "who": win.who,
            "what": win.what,
            "first_seen_event_time": win.first_seen_event_time,
            "is_high_value": win.is_high_value,
            "status": win.status
        })

        return win

    def drain_opened_clusters(self) -> List[Dict[str, Any]]:
        """Drain and return newly opened cluster events for downstream SLA clock initiation."""
        drained = list(self.opened_clusters)
        self.opened_clusters.clear()
        return drained

    def _cleanup_stale_windows(self, current_time: datetime) -> List[Dict[str, Any]]:
        evicted = []
        for k in list(self.active_windows.keys()):
            w = self.active_windows[k]
            if w.is_stale_for_eviction(current_time):
                evicted.append(self._finalize_window(w))
                del self.active_windows[k]
        return evicted

    def _finalize_window(self, window: AggregatedWindow) -> Dict[str, Any]:
        self.total_aggregates_out += 1
        self.total_evidence_links += len(window.raw_evidence)

        category = getattr(window, "category", "SYSTEM_HEALTH")
        dominant_http_status = window.http_statuses.most_common(1)[0][0] if window.http_statuses else None
        dominant_rule_id = window.rule_id_counter.most_common(1)[0][0] if window.rule_id_counter else window.rule_id

        top_paths = [{"path": p, "count": c} for p, c in window.path_counter.most_common(5)]
        distinct_targets_list = [{"target": t, "count": c} for t, c in window.target_counter.most_common()]
        cluster_metrics = {
            "http_status_distribution": dict(window.http_statuses),
            "user_agent_distribution": dict(window.user_agent_counter.most_common(10)),
            "unique_paths_count": len(window.path_counter),
            "top_5_paths": top_paths,
            "distinct_ips_count": len(window.distinct_src_ips),
            "distinct_targets_count": len(window.target_counter),
            "max_rule_level": window.max_rule_level,
            "dominant_rule_id": dominant_rule_id,
            "mitre_tactics": window.mitre_tactics,
            "is_scanner_ua": window.scanner_ua_detected
        }

        smart_samples = window.smart_tracker.get_combined_samples()

        wazuh_pointer = {
            "index_pattern": "wazuh-alerts-*",
            "agent_id": window.agent_id,
            "time_range": {
                "gte": window.first_seen_event_time.isoformat(),
                "lte": window.last_seen_event_time.isoformat()
            },
            "filter": {
                "rule_ids": [window.rule_id],
                "actor_subnet": window.who,
                "what_cluster": window.what
            }
        }

        agg_dict = {
            "aggregation_id": window.aggregation_id,
            "rule_id": window.rule_id,
            "rule_description": getattr(window, "rule_description", None),
            "deduplication_key": window.dedup_key,
            "tenant_id": window.tenant_id,
            "agent_id": window.agent_id,
            "source_ip": window.source_ip,
            "exact_source_ip": window.exact_source_ip,
            "distinct_src_ips": sorted(list(window.distinct_src_ips)),
            "destination_ip": window.destination_ip,
            "username": window.username,
            "event_count": window.event_count,
            "window_start": window.window_start,
            "window_end": window.window_end,
            "first_seen_event_time": window.first_seen_event_time,
            "last_seen_event_time": window.last_seen_event_time,
            "status": "CLOSED",
            "suppression_class": getattr(window, "suppression_class", "S2_DEDUPLICATION"),
            "category": category,
            "domain": getattr(window, "domain", getattr(window, "primary_category", "SYSTEM")),
            "target_category": getattr(window, "target_category", "Host_Telemetry"),
            "action_ttp": getattr(window, "action_ttp", getattr(window, "subcategory", "General")),
            "lifecycle_role": getattr(window, "lifecycle_role", "STATELESS"),
            "primary_category": getattr(window, "domain", getattr(window, "primary_category", "SYSTEM")),
            "subcategory": getattr(window, "action_ttp", getattr(window, "subcategory", "General")),
            "disposition": getattr(window, "disposition", "SAFE"),
            "confidence_score": getattr(window, "confidence_score", 50),
            "composite_cluster_key": getattr(window, "composite_key", None),
            "who_cluster": getattr(window, "who", None),
            "what_cluster": getattr(window, "what", None),
            "source_type": getattr(window, "source_type", "system"),
            "distinct_targets": distinct_targets_list,
            "actor": getattr(window, "actor", window.source_ip or f"agent:{window.agent_id}"),
            "target": getattr(window, "target", window.username or window.destination_ip or f"agent:{window.agent_id}"),
            "window_duration_seconds": getattr(window, "window_duration_seconds", int(window.window_duration.total_seconds())),
            "log_source": getattr(window, "log_source", None),
            "ioa_summary": getattr(window, "ioa_summary", None),
            "distinct_ioas": sorted(list(getattr(window, "distinct_ioas", set()))),
            "distinct_iocs": sorted(list(getattr(window, "distinct_iocs", set()))),
            "max_inline_risk_score": getattr(window, "max_inline_risk_score", 0),
            "ocsf_severity_id": getattr(window, "ocsf_severity_id", None),
            "classification_groups": getattr(window, "classification_groups", []),
            "mitre_tactics": getattr(window, "mitre_tactics", []),
            "os_platform": getattr(window, "os_platform", "unknown"),
            "dominant_http_status": dominant_http_status,
            "is_scanner_ua": window.scanner_ua_detected,
            "smart_evidence": smart_samples,
            "cluster_metrics": cluster_metrics,
            "wazuh_query_pointer": wazuh_pointer,
            "is_high_value": window.is_high_value,
            "bypass_reason": window.bypass_reason,
            "success_indicator": window.success_indicator,
            "external_auth_success": window.external_auth_success,
            "pkg_activity_nearby": window.pkg_activity_nearby,
            "parent_cluster_id": window.parent_cluster_id,
            "is_backfill": window.is_backfill,
            "raw_evidence": window.raw_evidence
        }
        return agg_dict

    def drain_completed_aggregates(self) -> List[Dict[str, Any]]:
        drained = list(self.completed_aggregates)
        self.completed_aggregates.clear()
        return drained

    def flush_all(self) -> List[Dict[str, Any]]:
        results = list(self.completed_aggregates)
        self.completed_aggregates.clear()
        for dedup_key, window in list(self.active_windows.items()):
            results.append(self._finalize_window(window))
        self.active_windows.clear()
        return results

    def get_summary_metrics(self) -> Dict[str, Any]:
        reduction_pct = 0.0
        if self.total_events_in > 0:
            reduction_pct = round(((self.total_events_in - self.total_aggregates_out) / self.total_events_in) * 100.0, 2)

        return {
            "total_raw_events_in": self.total_events_in,
            "total_aggregated_alerts_out": self.total_aggregates_out,
            "total_evidence_links_preserved": self.total_evidence_links,
            "overall_noise_reduction_percentage": f"{reduction_pct}%",
            "compression_ratio": f"{self.total_events_in / max(1, self.total_aggregates_out):.1f}:1"
        }

    def save_snapshot(self, filepath: str) -> None:
        """Persists in-flight active windows to disk for crash recovery."""
        snapshot = {}
        for key, win in self.active_windows.items():
            snapshot[key] = {
                "aggregation_id": win.aggregation_id,
                "dedup_key": win.dedup_key,
                "rule_id": win.rule_id,
                "agent_id": win.agent_id,
                "source_ip": win.source_ip,
                "destination_ip": win.destination_ip,
                "username": win.username,
                "start_time": win.window_start.isoformat(),
                "duration_seconds": win.window_duration_seconds,
                "event_count": win.event_count,
                "tenant_id": win.tenant_id,
                "category": win.category,
                "actor": win.actor,
                "target": win.target,
                "rule_description": win.rule_description,
                "ioa_summary": win.ioa_summary,
                "os_platform": win.os_platform,
                "log_source": win.log_source,
                "distinct_iocs": list(win.distinct_iocs) if isinstance(win.distinct_iocs, set) else win.distinct_iocs,
                "composite_key": win.composite_key,
                "who": win.who,
                "what": win.what,
                "primary_category": win.primary_category,
                "subcategory": win.subcategory,
                "disposition": win.disposition,
                "confidence_score": win.confidence_score,
                "domain": win.domain,
                "target_category": win.target_category,
                "action_ttp": win.action_ttp,
                "lifecycle_role": win.lifecycle_role,
                "is_high_value": win.is_high_value,
                "bypass_reason": win.bypass_reason,
                "success_indicator": win.success_indicator,
                "external_auth_success": win.external_auth_success,
                "pkg_activity_nearby": win.pkg_activity_nearby,
                "parent_cluster_id": win.parent_cluster_id,
                "is_backfill": win.is_backfill,
                "source_type": win.source_type,
                "suppression_class": win.suppression_class
            }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(snapshot, f)

    def load_snapshot(self, filepath: str) -> int:
        """Restores in-flight active windows from snapshot after process restart."""
        if not os.path.exists(filepath):
            return 0
        with open(filepath, "r", encoding="utf-8") as f:
            snapshot = json.load(f)
        
        restored = 0
        for key, data in snapshot.items():
            st = self.parse_iso_timestamp(data["start_time"])
            dur = timedelta(seconds=data.get("duration_seconds", 900))
            win = AggregatedWindow(
                aggregation_id=data["aggregation_id"],
                dedup_key=data["dedup_key"],
                rule_id=data["rule_id"],
                agent_id=data["agent_id"],
                source_ip=data.get("source_ip"),
                destination_ip=data.get("destination_ip"),
                username=data.get("username"),
                start_time=st,
                window_duration=dur,
                tenant_id=data.get("tenant_id", "DEFAULT"),
                category=data.get("category", "SYSTEM_HEALTH"),
                actor=data.get("actor"),
                target=data.get("target"),
                rule_description=data.get("rule_description"),
                ioa_summary=data.get("ioa_summary"),
                os_platform=data.get("os_platform", "unknown"),
                log_source=data.get("log_source"),
                extracted_iocs=data.get("distinct_iocs"),
                composite_key=data.get("composite_key"),
                who=data.get("who"),
                what=data.get("what"),
                primary_category=data.get("primary_category"),
                subcategory=data.get("subcategory"),
                disposition=data.get("disposition"),
                confidence_score=data.get("confidence_score"),
                domain=data.get("domain"),
                target_category=data.get("target_category"),
                action_ttp=data.get("action_ttp"),
                lifecycle_role=data.get("lifecycle_role"),
                is_high_value=data.get("is_high_value", False),
                bypass_reason=data.get("bypass_reason"),
                success_indicator=data.get("success_indicator", "none"),
                external_auth_success=data.get("external_auth_success", False),
                pkg_activity_nearby=data.get("pkg_activity_nearby", False),
                parent_cluster_id=data.get("parent_cluster_id"),
                is_backfill=data.get("is_backfill", False),
                source_type=data.get("source_type", "system"),
                suppression_class=data.get("suppression_class", "CLUSTERABLE")
            )
            win.event_count = data.get("event_count", 1)
            self.active_windows[key] = win
            restored += 1
        return restored
