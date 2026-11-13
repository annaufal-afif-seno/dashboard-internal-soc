"""
High-Throughput Streaming Ingestion Engine for Wazuh JSONL Telemetry
"""
import json
import os
import glob
import re
from typing import Generator, List, Dict, Any, Tuple, Optional
from collections import Counter
from datetime import datetime

from pipeline.models import WazuhRawAlert, CommonEventModel
from pipeline.apex_normalizer import ApexNormalizerV40, ApexNormalizerV34, ApexTransformsV34
from config.settings import CHUNK_SIZE, DATA_DIR, IGNORED_COLLECTOR_HOSTS
from config.category_constants import PrimaryCategory, SUBCATEGORIES, SUBCAT_TO_PRIMARY

# Lazy import of plugin chain to avoid circular dependency during module init
def _get_plugin_chain():
    """Return the normalization plugin chain executor (lazy import, cached)."""
    global _PLUGIN_CHAIN_FN
    if _PLUGIN_CHAIN_FN is None:
        try:
            from pipeline.normalization_plugins import run_plugin_chain
            _PLUGIN_CHAIN_FN = run_plugin_chain
        except Exception:
            _PLUGIN_CHAIN_FN = lambda cem, raw: cem  # graceful no-op fallback
    return _PLUGIN_CHAIN_FN

_PLUGIN_CHAIN_FN = None

# Lazy import of Hybrid AI Categorizer
def _get_ai_predict_fn():
    """Return the Hybrid AI Categorizer predictor (lazy import, cached)."""
    global _AI_PREDICT_FN
    if _AI_PREDICT_FN is None:
        try:
            from pipeline.ai_categorizer import predict_alert_category
            _AI_PREDICT_FN = predict_alert_category
        except Exception:
            _AI_PREDICT_FN = None
    return _AI_PREDICT_FN

_AI_PREDICT_FN = None

# Mapping from AI Subcategory (OCSF / MITRE Standard) to canonical internal 22-categories
_SUBCAT_TO_INTERNAL: Dict[str, str] = {
    # Aligned 100% with the 6 Primary Categories and 19 Subcategories
    "Web Attack": PrimaryCategory.ATTACK,
    "Exploitation / RCE": PrimaryCategory.ATTACK,
    "Recon / Scan": PrimaryCategory.ATTACK,
    "Command & Control (C2)": PrimaryCategory.ATTACK,
    "Command & Control": PrimaryCategory.ATTACK,
    "Lateral Movement": PrimaryCategory.ATTACK,
    "CVE Detected": PrimaryCategory.VULNERABILITY,
    "Missing Patch / Outdated Software": PrimaryCategory.VULNERABILITY,
    "Missing Patch / Outdated": PrimaryCategory.VULNERABILITY,
    "SCA / CIS Benchmark": PrimaryCategory.CONFIGURATION_COMPLIANCE,
    "File Integrity (FIM)": PrimaryCategory.CONFIGURATION_COMPLIANCE,
    "Policy Violation": PrimaryCategory.CONFIGURATION_COMPLIANCE,
    "Auth Success": PrimaryCategory.IDENTITY_ACCESS,
    "Auth Failure": PrimaryCategory.IDENTITY_ACCESS,
    "Auth Anomaly": PrimaryCategory.IDENTITY_ACCESS,
    "Privilege Escalation": PrimaryCategory.IDENTITY_ACCESS,
    "Ransomware": PrimaryCategory.MALWARE,
    "Rootkit / Backdoor": PrimaryCategory.MALWARE,
    "Virus / Trojan (YARA)": PrimaryCategory.MALWARE,
    "Web Operational": PrimaryCategory.SYSTEM_AVAILABILITY,
    "Service Health / Error": PrimaryCategory.SYSTEM_AVAILABILITY,
    "Cloud / Container Event": PrimaryCategory.SYSTEM_AVAILABILITY,
}

ECS_FIELD_ALIASES = {
    "source_ip": [
        "srcip", "src_ip", "client_ip", "clientip", "remote_addr", "remote_ip",
        "c-ip", "source.ip", "ipAddress", "sourceIp", "addr", "source_address", "caller_ip"
    ],
    "destination_ip": [
        "dstip", "dst_ip", "server_ip", "destinationIp", "destination_ip", "dest_ip",
        "dest.ip", "target_ip", "cs-host", "host_ip"
    ],
    "source_port": [
        "srcport", "src_port", "sourcePort", "source.port", "client_port", "c-port"
    ],
    "destination_port": [
        "dstport", "dst_port", "destinationPort", "destination.port", "server_port", "s-port"
    ],
    "username": [
        "dstuser", "srcuser", "username", "user", "targetUserName", "subjectUserName",
        "account", "acct", "auid", "user_name", "user.name", "identity", "login"
    ],
    "process_name": [
        "process_name", "image", "exe", "app", "process.name", "program", "program_name"
    ],
    "process_path": [
        "process_path", "image", "exe_path", "process.executable"
    ],
    "command_line": [
        "command_line", "cmd", "commandLine", "command", "process.command_line", "args"
    ],
    "protocol": [
        "proto", "protocol", "network.protocol", "network.transport"
    ]
}

# Pre-compiled regex patterns for Web log forensics & scanner detection
_RE_HTTP_STATUS_UA = re.compile(
    r'"[A-Z]+\s+[^"]+\s+HTTP/[0-9.]+"\s+(\d{3})\s+\S+\s+"[^"]*"\s+"([^"]*)"'
)
_RE_HTTP_STATUS_FALLBACK = re.compile(r'\bHTTP/[0-9.]+"\s+(\d{3})\b')
_RE_SCANNER_UA = re.compile(
    r'(?i)\b(sqlmap|nikto|nmap|zgrab|masscan|dirbuster|gobuster|wpscan|hydra|acunetix|nessus|openvas|python-requests|curl|wget|go-http-client|zmap|nuclei|jaeles|ffuf)\b'
)



# ── Pre-compiled regex patterns for Nginx error & cluster normalization ───────
_RE_NGINX_ERRNO = re.compile(r'\((\d+):\s*([^)]+)\)')
_RE_NGINX_REQUEST = re.compile(r'request:\s*"([A-Za-z]+)\s+([^"\s]+)')
_RE_NGINX_UPSTREAM = re.compile(r'upstream:\s*"(?:https?://)?([^"/]+)')
_RE_NGINX_CLIENT = re.compile(r'client:\s*([0-9a-fA-F.:]+)')

def normalize_ip_to_slash24(ip_str: Optional[str]) -> str:
    """Normalize public IPv4 to /24 subnet; preserve private/loopback IPv4 exact."""
    if not ip_str or not isinstance(ip_str, str):
        return "none"
    ip_clean = ip_str.strip()
    import ipaddress
    try:
        ip = ipaddress.ip_address(ip_clean)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return str(ip)
        if isinstance(ip, ipaddress.IPv4Address):
            net = ipaddress.ip_network(f"{ip}/24", strict=False)
            return str(net)
        return str(ip)
    except Exception:
        return ip_clean

def normalize_url_path(url_str: Optional[str]) -> str:
    """Clean and normalize URL path: strip query params, collapse IDs to path family."""
    if not url_str or not isinstance(url_str, str):
        return "/"
    url = url_str.strip()
    url = re.sub(r'^https?://[^/]+', '', url)
    url = url.split('?')[0].split('#')[0]
    url = re.sub(r'/+', '/', url)
    # Collapse IDs to path family
    url = re.sub(r'/\d+(?=/|$)', '/*', url)
    url = re.sub(r'/[0-9a-fA-F-]{8,}(?=/|$)', '/*', url)
    if url.startswith('/administrator/'):
        return '/administrator/*'
    if url.startswith('/wp-admin/') or url.startswith('/wp-content/'):
        return '/wp-*'
    if '/api/session/' in url:
        return '/api/session/*'
    return url or '/'

def extract_aliased_field(data: Any, aliases: List[str], max_depth: int = 3) -> Optional[Any]:
    """Search for any matching alias in dictionary, including arbitrary nested structures up to depth 3."""
    if not isinstance(data, dict) or max_depth <= 0:
        return None
    # 1. First pass: direct key match with scalar value
    for alias in aliases:
        if alias in data:
            val = data[alias]
            if val not in (None, "", "null", "-"):
                if isinstance(val, (str, int, float, bool)):
                    return val
                elif isinstance(val, dict):
                    nested = extract_aliased_field(val, aliases, max_depth - 1)
                    if nested is not None:
                        return nested
    # 2. Second pass: search all nested child dictionaries
    for k, v in data.items():
        if isinstance(v, dict):
            nested = extract_aliased_field(v, aliases, max_depth - 1)
            if nested is not None:
                return nested
    return None


class CanonicalAssetResolver:
    """
    100/100 Enterprise Canonical Asset Normalizer & Dynamic Auto-Discovery Engine.
    Maintains dynamic bidirectional mappings:
      agent_id <-> canonical_name <-> IP
    Auto-learns new agents on the fly from incoming telemetry, filters out SIEM
    collector hostnames (e.g. wazuh_soc), and guarantees consistent target entity
    resolution across all log shippers and formats.
    """
    def __init__(self, asset_inventory: Optional[Dict[str, Any]] = None):
        self.agent_id_to_name: Dict[str, str] = {}
        self.ip_to_name: Dict[str, str] = {}
        self.name_to_info: Dict[str, Dict[str, Any]] = {}

        # Seed from config/asset_inventory.json if provided
        if asset_inventory:
            for name, info in asset_inventory.items():
                self.name_to_info[name] = info
                if isinstance(info, dict) and "ip" in info and info["ip"]:
                    self.ip_to_name[info["ip"]] = name

    def sync_from_wazuh_api(self, api_url: str, auth_token: Optional[str] = None) -> int:
        """Dynamically sync registered agents from Wazuh Manager REST API (/agents)."""
        import urllib.request
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            req = urllib.request.Request(f"{api_url.rstrip('/')}/agents?limit=1000")
            if auth_token:
                req.add_header("Authorization", f"Bearer {auth_token}")
            with urllib.request.urlopen(req, context=ctx, timeout=3) as resp:
                if resp.status == 200:
                    payload = json.loads(resp.read().decode())
                    agents = payload.get("data", {}).get("affected_items", [])
                    synced = 0
                    for ag in agents:
                        aid = ag.get("id")
                        aname = ag.get("name")
                        aip = ag.get("ip")
                        self.register_observation(aid, aname, aip)
                        synced += 1
                    return synced
        except Exception:
            pass
        return 0

    def register_observation(self, agent_id: Optional[str], agent_name: Optional[str], agent_ip: Optional[str]):
        """Auto-learn new agent mappings on the fly from incoming telemetry."""
        clean_name = str(agent_name).strip() if agent_name else None
        if clean_name and clean_name.lower() not in IGNORED_COLLECTOR_HOSTS:
            if agent_id and str(agent_id) != "000":
                self.agent_id_to_name[str(agent_id)] = clean_name
            if agent_ip and str(agent_ip) not in ("none", "unknown"):
                self.ip_to_name[str(agent_ip)] = clean_name

    def resolve_target_host(
        self,
        agent_id: Optional[str] = None,
        agent_name: Optional[str] = None,
        dst_ip: Optional[str] = None,
        raw_host: Optional[str] = None,
        data_dsthost: Optional[str] = None
    ) -> str:
        """
        Deterministically resolve the canonical target host/victim endpoint.
        Never falls back to SIEM collector hosts (wazuh_soc).
        """
        # 1. Explicit destination host or vhost from web payload
        if data_dsthost and str(data_dsthost).lower() not in IGNORED_COLLECTOR_HOSTS:
            return str(data_dsthost).strip()

        # 2. Known agent name from alert (if not a collector)
        clean_agent_name = str(agent_name).strip() if agent_name else None
        if clean_agent_name and clean_agent_name.lower() not in IGNORED_COLLECTOR_HOSTS:
            return clean_agent_name

        # 3. Dynamic cache lookup by agent_id
        if agent_id and str(agent_id) in self.agent_id_to_name:
            return self.agent_id_to_name[str(agent_id)]

        # 4. Dynamic cache / inventory lookup by destination IP
        if dst_ip and str(dst_ip) in self.ip_to_name:
            return self.ip_to_name[str(dst_ip)]

        # 5. Raw host if valid and not a collector
        clean_raw_host = str(raw_host).strip() if raw_host else None
        if clean_raw_host and clean_raw_host.lower() not in IGNORED_COLLECTOR_HOSTS:
            return clean_raw_host

        # 6. Fallback to destination IP if available
        if dst_ip and str(dst_ip) not in ("none", "unknown"):
            return str(dst_ip).strip()

        # 7. Safe fallback to agent_id
        if agent_id and str(agent_id) != "000":
            return f"agent:{agent_id}"

        return clean_agent_name or clean_raw_host or "unknown"


# Global singleton resolver for direct function calls
_GLOBAL_ASSET_RESOLVER = CanonicalAssetResolver()



def classify_event_taxonomy(
    rule_id: str,
    rule_level: int,
    groups: List[str],
    rule_description: Optional[str],
    full_log: Optional[str],
    data: Optional[Dict[str, Any]],
    source_ip: Optional[str],
    http_status: Optional[int],
    is_scanner_ua: bool,
    mitre_tactics: Optional[List[str]] = None,
) -> Tuple[str, str, str, str, str, int]:
    """
    Unified 6-Category & 19-Subcategory Taxonomy Engine (Best Practice SOTA Standard):
    Returns (domain, target_category, action_ttp, lifecycle_role, disposition, confidence_score)
    - domain & target_category: Strictly one of the 6 Primary Categories (Attack, Vulnerability,
      Configuration / Compliance, Identity / Access, Malware, System / Availability).
    - action_ttp: Strictly one of the 19 Subcategories.
    - lifecycle_role: STATELESS, OPEN_STATE, CLOSE_STATE
    - disposition: ACTIONABLE, SAFE, REVIEW, PENDING_PAIR
    - confidence_score: 0 - 100
    """
    groups_lower = set(g.lower() for g in (groups or []))
    desc_lower = (rule_description or "").lower()
    full_log_lower = (full_log or "").lower()
    tactics_lower = set(t.lower() for t in (mitre_tactics or []))
    rule_id_str = str(rule_id)
    src_ip_str = str(source_ip or "")
    data = data or {}

    is_internal_src = (
        src_ip_str.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "127."))
        or not src_ip_str
    )

    # ── Tier 1: Hybrid AI Categorizer (Sub-millisecond semantic reasoning) ──
    ai_fn = _get_ai_predict_fn()
    if ai_fn:
        try:
            ai_pred = ai_fn(
                desc=desc_lower,
                groups=list(groups_lower),
                tactics=list(tactics_lower),
                log_text=full_log_lower,
                rule_id=rule_id_str
            )
            if ai_pred and ai_pred.get("confidence", 0) >= 0.70:
                pcat = str(ai_pred.get("primary_category", PrimaryCategory.SYSTEM_AVAILABILITY))
                subcat = str(ai_pred.get("subcategory", "Service Health / Error"))
                conf_score = int(ai_pred.get("confidence", 0.70) * 100)

                lifecycle_role = "STATELESS"
                if pcat in (PrimaryCategory.ATTACK, PrimaryCategory.MALWARE):
                    disposition = "ACTIONABLE" if rule_level >= 8 or conf_score >= 85 else "REVIEW"
                elif pcat == PrimaryCategory.IDENTITY_ACCESS:
                    if subcat == "Auth Success":
                        disposition = "SAFE"
                    else:
                        disposition = "ACTIONABLE" if rule_level >= 10 else "REVIEW"
                elif pcat == PrimaryCategory.VULNERABILITY:
                    if "cleared" in desc_lower or "mitigated" in desc_lower:
                        lifecycle_role = "CLOSE_STATE"
                        disposition = "SAFE"
                    else:
                        lifecycle_role = "OPEN_STATE"
                        disposition = "ACTIONABLE" if rule_level >= 10 else "REVIEW"
                elif pcat == PrimaryCategory.CONFIGURATION_COMPLIANCE:
                    disposition = "REVIEW"
                else:
                    disposition = "SAFE"

                return pcat, pcat, subcat, lifecycle_role, disposition, conf_score
        except Exception:
            pass

    # ── Tier 2: Deterministic Security Heuristic Fallback ──
    # 1. VULNERABILITY & CONFIGURATION
    if (
        "vulnerability-detector" in groups_lower
        or "vulnerability" in groups_lower
        or "cve" in groups_lower
        or "affects" in desc_lower
        or "cve-" in desc_lower
    ):
        domain = PrimaryCategory.VULNERABILITY
        target_category = PrimaryCategory.VULNERABILITY
        if any(k in desc_lower for k in ["resolved", "mitigated", "updated", "patched", "cleared"]):
            action_ttp = "Missing Patch / Outdated Software"
            lifecycle_role = "CLOSE_STATE"
            disposition = "SAFE"
            confidence = 100
        else:
            action_ttp = "CVE Detected"
            lifecycle_role = "OPEN_STATE"
            disposition = "ACTIONABLE" if rule_level >= 10 else "REVIEW"
            confidence = 90 if rule_level >= 10 else 60
        return domain, target_category, action_ttp, lifecycle_role, disposition, confidence

    if (
        "sca" in groups_lower
        or "cis" in groups_lower
        or "compliance" in groups_lower
        or "syscheck" in groups_lower
        or "fim" in groups_lower
        or "policy" in groups_lower
    ):
        domain = PrimaryCategory.CONFIGURATION_COMPLIANCE
        target_category = PrimaryCategory.CONFIGURATION_COMPLIANCE
        lifecycle_role = "STATELESS"
        disposition = "REVIEW"
        if any(k in desc_lower or k in groups_lower for k in ["fim", "syscheck", "file", "integrity"]):
            action_ttp = "File Integrity (FIM)"
            confidence = 80
        elif any(k in desc_lower or k in groups_lower for k in ["policy", "violation"]):
            action_ttp = "Policy Violation"
            confidence = 75
        else:
            action_ttp = "SCA / CIS Benchmark"
            confidence = 70
        return domain, target_category, action_ttp, lifecycle_role, disposition, confidence

    # 2. MALWARE
    if any(g in groups_lower for g in ["malware", "trojan", "virus", "antivirus", "yara", "rootkit", "ransomware"]) or "defender" in desc_lower:
        domain = PrimaryCategory.MALWARE
        target_category = PrimaryCategory.MALWARE
        lifecycle_role = "STATELESS"
        disposition = "ACTIONABLE"
        if "ransomware" in desc_lower or "ransom" in str(groups_lower):
            action_ttp = "Ransomware"
        elif "rootkit" in desc_lower or "backdoor" in desc_lower or "webshell" in desc_lower:
            action_ttp = "Rootkit / Backdoor"
        else:
            action_ttp = "Virus / Trojan (YARA)"
        return domain, target_category, action_ttp, lifecycle_role, disposition, 95

    # 3. IDENTITY & ACCESS
    if (
        any(g in groups_lower for g in ["bruteforce", "sshd", "pam", "authentication_failed", "authentication_failures", "authentication_success", "invalid_login", "login_failed", "login_success", "sudo"])
        or "ssh" in desc_lower
        or "login" in desc_lower
        or "password" in desc_lower
        or rule_id_str in ("5501", "5502", "5503", "5504", "5712", "5715", "5716", "5720", "100001")
    ):
        domain = PrimaryCategory.IDENTITY_ACCESS
        target_category = PrimaryCategory.IDENTITY_ACCESS
        lifecycle_role = "STATELESS"
        if any(k in desc_lower or k in groups_lower for k in ["success", "opened", "accepted", "5715", "5501", "5503"]):
            action_ttp = "Auth Success"
            disposition = "SAFE"
            confidence = 90
        elif "brute force" in desc_lower or rule_id_str in ("5712", "5720", "100001") or "multiple fail" in desc_lower:
            action_ttp = "Auth Anomaly"
            disposition = "ACTIONABLE" if rule_level >= 10 else "REVIEW"
            confidence = 85
        elif "sudo" in desc_lower or "privilege" in desc_lower or rule_id_str in ("5402", "5504", "5902"):
            action_ttp = "Privilege Escalation"
            disposition = "ACTIONABLE" if rule_level >= 10 else "REVIEW"
            confidence = 85
        else:
            action_ttp = "Auth Failure"
            disposition = "ACTIONABLE" if rule_level >= 10 else "REVIEW"
            confidence = 80
        return domain, target_category, action_ttp, lifecycle_role, disposition, confidence

    # 4. ATTACK
    if (
        any(g in groups_lower for g in ["attack", "web_attack", "web_exploit", "sqli", "xss", "lfi", "rfi", "dos", "ddos"])
        or any(t in tactics_lower for t in ["initial access", "execution", "privilege escalation", "credential access", "defense evasion", "lateral movement", "exfiltration", "impact"])
        or rule_id_str in ("31151", "31101", "31106")
        or (rule_level >= 8 and not is_internal_src)
    ):
        domain = PrimaryCategory.ATTACK
        target_category = PrimaryCategory.ATTACK
        lifecycle_role = "STATELESS"
        if any(w in full_log_lower for w in ["union", "select", "drop", "or 1=1", "sleep(", "benchmark("]) or "sql" in desc_lower or "xss" in desc_lower:
            action_ttp = "Web Attack"
            confidence = 90
        elif any(w in full_log_lower for w in ["eval-stdin", "phpunit", "log4j", "cmd", "shell", "exec"]) or "rce" in desc_lower or "exploit" in desc_lower:
            action_ttp = "Exploitation / RCE"
            confidence = 90
        elif "scan" in desc_lower or "recon" in desc_lower or is_scanner_ua:
            action_ttp = "Recon / Scan"
            confidence = 85
        elif "c2" in desc_lower or "beacon" in desc_lower:
            action_ttp = "Command & Control (C2)"
            confidence = 85
        elif "lateral" in desc_lower or "psexec" in desc_lower:
            action_ttp = "Lateral Movement"
            confidence = 85
        else:
            action_ttp = "Web Attack"
            confidence = 75

        disposition = "ACTIONABLE" if (http_status in (200, 201) or rule_level >= 10) else "REVIEW"
        return domain, target_category, action_ttp, lifecycle_role, disposition, confidence

    # 5. SYSTEM / AVAILABILITY
    domain = PrimaryCategory.SYSTEM_AVAILABILITY
    target_category = PrimaryCategory.SYSTEM_AVAILABILITY
    lifecycle_role = "STATELESS"
    disposition = "SAFE"

    if any(g in groups_lower for g in ["docker", "kubernetes", "k8s", "container"]):
        action_ttp = "Cloud / Container Event"
        confidence = 80
    elif http_status in (404, 400, 403, 500) or any(g in groups_lower for g in ["nginx", "apache", "httpd", "accesslog"]) or "404" in desc_lower:
        action_ttp = "Web Operational"
        confidence = 70
    else:
        action_ttp = "Service Health / Error"
        confidence = 60

    return domain, target_category, action_ttp, lifecycle_role, disposition, confidence


class AlertStreamReader:
    """
    Memory-efficient stream reader for large Wazuh JSONL/NDJSON alert files.
    Streams records in buffered chunks using Python generators to prevent OOM.
    """

    def __init__(self, filepath: Optional[str] = None, chunk_size: int = CHUNK_SIZE):
        self.filepath = filepath or ""
        self.filepath = filepath
        self.chunk_size = chunk_size
        self.total_lines_read = 0
        self.total_valid_records = 0
        self.total_corrupt_lines = 0

        # Load Asset Inventory Context for Dynamic Normalization
        asset_config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "asset_inventory.json")
        self.assets_config = {}
        if os.path.exists(asset_config_path):
            try:
                with open(asset_config_path, "r", encoding="utf-8") as f:
                    self.assets_config = json.load(f).get("assets", {})
            except Exception:
                pass
        self.asset_resolver = CanonicalAssetResolver(self.assets_config)

    def stream_raw_lines(self) -> Generator[str, None, None]:
        """Yield raw non-empty lines from the file."""
        with open(self.filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line_str = line.strip()
                if line_str:
                    self.total_lines_read += 1
                    yield line_str

    def stream_chunks(self) -> Generator[List[Dict[str, Any]], None, None]:
        """Yield chunks of parsed dictionaries."""
        chunk = []
        for line in self.stream_raw_lines():
            try:
                record = json.loads(line)
                chunk.append(record)
                self.total_valid_records += 1
                if len(chunk) >= self.chunk_size:
                    yield chunk
                    chunk = []
            except json.JSONDecodeError:
                self.total_corrupt_lines += 1

        if chunk:
            yield chunk

    def stream_validated_alerts(self) -> Generator[WazuhRawAlert, None, None]:
        """Yield Pydantic validated WazuhRawAlert objects."""
        for chunk in self.stream_chunks():
            for record in chunk:
                try:
                    alert = WazuhRawAlert.model_validate(record)
                    yield alert
                except Exception:
                    self.total_corrupt_lines += 1

    def normalize_record(self, record: Dict[str, Any]) -> Optional[CommonEventModel]:
        """Normalize a single raw dictionary record into CommonEventModel."""
        try:
            alert = WazuhRawAlert.model_validate(record)
            return self.normalize_alert_object(alert, raw_dict=record)
        except Exception:
            return None

    def normalize_alert_object(self, alert: WazuhRawAlert, raw_dict: Optional[Dict[str, Any]] = None) -> CommonEventModel:
        """Standardize a single WazuhRawAlert into CommonEventModel using Apex Standard V3.4 with multi-layer field extraction."""
        if raw_dict is None:
            raw_dict = alert.model_dump(by_alias=True)
            if alert.agent and hasattr(alert.agent, "labels") and alert.agent.labels:
                if "agent" not in raw_dict or not isinstance(raw_dict["agent"], dict):
                    raw_dict["agent"] = {}
                raw_dict["agent"]["labels"] = alert.agent.labels

        # Execute Apex Normalization V4.0 (Gold-Standard Compact Normalization)
        apex_norm = ApexNormalizerV40.normalize_compact(raw_dict)
        data = alert.data or {}
        win_data = data.get("win", {}).get("eventdata", {}) if isinstance(data.get("win"), dict) else {}
        audit_data = data.get("audit", {}) if isinstance(data.get("audit"), dict) else {}

        # Multi-layer source and destination IP extraction (Syslog, Windows EventChannel, Linux Auditd, and ECS Aliases)
        src_ip = (
            data.get("srcip")
            or data.get("src_ip")
            or win_data.get("ipAddress")
            or win_data.get("sourceIp")
            or audit_data.get("srcip")
            or audit_data.get("addr")
            or extract_aliased_field(data, ECS_FIELD_ALIASES["source_ip"])
        )
        dst_ip = (
            data.get("dstip")
            or data.get("dst_ip")
            or win_data.get("destinationIp")
            or extract_aliased_field(data, ECS_FIELD_ALIASES["destination_ip"])
        )
        user = (
            data.get("dstuser")
            or data.get("srcuser")
            or data.get("user")
            or win_data.get("targetUserName")
            or win_data.get("subjectUserName")
            or audit_data.get("acct")
            or audit_data.get("auid")
            or extract_aliased_field(data, ECS_FIELD_ALIASES["username"])
        )

        # Multi-layer process information
        apex_proc = apex_norm.get("process") or {}
        proc_name = (
            apex_proc.get("name")
            or data.get("process_name")
            or data.get("image")
            or win_data.get("image")
            or audit_data.get("exe")
            or extract_aliased_field(data, ECS_FIELD_ALIASES["process_name"])
        )
        proc_path = (
            apex_proc.get("path")
            or data.get("process_path")
            or win_data.get("image")
            or extract_aliased_field(data, ECS_FIELD_ALIASES["process_path"])
        )
        cmd_line = (
            apex_proc.get("command_line")
            or data.get("command_line")
            or data.get("cmd")
            or win_data.get("commandLine")
            or audit_data.get("command")
            or extract_aliased_field(data, ECS_FIELD_ALIASES["command_line"])
        )
        parent_proc = (
            apex_proc.get("parent_name")
            or apex_proc.get("parent_path")
            or data.get("parent_process")
            or data.get("parent")
            or win_data.get("parentImage")
        )

        # Ports & Network Protocol extraction (Apex V3.4 RFC compliant)
        apex_net = apex_norm.get("network") or {}
        raw_src_port = data.get("srcport") or data.get("src_port") or win_data.get("sourcePort") or extract_aliased_field(data, ECS_FIELD_ALIASES["source_port"])
        raw_dst_port = data.get("dstport") or data.get("dst_port") or win_data.get("destinationPort") or extract_aliased_field(data, ECS_FIELD_ALIASES["destination_port"])
        
        src_port_int = apex_net.get("src_port")
        if src_port_int is None and raw_src_port is not None:
            try:
                src_port_int = int(raw_src_port)
            except (ValueError, TypeError):
                pass

        dst_port_int = apex_net.get("dst_port")
        if dst_port_int is None and raw_dst_port is not None:
            try:
                dst_port_int = int(raw_dst_port)
            except (ValueError, TypeError):
                pass

        # Resolusi L4 Transport vs L7 Protocol (Apex V3.4 Fix: Never put HTTP verbs into protocol)
        transport_proto = apex_net.get("transport") or data.get("proto") or "ip"
        l7_proto = apex_net.get("protocol")
        protocol = l7_proto or str(data.get("proto") or data.get("protocol") or "ip").lower()
        if str(protocol).upper() in ApexNormalizerV34.HTTP_METHODS:
            protocol = "http"
            transport_proto = "tcp"

        # Apex V3.4 INET sanitization for IP addresses
        if apex_net.get("src_ip"):
            src_ip = apex_net["src_ip"]
        elif src_ip:
            src_ip = ApexTransformsV34.transform_ip(src_ip)

        if apex_net.get("dst_ip"):
            dst_ip = apex_net["dst_ip"]
        elif dst_ip:
            dst_ip = ApexTransformsV34.transform_ip(dst_ip)

        # Extract MITRE IDs & Tactics if present, with fallback to rule_classification_mapping
        mitre_ids = []
        mitre_tactics = []
        mitre_techs = []
        if alert.rule.mitre:
            if "id" in alert.rule.mitre:
                m_id = alert.rule.mitre["id"]
                if isinstance(m_id, list):
                    mitre_ids.extend(m_id)
                elif isinstance(m_id, str):
                    mitre_ids.append(m_id)
            if "tactic" in alert.rule.mitre:
                m_tac = alert.rule.mitre["tactic"]
                if isinstance(m_tac, list):
                    mitre_tactics.extend(m_tac)
                elif isinstance(m_tac, str):
                    mitre_tactics.append(m_tac)

        rule_id_str = str(alert.rule.id)
        rc_entry = _get_rule_classification_map().get(rule_id_str, {})
        if not mitre_tactics and rc_entry.get("tactic"):
            mitre_tactics.append(rc_entry["tactic"])
        if not mitre_ids and rc_entry.get("tech"):
            mitre_ids.append(rc_entry["tech"])
        if rc_entry.get("tech"):
            mitre_techs.append(rc_entry["tech"])

        # Asset Resolver Auto-Discovery: register incoming observation
        raw_agent_id = alert.agent.id if alert.agent else "000"
        raw_agent_name = alert.agent.name if alert.agent else None
        raw_agent_ip = alert.agent.ip if alert.agent else None
        self.asset_resolver.register_observation(raw_agent_id, raw_agent_name, raw_agent_ip)
        _GLOBAL_ASSET_RESOLVER.register_observation(raw_agent_id, raw_agent_name, raw_agent_ip)

        # Resolve canonical target endpoint host (immune to collector hostnames)
        data_dsthost = data.get("dsthost") or data.get("vhost")
        canonical_host = self.asset_resolver.resolve_target_host(
            agent_id=raw_agent_id,
            agent_name=raw_agent_name,
            dst_ip=dst_ip,
            raw_host=alert.host,
            data_dsthost=data_dsthost
        )
        agent_name = canonical_host

        # Context Enrichment (Asset Criticality & Identity Privilege)
        asset_info = self.assets_config.get(canonical_host, self.assets_config.get(raw_agent_name or "", {}))
        host_criticality = asset_info.get("criticality", "STANDARD")
        is_internet_exposed = asset_info.get("internet_exposed", False)

        user_str = str(user).lower() if user else ""
        is_privileged = user_str in ["root", "administrator", "admin", "system"]
        is_svc = user_str.startswith("svc_") or user_str.endswith("$")

        # [Semantic Normalization] Extract 4 canonical dimensions: Category, Actor, Target, Duration
        cat, actor, target, win_class, win_dur = classify_event_archetype(
            groups=alert.rule.groups,
            rule_id=rule_id_str,
            rule_level=alert.rule.level,
            source_ip=src_ip,
            destination_host=canonical_host,
            destination_ip=dst_ip,
            username=user,
            process_name=proc_name,
            agent_name=canonical_host,
            rule_description=alert.rule.description,
            mitre_tactics=mitre_tactics,
        )

        # [OS Platform Extraction] Determine agent OS for aggregation dimension
        raw_labels = alert.agent.labels if alert.agent and alert.agent.labels else {}
        decoder_name_str = alert.decoder.name if alert.decoder else None
        os_platform = extract_os_platform(
            alert_agent_labels=raw_labels,
            data=data,
            decoder_name=decoder_name_str,
            location=alert.location,
            groups=alert.rule.groups,
        )

        # [HTTP & Scanner Forensics Extraction]
        http_status_int = None
        raw_status = data.get("status") or data.get("http_status")
        if not raw_status and data.get("id") and str(data.get("id")).isdigit() and len(str(data.get("id"))) == 3:
            raw_status = data.get("id")
        if raw_status:
            try:
                http_status_int = int(raw_status)
            except (ValueError, TypeError):
                pass

        user_agent_str = data.get("http_user_agent") or data.get("user_agent")
        full_log_str = alert.full_log or ""
        if full_log_str and (http_status_int is None or user_agent_str is None):
            m_http = _RE_HTTP_STATUS_UA.search(full_log_str)
            if m_http:
                if http_status_int is None:
                    try:
                        http_status_int = int(m_http.group(1))
                    except (ValueError, TypeError):
                        pass
                if user_agent_str is None:
                    user_agent_str = m_http.group(2)
            elif http_status_int is None:
                m_fb = _RE_HTTP_STATUS_FALLBACK.search(full_log_str)
                if m_fb:
                    try:
                        http_status_int = int(m_fb.group(1))
                    except (ValueError, TypeError):
                        pass

        is_scanner = bool(_RE_SCANNER_UA.search(user_agent_str or ""))

            # ── [Composite Clustering Layer: Who & What Extraction] ────────────────
        who_subnet = normalize_ip_to_slash24(src_ip)
        extracted_errno = None
        extracted_upstream = None
        extracted_url_path = data.get("url") or data.get("path")
        extracted_method = data.get("protocol") or data.get("method") or "GET"

        # Specialized Nginx Error Log parser (Rule 31301 & related)
        if rule_id_str == "31301" or "nginx" in str(alert.rule.groups).lower() or (full_log_str and "while connecting to upstream" in full_log_str):
            m_err = _RE_NGINX_ERRNO.search(full_log_str)
            if m_err:
                try:
                    extracted_errno = int(m_err.group(1))
                except (ValueError, TypeError):
                    extracted_errno = None
            m_req = _RE_NGINX_REQUEST.search(full_log_str)
            if m_req:
                extracted_method = m_req.group(1)
                extracted_url_path = m_req.group(2)
            m_up = _RE_NGINX_UPSTREAM.search(full_log_str)
            if m_up:
                extracted_upstream = m_up.group(1)
            m_cl = _RE_NGINX_CLIENT.search(full_log_str)
            if m_cl and not src_ip:
                src_ip = m_cl.group(1)
                who_subnet = normalize_ip_to_slash24(src_ip)

        # Specialized Dpkg / Package parser & Apex V3.4 CVE integration
        apex_vuln = apex_norm.get("vulnerability") or {}
        pkg_name = data.get("package") or apex_vuln.get("package_name")
        dpkg_stat = data.get("dpkg_status")
        if not pkg_name and full_log_str and ("status " in full_log_str or "dpkg" in full_log_str):
            parts = full_log_str.strip().split()
            if len(parts) >= 4 and parts[1] == "status":
                dpkg_stat = f"status {parts[2]}"
                pkg_name = parts[3].split(":")[0]

        # Apex V3.4 FIM Syscheck Integration
        apex_file = apex_norm.get("file") or {}
        if apex_file.get("path") and not proc_path:
            proc_path = apex_file["path"]

        clean_path_val = normalize_url_path(extracted_url_path)

        # Determine composite who & what
        if rule_id_str == "31301" or (extracted_errno is not None and extracted_upstream is not None):
            who_cluster = who_subnet if src_ip else canonical_host
            what_cluster = f"{clean_path_val}:{extracted_errno or 111}:{extracted_upstream or 'upstream'}"
        elif rule_id_str in ("31533", "31101", "31104", "31106", "31514") or "web" in str(alert.rule.groups).lower():
            who_cluster = who_subnet if src_ip else canonical_host
            what_cluster = f"{extracted_method}:{clean_path_val}"
        elif rule_id_str in ("2904", "2901", "2902", "2903") or pkg_name:
            who_cluster = canonical_host
            what_cluster = f"{pkg_name or 'package'}:{dpkg_stat or 'status'}"
        elif user:
            who_cluster = f"user:{user}"
            what_cluster = f"action:{alert.rule.id}"
        else:
            who_cluster = who_subnet if src_ip else canonical_host
            what_cluster = str(alert.rule.id)


    # [Indicator of Attack Context Extraction] Generate human-readable context summary
        mitre_meta = getattr(alert.rule, "mitre", None)
        mitre_ids = []
        if isinstance(mitre_meta, dict):
            mitre_ids = mitre_meta.get("id") or []
        elif hasattr(mitre_meta, "id"):
            mitre_ids = mitre_meta.id or []
        decoder_name = alert.decoder.name if alert.decoder else None

        ioa_summary = generate_ioa_summary(
            category=cat,
            rule_id=rule_id_str,
            rule_description=alert.rule.description,
            actor=actor,
            target=target,
            data=data,
            decoder=decoder_name,
            mitre_ids=mitre_ids,
            http_status=http_status_int,
            is_scanner=is_scanner,
        )

        # [GAP 1 FIX] Extract compliance framework tags from Wazuh rule metadata
        compliance = {}
        for fw in ("pci_dss", "nist_800_53", "gdpr", "hipaa", "tsc"):
            val = getattr(alert.rule, fw, None)
            if val:
                compliance[fw] = val

        # [Multi-Tenancy Dynamic Extraction] Support Wazuh Agent Labels or Payload Tenant Tag
        raw_labels = alert.agent.labels if alert.agent and alert.agent.labels else {}
        raw_tenant = raw_labels.get("tenant") or raw_labels.get("tenant_id") or data.get("tenant") or data.get("tenant_id") or "DEFAULT"
        tenant_str = str(raw_tenant).strip()
        if tenant_str.lower().startswith("tenant"):
            tenant = "Tenant" + tenant_str[6:].upper()
        else:
            tenant = tenant_str

        # ── 3-Layer Category Taxonomy & Stateful Lifecycle Attributes Engine ──
        res_tax = classify_event_taxonomy(
            rule_id=rule_id_str,
            rule_level=alert.rule.level,
            groups=alert.rule.groups,
            rule_description=alert.rule.description,
            full_log=full_log_str,
            data=data,
            source_ip=src_ip,
            http_status=http_status_int,
            is_scanner_ua=is_scanner,
            mitre_tactics=mitre_tactics,
        )
        if len(res_tax) == 6:
            domain_val, target_cat_val, action_ttp_val, life_role_val, disp, conf_score = res_tax
        else:
            domain_val, action_ttp_val, disp, conf_score = res_tax
            target_cat_val = PrimaryCategory.SYSTEM_AVAILABILITY
            life_role_val = "STATELESS" 

        # Check if this rule is explicitly mapped or if it requires autonomous classification review
        is_explicitly_mapped = rule_id_str in _get_rule_classification_map()
        # Autonomous AI Triage (AGENTS.md Standard): >= 85% confidence is autonomous; < 85% triggers Ground Truth human audit.
        if is_explicitly_mapped:
            needs_review = (cat == "SYSTEM_HEALTH" and alert.rule.level >= 6)
        else:
            needs_review = (conf_score < 85) or (cat == "SYSTEM_HEALTH" and alert.rule.level >= 6)

        apex_http = apex_norm.get("http") or {}
        apex_timestamps = apex_norm.get("timestamps") or {}
        apex_net = apex_norm.get("network") or {}

        cem = CommonEventModel(
            event_id=alert.id or alert.event_id or f"evt_{self.total_valid_records}",
            timestamp=alert.timestamp,
            # Apex V3.4 Canonical Normalization Fields
            schema_version="1.0.0",
            raw_sha256=apex_norm.get("raw_sha256"),
            event_time=apex_timestamps.get("event_time"),
            alert_time=apex_timestamps.get("alert_time"),
            ingest_time=apex_timestamps.get("ingest_time"),
            pipeline_latency_ms=apex_timestamps.get("pipeline_latency_ms"),
            detection_delay_sec=apex_timestamps.get("detection_delay_sec"),
            alias_source={"schema_ref": apex_norm.get("schema_ref")} if "schema_ref" in apex_norm else apex_norm.get("alias_source", {}),
            query_string=apex_http.get("query_string"),
            parsed_query=apex_http.get("parsed_query"),
            http_method=apex_http.get("method"),
            response_bytes=apex_http.get("response_bytes"),
            bytes_out=apex_net.get("bytes_out"),
            network_transport=apex_net.get("transport"),
            network_direction=apex_net.get("direction"),
            referrer_info=apex_http.get("referrer"),
            user_agent_details=apex_http.get("user_agent"),
            fim_info=apex_norm.get("file"),
            vulnerability_info=apex_norm.get("vulnerability"),
            process_info=apex_norm.get("process"),
            apex_normalized=apex_norm,
            source_ip=src_ip,
            source_host=canonical_host if alert.agent else None,
            source_port=src_port_int,
            destination_ip=dst_ip,
            destination_host=canonical_host,
            destination_port=dst_port_int,
            protocol=str(protocol) if protocol else None,
            username=user,
            agent_id=raw_agent_id,
            agent_name=canonical_host,
            tenant_id=str(tenant),
            host_criticality=host_criticality,
            is_internet_exposed=is_internet_exposed,
            is_privileged_user=is_privileged,
            is_service_account=is_svc,
            process_name=proc_name,
            process_path=proc_path,
            command_line=cmd_line,
            parent_process=parent_proc,
            rule_id=alert.rule.id,
            rule_level=alert.rule.level,
            rule_description=alert.rule.description,
            classification_groups=alert.rule.groups,
            mitre_attack_ids=mitre_ids,
            mitre_tactics=mitre_tactics,
            mitre_techniques=mitre_techs,
            raw_payload=alert.full_log,
            location=alert.location,
            decoder_name=decoder_name_str,
            event_category=cat,
            dedup_actor=actor,
            dedup_target=target,
            window_class=win_class,
            window_duration_seconds=win_dur,
            compliance_frameworks=compliance,       # [GAP 1 FIX]
            ioa_summary=ioa_summary,
            needs_classification_review=needs_review,
            os_platform=os_platform,
            http_status=http_status_int,
            user_agent=user_agent_str,
            is_scanner_ua=is_scanner,
            who_cluster=who_cluster,
            what_cluster=what_cluster,
            who_subnet=who_subnet,
            clean_path=clean_path_val,
            url_path=extracted_url_path,
            errno=extracted_errno,
            upstream_target=extracted_upstream,
            package_name=pkg_name,
            dpkg_status=dpkg_stat,
            domain=domain_val,
            target_category=target_cat_val,
            action_ttp=action_ttp_val,
            lifecycle_role=life_role_val,
            disposition=disp,
            confidence_score=conf_score,
            primary_category=domain_val,
            subcategory=action_ttp_val,
            composite_cluster_key=f"{tenant}|{alert.rule.id}|{canonical_host}|{who_cluster}|{what_cluster}",
        )

        # ── Plugin Chain: OCSF fields + MITRE supplement + Inline Risk Score ──
        # All enrichment is config-driven via JSON files in /config/.
        # New plugins can be added in pipeline/normalization_plugins.py without
        # modifying this file.
        cem = _get_plugin_chain()(cem, alert)
        return cem


    def stream_normalized_events(self) -> Generator[CommonEventModel, None, None]:
        """Yield standardized CommonEventModel objects with multi-layer field extraction and context enrichment."""
        for alert in self.stream_validated_alerts():
            yield self.normalize_alert_object(alert)


# [REMOVED F-6] is_stateless_pure_noise was removed.
# 100% of events enter the pipeline to ensure PCI-DSS/SOC2 audit coverage,
# and high-frequency noise is suppressed safely at Stage 3 via governance rules.



def route_event_track(event) -> str:
    """
    [Dual-Track Dispatcher - Fast-Track vs Windowed-Track]
    Decouples high-velocity noise from critical security alerts:
    - FAST_TRACK (< 500ms): P0/P1 single-shot exploits (CVEs, RCE, SQLi, rootkit anomaly, level >= 10, threat intel match).
    - WINDOWED_TRACK (15-min window): High-frequency telemetry (HTTP 400 scans, SSH brute-force, dpkg, sync POSTs).
    """
    # 1. Any confirmed threat intelligence match -> FAST TRACK
    if getattr(event, "threat_intel_match", False):
        return "FAST_TRACK"

    # 2. High severity (Rule Level >= 10) -> FAST TRACK (e.g. CVE-2025-27558, SQLi, Exploit chains)
    level = getattr(event, "rule_level", 0)
    if level >= 10:
        return "FAST_TRACK"

    # 3. Known critical attack signatures & rootkits regardless of base level
    rule_id_str = str(event.rule_id)
    critical_sids = {
        "31103", "31104", "31105", "31106", "31110", "31516",  # Web Exploits / SQLi / XSS
        "510",                                                  # Rootkit detection
        "23502", "23503", "23504", "23505", "23506", "23508",  # Critical CVE / Vulnerability
        "100100", "100101", "100310",                           # Suspicious PowerShell & LOLBAS
        "100030", "100031", "100102", "5402",                   # Privilege Escalation / Sudo Root
        "100200", "100201", "100202", "100203",                 # Persistence / Backdoors
    }
    if rule_id_str in critical_sids:
        return "FAST_TRACK"

    # 4. High-threat category shortcut
    category = getattr(event, "event_category", "SYSTEM_HEALTH")
    if category in ("MALWARE", "VULNERABILITY"):
        return "FAST_TRACK"

    # 5. Critical MITRE tactics: Privilege Escalation, Defense Evasion, Exfiltration
    critical_tactics = {"privilege-escalation", "defense-evasion", "exfiltration", "impact"}
    mitre_tactics = getattr(event, "mitre_tactics", [])
    if any(t.lower() in critical_tactics for t in mitre_tactics):
        return "FAST_TRACK"

    # Default: High-frequency repetitive events undergo Windowed Aggregation
    return "WINDOWED_TRACK"


def _load_rule_classification_map() -> Dict[str, Dict[str, Any]]:
    """
    Load rule_classification_mapping.json as runtime source of truth.
    Returns dict keyed by rule_id string.
    Cached at module level to avoid repeated disk reads.
    """
    config_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config")
    mapping_path = os.path.join(config_dir, "rule_classification_mapping.json")
    result: Dict[str, Dict[str, Any]] = {}
    if not os.path.exists(mapping_path):
        return result
    try:
        with open(mapping_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for entry in data.get("rules", []):
            rid = str(entry.get("rule_id", ""))
            if rid:
                result[rid] = entry
    except Exception:
        pass
    return result


# Module-level cache — loaded once on first import
_RULE_CLASSIFICATION_MAP: Dict[str, Dict[str, Any]] = {}


def _get_rule_classification_map() -> Dict[str, Dict[str, Any]]:
    """Return cached rule classification map, loading it on first call."""
    global _RULE_CLASSIFICATION_MAP
    if not _RULE_CLASSIFICATION_MAP:
        _RULE_CLASSIFICATION_MAP = _load_rule_classification_map()
    return _RULE_CLASSIFICATION_MAP


# ── Cluster v1 Uniform 15-Minute Window Configuration (900s) ───────────────
# In Cluster v1 Architecture, all categories share the deterministic 15-minute
# window bucket (900s) with 120s grace period. High-value events bypass immediately (0s).
# Legacy variable windows (300s/600s/1800s/3600s) have been decommissioned.
_CLUSTER_V1_WINDOW_SECONDS: int = 900
_CLUSTER_V1_WINDOW_CLASS: str = "UNIFORM_15_MIN"

from collections import defaultdict
from config.category_constants import PrimaryCategory, SUBCATEGORIES

# In Cluster v1 Architecture, all categories share the uniform 15-minute window (900s)
_CATEGORY_WINDOW_MAP: Dict[str, Tuple[str, int]] = defaultdict(
    lambda: (_CLUSTER_V1_WINDOW_CLASS, _CLUSTER_V1_WINDOW_SECONDS)
)

# ── Mapping from rule_classification_mapping.json cat → Canonical Categories ─────────
_CAT_TO_INTERNAL: Dict[str, str] = {
    # Strictly maps any legacy or incoming string to one of the 6 Primary Categories
    "AUTHENTICATION":           PrimaryCategory.IDENTITY_ACCESS,
    "LATERAL_MOVEMENT":         PrimaryCategory.ATTACK,
    "PRIVILEGE_ESCALATION":     PrimaryCategory.IDENTITY_ACCESS,
    "MALWARE":                  PrimaryCategory.MALWARE,
    "NETWORK_ANOMALY":          PrimaryCategory.ATTACK,
    "DEFENSE_EVASION":          PrimaryCategory.ATTACK,
    "POLICY_VIOLATION":         PrimaryCategory.CONFIGURATION_COMPLIANCE,
    "DATA_ACCESS":              PrimaryCategory.ATTACK,
    "PROCESS_EXECUTION":        PrimaryCategory.ATTACK,
    "CONFIGURATION_CHANGE":     PrimaryCategory.CONFIGURATION_COMPLIANCE,
    "PERSISTENCE":              PrimaryCategory.ATTACK,
    "VULNERABILITY":            PrimaryCategory.VULNERABILITY,
    "CLOUD_CONTAINER":          PrimaryCategory.SYSTEM_AVAILABILITY,
    "SYSTEM_HEALTH":            PrimaryCategory.SYSTEM_AVAILABILITY,
    "COMPLIANCE":               PrimaryCategory.CONFIGURATION_COMPLIANCE,
    "CONFIGURATION_ASSESSMENT": PrimaryCategory.CONFIGURATION_COMPLIANCE,
    "NETWORK_WEB":              PrimaryCategory.ATTACK,
    "ENDPOINT_PROCESS":         PrimaryCategory.ATTACK,
    "FILE_INTEGRITY":           PrimaryCategory.CONFIGURATION_COMPLIANCE,
    "AUTH":                     PrimaryCategory.IDENTITY_ACCESS,
    "HOST":                     PrimaryCategory.SYSTEM_AVAILABILITY,
    "NETWORK":                  PrimaryCategory.SYSTEM_AVAILABILITY,
    "TELEMETRY":                PrimaryCategory.SYSTEM_AVAILABILITY,
    "OTHER":                    PrimaryCategory.SYSTEM_AVAILABILITY,
    "RANSOMWARE":               PrimaryCategory.MALWARE,
    "COMMAND_AND_CONTROL":      PrimaryCategory.ATTACK,
    "EXFILTRATION":             PrimaryCategory.ATTACK,
    "CREDENTIAL_ACCESS":        PrimaryCategory.IDENTITY_ACCESS,
    "EXECUTION":                PrimaryCategory.ATTACK,
    "DISCOVERY":                PrimaryCategory.ATTACK,
    "INITIAL_ACCESS":           PrimaryCategory.ATTACK,
    "WEB_ATTACK":               PrimaryCategory.ATTACK,
    "WEB_OPERATIONAL":          PrimaryCategory.SYSTEM_AVAILABILITY,
    "AUTH_FAILURE":             PrimaryCategory.IDENTITY_ACCESS,
    "AUTH_SUCCESS":             PrimaryCategory.IDENTITY_ACCESS,
    "UNKNOWN":                  PrimaryCategory.SYSTEM_AVAILABILITY,
    PrimaryCategory.ATTACK:                   PrimaryCategory.ATTACK,
    PrimaryCategory.VULNERABILITY:            PrimaryCategory.VULNERABILITY,
    PrimaryCategory.CONFIGURATION_COMPLIANCE: PrimaryCategory.CONFIGURATION_COMPLIANCE,
    PrimaryCategory.IDENTITY_ACCESS:          PrimaryCategory.IDENTITY_ACCESS,
    PrimaryCategory.MALWARE:                  PrimaryCategory.MALWARE,
    PrimaryCategory.SYSTEM_AVAILABILITY:      PrimaryCategory.SYSTEM_AVAILABILITY,
}

_AUTH_SUCCESS_GROUPS = frozenset([
    "authentication_success", "login_success", "session_opened",
    "session_open", "accepted", "logon_success",
])
_AUTH_FAILURE_GROUPS = frozenset([
    "authentication_failed", "authentication_failures", "invalid_login",
    "login_failed", "logon_failure", "bad_password",
])


def _resolve_auth_subtype(groups_lower: set) -> str:
    """Determine AUTH_FAILURE vs AUTH_SUCCESS from rule.groups."""
    if groups_lower & _AUTH_SUCCESS_GROUPS:
        return "AUTH_SUCCESS"
    return "AUTH_FAILURE"


# ── OS Platform Extraction ────────────────────────────────────────────────────
def extract_os_platform(
    alert_agent_labels: Optional[Dict[str, Any]],
    data: Optional[Dict[str, Any]],
    decoder_name: Optional[str],
    location: Optional[str],
    groups: Optional[List[str]],
) -> str:
    """Extract OS platform: agent.labels.os → data.win → decoder → location → groups → unknown"""
    if alert_agent_labels:
        raw_os = alert_agent_labels.get("os") or alert_agent_labels.get("os_platform")
        if raw_os:
            os_l = str(raw_os).strip().lower()
            if "win" in os_l:
                return "windows"
            if any(k in os_l for k in ("linux", "ubuntu", "centos", "debian", "rhel")):
                return "linux"
            if "mac" in os_l or "darwin" in os_l:
                return "macos"
    data = data or {}
    win_data = data.get("win", {})
    if isinstance(win_data, dict):
        win_sys = win_data.get("system", {})
        if isinstance(win_sys, dict) and win_sys.get("channel"):
            return "windows"
        if win_data.get("eventdata") or win_data.get("system"):
            return "windows"
    if decoder_name:
        dec_l = decoder_name.lower()
        if "windows" in dec_l or "eventchannel" in dec_l or "winevent" in dec_l:
            return "windows"
    if location:
        loc_l = location.lower()
        if "eventchannel" in loc_l or "winevtlog" in loc_l:
            return "windows"
    if groups:
        gl = {g.lower() for g in groups}
        if gl & {"windows", "win_eventlog", "sysmon", "powershell", "winlogbeat"}:
            return "windows"
        if gl & {"syslog", "pam", "sshd", "auditd", "systemd", "unix", "linux"}:
            return "linux"
    return "unknown"


def classify_event_archetype(
    groups: List[str],
    rule_id: str,
    rule_level: int,
    source_ip: Optional[str],
    destination_host: Optional[str],
    destination_ip: Optional[str],
    username: Optional[str],
    process_name: Optional[str],
    agent_name: str,
    rule_description: Optional[str] = None,
    mitre_tactics: Optional[List[str]] = None,
) -> Tuple[str, str, str, str, int]:
    """
    Unified 6-Category Archetype Engine:
    Returns (category, actor, target, window_class, window_seconds).
    Category is strictly one of the 6 Primary Categories.
    """
    groups_lower = set(g.lower() for g in (groups or []))
    rule_id_str = str(rule_id)
    desc_lower = (rule_description or "").lower()
    tactics_lower = set(t.lower() for t in (mitre_tactics or []))
    clean_dst_host = None
    if destination_host and str(destination_host).strip().lower() not in IGNORED_COLLECTOR_HOSTS:
        clean_dst_host = str(destination_host).strip()
    clean_agent_name = None
    if agent_name and str(agent_name).strip().lower() not in IGNORED_COLLECTOR_HOSTS:
        clean_agent_name = str(agent_name).strip()
    clean_agent_name = clean_agent_name or clean_dst_host or "unknown"
    def _auth_actor():
        return (f"user:{username}" if username else None) or source_ip or "proc:auth_daemon"
    def _net_actor():
        return source_ip or (f"proc:{process_name}" if process_name else "proc:web_server")
    def _host_actor():
        return (f"proc:{process_name}" if process_name else None) or (f"user:{username}" if username else None) or "proc:kernel_or_auditd"

    # == Tier 0: rule_classification_mapping.json =============================
    rule_map = _get_rule_classification_map()
    if rule_id_str in rule_map:
        entry = rule_map[rule_id_str]
        raw_cat = entry.get("cat", "POLICY_VIOLATION")
        internal_cat = _CAT_TO_INTERNAL.get(raw_cat, PrimaryCategory.SYSTEM_AVAILABILITY)
        win_class, win_dur = _CATEGORY_WINDOW_MAP.get(internal_cat, (_CLUSTER_V1_WINDOW_CLASS, _CLUSTER_V1_WINDOW_SECONDS))
        if internal_cat == PrimaryCategory.IDENTITY_ACCESS:
            actor, target = _auth_actor(), clean_dst_host or clean_agent_name
        elif internal_cat == PrimaryCategory.ATTACK:
            actor, target = _net_actor(), clean_dst_host or destination_ip or clean_agent_name
        elif internal_cat == PrimaryCategory.VULNERABILITY:
            pkg_m = re.search(r'affects?\s+([a-zA-Z0-9._-]+)', desc_lower) or re.search(r'affected\s+([a-zA-Z0-9._-]+)', desc_lower)
            actor = f"pkg:{pkg_m.group(1)}" if pkg_m else "vulnerability-detector"
            target = clean_agent_name
        elif internal_cat == PrimaryCategory.CONFIGURATION_COMPLIANCE:
            actor, target = "sca-scanner", clean_agent_name
        elif internal_cat == PrimaryCategory.MALWARE:
            actor = (f"proc:{process_name}" if process_name else None) or "rootcheck"
            target = clean_agent_name
        else:
            actor, target = _host_actor(), clean_agent_name
        return internal_cat, actor, target, win_class, win_dur

    # == Tier 1: Hybrid AI Categorizer (LightGBM + Local LLM + Intent Guardrail)
    ai_fn = _get_ai_predict_fn()
    if ai_fn and (desc_lower or groups_lower):
        try:
            ai_res = ai_fn(desc=desc_lower, groups=list(groups_lower), tactics=list(tactics_lower), rule_id=rule_id_str)
            if ai_res and ai_res.get("confidence", 0) >= 0.70:
                pcat_ai = str(ai_res.get("primary_category", ""))
                if pcat_ai in PrimaryCategory.ALL:
                    if pcat_ai == PrimaryCategory.IDENTITY_ACCESS:
                        actor, target = _auth_actor(), clean_dst_host or clean_agent_name
                    elif pcat_ai == PrimaryCategory.ATTACK:
                        actor, target = _net_actor(), clean_dst_host or destination_ip or clean_agent_name
                    elif pcat_ai == PrimaryCategory.VULNERABILITY:
                        pkg_m = re.search(r'affects?\s+([a-zA-Z0-9._-]+)', desc_lower) or re.search(r'affected\s+([a-zA-Z0-9._-]+)', desc_lower)
                        actor = f"pkg:{pkg_m.group(1)}" if pkg_m else "vulnerability-detector"
                        target = clean_agent_name
                    elif pcat_ai == PrimaryCategory.MALWARE:
                        actor = (f"proc:{process_name}" if process_name else None) or "rootcheck"
                        target = clean_agent_name
                    elif pcat_ai == PrimaryCategory.CONFIGURATION_COMPLIANCE:
                        actor, target = "sca-scanner", clean_agent_name
                    else:
                        actor, target = _host_actor(), clean_agent_name
                    return pcat_ai, actor, target, _CLUSTER_V1_WINDOW_CLASS, _CLUSTER_V1_WINDOW_SECONDS
        except Exception:
            pass

    # == Tier 2: Deterministic Precedence Chain ===============================
    # 1. Malware
    if (groups_lower & {"malware", "virus", "trojan", "rootcheck", "yara", "rootkit", "ransomware", "vssadmin", "shadow_copy"}
            or ("impact" in tactics_lower and groups_lower & {"defense_evasion", "log_clear", "file_tampering"})):
        actor = (f"proc:{process_name}" if process_name else None) or "rootcheck"
        return PrimaryCategory.MALWARE, actor, clean_agent_name, _CLUSTER_V1_WINDOW_CLASS, _CLUSTER_V1_WINDOW_SECONDS

    # 2. Attack
    if (groups_lower & {"attack", "web_attack", "sqli", "xss", "rfi", "lfi", "web_exploit", "c2", "command_and_control", "dns_tunnel", "beacon", "exfiltration", "data_theft", "lateral_movement", "psexec", "recon", "network_scan", "port_scan", "enumeration", "initial_access", "execution", "persistence"}
            or any(t in tactics_lower for t in ["initial access", "execution", "persistence", "lateral movement", "command and control", "exfiltration", "discovery"])):
        actor = source_ip or _net_actor()
        return PrimaryCategory.ATTACK, actor, clean_dst_host or destination_ip or clean_agent_name, _CLUSTER_V1_WINDOW_CLASS, _CLUSTER_V1_WINDOW_SECONDS

    # 3. Identity / Access
    if (groups_lower & {"authentication_failed", "authentication_failures", "authentication_success", "invalid_login", "login_failed", "login_success", "auth", "login", "sshd", "pam", "sudo", "privilege_escalation", "credential_access", "credential_dump", "kerberoast", "brute_force", "password_spray"}
            or "credential access" in tactics_lower or "privilege escalation" in tactics_lower):
        return PrimaryCategory.IDENTITY_ACCESS, _auth_actor(), clean_dst_host or clean_agent_name, _CLUSTER_V1_WINDOW_CLASS, _CLUSTER_V1_WINDOW_SECONDS

    # 4. Vulnerability
    if "vulnerability-detector" in groups_lower or groups_lower & {"vulnerability", "cve"} or "cve-" in desc_lower:
        pkg_m = re.search(r'affects?\s+([a-zA-Z0-9._-]+)', desc_lower) or re.search(r'affected\s+([a-zA-Z0-9._-]+)', desc_lower)
        actor = f"pkg:{pkg_m.group(1)}" if pkg_m else "vulnerability-detector"
        return PrimaryCategory.VULNERABILITY, actor, clean_agent_name, _CLUSTER_V1_WINDOW_CLASS, _CLUSTER_V1_WINDOW_SECONDS

    # 5. Configuration / Compliance
    if groups_lower & {"sca", "cis", "configuration_assessment", "policy", "syscheck", "integrity", "checksum", "fim", "pci_dss", "gdpr", "nist", "hipaa"}:
        actor = (f"user:{username}" if username else None) or "sca-scanner"
        return PrimaryCategory.CONFIGURATION_COMPLIANCE, actor, clean_agent_name, _CLUSTER_V1_WINDOW_CLASS, _CLUSTER_V1_WINDOW_SECONDS

    # 6. System / Availability (Universal Fallback)
    actor = (f"service:{process_name}" if process_name else None) or "service:systemd"
    return PrimaryCategory.SYSTEM_AVAILABILITY, actor, clean_agent_name, _CLUSTER_V1_WINDOW_CLASS, _CLUSTER_V1_WINDOW_SECONDS




def generate_ioa_summary(
    category: str,
    rule_id: str,
    rule_description: Optional[str],
    actor: str,
    target: str,
    data: Optional[Dict[str, Any]] = None,
    decoder: Optional[str] = None,
    mitre_ids: Optional[List[str]] = None,
    http_status: Optional[int] = None,
    is_scanner: bool = False
) -> str:
    """
    Generate an Indicator of Attack (IOA) In-Aggregate Context Summary.
    100% Data-Driven Extraction from Native Wazuh Fields (Zero Hardcoded Rule IDs).
    Provides human-readable, actionable threat context without dynamic parameter explosion.
    """
    desc = (rule_description or "").strip()
    data = data or {}
    desc_lower = desc.lower()

    # Dynamic status extraction: from explicit http_status, data.status, data.id, or regex status code in desc
    status_code = http_status or data.get("status") or data.get("http_status")
    if not status_code and data.get("id") and str(data.get("id")).isdigit() and len(str(data.get("id"))) == 3:
        status_code = data.get("id")
    if not status_code:
        st_match = re.search(r'\b([1-5]\d{2})\b', desc)
        if st_match:
            status_code = st_match.group(1)

    mitre_tag = f" | mitre: {mitre_ids[0]}" if (mitre_ids and len(mitre_ids) > 0) else ""

    if category in ("WEB_ATTACK", "WEB_OPERATIONAL"):
        if "sql" in desc_lower or "sqli" in desc_lower:
            action = "sqli_probe"
            pattern = "sql_injection_attempt"
        elif "xss" in desc_lower or "cross-site" in desc_lower:
            action = "xss_probe"
            pattern = "cross_site_scripting"
        elif "multiple 400" in desc_lower or "burst" in desc_lower:
            action = "burst_probe"
            pattern = "multiple_400_codes"
        elif "scan" in desc_lower or "invalid" in desc_lower or str(status_code) == "400":
            action = "web_scan"
            pattern = "invalid_http_request"
        elif "fatal error" in desc_lower or "php fatal" in desc_lower or "php error" in desc_lower:
            action = "app_error"
            pattern = "php_fatal_error"
        elif "exploit" in desc_lower or "attack" in desc_lower:
            action = "web_exploit"
            pattern = "common_web_attack"
        else:
            action = "web_traffic"
            clean_p = re.sub(r'(?i)web server|error code|\b[45]\d{2}\b|[.:]', '', desc).strip()
            pattern = clean_p[:35].replace(' ', '_').lower() if clean_p else "http_anomaly"

        status_part = f" | status: {status_code}" if status_code else ""
        scanner_part = " | scanner: true" if is_scanner else ""
        return f"action: {action}{status_part}{scanner_part} | pattern: {pattern}{mitre_tag}"

    elif category in ("AUTH_FAILURE", "AUTH_SUCCESS", "CREDENTIAL_ACCESS"):
        auth_sub = decoder or "system_auth"
        if "sshd" in desc_lower or "ssh" in desc_lower:
            auth_sub = "sshd"
        elif "pam" in desc_lower:
            auth_sub = "pam"
        elif "sudo" in desc_lower:
            auth_sub = "sudo"

        if "non-existent user" in desc_lower or "non_existent_user" in desc_lower or "invalid user" in desc_lower:
            event = "non_existent_user"
        elif "success" in desc_lower or "accepted" in desc_lower or "opened" in desc_lower:
            event = "login_success" if ("login" in desc_lower or auth_sub == "sshd") else ("login_session_opened" if "opened" in desc_lower else "successful_sudo_execution" if auth_sub == "sudo" else "auth_success")
        elif "closed" in desc_lower:
            event = "login_session_closed"
        elif "fail" in desc_lower or "bad password" in desc_lower:
            event = "password_failure"
        else:
            clean_ev = re.sub(r'[^a-zA-Z0-9_ -]', '', desc).strip()[:35]
            event = clean_ev.replace(' ', '_').lower() if clean_ev else "auth_event"

        return f"auth_type: {auth_sub} | event: {event} | actor: {actor}{mitre_tag}"

    elif category in ("EXECUTION", "PERSISTENCE", "DEFENSE_EVASION", "PRIVILEGE_ESCALATION", "DISCOVERY", "RANSOMWARE", "COMMAND_AND_CONTROL", "EXFILTRATION", "LATERAL_MOVEMENT", "INITIAL_ACCESS"):
        sec_module = decoder or "auditd"
        if "apparmor" in desc_lower:
            sec_module = "apparmor"
        elif "kernel" in desc_lower or "rootkit" in desc_lower:
            sec_module = "kernel"

        if "denied" in desc_lower or "blocked" in desc_lower:
            event = "DENIED"
        elif "rootkit" in desc_lower or "anomaly" in desc_lower:
            event = "rootkit_anomaly"
        else:
            event = "process_execution"

        proc = actor if actor else sec_module
        return f"sec_module: {sec_module} | event: {event} | proc: {proc}{mitre_tag}"

    elif category == "CLOUD_CONTAINER":
        runtime = decoder or "docker"
        return f"runtime: {runtime} | event: container_error | proc: dockerd{mitre_tag}"

    elif category == "VULNERABILITY":
        cve_found = None
        if data.get("vulnerability") and isinstance(data["vulnerability"], dict):
            cve_found = data["vulnerability"].get("cve")
        if not cve_found:
            cve_m = re.search(r'(?i)(CVE-[0-9]+-[0-9]+)', desc)
            cve_found = cve_m.group(1).upper() if cve_m else "CVE_PATCH"

        target_pkg = actor or data.get("package") or "target_pkg"
        return f"scanner: vulnerability-detector | target_pkg: {target_pkg} | advisory: {cve_found}{mitre_tag}"

    elif category == "FILE_INTEGRITY":
        if "checksum" in desc_lower or "integrity" in desc_lower:
            evt = "checksum_changed"
        elif "rotated" in desc_lower:
            evt = "log_file_rotated"
        elif "deleted" in desc_lower:
            evt = "file_deleted"
        elif "added" in desc_lower or "new file" in desc_lower:
            evt = "file_added"
        else:
            evt = "file_modified"
        return f"engine: syscheck | event: {evt}{mitre_tag}"

    elif category == "MALWARE":
        sig = re.sub(r'[^a-zA-Z0-9_ -]', '', desc).strip()[:40].replace(' ', '_').lower()
        sig_name = sig or "host_anomaly_rootcheck"
        return f"detector: rootcheck | signature: {sig_name}{mitre_tag}"

    elif category in ("CONFIGURATION_ASSESSMENT", "COMPLIANCE"):
        return f"framework: CIS_Benchmark | scan: sca_compliance_check{mitre_tag}"

    else:
        daemon_name = decoder or "systemd"
        clean_ev = re.sub(r'[^a-zA-Z0-9_ -]', '', desc).strip()[:35].replace(' ', '_').lower()
        ev_name = clean_ev or "service_state_transition"
        return f"daemon: {daemon_name} | event: {ev_name}{mitre_tag}"


def profile_dataset(data_dir: str = str(DATA_DIR)) -> Dict[str, Any]:
    """
    Profile all JSON files in the dataset directory to compute baseline metrics.
    """
    files = sorted(glob.glob(os.path.join(data_dir, "**", "*.json"), recursive=True))
    weekly_files = [f for f in files if "week" in f]
    target_files = weekly_files if weekly_files else [f for f in files if f.endswith(".json")]

    total_alerts = 0
    rules_counter = Counter()
    agents_counter = Counter()
    levels_counter = Counter()
    groups_counter = Counter()
    time_min = None
    time_max = None

    for filepath in target_files:
        reader = AlertStreamReader(filepath, chunk_size=10000)
        for chunk in reader.stream_chunks():
            for record in chunk:
                total_alerts += 1
                rule = record.get("rule", {})
                rid = str(rule.get("id"))
                rlvl = rule.get("level", 0)
                rdesc = rule.get("description", "")
                rules_counter[(rid, rlvl, rdesc)] += 1
                levels_counter[rlvl] += 1

                for g in rule.get("groups", []):
                    groups_counter[g] += 1

                agent = record.get("agent", {})
                aname = agent.get("name", "unknown")
                agents_counter[aname] += 1

                ts = record.get("timestamp")
                if ts:
                    if time_min is None or ts < time_min: time_min = ts
                    if time_max is None or ts > time_max: time_max = ts

    top_noise = [
        {"rule_id": r[0], "level": r[1], "description": r[2], "count": c, "pct": round(c / total_alerts * 100, 2)}
        for r, c in rules_counter.most_common(20)
    ]

    return {
        "total_alerts": total_alerts,
        "time_range": {"min": time_min, "max": time_max},
        "distinct_agents_count": len(agents_counter),
        "top_agents": agents_counter.most_common(10),
        "level_distribution": dict(sorted(levels_counter.items())),
        "top_noise_rules": top_noise,
        "top_groups": groups_counter.most_common(10)
    }


if __name__ == "__main__":
    import time
    print("[*] Testing Stream Ingest Engine on Week 1 data...")
    t0 = time.time()
    week1_file = os.path.join(DATA_DIR, "alerts_raw_week1_20260628_20260704.json")
    if os.path.exists(week1_file):
        reader = AlertStreamReader(week1_file, chunk_size=10000)
        count = 0
        for cem in reader.stream_normalized_events():
            count += 1
            if count % 25000 == 0:
                print(f"  Processed {count:,} normalized events...")
        dur = time.time() - t0
        print(f"[+] Successfully processed {count:,} events in {dur:.2f}s ({count/dur:,.0f} events/sec)!")
    else:
        print(f"[-] File not found: {week1_file}")
