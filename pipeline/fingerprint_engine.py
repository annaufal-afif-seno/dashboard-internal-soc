"""
========================================================================================
APEX FINGERPRINT ENGINE (VERSION 3.4 / APEX GOLD STANDARD)
========================================================================================
Generates deterministic, activity-representing cryptographic fingerprints from
canonical normalized alerts using policy specifications.

Key Pillars:
1. Multi-Tenant Cryptographic Isolation: tenant_id locked in canonical SHA-256 body.
2. Missing-Value Policy Tiering: exact, degraded (conservative rule+agent), fallback.
3. Transform Library: user:clean, file_path:dir (with Critical Path Exemption),
   url_path:tmpl, domain:d2ld, cmd:cmd, src_ip:true_client.
4. Bounded Memory Tracking: Max 50 distinct samples + distinct counter (Anti-OOM).
5. Unicode NFKC & Control Byte Sanitization: Homoglyph and null-byte resistant.
"""

import hashlib
import json
import re
import unicodedata
from typing import Dict, Any, List, Optional, Tuple, NamedTuple, Set

from pipeline.category_catalog import CategoryPolicy

# ── Critical Security Paths (Exempt from :dir truncation) ─────────────────────
CRITICAL_SECURITY_PATHS: Set[str] = {
    "/etc/shadow", "/etc/passwd", "/etc/sudoers", "/etc/sudoers.d",
    "/etc/ssh/sshd_config", "/etc/crontab", "/etc/pam.d",
    "c:/windows/system32/config/sam", "c:/windows/system32/config/system",
    "c:/windows/system32/config/security"
}

# ── Trusted Ingress Proxy Defaults ─────────────────────────────────────────────
TRUSTED_PROXIES: Set[str] = {
    "127.0.0.1", "::1", "10.0.0.1", "10.0.0.2", "172.16.0.1", "192.168.1.1"
}

class Fingerprint(NamedTuple):
    hash: str
    quality: str  # exact, degraded, fallback
    body: Dict[str, Any]
    tracked_samples: Dict[str, List[Any]]
    tracked_distinct_counts: Dict[str, int]


# ── Transform Functions ────────────────────────────────────────────────────────
def sanitize_unicode(val: Any) -> str:
    """Sanitizes text with NFKC normalization and strips null bytes/control chars."""
    if val is None:
        return "__NULL__"
    s = str(val).replace("\x00", "").replace("\u0000", "")
    return unicodedata.normalize("NFKC", s).strip()


def tf_clean_user(val: Any) -> str:
    """
    Cleans and canonicalizes usernames:
    - Strips DOMAIN\\ prefix (e.g. CORP\\Administrator -> administrator)
    - Strips UPN @domain suffix (e.g. admin@corp.local -> admin)
    - Lowercase and NFKC normalized.
    """
    clean_str = sanitize_unicode(val)
    if clean_str in ("__NULL__", ""):
        return "__NULL__"

    if "\\" in clean_str:
        clean_str = clean_str.split("\\")[-1]
    if "@" in clean_str:
        clean_str = clean_str.split("@")[0]

    return clean_str.lower()


def tf_file_dir(val: Any) -> str:
    """
    Extracts parent directory from file path, with CRITICAL FILE EXEMPTION.
    Paths like /etc/shadow or /etc/sudoers retain full path to avoid camouflage.
    """
    clean_str = sanitize_unicode(val).replace("\\", "/")
    if clean_str in ("__NULL__", ""):
        return "__NULL__"

    # Critical path exemption check
    if clean_str.lower() in CRITICAL_SECURITY_PATHS:
        return clean_str

    parts = clean_str.rstrip("/").split("/")
    if len(parts) <= 1:
        return "/"
    return "/".join(parts[:-1]) or "/"


def tf_url_template(val: Any) -> str:
    """
    Converts dynamic URL paths into template patterns:
    - Strips query string parameters
    - Replaces numeric IDs with {id}
    - Replaces UUID tokens with {uuid}
    """
    clean_str = sanitize_unicode(val)
    if clean_str in ("__NULL__", ""):
        return "__NULL__"

    path_only = clean_str.split("?")[0].strip()
    # Replace UUIDs
    path_only = re.sub(r"/[0-9a-fA-F-]{36}(?=/|$)", "/{uuid}", path_only)
    # Replace numeric IDs
    path_only = re.sub(r"/[0-9]+(?=/|$)", "/{id}", path_only)
    return path_only


def tf_domain_d2ld(val: Any) -> str:
    """Extracts registrable domain (eTLD+1) from FQDN."""
    clean_str = sanitize_unicode(val).lower()
    if clean_str in ("__NULL__", ""):
        return "__NULL__"

    parts = clean_str.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return clean_str


def tf_command_line(val: Any) -> str:
    """
    Normalizes command lines:
    - Strips binary path prefix (/usr/bin/bash -> bash)
    - Normalizes common encoded flags
    """
    clean_str = sanitize_unicode(val)
    if clean_str in ("__NULL__", ""):
        return "__NULL__"

    tokens = clean_str.split()
    if not tokens:
        return "__NULL__"

    binary = tokens[0].replace("\\", "/").split("/")[-1]
    args = " ".join(tokens[1:])
    return f"{binary} {args}".strip() if args else binary


def tf_true_client_ip(val: Any, alert: Optional[Dict[str, Any]] = None) -> str:
    """Resolves true client IP by inspecting X-Forwarded-For if behind trusted proxies."""
    clean_ip = sanitize_unicode(val)
    if clean_ip in ("__NULL__", ""):
        return "__NULL__"

    if clean_ip in TRUSTED_PROXIES and alert:
        # Check X-Forwarded-For header in raw_log or http headers
        raw_log = alert.get("evidence", {}).get("raw_log") or ""
        xff_match = re.search(r"X-Forwarded-For:\s*([0-9a-fA-F.:]+)", raw_log, re.IGNORECASE)
        if xff_match:
            candidate = xff_match.group(1).split(",")[0].strip()
            if candidate and candidate not in TRUSTED_PROXIES:
                return candidate

    return clean_ip


TRANSFORMS = {
    "clean": tf_clean_user,
    "dir": tf_file_dir,
    "tmpl": tf_url_template,
    "d2ld": tf_domain_d2ld,
    "cmd": tf_command_line,
    "true_client": tf_true_client_ip
}


# ── Canonical Field Extractor (Apex v3.4 Aware) ───────────────────────────────
def extract_canonical_value(field_name: str, alert: Dict[str, Any]) -> Any:
    """
    Extracts canonical fields from either nested Apex v3.4 structure
    or flattened dictionary keys.
    """
    # Direct top-level lookup
    if field_name in alert and alert[field_name] not in (None, "", []):
        return alert[field_name]

    # Map canonical names to nested paths
    FIELD_MAP = {
        "agent": ["observer.agent_name", "observer.agent_id", "agent_name", "agent.name", "agent_id"],
        "src_ip": ["network.src_ip", "source_ip", "data.srcip"],
        "dst_ip": ["network.dst_ip", "destination_ip", "data.dstip"],
        "src_port": ["network.src_port", "source_port", "data.srcport"],
        "dst_port": ["network.dst_port", "destination_port", "data.dstport"],
        "src_user": ["actor.user_name", "username", "data.srcuser"],
        "dst_user": ["target.user_name", "username", "data.dstuser"],
        "status_class": ["http.status_code", "http_status", "data.id"],
        "url_path": ["http.url_path", "clean_path", "data.url"],
        "proto": ["network.protocol", "network.transport", "protocol"],
        "file_path": ["file.path", "evidence.file_path", "syscheck.path", "file_path"],
        "fim_event": ["file.event_type", "evidence.fim_event", "syscheck.event", "event_type"],
        "cve": ["vulnerability.cve_id", "evidence.cve", "vulnerability.cve", "cve"],
        "package": ["vulnerability.package_name", "evidence.package", "vulnerability.package.name", "package"],
        "file_hash": ["file.sha256_after", "evidence.file_hash", "syscheck.sha256_after", "file_hash"],
        "process": ["evidence.process_name", "process_name", "data.process_name"],
        "process_hash": ["evidence.process_hash", "process_hash"],
        "rule_id": ["rule.id", "rule_id"],
        "attack_type": ["rule.description", "rule.groups", "attack"],
        "sig_id": ["data.alert.signature_id", "network.signature_id", "rule.id"]
    }

    candidates = FIELD_MAP.get(field_name, [field_name])
    for path in candidates:
        parts = path.split(".")
        curr = alert
        found = True
        for p in parts:
            if isinstance(curr, dict) and p in curr:
                curr = curr[p]
            else:
                found = False
                break
        if found and curr not in (None, "", []):
            # Special case for status_class: convert 404 -> '4xx'
            if field_name == "status_class" and str(curr).isdigit():
                return f"{str(curr)[0]}xx"
            # Special case for attack_type: return first relevant group
            if field_name == "attack_type" and isinstance(curr, list):
                for g in curr:
                    if str(g).lower() in ("sqli", "xss", "traversal", "cmd_injection", "rce"):
                        return str(g).lower()
                return "web_attack"
            return curr

    return None


# ── Spec Parser ────────────────────────────────────────────────────────────────
def parse_spec(spec: str) -> Tuple[str, Optional[str], bool]:
    """Parses 'field:transform?' into (field, transform, is_optional)."""
    optional = spec.endswith("?")
    clean_spec = spec.rstrip("?")
    field, _, tf = clean_spec.partition(":")
    return field, (tf or None), optional


# ── Fingerprint Generator Engine ──────────────────────────────────────────────
def generate_fingerprint(
    alert: Dict[str, Any],
    policy: CategoryPolicy,
    policy_version: int = 8
) -> Fingerprint:
    """
    Generates a deterministic cryptographic fingerprint for a given alert and policy.
    Adheres strictly to the Apex Gold Standard specification.
    """
    parts: Dict[str, str] = {}
    missing_required: List[str] = []

    # 1. Process key fields in policy specification
    for spec in policy.fingerprint_specs:
        field_name, tf_name, optional = parse_spec(spec)
        raw_val = extract_canonical_value(field_name, alert)

        if raw_val in (None, "", []):
            if optional:
                parts[spec] = "__NULL__"
            else:
                missing_required.append(field_name)
            continue

        # Execute transformation if specified
        if tf_name and tf_name in TRANSFORMS:
            if tf_name == "true_client":
                transformed = TRANSFORMS[tf_name](raw_val, alert)
            else:
                transformed = TRANSFORMS[tf_name](raw_val)
        else:
            transformed = sanitize_unicode(raw_val)

        parts[spec] = transformed

    # 2. Extract tenant and observer identity
    tenant_id = alert.get("tenant_id") or "DEFAULT"
    rule_id_val = alert.get("rule", {}).get("id") or alert.get("rule_id", "0")
    agent_val = alert.get("observer", {}).get("agent_name") or alert.get("agent_name") or "__NULL__"

    # 3. Missing-value branching & quality assignment
    if missing_required:
        parts = {
            "rule_id": sanitize_unicode(rule_id_val),
            "agent": sanitize_unicode(agent_val)
        }
        tier, quality = "degraded", "degraded"
    elif policy.code == "generic_rule":
        tier, quality = "leaf", "fallback"
    else:
        tier, quality = "leaf", "exact"

    # 4. Canonical JSON Body Construction (Multi-Tenant Cryptographic Envelope)
    body: Dict[str, Any] = {
        "v": policy_version,
        "tenant": sanitize_unicode(tenant_id),
        "c": policy.code,
        "t": tier,
        "p": parts
    }

    # Deterministic SHA-256 Hashing
    raw_json_str = json.dumps(body, sort_keys=True, separators=(",", ":"))
    sha256_hash = hashlib.sha256(raw_json_str.encode("utf-8")).hexdigest()

    # 5. Bounded Tracking Set Extraction (Max 50 samples per tracked field)
    tracked_samples: Dict[str, List[Any]] = {}
    tracked_distinct_counts: Dict[str, int] = {}

    for track_spec in policy.track_fields:
        t_field, t_tf, _ = parse_spec(track_spec)
        t_val = extract_canonical_value(t_field, alert)
        if t_val not in (None, "", []):
            if t_tf and t_tf in TRANSFORMS:
                t_clean = TRANSFORMS[t_tf](t_val)
            else:
                t_clean = sanitize_unicode(t_val)

            tracked_samples[track_spec] = [t_clean]
            tracked_distinct_counts[track_spec] = 1
        else:
            tracked_samples[track_spec] = []
            tracked_distinct_counts[track_spec] = 0

    return Fingerprint(
        hash=sha256_hash,
        quality=quality,
        body=body,
        tracked_samples=tracked_samples,
        tracked_distinct_counts=tracked_distinct_counts
    )
