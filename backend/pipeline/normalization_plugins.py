"""
Extensible Normalization Plugin Interface for Wazuh Pipeline
============================================================
Allows SOC engineers and analysts to add custom enrichment logic
without modifying the core ingest.py pipeline.

HOW TO ADD A NEW PLUGIN:
  1. Create a new class inheriting from NormalizationPlugin
  2. Implement the `enrich()` method
  3. Register it in ACTIVE_PLUGINS list at the bottom of this file
  4. No other code changes needed — the plugin chain runs automatically.

PLUGIN EXECUTION ORDER:
  Plugins run sequentially in the order defined in ACTIVE_PLUGINS.
  Each plugin receives the CEM *after* the previous plugin modified it.
  A plugin must always return a valid CommonEventModel.

PERFORMANCE CONTRACT:
  Each plugin must complete in < 500 microseconds per event.
  Never do I/O (DB, API, disk) inside enrich() — use module-level caches.
"""
import json
import os
import logging
from abc import ABC, abstractmethod
from typing import Optional, Any, Dict

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lazy imports to avoid circular import with ingest.py
# ---------------------------------------------------------------------------
def _import_models():
    from pipeline.models import CommonEventModel, WazuhRawAlert
    return CommonEventModel, WazuhRawAlert


# ---------------------------------------------------------------------------
# Abstract Base Class
# ---------------------------------------------------------------------------
class NormalizationPlugin(ABC):
    """
    Base class for all normalization plugins.
    Subclass this and implement enrich() to add custom enrichment logic.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique human-readable name for this plugin (used in logs)."""
        ...

    @abstractmethod
    def enrich(self, cem: Any, raw: Any) -> Any:
        """
        Enrich a CommonEventModel with additional fields.

        Args:
            cem: CommonEventModel object (after core normalization)
            raw: WazuhRawAlert object (original parsed alert)

        Returns:
            Modified CommonEventModel. Must always return a valid CEM.
        """
        ...


# ---------------------------------------------------------------------------
# Plugin 1: OCSF Field Mapper
# ---------------------------------------------------------------------------
class OCSFFieldMapperPlugin(NormalizationPlugin):
    """
    Maps internal 9-category taxonomy to OCSF v1.3 mandatory fields:
      - ocsf_class_uid
      - ocsf_category_uid
      - ocsf_activity_id
      - ocsf_severity_id

    Fully config-driven via config/ocsf_mapping.json.
    No hard-coded values in this class.
    """

    name = "OCSFFieldMapper"

    _UNLOADED = object()  # sentinel: distinguishes 'not loaded' from 'loaded but empty'

    def __init__(self):
        self._ocsf_map = self._UNLOADED
        self._severity_map = self._UNLOADED

    def _load(self):
        if self._ocsf_map is not self._UNLOADED:
            return
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "config", "ocsf_mapping.json"
        )
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._ocsf_map = data.get("categories", {})
            # Skip non-numeric keys (e.g., "comment") when building severity_map
            self._severity_map = {}
            for k, v in data.get("severity_map", {}).items():
                try:
                    self._severity_map[int(k)] = v
                except (ValueError, TypeError):
                    pass  # skip "comment" and other non-numeric keys
        except Exception as e:
            logger.warning(f"[OCSFFieldMapperPlugin] Failed to load ocsf_mapping.json: {e}")
            self._ocsf_map = {}
            self._severity_map = {}

    def enrich(self, cem: Any, raw: Any) -> Any:
        self._load()

        category = getattr(cem, "event_category", "SYSTEM_HEALTH")
        rule_level = getattr(cem, "rule_level", 0)

        ocsf_entry = self._ocsf_map.get(category, {})
        severity_id = self._severity_map.get(rule_level, 0)

        # Apply severity_bias from ocsf_mapping (e.g., MALWARE adds +2)
        bias = ocsf_entry.get("severity_bias", 0)
        severity_id = min(6, max(0, severity_id + bias))

        cem.ocsf_class_uid     = ocsf_entry.get("class_uid")
        cem.ocsf_category_uid  = ocsf_entry.get("category_uid")
        cem.ocsf_activity_id   = ocsf_entry.get("activity_id")
        cem.ocsf_severity_id   = severity_id if ocsf_entry else None

        return cem


# ---------------------------------------------------------------------------
# Plugin 2: MITRE Community Supplement
# ---------------------------------------------------------------------------
class MITRECommunitySupplementPlugin(NormalizationPlugin):
    """
    Fills MITRE tactic/technique gaps for Wazuh rules without upstream annotation.
    Priority 3 (lowest) — only activates when upstream + rule_classification_mapping
    both failed to provide MITRE data.

    Config: config/mitre_community_supplement.json
    Analysts can extend coverage by editing that JSON file.
    """

    name = "MITRECommunitySupplement"

    def __init__(self):
        self._supplement: Optional[Dict] = None

    def _load(self):
        if self._supplement is not None:
            return
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "config", "mitre_community_supplement.json"
        )
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._supplement = data.get("supplement", {})
        except Exception as e:
            logger.warning(f"[MITRECommunitySupplementPlugin] Failed to load: {e}")
            self._supplement = {}

    def enrich(self, cem: Any, raw: Any) -> Any:
        self._load()

        # Only activate if upstream MITRE data is missing
        if getattr(cem, "mitre_tactics", []) and getattr(cem, "mitre_attack_ids", []):
            return cem

        rule_id_str = str(getattr(cem, "rule_id", ""))
        entry = self._supplement.get(rule_id_str)
        if not entry:
            return cem

        # Fill missing MITRE fields
        if not getattr(cem, "mitre_tactics", []):
            tactic = entry.get("tactic")
            if tactic:
                cem.mitre_tactics = [tactic]

        if not getattr(cem, "mitre_attack_ids", []):
            technique = entry.get("technique")
            if technique:
                cem.mitre_attack_ids = [technique]
                if not getattr(cem, "mitre_techniques", []):
                    cem.mitre_techniques = [technique]

        return cem


# ---------------------------------------------------------------------------
# Plugin 3: Inline Risk Scorer
# ---------------------------------------------------------------------------
class InlineRiskScorerPlugin(NormalizationPlugin):
    """
    Computes a pre-aggregation inline_risk_score (0-100) at normalization time.

    Formula (all weights from config/inline_risk_weights.json):
      score = min(cap, floor(rule_level * level_multiplier)
                      + asset_criticality_score
                      + ocsf_severity_bias * 2
                      + boolean_bonuses)

    This eliminates the need for a JOIN to risk_scoring_factors for triage decisions,
    matching Splunk CIM 5.3 and Microsoft Sentinel risk scoring behavior.
    """

    name = "InlineRiskScorer"

    def __init__(self):
        self._weights: Optional[Dict] = None

    def _load(self):
        if self._weights is not None:
            return
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "config", "inline_risk_weights.json"
        )
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                self._weights = json.load(f)
        except Exception as e:
            logger.warning(f"[InlineRiskScorerPlugin] Failed to load inline_risk_weights.json: {e}")
            self._weights = {}

    def enrich(self, cem: Any, raw: Any) -> Any:
        self._load()
        w = self._weights

        formula       = w.get("formula", {})
        asset_map     = w.get("asset_criticality_scores", {})
        bonuses_map   = w.get("bonuses", {})
        cat_overrides = w.get("category_multiplier_overrides", {})

        cap        = int(formula.get("cap", 100))
        base_mult  = float(formula.get("level_multiplier", 6.0))

        category   = getattr(cem, "event_category", "SYSTEM_HEALTH")
        rule_level = getattr(cem, "rule_level", 0)
        criticality= getattr(cem, "host_criticality", "STANDARD")

        # Category-specific multiplier override
        mult = float(cat_overrides.get(category, base_mult))

        # Base score from rule level
        base_score = int(rule_level * mult)

        # Asset criticality score
        asset_score = int(asset_map.get(criticality, asset_map.get("_default", 5)))

        # OCSF severity bias (if OCSF plugin already ran)
        severity_bias_score = 0
        ocsf_sev = getattr(cem, "ocsf_severity_id", None)
        if ocsf_sev and w.get("ocsf_severity_bias", {}).get("enabled", False):
            severity_bias_score = max(0, ocsf_sev - 3) * 3  # bias: sev>=4 adds 3,6,9

        # Boolean bonuses
        bonus = 0
        for field, bonus_val in bonuses_map.items():
            if getattr(cem, field, False):
                bonus += int(bonus_val)

        total = min(cap, base_score + asset_score + severity_bias_score + bonus)
        cem.inline_risk_score = max(0, total)

        return cem


# ---------------------------------------------------------------------------
# Plugin 4: Generic IOC Extractor Fallback
# ---------------------------------------------------------------------------
class GenericIOCExtractorPlugin(NormalizationPlugin):
    """
    Regex-based IOC extraction fallback for alerts without rule-specific plugins.
    Extracts IPv4 addresses, MD5/SHA256 hashes, domains, CVE IDs, and URLs
    from full_log / raw_payload when no upstream plugin has populated them.

    This ensures unknown or new rule groups still get basic IOC enrichment
    without requiring a dedicated plugin for every Wazuh decoder.

    Performance: All regex patterns are pre-compiled at module load time.
    No I/O — pure in-memory regex matching.
    """

    name = "GenericIOCExtractor"

    # Pre-compiled patterns for common IOC types
    _RE_IPV4 = __import__('re').compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b'
    )
    _RE_MD5 = __import__('re').compile(r'\b[0-9a-fA-F]{32}\b')
    _RE_SHA256 = __import__('re').compile(r'\b[0-9a-fA-F]{64}\b')
    _RE_SHA1 = __import__('re').compile(r'\b[0-9a-fA-F]{40}\b')
    _RE_DOMAIN = __import__('re').compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'
        r'+(?:com|net|org|io|info|biz|xyz|top|ru|cn|uk|de|fr|nl|eu|cc|me|co)\b'
    )
    _RE_CVE = __import__('re').compile(r'\bCVE-\d{4}-\d{4,7}\b')
    _RE_URL = __import__('re').compile(
        r'https?://[^\s\'"<>]{5,256}'
    )

    # Private/internal IPs to exclude from IOC extraction
    _INTERNAL_PREFIXES = ('10.', '172.16.', '172.17.', '172.18.', '172.19.',
                          '172.20.', '172.21.', '172.22.', '172.23.',
                          '172.24.', '172.25.', '172.26.', '172.27.',
                          '172.28.', '172.29.', '172.30.', '172.31.',
                          '192.168.', '127.', '0.', '169.254.')

    def enrich(self, cem: Any, raw: Any) -> Any:
        # Only activate when no structured IOC data exists yet
        existing_iocs = getattr(cem, 'extracted_iocs', None)
        if existing_iocs:
            return cem

        # Collect text sources for regex scanning
        texts = []
        full_log = getattr(raw, 'full_log', None) if raw else None
        if full_log:
            texts.append(full_log)
        raw_payload = getattr(cem, 'raw_payload', None)
        if raw_payload and raw_payload not in texts:
            texts.append(raw_payload)
        rule_desc = getattr(cem, 'rule_description', None)
        if rule_desc:
            texts.append(rule_desc)

        if not texts:
            return cem

        combined = ' '.join(texts)
        iocs = {}

        # Extract external IPv4 addresses
        ips = self._RE_IPV4.findall(combined)
        external_ips = [ip for ip in ips if not ip.startswith(self._INTERNAL_PREFIXES)]
        if external_ips:
            iocs['ipv4'] = list(set(external_ips))[:10]

        # Extract file hashes
        sha256_hits = self._RE_SHA256.findall(combined)
        if sha256_hits:
            iocs['sha256'] = list(set(sha256_hits))[:5]

        # SHA1 (exclude SHA256 matches — SHA1 is 40 chars, SHA256 is 64)
        sha1_hits = [h for h in self._RE_SHA1.findall(combined)
                     if h not in (sha256_hits or [])]
        if sha1_hits:
            iocs['sha1'] = list(set(sha1_hits))[:5]

        md5_hits = [h for h in self._RE_MD5.findall(combined)
                    if h not in (sha1_hits or []) and h not in (sha256_hits or [])]
        if md5_hits:
            iocs['md5'] = list(set(md5_hits))[:5]

        # Extract domains (exclude internal/infrastructure)
        domains = self._RE_DOMAIN.findall(combined)
        if domains:
            iocs['domains'] = list(set(domains))[:10]

        # Extract CVE identifiers
        cves = self._RE_CVE.findall(combined)
        if cves:
            iocs['cves'] = list(set(cves))[:10]

        # Extract URLs
        urls = self._RE_URL.findall(combined)
        if urls:
            iocs['urls'] = list(set(urls))[:5]

        if iocs:
            # Store as structured dict on the CEM for downstream consumers
            if not hasattr(cem, 'extracted_iocs') or cem.extracted_iocs is None:
                cem.extracted_iocs = iocs
            # Append CVEs to ioa_summary if present
            if iocs.get('cves') and not getattr(cem, 'ioa_summary', None):
                cem.ioa_summary = f"CVEs detected: {', '.join(iocs['cves'])}"

        return cem



# ---------------------------------------------------------------------------
# Plugin 5: HTTP & Scanner Forensics Analyzer
# ---------------------------------------------------------------------------
class HTTPTrafficAnalyzerPlugin(NormalizationPlugin):
    """
    Extracts HTTP status codes and detects automated vulnerability scanners
    (sqlmap, nikto, dirbuster, gobuster, python-requests, curl, etc.)
    from raw payloads and web server access logs.
    Enriches CEM with http_status, user_agent, and is_scanner_ua.
    """
    name = "HTTPTrafficAnalyzer"

    _RE_HTTP = __import__('re').compile(
        r'"[A-Z]+\s+[^"]+\s+HTTP/[0-9.]+"\s+(\d{3})\s+\S+\s+"[^"]*"\s+"([^"]*)"'
    )
    _RE_STATUS_FB = __import__('re').compile(r'\bHTTP/[0-9.]+"\s+(\d{3})\b')
    _RE_SCANNER = __import__('re').compile(
        r'(?i)\b(sqlmap|nikto|nmap|zgrab|masscan|dirbuster|gobuster|wpscan|hydra|acunetix|nessus|openvas|python-requests|curl|wget|go-http-client|zmap|nuclei|jaeles|ffuf)\b'
    )

    def enrich(self, cem: Any, raw: Any) -> Any:
        # If already populated by ingest, do not overwrite
        if getattr(cem, "http_status", None) is not None and getattr(cem, "user_agent", None) is not None:
            return cem

        full_log = getattr(raw, 'full_log', None) or getattr(cem, 'raw_payload', None) or ""
        if not full_log:
            return cem

        m = self._RE_HTTP.search(full_log)
        if m:
            if getattr(cem, "http_status", None) is None:
                try:
                    cem.http_status = int(m.group(1))
                except Exception:
                    pass
            if getattr(cem, "user_agent", None) is None:
                cem.user_agent = m.group(2)
        elif getattr(cem, "http_status", None) is None:
            m_fb = self._RE_STATUS_FB.search(full_log)
            if m_fb:
                try:
                    cem.http_status = int(m_fb.group(1))
                except Exception:
                    pass

        ua = getattr(cem, "user_agent", None) or ""
        if ua and not getattr(cem, "is_scanner_ua", False):
            cem.is_scanner_ua = bool(self._RE_SCANNER.search(ua))

        return cem


# ---------------------------------------------------------------------------
# Plugin Registry — Edit this list to enable/disable/reorder plugins
# ---------------------------------------------------------------------------
# Order matters: OCSFFieldMapper must run before InlineRiskScorer
# so that ocsf_severity_id is available for the risk formula.
# GenericIOCExtractor runs last as a fallback for unstructured IOC data.
ACTIVE_PLUGINS: list = [
    OCSFFieldMapperPlugin(),
    MITRECommunitySupplementPlugin(),
    InlineRiskScorerPlugin(),
    GenericIOCExtractorPlugin(),
    HTTPTrafficAnalyzerPlugin(),
]


def run_plugin_chain(cem: Any, raw: Any) -> Any:
    """
    Execute all active normalization plugins in registration order.
    Errors in individual plugins are caught and logged — they never crash the pipeline.
    """
    for plugin in ACTIVE_PLUGINS:
        try:
            cem = plugin.enrich(cem, raw)
        except Exception as e:
            logger.error(f"[NormalizationPlugin:{plugin.name}] Error enriching event {getattr(cem, 'event_id', '?')}: {e}")
    return cem
