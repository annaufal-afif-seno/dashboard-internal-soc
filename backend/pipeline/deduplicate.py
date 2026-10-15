"""
Stage 2: Sliding-Window Deduplication & Noise Aggregation Engine
Collapses High-Frequency Repetitive Burst Events into Actionable Aggregated Objects
while Preserving Relational Links to Raw Forensic Evidence (100% Evidence Preserved)
Production Hardened: Includes In-Flight Sliding-Window Garbage Collection
"""
import os
import hashlib
import uuid
import json
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone, timedelta
from dateutil import parser as dt_parser

from pipeline.models import CommonEventModel, AggregatedAlertDB, AggregateEvidenceMappingDB
from config.settings import BASE_DIR, PERSISTENCE_DIR
from collections import defaultdict, Counter


def calculate_dedup_key(
    rule_id: str,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    username: Optional[str] = None,
    agent_id: Optional[str] = None,
    event_type: Optional[str] = None,
    tenant_id: Optional[str] = "DEFAULT"
) -> str:
    """
    [Legacy Compatibility Engine] Composite MD5 dedup key generator.
    Maintained for backward test compatibility.
    In production runtime, calculate_canonical_dedup_key() is the active
    5-dimensional OCSF/ECS canonical deduplication engine.
    Format: MD5(rule_id | src_ip | dst_ip | username | agent_id | event_type | tenant_id)
    """
    raw_str = f"{rule_id}|{src_ip or 'none'}|{dst_ip or 'none'}|{username or 'none'}|{agent_id or 'none'}|{event_type or 'none'}|{tenant_id or 'DEFAULT'}"
    return hashlib.md5(raw_str.encode("utf-8")).hexdigest()


# Peta nama key dari aggregation_rules.json → field CommonEventModel
_KEY_FIELD_MAP = {
    "rule_id":          lambda e, rid, et: rid,
    "source_ip":        lambda e, rid, et: getattr(e, "source_ip", None) or "none",
    "src_ip":           lambda e, rid, et: getattr(e, "source_ip", None) or "none",
    "destination_ip":   lambda e, rid, et: getattr(e, "destination_ip", None) or "none",
    "dst_ip":           lambda e, rid, et: getattr(e, "destination_ip", None) or "none",
    "destination_host": lambda e, rid, et: getattr(e, "destination_host", None) or getattr(e, "dedup_target", None) or getattr(e, "agent_name", None) or "none",
    "username":         lambda e, rid, et: getattr(e, "username", None) or "none",
    "agent_id":         lambda e, rid, et: getattr(e, "agent_id", None) or "none",
    "agent_name":       lambda e, rid, et: getattr(e, "agent_name", None) or "none",
    "event_type":       lambda e, rid, et: et or "none",
    "tenant_id":        lambda e, rid, et: getattr(e, "tenant_id", "DEFAULT") or "DEFAULT",
    # Semantic Canonical Fields:
    "category":         lambda e, rid, et: getattr(e, "event_category", "SYSTEM_HEALTH") or "SYSTEM_HEALTH",
    "event_category":   lambda e, rid, et: getattr(e, "event_category", "SYSTEM_HEALTH") or "SYSTEM_HEALTH",
    "actor":            lambda e, rid, et: getattr(e, "dedup_actor", None) or getattr(e, "source_ip", None) or "none",
    "dedup_actor":      lambda e, rid, et: getattr(e, "dedup_actor", None) or getattr(e, "source_ip", None) or "none",
    "target":           lambda e, rid, et: getattr(e, "dedup_target", None) or getattr(e, "destination_host", None) or "none",
    "dedup_target":     lambda e, rid, et: getattr(e, "dedup_target", None) or getattr(e, "destination_host", None) or "none",
    "action":           lambda e, rid, et: rid,
    "os_platform":      lambda e, rid, et: getattr(e, "os_platform", "unknown") or "unknown",
    "os":               lambda e, rid, et: getattr(e, "os_platform", "unknown") or "unknown",
}
_ALL_DEFAULT_KEYS = ["rule_id", "actor", "target", "tenant_id"]  # Semantic canonical fallback (ECS-aligned)


def calculate_canonical_dedup_key(
    category: str,
    actor: str,
    target: str,
    action: str,
    tenant_id: str = "DEFAULT",
    os_platform: str = "unknown",
) -> str:
    """
    [Semantic Normalization Layer - OCSF / ECS Standard]
    Unified 5-Dimensional Canonical Dedup Key Formula:
    Format: MD5(category | actor | target | action | os_platform | tenant_id)
    Guarantees 100% uniformity while preserving critical threat boundaries.
    """
    raw_str = f"{category}|{actor}|{target}|{action}|{os_platform}|{tenant_id or 'DEFAULT'}"
    return hashlib.md5(raw_str.encode("utf-8")).hexdigest()


def calculate_dedup_key_dynamic(
    event: Any,
    key_fields: List[str],
    rule_id_str: str,
    event_type_str: Optional[str]
) -> str:
    """
    [Fix C1] Generate a deterministic MD5 dedup key using only the field subset
    specified in aggregation_rules.json for this rule. Falls back to all-fields
    default if a key name is unrecognised.
    """
    parts = []
    for k in key_fields:
        extractor = _KEY_FIELD_MAP.get(k)
        if extractor:
            parts.append(str(extractor(event, rule_id_str, event_type_str)))
        else:
            # Unknown key name — treat as literal constant so it doesn't break the hash
            parts.append(k)
    raw_str = "|".join(parts)
    return hashlib.md5(raw_str.encode("utf-8")).hexdigest()



class AggregatedWindow:
    """Represents an active sliding window for a deduplication key."""

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
        tenant_id: str = "DEFAULT",  # [Fix C3] Store actual tenant_id per window
        category: str = "SYSTEM_HEALTH",
        actor: Optional[str] = None,
        target: Optional[str] = None,
        rule_description: Optional[str] = None,
        ioa_summary: Optional[str] = None,
        os_platform: str = "unknown",
        log_source: Optional[str] = None,
        extracted_iocs: Optional[Dict[str, Any]] = None,
    ):
        self.aggregation_id = aggregation_id
        self.dedup_key = dedup_key
        self.rule_id = rule_id
        self.rule_description = rule_description
        self.agent_id = agent_id
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.username = username
        self.tenant_id = tenant_id  # [Fix C3] Preserve tenant_id for output
        self.category = category
        self.actor = actor or source_ip or f"agent:{agent_id}"
        self.target = target or username or destination_ip or f"agent:{agent_id}"
        self.ioa_summary = ioa_summary
        self.os_platform = os_platform
        self.log_source = log_source
        self.distinct_ioas: Set[str] = set()
        if ioa_summary:
            self.distinct_ioas.add(ioa_summary)
        self.distinct_iocs: Set[str] = set()
        if source_ip and not source_ip.startswith(('10.', '172.16.', '172.17.', '172.18.', '172.19.',
                                                  '172.20.', '172.21.', '172.22.', '172.23.',
                                                  '172.24.', '172.25.', '172.26.', '172.27.',
                                                  '172.28.', '172.29.', '172.30.', '172.31.',
                                                  '192.168.', '127.', '0.', '169.254.', 'localhost')):
            self.distinct_iocs.add(f"ipv4:{source_ip}")
        if extracted_iocs and isinstance(extracted_iocs, dict):
            for k, val_list in extracted_iocs.items():
                if isinstance(val_list, list):
                    for v in val_list:
                        if len(self.distinct_iocs) < 100:
                            self.distinct_iocs.add(f"{k}:{v}")
        self.window_start = start_time
        self.window_duration = window_duration
        self.window_duration_seconds = int(window_duration.total_seconds())
        self.window_end = start_time + window_duration
        self.last_event_time = start_time
        self.event_count = 1
        self.max_inline_risk_score: int = 0  # Highest risk score across all events in this window
        self.ocsf_severity_id: Optional[int] = None  # Highest OCSF severity in this window
        self.raw_evidence: List[Tuple[str, datetime]] = []
        self.status = "OPEN"
        # Semantic context carried forward from the first triggering event
        # Required by CorrelationEngine.process_aggregate() for stage-matching
        self.classification_groups: List[str] = []
        self.mitre_tactics: List[str] = []
        # HTTP & Scanner Forensics
        self.http_statuses: Counter = Counter()
        self.scanner_ua_detected: bool = False

    def add_event(
        self,
        event_id: str,
        event_time: datetime,
        ioa_summary: Optional[str] = None,
        inline_risk_score: Optional[int] = None,
        ocsf_severity_id: Optional[int] = None,
        extracted_iocs: Optional[Dict[str, Any]] = None,
        log_source: Optional[str] = None,
        http_status: Optional[int] = None,
        is_scanner_ua: bool = False,
    ):
        """Increment counter and record evidence mapping with chronological boundary tracking."""
        self.event_count += 1
        if http_status is not None:
            self.http_statuses[http_status] += 1
        if is_scanner_ua:
            self.scanner_ua_detected = True
        if ioa_summary:
            if not self.ioa_summary:
                self.ioa_summary = ioa_summary
            if len(self.distinct_ioas) < 100:
                self.distinct_ioas.add(ioa_summary)
        if log_source and not self.log_source:
            self.log_source = log_source
        if extracted_iocs and isinstance(extracted_iocs, dict):
            for k, val_list in extracted_iocs.items():
                if isinstance(val_list, list):
                    for v in val_list:
                        if len(self.distinct_iocs) < 100:
                            self.distinct_iocs.add(f"{k}:{v}")
        if event_time > self.last_event_time:
            self.last_event_time = event_time
        # [Strict Duration Ceiling] Never pull window_start backwards beyond duration window
        if event_time < self.window_start and (self.window_end - event_time) <= (self.window_duration + timedelta(seconds=15)):
            self.window_start = event_time
        self.raw_evidence.append((event_id, event_time))
        # Track peak risk and severity across all events in this window
        if inline_risk_score is not None and inline_risk_score > self.max_inline_risk_score:
            self.max_inline_risk_score = inline_risk_score
        if ocsf_severity_id is not None:
            if self.ocsf_severity_id is None or ocsf_severity_id > self.ocsf_severity_id:
                self.ocsf_severity_id = ocsf_severity_id

    def is_expired(self, current_time: datetime, grace_seconds: int = 15) -> bool:
        """Check if current event timestamp exceeds this window's end or is out-of-order before window start."""
        # Standard forward expiration past window end
        if current_time > (self.window_end + timedelta(seconds=grace_seconds)):
            return True
        # [Anti-Time-Travel Guard] If event is older than window start minus grace, close active window
        if current_time < (self.window_start - timedelta(seconds=grace_seconds)):
            return True
        return False

    def is_stale_for_eviction(self, current_time: datetime) -> bool:
        """Check if window is older than 2x duration for memory eviction or time shifted back."""
        if current_time > (self.window_end + self.window_duration):
            return True
        if current_time < (self.window_start - self.window_duration):
            return True
        return False



class SlidingWindowAggregator:
    """
    High-Performance In-Memory Sliding-Window Aggregator.
    Deduplicates burst events across configurable time windows and emits
    compressed AggregatedAlert objects with forensic evidence links.
    """

    def __init__(self, config_path: Optional[str] = None):
        if config_path is None:
            config_path = str(BASE_DIR / "config" / "aggregation_rules.json")

        self.rules_config: Dict[str, Any] = {}
        self.default_window_seconds = 900  # 15 mins
        if os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.default_window_seconds = data.get("default_window_seconds", 900)
                self.rules_config = data.get("rules", {})

        # Active windows map: dedup_key -> AggregatedWindow
        self.active_windows: Dict[str, AggregatedWindow] = {}
        self.completed_aggregates: List[Dict[str, Any]] = []
        self.total_events_in = 0
        self.total_aggregates_out = 0
        self.total_evidence_links = 0
        self._gc_interval = 25000  # Run garbage collection every 25k events
        self.last_valid_timestamp: Optional[datetime] = None

    def parse_iso_timestamp(self, ts_str: str) -> datetime:
        """Parse ISO8601 or Wazuh timestamp string into timezone-aware datetime with stable fallback."""
        try:
            dt = dt_parser.parse(ts_str)
            self.last_valid_timestamp = dt
            return dt
        except Exception:
            return self.last_valid_timestamp or datetime.now(timezone.utc)

    def get_window_duration(self, rule_id: str, event: Optional[Any] = None) -> timedelta:
        """Get window duration: checks config first, then event's normalized duration, else default."""
        rule_cfg = self.rules_config.get(str(rule_id))
        if rule_cfg and "window_seconds" in rule_cfg:
            return timedelta(seconds=rule_cfg["window_seconds"])
        if event and hasattr(event, "window_duration_seconds") and event.window_duration_seconds:
            return timedelta(seconds=event.window_duration_seconds)
        return timedelta(seconds=self.default_window_seconds)

    def process_event(self, event: CommonEventModel) -> Optional[Dict[str, Any]]:
        """
        Process a single CommonEventModel event through the deduplicator.
        Returns a completed AggregatedAlert dict if an expired window is closed, else None.
        """
        self.total_events_in += 1
        event_time = self.parse_iso_timestamp(event.timestamp)
        rule_id_str = str(event.rule_id)
        rule_id_int = int(event.rule_id) if event.rule_id.isdigit() else 0

        # Periodic in-flight memory garbage collection (persisting evicted windows)
        if self.total_events_in % self._gc_interval == 0:
            evicted = self._cleanup_stale_windows(event_time)
            self.completed_aggregates.extend(evicted)

        # Sort classification groups to guarantee deterministic deduplication key
        norm_groups = sorted(event.classification_groups) if event.classification_groups else []
        event_type_str = norm_groups[0] if norm_groups else None

        # [Semantic Normalization & Unified Key Calculation]
        rule_cfg = self.rules_config.get(rule_id_str, {})
        tenant_id = getattr(event, "tenant_id", "DEFAULT") or "DEFAULT"
        category = getattr(event, "event_category", "SYSTEM_HEALTH") or "SYSTEM_HEALTH"

        if "keys" in rule_cfg:
            # Custom key override specified explicitly in JSON
            dedup_key = calculate_dedup_key_dynamic(
                event=event,
                key_fields=rule_cfg["keys"],
                rule_id_str=rule_id_str,
                event_type_str=event_type_str
            )
        elif hasattr(event, "dedup_actor") and event.dedup_actor and event.dedup_target:
            # [Standard Canonical Formula] 1 Unified Formula: MD5(Category | Actor | Target | Action | Tenant)
            dedup_key = calculate_canonical_dedup_key(
                category=category,
                actor=event.dedup_actor,
                target=event.dedup_target,
                action=rule_id_str,
                tenant_id=tenant_id,
                os_platform=getattr(event, "os_platform", "unknown"),
            )
        else:
            # [Fix F-1] Canonical fallback with safe dimension defaults (guarantees category and os_platform are never lost)
            dedup_key = calculate_canonical_dedup_key(
                category=category,
                actor=getattr(event, "source_ip", None) or f"agent:{event.agent_id}",
                target=getattr(event, "agent_name", None) or f"agent:{event.agent_id}",
                action=rule_id_str,
                tenant_id=tenant_id,
                os_platform=getattr(event, "os_platform", "unknown"),
            )

        window_duration = self.get_window_duration(rule_id_str, event=event)
        closed_alert = None

        if dedup_key in self.active_windows:
            window = self.active_windows[dedup_key]
            if window.is_expired(event_time):
                # Flush the expired window
                closed_alert = self._finalize_window(window)
                # Create a new active window
                new_agg_id = f"agg_{uuid.uuid4().hex}"
                new_window = AggregatedWindow(
                    aggregation_id=new_agg_id,
                    dedup_key=dedup_key,
                    rule_id=rule_id_int,
                    agent_id=event.agent_id,
                    source_ip=event.source_ip,
                    destination_ip=event.destination_ip,
                    username=event.username,
                    start_time=event_time,
                    window_duration=window_duration,
                    tenant_id=tenant_id,  # [Fix C3] Pass actual tenant_id
                    category=category,
                    actor=getattr(event, "dedup_actor", None),
                    target=getattr(event, "dedup_target", None),
                    rule_description=getattr(event, "rule_description", None),
                    ioa_summary=getattr(event, "ioa_summary", None),
                    os_platform=getattr(event, "os_platform", "unknown"),
                    log_source=getattr(event, "location", None),
                    extracted_iocs=getattr(event, "extracted_iocs", None),
                )
                new_window.raw_evidence.append((event.event_id, event_time))
                new_window.max_inline_risk_score = getattr(event, "inline_risk_score", None) or 0
                new_window.ocsf_severity_id = getattr(event, "ocsf_severity_id", None)
                new_window.classification_groups = list(getattr(event, "classification_groups", None) or [])
                new_window.mitre_tactics = list(getattr(event, "mitre_tactics", None) or [])
                if getattr(event, "http_status", None) is not None:
                    new_window.http_statuses[event.http_status] += 1
                if getattr(event, "is_scanner_ua", False):
                    new_window.scanner_ua_detected = True
                self.active_windows[dedup_key] = new_window
            else:
                # Add to current active window
                window.add_event(
                    event.event_id,
                    event_time,
                    ioa_summary=getattr(event, "ioa_summary", None),
                    inline_risk_score=getattr(event, "inline_risk_score", None),
                    ocsf_severity_id=getattr(event, "ocsf_severity_id", None),
                    extracted_iocs=getattr(event, "extracted_iocs", None),
                    log_source=getattr(event, "location", None),
                    http_status=getattr(event, "http_status", None),
                    is_scanner_ua=getattr(event, "is_scanner_ua", False),
                )
        else:
            # Create new active window
            new_agg_id = f"agg_{uuid.uuid4().hex}"
            new_window = AggregatedWindow(
                aggregation_id=new_agg_id,
                dedup_key=dedup_key,
                rule_id=rule_id_int,
                agent_id=event.agent_id,
                source_ip=event.source_ip,
                destination_ip=event.destination_ip,
                username=event.username,
                start_time=event_time,
                window_duration=window_duration,
                tenant_id=tenant_id,  # [Fix C3] Pass actual tenant_id
                category=category,
                actor=getattr(event, "dedup_actor", None),
                target=getattr(event, "dedup_target", None),
                rule_description=getattr(event, "rule_description", None),
                ioa_summary=getattr(event, "ioa_summary", None),
                os_platform=getattr(event, "os_platform", "unknown"),
                log_source=getattr(event, "location", None),
                extracted_iocs=getattr(event, "extracted_iocs", None),
            )
            new_window.raw_evidence.append((event.event_id, event_time))
            new_window.max_inline_risk_score = getattr(event, "inline_risk_score", None) or 0
            new_window.ocsf_severity_id = getattr(event, "ocsf_severity_id", None)
            new_window.classification_groups = list(getattr(event, "classification_groups", None) or [])
            new_window.mitre_tactics = list(getattr(event, "mitre_tactics", None) or [])
            if getattr(event, "http_status", None) is not None:
                new_window.http_statuses[event.http_status] += 1
            if getattr(event, "is_scanner_ua", False):
                new_window.scanner_ua_detected = True
            self.active_windows[dedup_key] = new_window

        return closed_alert


    def _cleanup_stale_windows(self, current_time: datetime) -> List[Dict[str, Any]]:
        """Evict windows that have expired past their threshold to maintain flat RAM usage."""
        evicted = []
        for k in list(self.active_windows.keys()):
            w = self.active_windows[k]
            if w.is_stale_for_eviction(current_time):
                evicted.append(self._finalize_window(w))
                del self.active_windows[k]
        return evicted

    def _finalize_window(self, window: AggregatedWindow) -> Dict[str, Any]:
        """
        Convert a completed window into an AggregatedAlert dict.
        Status is always CLOSED — window has expired, aggregation is done.
        Decisions on priority (P0-P4) are the responsibility of the Scoring Engine (Stage 4).
        Suppression decisions are the responsibility of Wazuh Rule XML, not this layer.
        """
        self.total_aggregates_out += 1
        self.total_evidence_links += len(window.raw_evidence)

        category = getattr(window, "category", "SYSTEM_HEALTH")
        dominant_http_status = window.http_statuses.most_common(1)[0][0] if window.http_statuses else None

        agg_dict = {
            "aggregation_id": window.aggregation_id,
            "rule_id": window.rule_id,
            "rule_description": getattr(window, "rule_description", None),
            "deduplication_key": window.dedup_key,
            "tenant_id": window.tenant_id,
            "agent_id": window.agent_id,
            "source_ip": window.source_ip,
            "destination_ip": window.destination_ip,
            "username": window.username,
            "event_count": window.event_count,
            "window_start": window.window_start,
            "window_end": window.window_end,
            "status": "CLOSED",  # Window selesai. Scoring Engine yang menilai P0-P4.
            "category": category,
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
            "raw_evidence": window.raw_evidence
        }
        return agg_dict



    def drain_completed_aggregates(self) -> List[Dict[str, Any]]:
        """Drain and return any aggregates completed by periodic memory garbage collection."""
        drained = list(self.completed_aggregates)
        self.completed_aggregates.clear()
        return drained

    def flush_all(self) -> List[Dict[str, Any]]:
        """Flush all remaining active windows AND any GC-evicted aggregates at end of stream."""
        results = list(self.completed_aggregates)
        self.completed_aggregates.clear()
        for dedup_key, window in list(self.active_windows.items()):
            results.append(self._finalize_window(window))
        self.active_windows.clear()
        return results

    def get_summary_metrics(self) -> Dict[str, Any]:
        """Calculate overall compression and noise reduction metrics."""
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

    def export_state(self) -> Dict[str, Any]:
        """Export in-flight deduplication state for persistence across restarts."""
        serialized_windows = {}
        for k, w in self.active_windows.items():
            serialized_windows[k] = {
                "aggregation_id": w.aggregation_id,
                "dedup_key": w.dedup_key,
                "rule_id": w.rule_id,
                "agent_id": w.agent_id,
                "source_ip": w.source_ip,
                "destination_ip": w.destination_ip,
                "username": w.username,
                "tenant_id": getattr(w, "tenant_id", "DEFAULT"),
                "category": getattr(w, "category", "SYSTEM_HEALTH"),
                "rule_description": getattr(w, "rule_description", None),
                "actor": getattr(w, "actor", None),
                "target": getattr(w, "target", None),
                "window_duration_seconds": getattr(w, "window_duration_seconds", int(w.window_duration.total_seconds())),
                "window_start": w.window_start.isoformat(),
                "window_end": w.window_end.isoformat(),
                "last_event_time": w.last_event_time.isoformat(),
                "event_count": w.event_count,
                "status": w.status,
                "max_inline_risk_score": getattr(w, "max_inline_risk_score", 0),
                "ocsf_severity_id": getattr(w, "ocsf_severity_id", None),
                "classification_groups": getattr(w, "classification_groups", []),
                "mitre_tactics": getattr(w, "mitre_tactics", []),
                "os_platform": getattr(w, "os_platform", "unknown"),
                "raw_evidence": [(eid, dt.isoformat()) for eid, dt in w.raw_evidence]
            }
        return {
            "total_events_in": self.total_events_in,
            "total_aggregates_out": self.total_aggregates_out,
            "active_windows": serialized_windows
        }

    def save_snapshot(self, filepath: Optional[str] = None) -> str:
        """Save active in-flight deduplication windows to JSON on disk."""
        if filepath is None:
            filepath = str(PERSISTENCE_DIR / "dedup_state_snapshot.json")
        data = self.export_state()
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return filepath

    def load_snapshot(self, filepath: Optional[str] = None) -> int:
        """
        Restore in-flight deduplication state from JSON snapshot on disk.
        Returns number of active windows successfully restored into memory.
        """
        if filepath is None:
            filepath = str(PERSISTENCE_DIR / "dedup_state_snapshot.json")
        if not os.path.exists(filepath):
            return 0

        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.total_events_in = data.get("total_events_in", self.total_events_in)
        self.total_aggregates_out = data.get("total_aggregates_out", self.total_aggregates_out)
        restored_count = 0

        for k, win_dict in data.get("active_windows", {}).items():
            start_time = self.parse_iso_timestamp(win_dict["window_start"])
            end_time = self.parse_iso_timestamp(win_dict["window_end"])
            duration = end_time - start_time
            if duration.total_seconds() <= 0:
                duration = timedelta(seconds=900)

            win = AggregatedWindow(
                aggregation_id=win_dict["aggregation_id"],
                dedup_key=win_dict["dedup_key"],
                rule_id=int(win_dict["rule_id"]),
                agent_id=win_dict["agent_id"],
                source_ip=win_dict.get("source_ip"),
                destination_ip=win_dict.get("destination_ip"),
                username=win_dict.get("username"),
                start_time=start_time,
                window_duration=duration,
                tenant_id=win_dict.get("tenant_id", "DEFAULT"),
                category=win_dict.get("category", "SYSTEM_HEALTH"),
                actor=win_dict.get("actor"),
                target=win_dict.get("target"),
                rule_description=win_dict.get("rule_description"),
                os_platform=win_dict.get("os_platform", "unknown"),
            )
            win.event_count = win_dict.get("event_count", 1)
            win.max_inline_risk_score = win_dict.get("max_inline_risk_score", 0)
            win.ocsf_severity_id = win_dict.get("ocsf_severity_id")
            win.classification_groups = win_dict.get("classification_groups", [])
            win.mitre_tactics = win_dict.get("mitre_tactics", [])
            win.status = win_dict.get("status", "OPEN")
            if "last_event_time" in win_dict:
                win.last_event_time = self.parse_iso_timestamp(win_dict["last_event_time"])
            if "raw_evidence" in win_dict:
                win.raw_evidence = [
                    (eid, self.parse_iso_timestamp(ets))
                    for eid, ets in win_dict["raw_evidence"]
                ]
            self.active_windows[k] = win
            restored_count += 1

        return restored_count
