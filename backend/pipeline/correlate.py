"""
Stage 4: Multi-Stage Behavioral Attack Chain Correlation Engine
Tracks Stateful Multi-Event Intrusion Sequences across 15-30 Minute Sliding Windows
Production Hardened: Enforces Strict Temporal Monotonic Ordering across Attack Stages
Two-Tier Lookback: Integrates historical cumulative_alerts for cross-day attacker persistence detection
"""
import os
import json
import hashlib
from collections import defaultdict
from typing import Dict, Any, List, Optional, Tuple, Set
from datetime import datetime, timezone, timedelta
from dateutil import parser as dt_parser

from pipeline.models import CommonEventModel, CorrelatedIncidentDB, IncidentStageDB
from pipeline.score import RiskScorer, SLA_MATRIX_MINUTES
from config.settings import BASE_DIR

PRIORITY_RANK = {"P0": 4, "P1": 3, "P2": 2, "P3": 1, "P4": 0}


def event_matches_stage(event: CommonEventModel, stage_def: Dict[str, Any]) -> bool:
    """
    Evaluates whether an event matches a correlation stage definition using:
    1. Legacy rule_ids (backward compatibility)
    2. Semantic category & MITRE tactics / classification groups
    """
    rule_id_str = str(event.rule_id)

    # 1. Direct rule_id match (Fast path & legacy support)
    if "rule_ids" in stage_def and rule_id_str in stage_def["rule_ids"]:
        return True

    # 2. Semantic category match
    if "categories" in stage_def:
        if event.event_category in stage_def["categories"]:
            # If specific tactics required, check tactic match
            if "mitre_tactics" in stage_def:
                if any(t.lower() in [mt.lower() for mt in event.mitre_tactics] for t in stage_def["mitre_tactics"]):
                    return True
            # If specific groups required, check group match
            if "groups_any" in stage_def:
                event_groups_lower = [g.lower() for g in event.classification_groups]
                if any(g.lower() in event_groups_lower for g in stage_def["groups_any"]):
                    return True
            # If category matched and no deeper tactic/group filters specified
            if "mitre_tactics" not in stage_def and "groups_any" not in stage_def:
                return True

    # 3. Direct classification groups match
    if "groups_any" in stage_def:
        event_groups_lower = [g.lower() for g in event.classification_groups]
        if any(g.lower() in event_groups_lower for g in stage_def["groups_any"]):
            return True

    # 4. Direct MITRE tactics match
    if "mitre_tactics" in stage_def:
        if any(t.lower() in [mt.lower() for mt in event.mitre_tactics] for t in stage_def["mitre_tactics"]):
            return True

    return False


class CorrelationTrack:
    """State tracker for an active attack sequence with semantic & cardinality support."""

    def __init__(self, rule_config: Dict[str, Any], correlation_key: str, start_time: datetime):
        self.rule_id = rule_config["id"]
        self.rule_code = rule_config["code"]
        self.rule_name = rule_config["name"]
        self.description = rule_config["description"]
        self.timeframe = timedelta(seconds=rule_config["timeframe_seconds"])
        # Support both new key (base_severity_weight) and legacy key (target_severity) for backward compat
        self.base_severity_weight = rule_config.get("base_severity_weight") or rule_config.get("target_severity", "P2")
        self.trigger_stages = rule_config["trigger_stages"]
        self.match_keys = rule_config["match_keys"]
        self.correlation_key = correlation_key

        self.start_time = start_time
        self.last_event_time = start_time
        self.window_end = start_time + self.timeframe

        # Recorded stages: stage_name -> list of (event_id, event_time, rule_id)
        self.recorded_stages: Dict[str, List[Tuple[str, datetime, str]]] = {
            s["stage"]: [] for s in self.trigger_stages
        }
        self.stage_first_times: Dict[str, datetime] = {}
        self.has_threat_intel: bool = False
        self.participating_events: List[CommonEventModel] = []
        self.distinct_targets: Set[str] = set()
        self.distinct_actors: Set[str] = set()
        self.is_completed = False

    def add_candidate_event(self, event: CommonEventModel, event_time: datetime) -> bool:
        """Evaluate if incoming event satisfies any stage in the attack chain with temporal validation."""
        if event_time > self.window_end:
            return False

        matched_stage = None
        for stage_def in self.trigger_stages:
            stage_name = stage_def["stage"]
            if event_matches_stage(event, stage_def):
                rule_id_str = str(event.rule_id)
                self.recorded_stages[stage_name].append((event.event_id, event_time, rule_id_str))
                if stage_name not in self.stage_first_times:
                    self.stage_first_times[stage_name] = event_time
                matched_stage = stage_name
                break

        if matched_stage:
            if getattr(event, 'threat_intel_match', False):
                self.has_threat_intel = True

            # Cap participating events to 50 for evidence reporting to prevent RAM exhaustion
            if len(self.participating_events) < 50:
                self.participating_events.append(event)

            # Track distinct entities for cardinality rules (Lateral Movement & Distributed Spray)
            actor = event.source_ip or getattr(event, 'dedup_actor', None) or event.username or event.agent_name
            target = event.destination_host or getattr(event, 'dedup_target', None) or event.agent_name
            if actor:
                self.distinct_actors.add(actor)
            if target:
                self.distinct_targets.add(target)

            if event_time > self.last_event_time:
                self.last_event_time = event_time
            # Adaptive sliding timeframe extension (Anti-Dormant / Anti-Evasion Hardening):
            # When an attack stage is detected, extend window_end so attackers sleeping between stages
            # cannot outlast the correlation window.
            self.window_end = max(self.window_end, event_time + self.timeframe)
            self._check_completion()
            return True

        return False

    def _check_completion(self):
        """
        Check if all required stages have reached their minimum event threshold,
        satisfy cardinality constraints (min_distinct_targets, min_distinct_actors),
        AND satisfy temporal monotonic sequence ordering (Stage N >= Stage N-1).
        Strictly O(1) performance using cached stage_first_times and has_threat_intel.
        """
        stage_first_times: List[datetime] = []

        for stage_def in self.trigger_stages:
            stage_name = stage_def["stage"]
            min_count = stage_def.get("min_count", 1)

            # Context-Aware Threshold Override (O(1))
            if stage_def.get("threat_intel_override") and self.has_threat_intel:
                min_count = 1

            records = self.recorded_stages[stage_name]
            if len(records) < min_count:
                self.is_completed = False
                return

            # Check cardinality constraints
            min_targets = stage_def.get("min_distinct_targets")
            if min_targets and len(self.distinct_targets) < min_targets:
                self.is_completed = False
                return

            min_actors = stage_def.get("min_distinct_actors")
            if min_actors and len(self.distinct_actors) < min_actors:
                self.is_completed = False
                return

            # Record earliest timestamp of this stage (O(1) lookup)
            stage_first_times.append(self.stage_first_times[stage_name])

        # Enforce temporal monotonic order across stages (with 5-second clock skew tolerance)
        for i in range(1, len(stage_first_times)):
            if stage_first_times[i] < (stage_first_times[i - 1] - timedelta(seconds=5)):
                self.is_completed = False
                return

        self.is_completed = True

    def is_expired(self, current_time: datetime) -> bool:
        return current_time > self.window_end


class _AggregateAdapter:
    """
    Lightweight adapter that makes an ACTIONABLE aggregate dict duck-type compatible
    with CommonEventModel so it can be fed into existing CorrelationTrack methods
    (event_matches_stage, add_candidate_event, _build_incident) without modification.
    """
    __slots__ = (
        "rule_id", "event_category", "mitre_tactics", "classification_groups",
        "event_id", "timestamp", "source_ip", "username", "agent_name",
        "destination_host", "dedup_actor", "dedup_target", "threat_intel_match",
        "max_inline_risk_score", "event_count", "deduplication_key",
    )

    def __init__(self, agg: Dict[str, Any]):
        self.rule_id = str(agg.get("rule_id", "0"))
        self.event_category = agg.get("category", "UNKNOWN")
        self.mitre_tactics = agg.get("mitre_tactics") or []
        self.classification_groups = agg.get("classification_groups") or []
        self.event_id = agg.get("aggregation_id", "unknown")
        w_start = agg.get("window_start")
        self.timestamp = (
            w_start.isoformat() if hasattr(w_start, "isoformat")
            else str(w_start or "")
        )
        # Network / identity fields — prefer raw IP, fall back to actor/target strings
        actor = agg.get("actor") or ""
        self.source_ip = agg.get("source_ip") or (actor if actor.startswith("ip:") and ":" in actor else None) or actor or None
        self.username = agg.get("username")
        target = agg.get("target") or agg.get("agent_id", "unknown")
        self.agent_name = target
        self.destination_host = target
        self.dedup_actor = agg.get("actor")
        self.dedup_target = agg.get("target")
        self.threat_intel_match = bool(agg.get("threat_intel_match", False))
        self.max_inline_risk_score = agg.get("max_inline_risk_score", 0)
        self.event_count = agg.get("event_count", 1)
        self.deduplication_key = agg.get("deduplication_key", "")

class TicketDeduplicationGuard:
    """
    PRD Section 5.3: Jika aggregate (penyerang X, korban X, tenant X) muncul
    dan sudah ada tiket yang SLA-nya belum habis, tidak dibuat tiket baru.
    Aggregate dimasukkan ke tiket yang sama sampai SLA habis.

    Returns:
    - 'APPEND'     -> tiket masih terbuka, aggregate masuk ke tiket yang sama
    - 'CREATE_NEW' -> tidak ada tiket terbuka, buat tiket baru
    """

    def __init__(self, db_manager=None, dedup_window_hours: int = 24):
        self._db = db_manager
        self._window_hours = dedup_window_hours

    def check(
        self,
        actor: str,
        target: str,
        rule_id: Optional[Any] = None,
        tenant_id: str = "DEFAULT",
        reference_time: Optional[datetime] = None
    ) -> Tuple[str, Optional[str]]:
        """
        Check if an active open ticket exists for (actor, target, tenant) within its unexpired SLA.
        Returns:
        - ('APPEND', incident_id) if active ticket exists within unexpired SLA
        - ('CREATE_NEW', None) if no active ticket exists or SLA has expired
        """
        if self._db is None:
            return ("CREATE_NEW", None)

        ref = reference_time or datetime.now(timezone.utc)
        ref_naive = ref.replace(tzinfo=None) if getattr(ref, "tzinfo", None) else ref
        resolved_tenant = tenant_id or "DEFAULT"

        try:
            with self._db.get_connection() as conn:
                with conn.cursor() as cur:
                    has_actor = bool(actor and actor not in ("unknown", "none", ""))
                    actor_clause = "i.attacker_source_ip = %s" if has_actor else "(i.attacker_source_ip IS NULL OR i.attacker_source_ip = 'unknown')"

                    query = f"""
                        SELECT q.incident_id
                        FROM soc_ops.soc_triage_queue q
                        JOIN correlation.correlated_incidents i ON q.incident_id = i.incident_id
                        WHERE q.triage_status IN ('OPEN', 'INVESTIGATE', 'INVESTIGATING', 'NEW', 'HOLDING_P4')
                          AND {actor_clause}
                          AND i.target_host = %s
                          AND (i.tenant_id = %s OR %s IS NULL)
                          AND (
                            (q.priority = 'P0' AND (COALESCE(q.priority_changed_at, q.priority_established_at, q.created_at) + INTERVAL '15 minutes') > %s) OR
                            (q.priority = 'P1' AND (COALESCE(q.priority_changed_at, q.priority_established_at, q.created_at) + INTERVAL '60 minutes') > %s) OR
                            (q.priority = 'P2' AND (COALESCE(q.priority_changed_at, q.priority_established_at, q.created_at) + INTERVAL '4 hours') > %s) OR
                            (q.priority = 'P3' AND (COALESCE(q.priority_changed_at, q.priority_established_at, q.created_at) + INTERVAL '1 day') > %s) OR
                            (q.priority = 'P4' AND (COALESCE(q.priority_changed_at, q.priority_established_at, q.created_at) + INTERVAL '7 days') > %s)
                          )
                        ORDER BY q.created_at DESC
                        LIMIT 1;
                    """
                    params = [actor] if has_actor else []
                    params.extend([target, resolved_tenant, resolved_tenant, ref_naive, ref_naive, ref_naive, ref_naive, ref_naive])
                    cur.execute(query, tuple(params))
                    row = cur.fetchone()
                    if row:
                        return ("APPEND", str(row[0]))
            return ("CREATE_NEW", None)
        except Exception:
            return ("CREATE_NEW", None)


class CorrelationEngine:
    """
    Stateful Behavioral Correlation Engine.
    Correlates multiple security events across agents, IP addresses, and accounts
    into contextual security incidents with chronological attack stages.
    """

    def __init__(self, config_path: Optional[str] = None, db_manager=None):
        if config_path is None:
            config_path = str(BASE_DIR / "config" / "correlation_rules.json")

        self.rules: List[Dict[str, Any]] = []
        self._ticket_dedup_window_hours: int = 24

        if os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.rules = data.get("correlation_rules", [])
                self._ticket_dedup_window_hours = data.get("ticket_dedup_window_hours", 24)

        # Active tracks for CEM-based correlation (existing — unchanged)
        self.active_tracks: Dict[str, CorrelationTrack] = {}
        # Active tracks for aggregate-based correlation (new)
        self._agg_tracks: Dict[str, CorrelationTrack] = {}
        # Pure Entity-based 24h correlation tracks
        self.entity_tracks: Dict[str, Dict[str, Any]] = {}
        self.actor_targets: Dict[str, List[Tuple[str, datetime, CommonEventModel]]] = defaultdict(list)
        self.target_actors: Dict[str, List[Tuple[str, datetime, CommonEventModel]]] = defaultdict(list)
        self.host_tamper_tracks: Dict[str, List[Tuple[CommonEventModel, datetime]]] = defaultdict(list)
        self.host_access_tracks: Dict[str, List[Tuple[CommonEventModel, datetime]]] = defaultdict(list)
        self._emitted_lateral_actors: Set[str] = set()
        self._emitted_spray_targets: Set[str] = set()
        self.generated_incidents: List[Dict[str, Any]] = []
        self.total_incidents_created = 0

        # Optional DB manager for Two-Tier Historical Lookback
        self._db = db_manager

        # Ticket deduplication guard (24h per actor/target)
        self._ticket_guard = TicketDeduplicationGuard(
            db_manager=db_manager,
            dedup_window_hours=self._ticket_dedup_window_hours,
        )

        # Stateful Priority Engine & Risk Scorer
        self._risk_scorer = RiskScorer(db_name=getattr(db_manager, "dbname", "wazuh_soc_db") if db_manager else "wazuh_soc_db")

        # Groups that indicate a successful authentication (trigger for historical lookback)
        self._AUTH_SUCCESS_GROUPS = frozenset([
            "authentication_success", "login_success"
        ])

    def parse_timestamp(self, ts_str: str) -> datetime:
        try:
            return dt_parser.parse(ts_str)
        except Exception:
            return datetime.now(timezone.utc)

    def _process_pure_entity_event(
        self, event: CommonEventModel, event_time: datetime
    ) -> List[Dict[str, Any]]:
        """
        Pure Entity Correlation Engine (24-Hour Rolling Window).
        Tracks behavioral attack chains dynamically based on (tenant_id, actor, target_host)
        without relying on static rule templates CORR-001 through CORR-008.
        """
        import uuid as _uuid
        newly_completed: List[Dict[str, Any]] = []

        tenant_id = getattr(event, "tenant_id", None) or "DEFAULT"
        actor = event.source_ip or getattr(event, "dedup_actor", None) or event.username or "nosrc"
        target = event.destination_host or event.agent_name or getattr(event, "dedup_target", None) or "notarget"
        user = event.username or "nouser"
        rule_id_str = str(event.rule_id)
        rule_level = getattr(event, "rule_level", 0) or 0
        groups = [g.lower() for g in (event.classification_groups or [])]
        tactics = [t.lower() for t in (event.mitre_tactics or [])]
        desc = (event.rule_description or "").lower()
        has_ti = bool(getattr(event, "threat_intel_match", False))
        cutoff_24h = event_time - timedelta(hours=24)

        # 1. Update/initialize Entity Track for (tenant_id, actor, target)
        entity_key = f"{tenant_id}_{actor}_{target}"
        if entity_key not in self.entity_tracks:
            self.entity_tracks[entity_key] = {
                "tenant_id": tenant_id,
                "actor": actor,
                "target": target,
                "user": user,
                "start_time": event_time,
                "last_event_time": event_time,
                "failed_logins": [],
                "has_threat_intel": False,
                "participating_events": [],
            }
        track = self.entity_tracks[entity_key]
        track["last_event_time"] = event_time
        if has_ti:
            track["has_threat_intel"] = True

        # Evict failed logins older than 24h
        track["failed_logins"] = [
            (e, t) for e, t in track["failed_logins"] if t >= cutoff_24h
        ]

        # ── Pattern A: Lateral Movement Sweep (1 Actor -> >= 3 Distinct Targets in 24h) ──
        is_lateral = (
            any(g in ("lateral_movement", "smb", "remote_exec", "psexec", "wmi", "winrm") for g in groups)
            or "lateral movement" in tactics
            or rule_id_str == "106000"
        )
        if is_lateral and actor not in ("nosrc", "unknown", "") and target not in ("notarget", "unknown", ""):
            self.actor_targets[actor].append((target, event_time, event))
            self.actor_targets[actor] = [
                (tgt, t, e) for tgt, t, e in self.actor_targets[actor] if t >= cutoff_24h
            ]
            distinct_tgts = {tgt for tgt, t, e in self.actor_targets[actor]}
            if len(distinct_tgts) >= 3 and actor not in self._emitted_lateral_actors:
                self._emitted_lateral_actors.add(actor)
                self.total_incidents_created += 1
                inc_id = f"INC-ENTITY-{_uuid.uuid4().hex[:12].upper()}"
                all_evts = [e for _, _, e in self.actor_targets[actor]]
                stages = []
                for seq, (tgt, t, evt) in enumerate(self.actor_targets[actor], 1):
                    stages.append({
                        "incident_id": inc_id,
                        "sequence_order": seq,
                        "stage_name": "LATERAL_MOVEMENT_HOP",
                        "reference_id": evt.event_id,
                        "evidence_type": "NORMALIZED_EVENT",
                        "stage_description": f"Actor [{actor}] accessed host [{tgt}] via {evt.rule_description or 'lateral movement'} at {t.isoformat()}"
                    })

                newly_completed.append({
                    "incident_id": inc_id,
                    "correlation_rule_id": "CORR-ENTITY",
                    "rule_code": "LATERAL_MOVEMENT_SWEEP",
                    "tenant_id": tenant_id,
                    "title": f"[P1] Lateral Movement Sweep across {len(distinct_tgts)} Hosts by {actor}",
                    "narrative": f"Single actor [{actor}] accessed {len(distinct_tgts)} distinct target hosts ({', '.join(sorted(distinct_tgts))}) within 24h window.",
                    "initial_access_vector": "NETWORK_EXPLOITATION",
                    "attacker_source_ip": actor,
                    "compromised_account": user if user != "nouser" else None,
                    "target_host": target,
                    "incident_status": "DETECTED",
                    "first_seen_at": self.actor_targets[actor][0][1],
                    "last_seen_at": event_time,
                    "target_severity": "P1",
                    "stages": stages,
                    "related_incident_ids": [],
                    "events_count": len(all_evts),
                    "distinct_targets_count": len(distinct_tgts),
                    "distinct_actors_count": 1,
                    "is_reopen": False,
                    "parent_incident_id": None,
                })

        # ── Pattern B: Distributed Password Spray (>= 5 Distinct Actors -> 1 Target in 24h) ──
        is_failed_login = (
            any(g in ("authentication_failed", "authentication_failures", "invalid_login", "sshd", "pam") for g in groups)
            or rule_id_str in ("5710", "100020")
            or ("failed" in desc and "auth" in desc)
            or "failed login" in desc
            or "single failed authentication" in desc
        )
        if is_failed_login and target not in ("notarget", "unknown", ""):
            self.target_actors[target].append((actor, event_time, event))
            self.target_actors[target] = [
                (act, t, e) for act, t, e in self.target_actors[target] if t >= cutoff_24h
            ]
            distinct_acts = {act for act, t, e in self.target_actors[target] if act not in ("nosrc", "unknown", "")}
            if len(distinct_acts) >= 5 and target not in self._emitted_spray_targets:
                self._emitted_spray_targets.add(target)
                self.total_incidents_created += 1
                inc_id = f"INC-ENTITY-{_uuid.uuid4().hex[:12].upper()}"
                all_evts = [e for _, _, e in self.target_actors[target]]
                stages = []
                for seq, (act, t, evt) in enumerate(self.target_actors[target], 1):
                    stages.append({
                        "incident_id": inc_id,
                        "sequence_order": seq,
                        "stage_name": "SPRAY_ATTEMPT",
                        "reference_id": evt.event_id,
                        "evidence_type": "NORMALIZED_EVENT",
                        "stage_description": f"Failed login attempt from [{act}] against [{target}] at {t.isoformat()}"
                    })

                newly_completed.append({
                    "incident_id": inc_id,
                    "correlation_rule_id": "CORR-ENTITY",
                    "rule_code": "DISTRIBUTED_PASSWORD_SPRAY",
                    "tenant_id": tenant_id,
                    "title": f"[P1] Distributed Password Spray on {target} from {len(distinct_acts)} Sources",
                    "narrative": f"Distributed password spray detected against target [{target}] from {len(distinct_acts)} distinct source IPs.",
                    "initial_access_vector": "NETWORK_EXPLOITATION",
                    "attacker_source_ip": list(distinct_acts)[0],
                    "compromised_account": user if user != "nouser" else None,
                    "target_host": target,
                    "incident_status": "DETECTED",
                    "first_seen_at": self.target_actors[target][0][1],
                    "last_seen_at": event_time,
                    "target_severity": "P1",
                    "stages": stages,
                    "related_incident_ids": [],
                    "events_count": len(all_evts),
                    "distinct_targets_count": 1,
                    "distinct_actors_count": len(distinct_acts),
                    "is_reopen": False,
                    "parent_incident_id": None,
                })

        # ── Pattern C: Brute Force to Success on Same Entity (Actor -> Target) ──
        if is_failed_login:
            track["failed_logins"].append((event, event_time))

        is_success_login = (
            any(g in ("authentication_success", "login_success") for g in groups)
            or rule_id_str in ("100010", "5715")
            or "successful" in desc
            or "succ auth" in desc
        )
        if is_success_login:
            min_failed = 1 if track["has_threat_intel"] else 5
            if len(track["failed_logins"]) >= min_failed:
                self.total_incidents_created += 1
                inc_id = f"INC-ENTITY-{_uuid.uuid4().hex[:12].upper()}"
                stages = []
                seq = 1
                for f_evt, f_time in track["failed_logins"]:
                    stages.append({
                        "incident_id": inc_id,
                        "sequence_order": seq,
                        "stage_name": "AUTH_BRUTE_FORCE_STAGE",
                        "reference_id": f_evt.event_id,
                        "evidence_type": "NORMALIZED_EVENT",
                        "stage_description": f"Triggered by Stage [AUTH_BRUTE_FORCE_STAGE] via Rule/Archetype {f_evt.rule_id} at {f_time.isoformat()}"
                    })
                    seq += 1

                stages.append({
                    "incident_id": inc_id,
                    "sequence_order": seq,
                    "stage_name": "AUTH_SUCCESS_STAGE",
                    "reference_id": event.event_id,
                    "evidence_type": "NORMALIZED_EVENT",
                    "stage_description": f"Triggered by Stage [AUTH_SUCCESS_STAGE] via Rule/Archetype {event.rule_id} at {event_time.isoformat()}"
                })

                newly_completed.append({
                    "incident_id": inc_id,
                    "correlation_rule_id": "CORR-ENTITY",
                    "rule_code": "AUTH_BRUTE_FORCE_SUCCESS",
                    "tenant_id": tenant_id,
                    "title": f"[P0] Successful Authentication after Brute Force on {target} by {actor}",
                    "narrative": (
                        f"Attack Chain Detected: Brute Force followed by Successful Login. Origin: {actor}, "
                        f"Target Host: {target}, Compromised Account: {user}. "
                        f"Spanned across {len(stages)} forensic stages."
                    ),
                    "initial_access_vector": "NETWORK_EXPLOITATION" if actor not in ("nosrc", "unknown") else "LOCAL_ACCESS",
                    "attacker_source_ip": actor if actor not in ("nosrc", "unknown") else None,
                    "compromised_account": user if user not in ("nouser", "unknown") else None,
                    "target_host": target,
                    "incident_status": "DETECTED",
                    "first_seen_at": track["failed_logins"][0][1],
                    "last_seen_at": event_time,
                    "target_severity": "P0" if track["has_threat_intel"] else "P1",
                    "stages": stages,
                    "related_incident_ids": [],
                    "events_count": len(track["failed_logins"]) + 1,
                    "distinct_targets_count": 1,
                    "distinct_actors_count": 1,
                    "is_reopen": False,
                    "parent_incident_id": None,
                })
                # Evict/reset track state to avoid immunity bug
                track["failed_logins"] = []
                track["has_threat_intel"] = False

        # ── Pattern D: Ransomware Defense Evasion & Impact on Target Host ──
        is_tamper = (
            any(g in ("vssadmin", "shadow_copy", "tamper", "defense_evasion") for g in groups)
            or "defense evasion" in tactics
            or "vssadmin" in desc
            or "shadow copy" in desc
        )
        if is_tamper and target not in ("notarget", "unknown", ""):
            self.host_tamper_tracks[target].append((event, event_time))

        is_impact = (
            any(g in ("ransomware", "mass_file_modification", "encrypt") for g in groups)
            or "impact" in tactics
            or "ransomware" in desc
            or "encryption" in desc
        )
        if is_impact and target in self.host_tamper_tracks and self.host_tamper_tracks[target]:
            self.host_tamper_tracks[target] = [
                (e, t) for e, t in self.host_tamper_tracks[target] if t >= cutoff_24h
            ]
            if self.host_tamper_tracks[target]:
                self.total_incidents_created += 1
                inc_id = f"INC-ENTITY-{_uuid.uuid4().hex[:12].upper()}"
                tamper_evt, t_time = self.host_tamper_tracks[target][0]
                stages = [
                    {
                        "incident_id": inc_id,
                        "sequence_order": 1,
                        "stage_name": "DEFENSE_EVASION_TAMPER",
                        "reference_id": tamper_evt.event_id,
                        "evidence_type": "NORMALIZED_EVENT",
                        "stage_description": f"Triggered by Stage [DEFENSE_EVASION_TAMPER] via Rule/Archetype {tamper_evt.rule_id} at {t_time.isoformat()}"
                    },
                    {
                        "incident_id": inc_id,
                        "sequence_order": 2,
                        "stage_name": "MASS_FILE_IMPACT",
                        "reference_id": event.event_id,
                        "evidence_type": "NORMALIZED_EVENT",
                        "stage_description": f"Triggered by Stage [MASS_FILE_IMPACT] via Rule/Archetype {event.rule_id} at {event_time.isoformat()}"
                    }
                ]

                newly_completed.append({
                    "incident_id": inc_id,
                    "correlation_rule_id": "CORR-ENTITY",
                    "rule_code": "RANSOMWARE_TAMPER_AND_IMPACT",
                    "tenant_id": tenant_id,
                    "title": f"[P0] Ransomware Defense Evasion and Mass File Encryption on {target}",
                    "narrative": f"Ransomware attack chain detected on [{target}]: shadow copy deletion followed by mass file modification.",
                    "initial_access_vector": "LOCAL_ACCESS" if actor in ("nosrc", "unknown") else "NETWORK_EXPLOITATION",
                    "attacker_source_ip": actor if actor not in ("nosrc", "unknown") else None,
                    "compromised_account": user if user not in ("nouser", "unknown") else None,
                    "target_host": target,
                    "incident_status": "DETECTED",
                    "first_seen_at": t_time,
                    "last_seen_at": event_time,
                    "target_severity": "P0",
                    "stages": stages,
                    "related_incident_ids": [],
                    "events_count": len(self.host_tamper_tracks[target]) + 1,
                    "distinct_targets_count": 1,
                    "distinct_actors_count": 1,
                    "is_reopen": False,
                    "parent_incident_id": None,
                })
                self.host_tamper_tracks[target] = []

        # ── Pattern E: Generic Host Multi-Tactic Chain (Initial Access -> Execution) ──
        is_init_access = (
            "initial access" in tactics
            or any(g in ("web_attack", "exploit", "initial_access") for g in groups)
        )
        if is_init_access and target not in ("notarget", "unknown", ""):
            self.host_access_tracks[target].append((event, event_time))

        is_execution = (
            "execution" in tactics
            or any(g in ("reverse_shell", "shell", "execution", "payload") for g in groups)
        )
        if is_execution and target in self.host_access_tracks and self.host_access_tracks[target]:
            self.host_access_tracks[target] = [
                (e, t) for e, t in self.host_access_tracks[target] if t >= cutoff_24h
            ]
            if self.host_access_tracks[target]:
                self.total_incidents_created += 1
                inc_id = f"INC-ENTITY-{_uuid.uuid4().hex[:12].upper()}"
                access_evt, a_time = self.host_access_tracks[target][0]
                stages = [
                    {
                        "incident_id": inc_id,
                        "sequence_order": 1,
                        "stage_name": "INITIAL_ACCESS",
                        "reference_id": access_evt.event_id,
                        "evidence_type": "NORMALIZED_EVENT",
                        "stage_description": f"Triggered by Stage [INITIAL_ACCESS] via Rule/Archetype {access_evt.rule_id} at {a_time.isoformat()}"
                    },
                    {
                        "incident_id": inc_id,
                        "sequence_order": 2,
                        "stage_name": "EXECUTION",
                        "reference_id": event.event_id,
                        "evidence_type": "NORMALIZED_EVENT",
                        "stage_description": f"Triggered by Stage [EXECUTION] via Rule/Archetype {event.rule_id} at {event_time.isoformat()}"
                    }
                ]

                newly_completed.append({
                    "incident_id": inc_id,
                    "correlation_rule_id": "CORR-ENTITY",
                    "rule_code": "GENERIC_HOST_MULTI_TACTIC_CHAIN",
                    "tenant_id": tenant_id,
                    "title": f"[P0] Multi-Tactic Attack Sequence on {target}",
                    "narrative": f"Generic multi-tactic attack sequence detected on [{target}]: Initial Access followed by Execution payload.",
                    "initial_access_vector": "NETWORK_EXPLOITATION" if actor not in ("nosrc", "unknown") else "LOCAL_ACCESS",
                    "attacker_source_ip": actor if actor not in ("nosrc", "unknown") else None,
                    "compromised_account": user if user not in ("nouser", "unknown") else None,
                    "target_host": target,
                    "incident_status": "DETECTED",
                    "first_seen_at": a_time,
                    "last_seen_at": event_time,
                    "target_severity": "P0",
                    "stages": stages,
                    "related_incident_ids": [],
                    "events_count": len(self.host_access_tracks[target]) + 1,
                    "distinct_targets_count": 1,
                    "distinct_actors_count": 1,
                    "is_reopen": False,
                    "parent_incident_id": None,
                })
                self.host_access_tracks[target] = []

        return newly_completed

    def process_event(self, event: CommonEventModel) -> List[Dict[str, Any]]:
        """
        Evaluate an event against active correlation tracks (pure entity or rule-based).
        Returns a list of newly completed incident dicts (if any).

        Execution order is intentional:
          1. Pure Entity Correlation (when no static rules configured) OR in-session track evaluation
          2. New track initiation
          3. Rule Precedence Filter (suppress GENERIC if specific fired)
          4. Two-Tier Historical Lookback — runs LAST, so it can see all
             in-session incidents and skip if actor already covered this cycle
        """
        event_time = self.parse_timestamp(event.timestamp)
        newly_completed_incidents = []

        if not self.rules:
            # Pure Entity-based correlation engine (24h window)
            newly_completed_incidents = self._process_pure_entity_event(event, event_time)
        else:
            # 1. Update existing active track (O(1) direct dictionary lookup per rule)
            for rule_cfg in self.rules:
                corr_key = self._extract_correlation_key(event, rule_cfg["match_keys"])
                track_id = f"{rule_cfg['id']}_{corr_key}"
                track = self.active_tracks.get(track_id)
                if track is not None:
                    if track.is_expired(event_time):
                        del self.active_tracks[track_id]
                    else:
                        track.add_candidate_event(event, event_time)
                        if track.is_completed and not getattr(track, "_emitted", False):
                            inc_dict = self._build_incident(track)
                            newly_completed_incidents.append(inc_dict)
                            track._emitted = True
                            if track_id in self.active_tracks:
                                del self.active_tracks[track_id]

            # 2. Check if event initiates a new correlation track (O(1) existence check)
            for rule_cfg in self.rules:
                corr_key = self._extract_correlation_key(event, rule_cfg["match_keys"])
                track_id = f"{rule_cfg['id']}_{corr_key}"
                if track_id not in self.active_tracks:
                    first_stage = rule_cfg["trigger_stages"][0]
                    if event_matches_stage(event, first_stage):
                        new_track = CorrelationTrack(rule_cfg, corr_key, event_time)
                        new_track.add_candidate_event(event, event_time)
                        self.active_tracks[track_id] = new_track
                        if new_track.is_completed and not getattr(new_track, "_emitted", False):
                            inc_dict = self._build_incident(new_track)
                            newly_completed_incidents.append(inc_dict)
                            new_track._emitted = True
                            if track_id in self.active_tracks:
                                del self.active_tracks[track_id]

        # Periodic lazy cleanup of expired tracks every 5,000 events
        self._event_counter = getattr(self, "_event_counter", 0) + 1
        if self._event_counter % 5000 == 0:
            expired = [tid for tid, trk in self.active_tracks.items() if trk.is_expired(event_time)]
            for tid in expired:
                del self.active_tracks[tid]

        # 3. Rule Precedence & De-duplication:
        # If a specific attack rule (e.g. CORR-007 Ransomware, CORR-001 Brute Force)
        # emits an incident for a target host, suppress redundant generic safety-net incidents
        # (e.g. CORR-008 GENERIC_...) on the same host to keep SOC queues noise-free.
        specific_hosts = {
            inc.get("target_host") for inc in newly_completed_incidents
            if not inc.get("rule_code", "").startswith("GENERIC_")
            and inc.get("target_host")
        }
        if specific_hosts:
            newly_completed_incidents = [
                inc for inc in newly_completed_incidents
                if not (
                    inc.get("rule_code", "").startswith("GENERIC_")
                    and inc.get("target_host") in specific_hosts
                )
            ]

        # 4. Two-Tier Historical Lookback (runs LAST):
        # Pass already-generated incidents so historical can skip actors
        # that already received an in-session incident this cycle (prevents double-ticket).
        historical_inc = self._check_historical_escalation(
            event, event_time, in_session_incidents=newly_completed_incidents
        )
        if historical_inc:
            newly_completed_incidents.append(historical_inc)

        return newly_completed_incidents

    def _event_matches_track(self, event: CommonEventModel, track: CorrelationTrack) -> bool:
        event_corr_key = self._extract_correlation_key(event, track.match_keys)
        return event_corr_key == track.correlation_key

    def _extract_correlation_key(self, event: CommonEventModel, match_keys: List[str]) -> str:
        parts = []
        for k in match_keys:
            if k == "source_ip":
                parts.append(event.source_ip or getattr(event, 'dedup_actor', None) or "nosrc")
            elif k in ("agent_name", "target"):
                parts.append(event.destination_host or event.agent_name or getattr(event, 'dedup_target', None) or "noagent")
            elif k in ("actor",):
                parts.append(event.source_ip or getattr(event, 'dedup_actor', None) or event.username or "noactor")
            elif k == "username":
                parts.append(event.username or "nouser")
            elif k == "destination_host":
                parts.append(event.destination_host or "nodst")
            else:
                parts.append(str(getattr(event, k, "val")))
        return "_".join(parts)

    def _build_incident(self, track: CorrelationTrack) -> Dict[str, Any]:
        """Construct full incident dictionary with chronological attack stages and forensic links."""
        self.total_incidents_created += 1
        import uuid as _uuid
        # [F10] Use UUID4 for incident_id with INC-ENTITY format
        incident_id = f"INC-ENTITY-{_uuid.uuid4().hex[:12].upper()}"

        user = next((e.username for e in track.participating_events if e.username and e.username != "nouser"), "unknown")
        src_ip = next((e.source_ip for e in track.participating_events if e.source_ip and e.source_ip != "nosrc"), "unknown")
        target_host = next((e.agent_name or e.destination_host for e in track.participating_events if (e.agent_name or e.destination_host)), "unknown")

        stages = []
        seq = 1
        for stage_def in track.trigger_stages:
            stage_name = stage_def["stage"]
            evts = track.recorded_stages.get(stage_name, [])
            for evt_id, evt_time, rid in sorted(evts, key=lambda x: x[1]):
                stages.append({
                    "incident_id": incident_id,
                    "sequence_order": seq,
                    "stage_name": stage_name,
                    "reference_id": evt_id,
                    "evidence_type": "NORMALIZED_EVENT",
                    "stage_description": f"Triggered by Stage [{stage_name}] via Rule/Archetype {rid} at {evt_time.isoformat()}"
                })
                seq += 1

        # [F10] Cooldown-aware re-open check:
        # Sebelum query related incidents, cek apakah ada tiket lama yang masih dalam cooldown.
        # Jika ya → set parent_incident_id dan is_reopen=True agar DB layer dapat append ke tiket lama.
        # Jika tidak → buat tiket baru (normal flow).
        is_reopen = False
        parent_incident_id = None
        actor_for_cooldown = src_ip if src_ip not in ("nosrc", "unknown") else None
        cooldown_result = self.check_incident_cooldown(
            attacker_ip=actor_for_cooldown,
            target_host=target_host if target_host != "unknown" else None,
            tenant_id="DEFAULT"
        )
        if cooldown_result:
            parent_incident_id = cooldown_result["incident_id"]
            is_reopen = True

        # Cross-reference: query prior related incidents (P2, P3, etc.) for this actor / target
        related_ids = []
        if parent_incident_id:
            related_ids.append(parent_incident_id)
        if self._db is not None:
            try:
                with self._db.get_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("""
                            SELECT i.incident_id 
                            FROM correlation.correlated_incidents i
                            WHERE (i.attacker_source_ip = %s OR i.target_host = %s)
                              AND i.incident_id != %s
                            ORDER BY i.first_seen_at DESC
                            LIMIT 5;
                        """, (src_ip, target_host, incident_id))
                        related_ids += [r[0] for r in cur.fetchall() if r[0] not in related_ids]
            except Exception:
                pass

        # De-duplicate related_ids list
        related_ids = list(dict.fromkeys(related_ids))[:5]

        narrative = (
            f"Attack Chain Detected: {track.rule_name}. Origin: {src_ip}, "
            f"Target Host: {target_host}, Compromised Account: {user}. "
            f"Spanned across {len(stages)} forensic stages with {len(track.distinct_targets)} distinct target(s) "
            f"and {len(track.distinct_actors)} distinct actor(s)."
        )
        if is_reopen and parent_incident_id:
            narrative += f" [RE-OPEN] Appended to existing incident {parent_incident_id} (within 72h cooldown window)."
        elif related_ids:
            narrative += f" Cross-reference: Linked to prior related incident(s): {', '.join(related_ids)}."

        incident = {
            "incident_id": incident_id,
            "correlation_rule_id": "CORR-ENTITY" if str(track.rule_id).startswith("CORR-00") else track.rule_id,
            "rule_code": track.rule_code,
            "tenant_id": "DEFAULT",
            "title": f"[{track.base_severity_weight}] {track.rule_name} on {target_host} by {src_ip}",
            "narrative": narrative,
            "initial_access_vector": "NETWORK_EXPLOITATION" if src_ip not in ("nosrc", "unknown") else "LOCAL_ACCESS",
            "attacker_source_ip": src_ip if src_ip not in ("nosrc", "unknown") else None,
            "compromised_account": user if user not in ("nouser", "unknown") else None,
            "target_host": target_host,
            "incident_status": "DETECTED",
            "first_seen_at": track.start_time,
            "last_seen_at": track.last_event_time,
            "target_severity": track.base_severity_weight,
            "stages": stages,
            "related_incident_ids": related_ids,
            "events_count": len(track.participating_events),
            "distinct_targets_count": len(track.distinct_targets),
            "distinct_actors_count": len(track.distinct_actors),
            # [F10] Cooldown re-open metadata — digunakan oleh bulk_insert_incidents_and_triage()
            # untuk memutuskan: UPDATE last_seen_at di tiket lama vs INSERT tiket baru
            "is_reopen": is_reopen,
            "parent_incident_id": parent_incident_id,
        }
        return incident


    def _check_historical_escalation(
        self,
        event: CommonEventModel,
        event_time: datetime,
        lookback_days: int = 7,
        failure_threshold: int = 3,
        in_session_incidents: Optional[List[Dict[str, Any]]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Two-Tier Historical Lookback: Query cumulative_alerts for prior authentication failure
        history from the same actor (source_ip) BEFORE this successful login event.

        Triggers a HISTORICAL_BRUTE_FORCE_ESCALATION incident if:
        - Event is a successful login (group: authentication_success / login_success)
        - DB manager is available (graceful skip if None or DB is offline)
        - cumulative_alerts has >= failure_threshold AUTH failures from same actor in last lookback_days
        - The last failure was BEFORE this current success event (not concurrent)
        - Actor has NOT already been covered by an in-session incident this cycle
          (prevents double-ticket when CORR-001 and historical lookback both trigger)

        Returns an incident dict or None.
        """
        # Only trigger on successful authentication events
        event_groups = [g.lower() for g in (event.classification_groups or [])]
        is_auth_success = (
            event.event_category in ("AUTH_SUCCESS", "AUTH_FAILURE", "AUTH", "AUTHENTICATION")
            and any(g in self._AUTH_SUCCESS_GROUPS for g in event_groups)
        )
        if not is_auth_success:
            return None

        # Skip if no DB connection (test mode / offline mode — graceful degradation)
        if self._db is None:
            return None

        actor = event.source_ip or event.username
        if not actor:
            return None

        # Anti-Double-Ticket Guard:
        # If this actor already received an in-session incident (e.g. CORR-001 Brute Force)
        # in this same process_event() cycle, skip historical escalation entirely.
        # One actor = one ticket per cycle. SOC queue stays noise-free.
        if in_session_incidents:
            actor_already_covered = any(
                inc.get("attacker_source_ip") == actor
                and not inc.get("rule_code", "").startswith("GENERIC_")
                and inc.get("rule_code") != "HISTORICAL_BRUTE_FORCE_ESCALATION"
                for inc in in_session_incidents
            )
            if actor_already_covered:
                return None

        target = event.agent_name or event.destination_host
        lookback_start = event_time.replace(tzinfo=None) - timedelta(days=lookback_days)

        try:
            with self._db.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT
                            cumulative_id,
                            actor,
                            total_event_count,
                            first_seen_at,
                            last_seen_at
                        FROM suppression.cumulative_alerts
                        WHERE
                            actor = %s
                            AND category IN ('AUTH', 'AUTHENTICATION')
                            AND last_seen_at >= %s
                            AND last_seen_at < %s
                            AND total_event_count >= %s
                        LIMIT 1;
                    """, (actor, lookback_start, event_time.replace(tzinfo=None), failure_threshold))
                    row = cur.fetchone()

            if not row:
                return None

            cum_id, hist_actor, hist_count, hist_first, hist_last = row
            days_tracked = (event_time.replace(tzinfo=None) - hist_first).days if hist_first else 0

            # Build escalation incident
            self.total_incidents_created += 1
            inc_hash = hashlib.md5(
                f"HISTORICAL_{actor}_{event_time.isoformat()}".encode()
            ).hexdigest()[:16]
            incident_id = f"INC-HIST-{inc_hash.upper()}"

            # Cross-reference: query prior related incidents for this actor / target
            related_ids = []
            try:
                with self._db.get_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("""
                            SELECT i.incident_id 
                            FROM correlation.correlated_incidents i
                            WHERE (i.attacker_source_ip = %s OR i.target_host = %s)
                              AND i.incident_id != %s
                            ORDER BY i.first_seen_at DESC
                            LIMIT 5;
                        """, (actor, target, incident_id))
                        related_ids = [r[0] for r in cur.fetchall()]
            except Exception:
                pass

            narrative = (
                f"Actor [{actor}] recorded {hist_count} authentication failures over {days_tracked} days "
                f"(first seen: {hist_first}, last failure: {hist_last}), "
                f"followed by successful login on [{target}] at {event_time.isoformat()}. "
                f"Cross-session persistence detected via cumulative_alerts profile [{cum_id}]."
            )
            if related_ids:
                narrative += f" Cross-reference: Linked to prior related incident(s): {', '.join(related_ids)}."

            return {
                "incident_id": incident_id,
                "correlation_rule_id": "CORR-HISTORICAL",
                "rule_code": "HISTORICAL_BRUTE_FORCE_ESCALATION",
                "tenant_id": "DEFAULT",
                "title": f"Historical Attacker Escalation: {actor} breached after {days_tracked}-day persistence",
                "narrative": narrative,
                "initial_access_vector": "NETWORK_EXPLOITATION",
                "attacker_source_ip": event.source_ip,
                "compromised_account": event.username,
                "target_host": target,
                "incident_status": "DETECTED",
                "first_seen_at": hist_first if hist_first else event_time,
                "last_seen_at": event_time,
                "target_severity": "P0",
                "stages": [
                    {
                        "incident_id": incident_id,
                        "sequence_order": 1,
                        "stage_name": "HISTORICAL_AUTH_FAILURES",
                        "reference_id": cum_id,
                        "evidence_type": "CUMULATIVE_PROFILE",
                        "stage_description": (
                            f"{hist_count} total failures from actor [{actor}] "
                            f"over {days_tracked} days (cumulative profile: {cum_id})"
                        )
                    },
                    {
                        "incident_id": incident_id,
                        "sequence_order": 2,
                        "stage_name": "SUCCESSFUL_BREACH",
                        "reference_id": event.event_id,
                        "evidence_type": "NORMALIZED_EVENT",
                        "stage_description": (
                            f"Successful login by [{actor}] on target [{target}] "
                            f"after {days_tracked}-day persistence campaign"
                        )
                    }
                ],
                "related_incident_ids": related_ids,
                "events_count": hist_count + 1,
                "distinct_targets_count": 1,
                "distinct_actors_count": 1,
            }

        except Exception:
            # Graceful degradation: if DB query fails for any reason (timeout, offline, etc.)
            # silently skip historical escalation — do NOT crash the main pipeline
            return None

    def export_state(self) -> Dict[str, Any]:
        """Export in-flight active correlation tracks for persistence across restarts."""
        serialized_tracks = {}
        for tid, t in self.active_tracks.items():
            serialized_tracks[tid] = {
                "rule_id": t.rule_id,
                "correlation_key": t.correlation_key,
                "start_time": t.start_time.isoformat(),
                "window_end": t.window_end.isoformat(),
                "last_event_time": t.last_event_time.isoformat(),
                "stages": {
                    s: [(eid, et.isoformat(), rid) for eid, et, rid in evts]
                    for s, evts in t.recorded_stages.items()
                }
            }
        return {
            "total_incidents_created": self.total_incidents_created,
            "active_tracks": serialized_tracks
        }

    def save_snapshot(self, filepath: Optional[str] = None) -> str:
        """Save active in-flight correlation state to JSON snapshot on disk."""
        if filepath is None:
            from config.settings import PERSISTENCE_DIR
            filepath = str(PERSISTENCE_DIR / "correlation_state_snapshot.json")
        data = self.export_state()
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return filepath

    def get_burst_count(self, actor: str, target: str) -> int:
        """Query cumulative burst window count from suppression.cumulative_alerts."""
        if self._db is None:
            return 1
        try:
            with self._db.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT COALESCE(MAX(total_burst_windows), 1)
                        FROM suppression.cumulative_alerts
                        WHERE actor = %s OR target = %s;
                    """, (actor, target))
                    row = cur.fetchone()
                    if row and row[0]:
                        return int(row[0])
        except Exception:
            pass
        return 1

    def get_open_ticket(
        self,
        actor: str,
        target: str,
        tenant_id: Optional[str] = None,
        priority: Optional[str] = None,
        reference_time: Optional[datetime] = None,
    ) -> Optional[str]:
        """Check if an open/in-progress ticket exists for exact (actor, target, tenant) within active SLA."""
        details = self.get_open_ticket_details(actor, target, tenant_id=tenant_id, reference_time=reference_time)
        return details[0] if details else None

    def get_open_ticket_details(
        self,
        actor: str,
        target: str,
        tenant_id: Optional[str] = None,
        lookback_hours: int = 24,
        reference_time: Optional[datetime] = None,
    ) -> Optional[Tuple[str, str]]:
        """
        Check if an active open ticket exists for the exact entity triple:
        (actor / attacker_source_ip + target / target_host + tenant_id)
        strictly while its SLA clock is still unexpired.
        Returns: (incident_id, current_priority) or None.
        """
        if self._db is None:
            return None
        try:
            with self._db.get_connection() as conn:
                with conn.cursor() as cur:
                    has_actor = bool(actor and actor not in ("unknown", "none", ""))
                    actor_clause = "i.attacker_source_ip = %s" if has_actor else "(i.attacker_source_ip IS NULL OR i.attacker_source_ip = 'unknown')"

                    ref_ts = reference_time or datetime.now(timezone.utc)
                    ref_naive = ref_ts.replace(tzinfo=None) if getattr(ref_ts, "tzinfo", None) else ref_ts

                    # Strictly match exact (attacker AND target AND tenant) within active unexpired SLA
                    query = f"""
                        SELECT q.incident_id, q.priority
                        FROM soc_ops.soc_triage_queue q
                        JOIN correlation.correlated_incidents i ON q.incident_id = i.incident_id
                        WHERE q.triage_status IN ('OPEN', 'INVESTIGATE', 'INVESTIGATING', 'NEW', 'HOLDING_P4')
                          AND {actor_clause}
                          AND i.target_host = %s
                          AND (i.tenant_id = %s OR %s IS NULL)
                          AND (
                            (q.priority = 'P0' AND (COALESCE(q.priority_changed_at, q.priority_established_at, q.created_at) + INTERVAL '15 minutes') > %s) OR
                            (q.priority = 'P1' AND (COALESCE(q.priority_changed_at, q.priority_established_at, q.created_at) + INTERVAL '60 minutes') > %s) OR
                            (q.priority = 'P2' AND (COALESCE(q.priority_changed_at, q.priority_established_at, q.created_at) + INTERVAL '4 hours') > %s) OR
                            (q.priority = 'P3' AND (COALESCE(q.priority_changed_at, q.priority_established_at, q.created_at) + INTERVAL '1 day') > %s) OR
                            (q.priority = 'P4' AND (COALESCE(q.priority_changed_at, q.priority_established_at, q.created_at) + INTERVAL '7 days') > %s)
                          )
                        ORDER BY q.created_at DESC LIMIT 1;
                    """
                    params = [actor] if has_actor else []
                    params.extend([target, tenant_id, tenant_id, ref_naive, ref_naive, ref_naive, ref_naive, ref_naive])
                    cur.execute(query, tuple(params))
                    row = cur.fetchone()
                    if row:
                        return (str(row[0]), str(row[1]))
        except Exception:
            pass
        return None

    def upgrade_ticket_in_place(
        self,
        incident_id: str,
        new_priority: str,
        justification: str = "Stateful attack progression escalation",
        escalated_at: Optional[datetime] = None,
    ) -> bool:
        """
        Upgrade an active open ticket in-place and RESET the SLA stopwatch:
        - priority is elevated (e.g. P4 -> P3 -> P2 -> P1 -> P0)
        - priority_established_at is set to escalated_at (arrival timestamp of elevating aggregate)
        - SLA clock starts strictly from the moment this priority level was established!
        - If ticket was in HOLDING_P4, it is moved to 'NEW' for immediate SOC triage.
        """
        if self._db is None:
            return False
        score_map = {"P0": 95, "P1": 75, "P2": 55, "P3": 35, "P4": 15}
        new_score = score_map.get(new_priority, 50)
        sla_mins = SLA_MATRIX_MINUTES.get(new_priority, 10080)
        new_deadline = ts_now + timedelta(minutes=sla_mins)
        try:
            with self._db.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        UPDATE soc_ops.soc_triage_queue
                        SET priority = %s,
                            priority_changed_at = %s,
                            priority_established_at = %s,
                            sla_deadline = %s,
                            triage_status = CASE WHEN triage_status = 'HOLDING_P4' THEN 'OPEN' ELSE triage_status END,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE incident_id = %s;
                    """, (new_priority, ts_now, ts_now, new_deadline, incident_id))
                    cur.execute("""
                        UPDATE risk_engine.calculated_risk_scores
                        SET total_score = %s, soc_priority = %s, calculated_at = CURRENT_TIMESTAMP
                        WHERE incident_id = %s;
                    """, (new_score, new_priority, incident_id))
                    cur.execute("""
                        UPDATE correlation.correlated_incidents
                        SET title = title || ' [ESCALATED TO ' || %s || ']',
                            narrative = narrative || ' ' || %s,
                            last_seen_at = %s,
                            target_severity = %s
                        WHERE incident_id = %s;
                    """, (new_priority, justification, ts_now, new_priority, incident_id))
                    return True
        except Exception:
            return False

    def evaluate_standalone_aggregate(
        self,
        aggregate: Dict[str, Any],
        reference_time: Optional[datetime] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Evaluates a standalone 15-minute aggregate object for ticketing adhering to PRD:
        - Determines priority (P0-P4) using PriorityEngine based on aggregate category/stages.
        - Checks if an active unexpired ticket exists for (tenant, actor, target).
        - If active ticket exists: Appends to it (action: APPENDED_TO_OPEN).
        - If no active ticket: Creates NEW ticket with category priority, SLA, and 24h historical stages.
        """
        actor = aggregate.get("source_ip") or aggregate.get("actor") or "unknown_actor"
        target = aggregate.get("target_host") or aggregate.get("target") or aggregate.get("agent_name") or f"agent-{aggregate.get('agent_id', '000')}"
        tenant_id = aggregate.get("tenant_id", "DEFAULT")
        agg_id = aggregate.get("aggregation_id", f"agg_{actor}_{target}")
        w_start = aggregate.get("window_start") or datetime.now(timezone.utc)
        w_end = aggregate.get("window_end") or datetime.now(timezone.utc)
        ref_time = reference_time or (self.parse_timestamp(w_end) if isinstance(w_end, str) else w_end)

        # 1. Determine priority and SLA based on category mapping
        prio, reason, sla_mins = self._risk_scorer.determine_priority(aggregate)
        event_count = aggregate.get("event_count", 1)

        # 2. Check if an active open ticket exists for this exact entity triple within active SLA
        open_details = self.get_open_ticket_details(actor, target, tenant_id=tenant_id, reference_time=ref_time)
        if open_details:
            open_ticket_id, current_prio = open_details
            new_p = self._append_to_existing_ticket(open_ticket_id, aggregate, reference_time=ref_time)
            if new_p and PRIORITY_RANK.get(new_p, 0) > PRIORITY_RANK.get(current_prio, 0):
                return {
                    "action": "UPGRADED_OPEN_TICKET",
                    "incident_id": open_ticket_id,
                    "previous_priority": current_prio,
                    "new_priority": new_p,
                    "reason": f"Escalated from {current_prio} to {new_p} within active SLA."
                }
            return {
                "action": "APPENDED_TO_OPEN",
                "incident_id": open_ticket_id,
                "current_priority": new_p or current_prio,
                "reason": "Appended to existing open ticket within active SLA."
            }

        inc_hash = hashlib.md5(f"{prio}_{agg_id}_{actor}_{target}".encode()).hexdigest()[:16]
        incident_id = f"INC-{prio}-{inc_hash.upper()}"
        triage_id = f"TRG-{prio}-{inc_hash.upper()}"

        title = f"[{prio}] {aggregate.get('ioa_summary') or aggregate.get('rule_description') or 'Security Event'} on {target} by {actor}"
        narrative = (
            f"Consolidated security activity on [{target}] from [{actor}] ({event_count} events). "
            f"Assigned {prio} based on category: {reason}."
        )

        stages, earliest_seen = self._build_incident_stages_with_24h_lookback(
            incident_id=incident_id, current_agg=aggregate, reference_time=ref_time
        )

        # Determine priority across Induk and 24h correlated child stages
        prio, reason, sla_mins = self._risk_scorer.determine_priority({"stages": stages})

        # Build ticket_aggregates tracking (1 Induk + 24h correlated children)
        curr_agg_id = str(aggregate.get("aggregation_id") or "")
        ticket_aggs = []
        for stg in stages:
            if stg.get("evidence_type") == "AGGREGATED_ALERT":
                ref_id = str(stg.get("reference_id") or "")
                is_induk = (ref_id == curr_agg_id)
                ticket_aggs.append({
                    "aggregation_id": ref_id,
                    "is_induk": is_induk,
                    "is_escalation_trigger": False,
                    "added_at": ref_time
                })

        return {
            "action": "CREATED_NEW_TICKET",
            "incident_id": incident_id,
            "triage_id": triage_id,
            "correlation_rule_id": "CORR-ENTITY",
            "title": title,
            "narrative": narrative,
            "attacker_source_ip": actor,
            "target_host": target,
            "target_severity": prio,
            "priority": prio,
            "first_seen_at": earliest_seen or w_start,
            "first_detected_at": earliest_seen or w_start or ref_time,
            "last_seen_at": w_end,
            "priority_established_at": ref_time,
            "priority_changed_at": ref_time,
            "sla_minutes": sla_mins,
            "sla_deadline": (ref_time + timedelta(minutes=sla_mins)) if isinstance(ref_time, datetime) else None,
            "related_incident_ids": [],
            "burst_count": 1,
            "stages": stages,
            "ticket_aggregates": ticket_aggs,
        }

    # =========================================================================
    # [GAP 1 FIX] — process_aggregate(): Main entry point for ACTIONABLE aggregates
    # =========================================================================

    def process_aggregate(
        self,
        agg: Dict[str, Any],
        reference_time: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """
        [GAP 1 FIX] Process a single ACTIONABLE aggregate through the full
        correlation engine. Called for EVERY ACTIONABLE aggregate after suppression,
        not just FAST_TRACK events. This fixes the broken normalization → aggregation
        → correlation pipeline chain.

        Execution order:
          1. Behavioral rule matching on aggregate tracks (_agg_tracks)
          2. Rule precedence dedup filter (suppress generic if specific fired)
          3. Entity-based stateful aggregate evaluation
          4. Ticket deduplication guard (entity triple check)
        """
        w_start = agg.get("window_start")
        if isinstance(w_start, str):
            event_time = self.parse_timestamp(w_start)
        elif isinstance(w_start, datetime):
            event_time = w_start
        else:
            event_time = reference_time or datetime.now(timezone.utc)

        adapter = _AggregateAdapter(agg)
        newly_completed: List[Dict[str, Any]] = []

        # ── Step 1: Behavioral rule matching ──────────────────────────────────
        for rule_cfg in self.rules:
            corr_key = self._extract_correlation_key(adapter, rule_cfg["match_keys"])
            track_id = f"AGG_{rule_cfg['id']}_{corr_key}"

            track = self._agg_tracks.get(track_id)
            if track is not None:
                if track.is_expired(event_time):
                    del self._agg_tracks[track_id]
                else:
                    track.add_candidate_event(adapter, event_time)
                    if track.is_completed and not getattr(track, "_emitted", False):
                        inc = self._build_incident(track)
                        inc["max_inline_risk_score"] = agg.get("max_inline_risk_score", 0)
                        newly_completed.append(inc)
                        track._emitted = True
                        if track_id in self._agg_tracks:
                            del self._agg_tracks[track_id]

            if track_id not in self._agg_tracks:
                first_stage = rule_cfg["trigger_stages"][0]
                if event_matches_stage(adapter, first_stage):
                    new_track = CorrelationTrack(rule_cfg, corr_key, event_time)
                    new_track.add_candidate_event(adapter, event_time)
                    self._agg_tracks[track_id] = new_track
                    if new_track.is_completed and not getattr(new_track, "_emitted", False):
                        inc = self._build_incident(new_track)
                        inc["max_inline_risk_score"] = agg.get("max_inline_risk_score", 0)
                        newly_completed.append(inc)
                        new_track._emitted = True
                        if track_id in self._agg_tracks:
                            del self._agg_tracks[track_id]

        # Lazy cleanup of expired aggregate tracks every 5 000 events
        self._event_counter = getattr(self, "_event_counter", 0) + 1
        if self._event_counter % 5000 == 0:
            expired = [
                tid for tid, trk in self._agg_tracks.items()
                if trk.is_expired(event_time)
            ]
            for tid in expired:
                del self._agg_tracks[tid]

        # ── Step 2: Rule precedence filter ────────────────────────────────────
        specific_hosts = {
            inc.get("target_host")
            for inc in newly_completed
            if not inc.get("rule_code", "").startswith("GENERIC_")
            and inc.get("target_host")
        }
        if specific_hosts:
            newly_completed = [
                inc for inc in newly_completed
                if not (
                    inc.get("rule_code", "").startswith("GENERIC_")
                    and inc.get("target_host") in specific_hosts
                )
            ]

        # ── Step 3: Entity-based stateful evaluation ──────────────────────────
        if not newly_completed:
            standalone = self.evaluate_standalone_aggregate(agg, reference_time=event_time)
            if standalone and standalone.get("action") == "CREATED_NEW_TICKET":
                inc = self._standalone_to_incident(standalone, agg)
                inc["_ticket_action"] = "CREATE_NEW"
                newly_completed.append(inc)

        # ── Step 5: Ticket deduplication guard (entity triple check) ──────────
        final_incidents: List[Dict[str, Any]] = []
        for inc in newly_completed:
            if inc.get("_ticket_action"):
                final_incidents.append(inc)
                continue

            actor_val = (
                inc.get("attacker_source_ip")
                or agg.get("actor")
                or agg.get("source_ip")
                or "unknown"
            )
            target_val = inc.get("target_host") or agg.get("target") or "unknown"

            action, existing_id = self._ticket_guard.check(
                actor=actor_val,
                target=target_val,
                rule_id=agg.get("rule_id"),
                tenant_id=agg.get("tenant_id") or inc.get("tenant_id") or "DEFAULT",
                reference_time=event_time,
            )

            if action == "APPEND" and existing_id:
                # Tiket masih OPEN dengan SLA aktif -> append stage, upgrade in-place jika prioritas naik
                self._append_to_existing_ticket(existing_id, agg, reference_time=event_time)
                inc["_ticket_action"] = "APPEND"
                inc["_existing_ticket_id"] = existing_id
                inc["is_reopen"] = True
                inc["parent_incident_id"] = existing_id
            else:
                inc["_ticket_action"] = "CREATE_NEW"

            final_incidents.append(inc)

        return final_incidents

    def _build_incident_stages_with_24h_lookback(
        self,
        incident_id: str,
        current_agg: Dict[str, Any],
        reference_time: Optional[datetime] = None,
    ) -> Tuple[List[Dict[str, Any]], Optional[datetime]]:
        """
        [Stateful 24-Hour Attack Chain Correlation]
        Gathers all historical aggregates for (tenant, actor, target) from
        suppression.aggregated_alerts within the rolling 24-hour lookback window,
        and appends current_agg as the culminating stage.
        If 10 prior aggregates exist -> produces 11 sequential forensic stages.
        If 11 prior aggregates exist -> produces 12 sequential forensic stages.
        Returns (stages: List[Dict], earliest_start_time: Optional[datetime]).
        """
        stages: List[Dict[str, Any]] = []
        actor = current_agg.get("source_ip") or current_agg.get("actor") or "unknown"
        target = current_agg.get("target_host") or current_agg.get("target") or "unknown"
        tenant_id = current_agg.get("tenant_id", "DEFAULT")
        curr_agg_id = str(current_agg.get("aggregation_id") or "")
        curr_rule_id = current_agg.get("rule_id", "unknown")
        curr_desc = (
            current_agg.get("rule_description")
            or current_agg.get("ioa_summary")
            or f"Aggregate alert (Rule {curr_rule_id})"
        )
        curr_count = current_agg.get("event_count", 1)

        ref_dt = reference_time or current_agg.get("window_end") or datetime.now(timezone.utc)
        if isinstance(ref_dt, str):
            ref_dt = self.parse_timestamp(ref_dt)
        ref_naive = ref_dt.replace(tzinfo=None) if getattr(ref_dt, "tzinfo", None) else ref_dt
        lookback_start = ref_naive - timedelta(hours=24)
        earliest_seen: Optional[datetime] = None

        if self._db is not None and actor != "unknown" and target != "unknown":
            try:
                with self._db.get_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            SELECT aggregation_id, rule_id, rule_description, category,
                                   event_count, window_start, window_end, ioa_summary
                            FROM suppression.aggregated_alerts
                            WHERE tenant_id = %s
                              AND (actor = %s OR source_ip = %s)
                              AND (target = %s OR destination_ip = %s)
                              AND window_end >= %s
                              AND window_end <= %s
                              AND aggregation_id != %s
                            ORDER BY window_start ASC;
                            """,
                            (
                                tenant_id, actor, actor, target, target,
                                lookback_start, ref_naive, curr_agg_id
                            ),
                        )
                        rows = cur.fetchall()
                        for seq, (agg_id, rid, rdesc, cat, cnt, w_start, w_end, ioa) in enumerate(rows, 1):
                            if earliest_seen is None:
                                earliest_seen = w_start
                            summary = rdesc or ioa or f"Alert cluster (Rule {rid})"
                            stages.append({
                                "incident_id": incident_id,
                                "sequence_order": seq,
                                "stage_name": cat or "ATTACK_STEP",
                                "reference_id": str(agg_id),
                                "evidence_type": "AGGREGATED_ALERT",
                                "stage_description": (
                                    f"Rule {rid}: {summary} ({cnt} events) at {w_start}"
                                ),
                            })
            except Exception:
                pass  # Graceful fallback if DB fails or offline

        # Append the current aggregate as the latest stage
        next_seq = len(stages) + 1
        curr_cat = current_agg.get("category", "ATTACK_STEP")
        stages.append({
            "incident_id": incident_id,
            "sequence_order": next_seq,
            "stage_name": curr_cat,
            "reference_id": curr_agg_id or f"agg_latest_{next_seq}",
            "evidence_type": "AGGREGATED_ALERT",
            "stage_description": (
                f"Rule {curr_rule_id}: {curr_desc} ({curr_count} events) at {ref_naive}"
            ),
        })
        if earliest_seen is None:
            earliest_seen = current_agg.get("window_start")
        return stages, earliest_seen

    def _standalone_to_incident(
        self,
        standalone: Dict[str, Any],
        agg: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Convert evaluate_standalone_aggregate() result into a full incident dict with 24h lookback stages."""
        incident_id = standalone.get("incident_id")
        p_val = standalone.get("priority", "P4")
        ref_dt = standalone.get("priority_established_at") or agg.get("window_end") or agg.get("window_start")
        if isinstance(ref_dt, str):
            ref_dt = self.parse_timestamp(ref_dt)

        stages = standalone.get("stages")
        earliest_seen = standalone.get("first_seen_at")
        if not stages:
            stages, earliest_seen = self._build_incident_stages_with_24h_lookback(
                incident_id=incident_id,
                current_agg=agg,
                reference_time=ref_dt
            )

        return {
            "incident_id": incident_id,
            "correlation_rule_id": standalone.get("correlation_rule_id", "CORR-ENTITY"),
            "rule_code": standalone.get("rule_code", "STANDALONE_AGGREGATE"),
            "tenant_id": agg.get("tenant_id", "DEFAULT"),
            "title": standalone.get("title", f"[{p_val}] {agg.get('ioa_summary', 'Security Alert')} on {agg.get('target', 'unknown')}"),
            "narrative": standalone.get("narrative", f"Stateful incident. Assigned {p_val}."),
            "initial_access_vector": (
                "NETWORK_EXPLOITATION"
                if (agg.get("source_ip") or agg.get("actor"))
                else "LOCAL_ACCESS"
            ),
            "attacker_source_ip": agg.get("source_ip") or agg.get("actor"),
            "compromised_account": agg.get("username"),
            "target_host": standalone.get("target_host") or agg.get("target"),
            "incident_status": "DETECTED",
            "first_seen_at": earliest_seen or agg.get("window_start"),
            "first_detected_at": earliest_seen or agg.get("window_start") or ref_dt,
            "last_seen_at": agg.get("window_end"),
            "target_severity": p_val,
            "priority": p_val,
            "priority_established_at": ref_dt,
            "priority_changed_at": ref_dt,
            "sla_minutes": standalone.get("sla_minutes", 10080),
            "sla_deadline": (ref_dt + timedelta(minutes=standalone.get("sla_minutes", 10080))) if isinstance(ref_dt, datetime) else None,
            "stages": stages,
            "related_incident_ids": standalone.get("related_incident_ids", []),
            "events_count": agg.get("event_count", 1),
            "distinct_targets_count": 1,
            "distinct_actors_count": 1,
            "is_reopen": False,
            "parent_incident_id": None,
            "max_inline_risk_score": agg.get("max_inline_risk_score", 0),
            "dominant_http_status": agg.get("dominant_http_status"),
            "is_scanner_ua": agg.get("is_scanner_ua", False),
            "triage_status": standalone.get("triage_status", "NEW"),
            "ticket_aggregates": standalone.get("ticket_aggregates", []),
            "triage_id": standalone.get("triage_id"),
        }

    def _append_to_existing_ticket(
        self,
        incident_id: str,
        agg: Dict[str, Any],
        reference_time: Optional[datetime] = None,
    ) -> Optional[str]:
        """
        Append new aggregate window as a forensic stage to an existing ticket,
        update last_seen_at, increment event_count, re-evaluate stateful priority,
        and if priority elevates, UPGRADE IN-PLACE and RESET SLA STOPWATCH!
        """
        if self._db is None:
            return None
        try:
            w_start = agg.get("window_start")
            w_end = agg.get("window_end")
            ev_count = agg.get("event_count", 1)
            agg_id = agg.get("aggregation_id", "unknown")
            category = self._risk_scorer._normalize_category(agg.get("category", "BURST_WINDOW"))
            desc = agg.get("ioa_summary") or agg.get("rule_description") or f"Burst window: {ev_count} events"

            if reference_time:
                last_seen = reference_time
            elif isinstance(w_end, str):
                last_seen = self.parse_timestamp(w_end)
            elif isinstance(w_end, datetime):
                last_seen = w_end
            else:
                last_seen = datetime.now(timezone.utc)
            last_naive = (
                last_seen.replace(tzinfo=None)
                if getattr(last_seen, "tzinfo", None)
                else last_seen
            )

            with self._db.get_connection() as conn:
                with conn.cursor() as cur:
                    # 1. Update correlated_incidents last_seen_at & events_count
                    cur.execute(
                        """
                        UPDATE correlation.correlated_incidents
                        SET last_seen_at = GREATEST(last_seen_at, %s),
                            events_count = COALESCE(events_count, 1) + %s
                        WHERE incident_id = %s;
                        """,
                        (last_naive, ev_count, incident_id),
                    )
                    # 2. Append new stage into incident_stages
                    cur.execute(
                        """
                        SELECT COALESCE(MAX(sequence_order), 0) + 1
                        FROM correlation.incident_stages
                        WHERE incident_id = %s;
                        """,
                        (incident_id,),
                    )
                    next_seq = (cur.fetchone() or [1])[0]

                    cur.execute(
                        """
                        INSERT INTO correlation.incident_stages
                            (incident_id, sequence_order, stage_name, reference_id, evidence_type, stage_description)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        ON CONFLICT (incident_id, sequence_order) DO NOTHING;
                        """,
                        (
                            incident_id,
                            next_seq,
                            category,
                            agg_id,
                            "AGGREGATED_ALERT",
                            f"Rule {agg.get('rule_id', 'unknown')}: {desc}",
                        ),
                    )

                    # 3. Fetch all stages and re-evaluate stateful priority
                    cur.execute(
                        """
                        SELECT stage_name
                        FROM correlation.incident_stages
                        WHERE incident_id = %s
                        ORDER BY sequence_order ASC;
                        """,
                        (incident_id,)
                    )
                    all_stage_names = [r[0] for r in cur.fetchall()]

                    cur.execute(
                        """
                        SELECT priority
                        FROM soc_ops.soc_triage_queue
                        WHERE incident_id = %s;
                        """,
                        (incident_id,)
                    )
                    row_p = cur.fetchone()
                    curr_priority = str(row_p[0]).upper() if row_p and row_p[0] else "P4"

                    new_p, justification, new_sla = self._risk_scorer.determine_stateful_priority(
                        {"stages": [{"stage_name": s} for s in all_stage_names]}
                    )

                    is_escalation = PRIORITY_RANK.get(new_p, 0) > PRIORITY_RANK.get(curr_priority, 0)
                    if is_escalation:
                        # IN-PLACE ELEVATION: Reset SLA stopwatch to the arrival timestamp of this elevating aggregate!
                        self.upgrade_ticket_in_place(
                            incident_id=incident_id,
                            new_priority=new_p,
                            justification=f"In-place escalation ({curr_priority} -> {new_p}): {justification}",
                            escalated_at=last_seen
                        )

                    # Track appended aggregate in soc_ops.ticket_aggregates
                    cur.execute("""
                        SELECT triage_id FROM soc_ops.soc_triage_queue WHERE incident_id = %s;
                    """, (incident_id,))
                    row_trg = cur.fetchone()
                    triage_id_for_agg = row_trg[0] if row_trg else incident_id

                    cur.execute("""
                        INSERT INTO soc_ops.ticket_aggregates
                            (ticket_id, aggregation_id, is_induk, is_escalation_trigger, added_at)
                        VALUES (%s, %s, FALSE, %s, %s)
                        ON CONFLICT (ticket_id, aggregation_id) DO NOTHING;
                    """, (
                        triage_id_for_agg,
                        agg_id,
                        is_escalation,
                        last_naive
                    ))

                    if is_escalation:
                        return new_p
                    return curr_priority

        except Exception:
            return None
