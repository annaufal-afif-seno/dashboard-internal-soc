"""
Stage 2 & 7: Suppression Rule SLA Governance, Expiration Auditor & KPI Engine
Enforces Separation of Duties, Lifecycle Tracking (S1-S5), Suppression Escape Auditing,
Baseline Drift Sigma (Z-Score) Calculation, and Daily Operational Metrics Aggregation
"""
import os
import json
import math
from typing import Dict, Any, List, Optional, Tuple, Set
from datetime import datetime, date, timezone, timedelta
from decimal import Decimal

from pipeline.models import (
    SuppressionRuleDB,
    SuppressionAuditLogDB,
    OperationalMetricsDailyDB,
    IocIndicator,
    IoaPattern,
    NeverSuppressGuard
)
from config.settings import BASE_DIR


class SuppressionGovernanceManager:
    """
    Manages the lifecycle of governable suppression rules with GRC compliance.
    Enforces the Golden Rule: 'No suppression without an owner and expiration date.'
    Enforces Separation of Duties: 'author != approver'.
    """

    def __init__(self):
        self.rules: Dict[str, SuppressionRuleDB] = {}
        self.audit_logs: List[SuppressionAuditLogDB] = []
        self._load_default_seed_rules()

    def _load_default_seed_rules(self):
        """Initialize with baseline seed suppression rules and JSON registry."""
        registry_path = BASE_DIR / "config" / "suppression_rules_registry.json"
        loaded_from_json = False
        if os.path.exists(registry_path):
            try:
                with open(registry_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                policies = data.get("suppression_policies", [])
                class_map = {
                    # Kelas baru sesuai arsitektur: Suppression = keputusan kebijakan pada agregat
                    "KNOWN_GOOD":            "S1_KNOWN_GOOD",
                    "EXPECTED_ADMIN_ACTIVITY": "S1_KNOWN_GOOD",
                    "LOW_VALUE":             "S1_KNOWN_GOOD",
                    # S2_DEDUPLICATION dihapus — dedup sudah dilakukan oleh aggregation stage
                    "DEDUPLICATION":         "S1_KNOWN_GOOD",   # remap: dedup = known-good sumber
                    # S3_AGGREGATION dihapus — aggregation sudah jadi stage terpisah
                    "AGGREGATION":           "S1_KNOWN_GOOD",   # remap: noise = known-good sumber
                    # Kelas policy yang benar
                    "FALSE_POSITIVE":        "S2_FALSE_POSITIVE",
                    "MAINTENANCE":           "S3_MAINTENANCE",
                    "EXCEPTION":             "S4_EXCEPTION",
                    "TEMPORARY_EXCEPTION":   "S5_CONDITIONAL",
                    "CONDITIONAL":           "S5_CONDITIONAL",
                }
                for p in policies:
                    sup_id = p.get("id")
                    target_rules = [int(r) for r in p.get("target_rules", []) if str(r).isdigit()]
                    cat = p.get("category", "KNOWN_GOOD")
                    sup_class = class_map.get(cat, "S1_KNOWN_GOOD")
                    c_date = date.fromisoformat(p.get("created", "2026-07-01"))
                    e_date = date.fromisoformat(p.get("expires", "2027-03-31"))
                    rule = SuppressionRuleDB(
                        suppression_id=sup_id,
                        rule_name=p.get("reason", f"Suppression Rule {sup_id}")[:128],
                        suppression_class=sup_class,
                        target_rule_ids=target_rules,
                        author=p.get("owner", "sec_eng_auto"),
                        approver=p.get("approver", "soc_lead_auto"),
                        ticket_id=f"CRQ-{sup_id}",
                        business_reason=p.get("reason", ""),
                        scope_definition=p.get("conditions", {}),
                        status=p.get("status", "ACTIVE"),
                        created_date=c_date,
                        expires_date=e_date,
                        review_cycle="MONTHLY",
                        drift_baseline_count=p.get("historical_volume", 1000),
                        current_drift_sigma=Decimal("0.00")
                    )
                    self.rules[sup_id] = rule
                    self.audit_logs.append(SuppressionAuditLogDB(
                        suppression_id=sup_id,
                        action="CREATED",
                        performed_by=rule.author,
                        notes=f"Auto-loaded from registry: {rule.business_reason[:80]}"
                    ))
                if self.rules:
                    loaded_from_json = True
            except Exception as e:
                import logging
                logging.getLogger(__name__).error(
                    f"[GOVERNANCE] Failed to load suppression_rules_registry.json: {e}. "
                    f"Falling back to baseline seed rules."
                )

        if not loaded_from_json:
            seed_rules = [
                SuppressionRuleDB(
                    suppression_id="SUP-2026-001",
                    rule_name="Nessus Primary Vulnerability Scanner",
                    suppression_class="S1_KNOWN_GOOD",
                    target_rule_ids=[5710, 31101, 100300],
                    author="sec_eng_john",
                    approver="soc_lead_alice",
                    ticket_id="CRQ-2026-9001",
                    business_reason="Approved monthly internal and external vulnerability scanning",
                    scope_definition={"source_ips": ["10.10.50.20", "10.10.50.21"]},
                    status="ACTIVE",
                    created_date=date(2026, 7, 1),
                    expires_date=date(2026, 12, 31),
                    review_cycle="MONTHLY",
                    drift_baseline_count=5000,
                    current_drift_sigma=Decimal("0.00")
                ),
                SuppressionRuleDB(
                    suppression_id="SUP-2026-002",
                    rule_name="Routine Non-Critical AppArmor Noise",
                    suppression_class="S1_KNOWN_GOOD",
                    target_rule_ids=[52002],
                    author="sec_eng_john",
                    approver="soc_lead_alice",
                    ticket_id="CRQ-2026-9002",
                    business_reason="Filter routine getattr/open benign AppArmor denials on container workloads",
                    scope_definition={"operations": ["getattr", "open"]},
                    status="ACTIVE",
                    created_date=date(2026, 7, 1),
                    expires_date=date(2026, 10, 1),
                    review_cycle="MONTHLY",
                    drift_baseline_count=450000,
                    current_drift_sigma=Decimal("0.00")
                ),
                SuppressionRuleDB(
                    suppression_id="SUP-2026-003",
                    rule_name="Web Server 400 Bot Burst — Known-Good Internet Noise",
                    suppression_class="S1_KNOWN_GOOD",
                    target_rule_ids=[31101, 31533],
                    author="sec_eng_john",
                    approver="soc_lead_alice",
                    ticket_id="CRQ-2026-9003",
                    business_reason="Collapse high frequency 400 errors from internet scanners into single summary object",
                    scope_definition={"window_minutes": 15},
                    status="ACTIVE",
                    created_date=date(2026, 7, 1),
                    expires_date=date(2027, 1, 1),
                    review_cycle="QUARTERLY",
                    drift_baseline_count=260000,
                    current_drift_sigma=Decimal("0.00")
                )
            ]
            for r in seed_rules:
                self.rules[r.suppression_id] = r
                self.audit_logs.append(SuppressionAuditLogDB(
                    suppression_id=r.suppression_id,
                    action="CREATED",
                    performed_by=r.author,
                    notes=f"Initial rule creation approved by {r.approver}"
                ))

    def register_rule(self, rule: SuppressionRuleDB):
        """Directly register or update an active suppression rule in-memory."""
        self.rules[rule.suppression_id] = rule

    def reload_from_registry(self, registry_path: Optional[str] = None):
        """Reload all suppression policies dynamically from suppression_rules_registry.json without restarting the pipeline."""
        self._load_default_seed_rules()


    def create_rule(
        self,
        suppression_id: str,
        rule_name: str,
        suppression_class: str,
        target_rule_ids: List[int],
        author: str,
        approver: str,
        ticket_id: str,
        business_reason: str,
        scope_definition: Dict[str, Any],
        expires_date: date,
        review_cycle: str = "MONTHLY",
        drift_baseline_count: int = 0,
        enforcement_mode: str = "PIPELINE_MUTE"
    ) -> SuppressionRuleDB:
        """Create a new governable suppression rule with Separation of Duties check."""
        if author == approver:
            raise ValueError(f"Separation of Duties violation: Author '{author}' cannot self-approve suppression rule.")

        if expires_date <= date.today() - timedelta(days=1):
            raise ValueError(f"Expiration date {expires_date} cannot be in the past.")

        # Expiration SLA per class:
        # S1_KNOWN_GOOD     → 180 hari (scanner, known tools — stabil)
        # S2_FALSE_POSITIVE → 90 hari  (FP wajib di-review tiap kuartal)
        # S3_MAINTENANCE    → 90 hari  (maintenance window sementara)
        # S4_EXCEPTION      → 30 hari  (exception bisnis — harus sangat singkat)
        # S5_CONDITIONAL    → 90 hari  (conditional — wajib ditinjau rutin)
        if suppression_class == "S1_KNOWN_GOOD":
            max_validity_days = 180
        elif suppression_class == "S4_EXCEPTION":
            max_validity_days = 30
        else:
            max_validity_days = 90
        if (expires_date - date.today()).days > max_validity_days:
            raise ValueError(
                f"Suppression SLA violation: Expiration duration cannot exceed {max_validity_days} days "
                f"for class '{suppression_class}'."
            )

        new_rule = SuppressionRuleDB(
            suppression_id=suppression_id,
            rule_name=rule_name,
            suppression_class=suppression_class,
            target_rule_ids=target_rule_ids,
            author=author,
            approver=approver,
            ticket_id=ticket_id,
            business_reason=business_reason,
            scope_definition=scope_definition,
            status="ACTIVE",
            enforcement_mode=enforcement_mode,
            created_date=date.today(),
            expires_date=expires_date,
            review_cycle=review_cycle,
            drift_baseline_count=drift_baseline_count,
            current_drift_sigma=Decimal("0.00")
        )

        self.rules[suppression_id] = new_rule
        self.audit_logs.append(SuppressionAuditLogDB(
            suppression_id=suppression_id,
            action="CREATED",
            performed_by=author,
            notes=f"Created with ticket {ticket_id}, approved by {approver}"
        ))
        return new_rule

    def calculate_drift_sigma(self, rule_id: str, current_count: int, std_dev: Optional[float] = None) -> Decimal:
        """
        Calculate the baseline drift sigma Z-score:
        Sigma = (Current_Count - Baseline_Count) / Standard_Deviation
        """
        rule = self.rules.get(rule_id)
        if not rule or rule.drift_baseline_count == 0:
            return Decimal("0.00")

        baseline = rule.drift_baseline_count
        if std_dev is None or std_dev <= 0:
            std_dev = math.sqrt(baseline) if baseline > 0 else 1.0

        z_score = (current_count - baseline) / std_dev
        sigma = Decimal(f"{round(z_score, 2):.2f}")
        rule.current_drift_sigma = sigma

        if abs(sigma) >= Decimal("3.00"):
            self.audit_logs.append(SuppressionAuditLogDB(
                suppression_id=rule_id,
                action="REVIEWED",
                performed_by="DRIFT_MONITOR",
                notes=f"Significant volume drift detected: Sigma = {sigma} (Current: {current_count:,}, Baseline: {baseline:,})"
            ))
        return sigma

    def audit_expirations(self, current_date: Optional[date] = None) -> List[str]:
        """
        Audit all active rules for expiration. Automatically transitions expired rules to 'EXPIRED'.
        Returns list of newly expired suppression rule IDs.
        """
        if current_date is None:
            current_date = date.today()

        expired_ids = []
        for r_id, rule in self.rules.items():
            if rule.status in ("ACTIVE", "PENDING_WAZUH_DEPLOY") and rule.expires_date < current_date:
                rule.status = "EXPIRED"
                expired_ids.append(r_id)
                self.audit_logs.append(SuppressionAuditLogDB(
                    suppression_id=r_id,
                    action="EXPIRED",
                    performed_by="SYSTEM_AUDITOR",
                    notes=f"Rule expired on {rule.expires_date} (Audited on {current_date})"
                ))
        return expired_ids

    def check_suppression_escape(
        self,
        suppressed_entities: Set[str],
        confirmed_incidents: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Detect if any entity (IP/Host/User) covered by an active suppression rule
        was involved in a confirmed P0/P1 security incident.
        """
        escapes = []
        for inc in confirmed_incidents:
            src_ip = inc.get("attacker_source_ip")
            target_host = inc.get("target_host")
            user = inc.get("compromised_account")
            priority = inc.get("target_severity", "")

            if priority in ["P0", "P1"]:
                matched_entities = []
                if src_ip and src_ip in suppressed_entities:
                    matched_entities.append(f"Source IP: {src_ip}")
                if target_host and target_host in suppressed_entities:
                    matched_entities.append(f"Target Host: {target_host}")
                if user and user in suppressed_entities:
                    matched_entities.append(f"User: {user}")

                if matched_entities:
                    escapes.append({
                        "incident_id": inc.get("incident_id"),
                        "incident_title": inc.get("title"),
                        "priority": priority,
                        "matched_entities": matched_entities,
                        "detected_at": inc.get("last_seen_at")
                    })
        return escapes

    def generate_daily_metrics(
        self,
        metric_date: date,
        raw_count: int,
        wazuh_alerts_count: int,
        suppressed_count: int,
        aggregated_count: int,
        correlated_count: int,
        analyst_reviewed_count: int,
        true_positives_count: int,
        suppression_escapes_count: int = 0,
        avg_mttt_sec: float = 320.0
    ) -> OperationalMetricsDailyDB:
        """Calculate and return daily operational rollup metrics."""
        actionable_count = true_positives_count
        reduction_pct = Decimal("0.00")
        if raw_count > 0:
            reduction_num = Decimal(str(raw_count - (aggregated_count + correlated_count)))
            reduction_pct = round((reduction_num / Decimal(str(raw_count))) * Decimal("100.0"), 2)

        return OperationalMetricsDailyDB(
            metric_date=metric_date,
            raw_events_count=raw_count,
            wazuh_alerts_count=wazuh_alerts_count,
            suppressed_events_count=suppressed_count,
            aggregated_alerts_count=aggregated_count,
            correlated_incidents_count=correlated_count,
            analyst_reviewed_count=analyst_reviewed_count,
            true_positives_count=true_positives_count,
            actionable_incidents_count=actionable_count,
            suppression_escapes_count=suppression_escapes_count,
            avg_mean_time_to_triage_sec=avg_mttt_sec,
            alert_reduction_percentage=reduction_pct
        )

    def evaluate_event_suppression(self, event: Any) -> Optional[SuppressionRuleDB]:
        """
        Evaluate if an individual event matches an active suppression rule via:
        1. Specific target rule ID
        2. Universal Category archetype & scope (source IP, paths, profiles, maintenance)
        """
        rule_id_int = int(event.rule_id) if str(event.rule_id).isdigit() else 0
        cat = getattr(event, "event_category", "")
        actor = getattr(event, "dedup_actor", "") or getattr(event, "source_ip", "") or ""
        target = getattr(event, "dedup_target", "") or getattr(event, "destination_host", "") or ""
        payload = (getattr(event, "raw_payload", "") or "").lower()

        for r_id, rule in self.rules.items():
            if rule.status not in ("ACTIVE", "PENDING_WAZUH_DEPLOY"):
                continue
            if rule.expires_date < date.today():
                continue

            # 1. Target rule ID match
            id_matched = (rule_id_int in rule.target_rule_ids) if rule.target_rule_ids else False

            # 2. Archetype / Universal Category match (Scales to 4500 rules)
            cat_matched = False
            scope = rule.scope_definition or {}
            if "categories" in scope and cat in scope["categories"]:
                cat_matched = True

            if not (id_matched or cat_matched):
                continue

            # Check scope conditions
            if "source_ip" in scope and scope["source_ip"] != actor:
                continue
            if "source_ips" in scope and actor not in scope["source_ips"]:
                continue
            if "operations" in scope and not any(op in payload for op in scope["operations"]):
                continue
            if "paths" in scope and not any(p in payload for p in scope["paths"]):
                continue

            return rule

        return None

    def evaluate_aggregate_suppression(self, agg_alert: Dict[str, Any]) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        [Stage 3: Post-Aggregation Threshold & Policy Filter — Enhanced with IOC/IOA Matching]
        Evaluates a completed windowed aggregate object against ALL active suppression rules.
        Returns: (is_suppressed: bool, suppression_id: Optional[str], reason: Optional[str])

        Enhancement v2: Adds IOC indicator matching (hash, domain, C2), IOA pattern matching
        (command_line, process_path, registry_key), and never-suppress blacklist override.
        """
        rule_id = agg_alert.get("rule_id", 0)
        category = agg_alert.get("category", "")
        event_count = agg_alert.get("event_count", 1)
        actor = agg_alert.get("actor", "") or ""
        target = agg_alert.get("target", "") or ""
        src_ip = agg_alert.get("source_ip", "") or ""
        dst_ip = agg_alert.get("destination_ip", "") or ""
        username = agg_alert.get("username", "") or ""
        agent_id = str(agg_alert.get("agent_id", "") or "")
        groups = [g.lower() for g in (agg_alert.get("classification_groups") or [])]
        tactics = [t.lower() for t in (agg_alert.get("mitre_tactics") or [])]
        max_inline_risk = int(agg_alert.get("max_inline_risk_score", 0) or 0)

        # Extract enriched IOC fields from the aggregate alert payload
        alert_file_hash = (agg_alert.get("file_hash") or agg_alert.get("data_md5")
                           or agg_alert.get("data_sha256") or "")
        alert_domain = (agg_alert.get("dns_query") or agg_alert.get("data_dns_question_name") or "")
        alert_command_line = agg_alert.get("command_line", "") or ""
        alert_process_path = agg_alert.get("process_path", "") or ""
        alert_url = agg_alert.get("url", "") or agg_alert.get("url_path", "") or ""
        alert_registry_key = agg_alert.get("registry_key", "") or ""

        # Lookup dicts for IOC/IOA matching
        alert_ioc_values = {
            "IPV4": [src_ip, dst_ip, actor], "IPV6": [src_ip, dst_ip, actor],
            "CIDR": [src_ip, dst_ip], "MD5": [alert_file_hash],
            "SHA256": [alert_file_hash], "SHA1": [alert_file_hash],
            "DOMAIN": [alert_domain, target], "C2_DOMAIN": [alert_domain, target],
            "URL": [alert_url], "EMAIL": [username],
        }
        alert_field_values = {
            "url_path": alert_url, "url": alert_url,
            "command_line": alert_command_line, "process_path": alert_process_path,
            "data.dns.question.name": alert_domain,
            "data.file.hash.md5": alert_file_hash,
            "data.file.hash.sha256": alert_file_hash,
            "data.registry.key": alert_registry_key,
            "source_ip": src_ip, "destination_ip": dst_ip,
            "username": username, "agent_id": agent_id,
        }

        for r_id, rule in self.rules.items():
            if rule.status not in ("ACTIVE", "PENDING_WAZUH_DEPLOY"):
                continue
            if rule.expires_date < date.today():
                continue

            # ── PHASE 0: Never-Suppress Blacklist Override ──
            guard = rule.get_never_suppress_guard()
            if guard:
                if guard.min_risk_score_override and max_inline_risk >= guard.min_risk_score_override:
                    continue  # Risk too high for safe suppression
                blacklisted = False
                for bl_type in guard.ioc_blacklist_types:
                    bl_upper = bl_type.upper()
                    alert_vals = alert_ioc_values.get(bl_upper, [])
                    if any(v and v.strip() for v in alert_vals):
                        for ioc in rule.get_ioc_indicators():
                            if (ioc.action == "never_suppress" and ioc.type == bl_upper and
                                    any(ioc.value.lower() in v.lower() for v in alert_vals if v)):
                                blacklisted = True
                                break
                    if blacklisted:
                        break
                if blacklisted:
                    continue

            # ── PHASE 1: Primary Match (Rule ID / Category / Group / Tactic) ──
            id_matched = (rule_id in rule.target_rule_ids) if rule.target_rule_ids else False
            scope = rule.scope_definition or {}
            cat_matched = ("categories" in scope and category in scope["categories"])
            group_matched = bool(
                "classification_groups" in scope and
                any(g.lower() in groups for g in scope["classification_groups"])
            )
            tactic_matched = bool(
                "mitre_tactics" in scope and
                any(t.lower() in tactics for t in scope["mitre_tactics"])
            )

            if not (id_matched or cat_matched or group_matched or tactic_matched):
                continue

            # ── PHASE 2: Legacy Scope Checks (IP / Host / User) ──
            if scope.get("source_ip") and scope["source_ip"] not in (actor, src_ip):
                continue
            if scope.get("source_ips") and not any(ip in (actor, src_ip) for ip in scope["source_ips"]):
                continue
            if scope.get("actor") and scope["actor"] != actor:
                continue

            if scope.get("target_host") and scope["target_host"] not in (target, dst_ip, agent_id):
                continue
            if scope.get("target_hosts") and not any(h in (target, dst_ip, agent_id) for h in scope["target_hosts"]):
                continue
            if scope.get("target") and scope["target"] != target:
                continue

            if scope.get("username") and scope["username"] != username:
                continue
            if scope.get("users") and username not in scope["users"]:
                continue

            # ── PHASE 3: Enriched IOC Indicator Matching ──
            ioc_indicators = rule.get_ioc_indicators()
            if ioc_indicators:
                ioc_match_found = False
                for ioc in ioc_indicators:
                    if ioc.action == "never_suppress":
                        continue  # Handled in Phase 0
                    candidate_values = alert_ioc_values.get(ioc.type, [])
                    if ioc.direction == "source":
                        candidate_values = [src_ip, actor]
                    elif ioc.direction == "destination":
                        candidate_values = [dst_ip, target]
                    for cv in candidate_values:
                        if cv and ioc.value.lower() in cv.lower():
                            ioc_match_found = True
                            break
                    if ioc_match_found:
                        break
                if not ioc_match_found:
                    continue

            # ── PHASE 4: Enriched IOA Pattern Matching (AND logic) ──
            ioa_patterns = rule.get_ioa_patterns()
            if ioa_patterns:
                ioa_all_match = True
                for ioa in ioa_patterns:
                    field_val = alert_field_values.get(ioa.field, "")
                    if not field_val:
                        field_val = str(agg_alert.get(ioa.field, "")) or ""
                    if not self._match_ioa_operator(ioa.operator, ioa.value, field_val):
                        ioa_all_match = False
                        break
                if not ioa_all_match:
                    continue

            # ── PHASE 5: Safety Thresholds ──
            max_count = scope.get("max_count")
            if max_count and event_count > max_count:
                return False, r_id, f"Aggregate volume {event_count} exceeded suppression threshold {max_count}"

            max_risk = scope.get("max_risk_score")
            if max_risk is not None and max_inline_risk > max_risk:
                return False, r_id, f"Aggregate risk score {max_inline_risk} exceeded maximum allowed suppression risk {max_risk}"

            # Within suppression policy
            return True, r_id, rule.business_reason

        return False, None, None

    @staticmethod
    def _match_ioa_operator(operator: str, pattern: str, field_value: str) -> bool:
        """Match a single IOA operator against a field value."""
        import re as _re
        if not field_value:
            return False
        fv = field_value.lower()
        pv = pattern.lower()
        if operator == "equals":
            return fv == pv
        elif operator == "not_equals":
            return fv != pv
        elif operator == "contains":
            return pv in fv
        elif operator == "not_contains":
            return pv not in fv
        elif operator == "startswith":
            return fv.startswith(pv)
        elif operator == "endswith":
            return fv.endswith(pv)
        elif operator == "regex":
            try:
                return bool(_re.search(pattern, field_value, _re.IGNORECASE))
            except _re.error:
                return False
        elif operator == "not_regex":
            try:
                return not bool(_re.search(pattern, field_value, _re.IGNORECASE))
            except _re.error:
                return True
        return False

    def auto_suggest_group(self, tenant_id: str, target_host: str, target_sids: List[int], conn,
                           mitre_tactics: List[str] = None, mitre_techniques: List[str] = None,
                           use_case: str = None, actor: str = None) -> Optional[str]:
        """
        Multi-dimensional auto-clustering for suppression group assignment.
        Scores candidate groups across 5 dimensions:
          1. Tenant match (weight 0.25)
          2. Asset/Host overlap (weight 0.20)
          3. SID overlap (weight 0.20)
          4. MITRE ATT&CK tactic+technique overlap (weight 0.20)
          5. Actor/use_case affinity (weight 0.15)
        Returns the group_id with highest composite score (>= 0.40 threshold), or None.
        """
        mitre_tactics = [t.lower() for t in (mitre_tactics or [])]
        mitre_techniques = [t.lower() for t in (mitre_techniques or [])]
        use_case = (use_case or "").lower()
        actor = (actor or "").lower()

        with conn.cursor() as cur:
            cur.execute("""
                SELECT g.group_id, g.group_name, g.group_type, g.tenant_id,
                       g.mitre_tactics, g.mitre_techniques, g.shared_scope,
                       ARRAY_AGG(DISTINCT r.target_rule_ids) AS all_sids
                FROM suppression.suppression_groups g
                LEFT JOIN suppression.suppression_rules r ON r.group_id = g.group_id AND r.status = 'ACTIVE'
                WHERE g.status = 'ACTIVE'
                GROUP BY g.group_id
            """)
            candidates = cur.fetchall()

        best_id = None
        best_score = 0.0
        threshold = 0.40

        for row in candidates:
            g_id, g_name, g_type, g_tenant = row[0], row[1], row[2], row[3]
            g_tactics = [t.lower() for t in (row[4] or [])]
            g_techs = [t.lower() for t in (row[5] or [])]
            g_scope = row[6] if isinstance(row[6], dict) else {}
            g_all_sids_raw = row[7] or []
            g_sids = set()
            for sid_list in g_all_sids_raw:
                if isinstance(sid_list, list):
                    g_sids.update(sid_list)
                elif sid_list is not None:
                    g_sids.add(sid_list)

            # Dimension 1: Tenant (0.25)
            d_tenant = 1.0 if (g_tenant == tenant_id or g_tenant == "ALL") else 0.0

            # Dimension 2: Asset/Host (0.20)
            g_host = (g_scope.get("hostname") or "").lower()
            d_asset = 1.0 if (g_host and g_host == (target_host or "").lower()) else 0.0

            # Dimension 3: SID overlap (0.20) — Jaccard similarity
            s_new = set(target_sids)
            if s_new and g_sids:
                d_sid = len(s_new & g_sids) / len(s_new | g_sids)
            else:
                d_sid = 0.0

            # Dimension 4: MITRE overlap (0.20) — tactic+technique Jaccard
            m_new = set(mitre_tactics + mitre_techniques)
            m_grp = set(g_tactics + g_techs)
            if m_new and m_grp:
                d_mitre = len(m_new & m_grp) / len(m_new | m_grp)
            else:
                d_mitre = 0.0

            # Dimension 5: Actor/use_case affinity (0.15)
            d_actor = 0.0
            g_name_lower = (g_name or "").lower()
            if actor and actor in g_name_lower:
                d_actor = 1.0
            elif use_case and use_case in g_name_lower:
                d_actor = 0.7
            elif g_type and use_case and g_type.lower() == use_case:
                d_actor = 0.5

            score = (0.25 * d_tenant + 0.20 * d_asset + 0.20 * d_sid +
                     0.20 * d_mitre + 0.15 * d_actor)

            if score > best_score:
                best_score = score
                best_id = g_id

        return best_id if best_score >= threshold else None

    def create_group(self, group_data: dict, conn) -> str:
        """
        Create a new suppression group with sequential ID.
        """
        year = datetime.now().year
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM suppression.suppression_groups WHERE group_id LIKE %s", (f"GRP-{year}-%%",))
            count = cur.fetchone()[0]
            group_id = f"GRP-{year}-{count + 1:03d}"
            
            cur.execute("""
                INSERT INTO suppression.suppression_groups (group_id, tenant_id, group_name, group_type, shared_scope, status)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                group_id,
                group_data.get('tenant_id', 'ALL'),
                group_data.get('group_name', ''),
                group_data.get('group_type', 'GLOBAL'),
                json.dumps(group_data.get('shared_scope', {})),
                group_data.get('status', 'ACTIVE')
            ))
            
        self.audit_logs.append(SuppressionAuditLogDB(
            suppression_id=group_id,
            action="CREATED",
            performed_by=group_data.get('owner', 'system'),
            notes=f"Group {group_id} created"
        ))
        return group_id

    def assign_rule_to_group(self, suppression_id: str, group_id: str, performed_by: str, conn) -> None:
        """
        Assign an existing suppression rule to a suppression group.
        """
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE suppression.suppression_rules 
                SET group_id = %s 
                WHERE suppression_id = %s
            """, (group_id, suppression_id))
            
        self.audit_logs.append(SuppressionAuditLogDB(
            suppression_id=suppression_id,
            action="MODIFIED",
            performed_by=performed_by,
            notes=f"Assigned to group {group_id}"
        ))

    def merge_rules_to_group(self, suppression_ids: list, group_id: str, performed_by: str, conn) -> int:
        """
        Assign multiple suppression rules to a group.
        """
        count = 0
        for sid in suppression_ids:
            self.assign_rule_to_group(sid, group_id, performed_by, conn)
            count += 1
        return count

    def generate_wazuh_xml(self, conn) -> str:
        """
        Generate Wazuh rule XML for all ACTIVE groups and their child rules.
        Enhanced v2: Emits IOC-specific <field> elements (data.md5, data.dns.question.name,
        etc.) and IOA pattern elements (<regex>, <match>) from enriched scope_definition.
        """
        xml_lines = [f"<!-- Generated by ASOC at {datetime.now(timezone.utc).isoformat()} -->"]
        xml_lines.append('<group name="asoc_suppression,">')
        
        with conn.cursor() as cur:
            cur.execute("""
                SELECT group_id, group_name, tenant_id, shared_scope
                FROM suppression.suppression_groups
                WHERE status = 'ACTIVE'
                ORDER BY group_id
            """)
            groups = cur.fetchall()
            
            for idx, g_row in enumerate(groups):
                group_id, group_name, tenant_id, shared_scope = g_row
                
                cur.execute("""
                    SELECT target_rule_ids, scope_definition
                    FROM suppression.suppression_rules
                    WHERE group_id = %s AND status = 'ACTIVE'
                """, (group_id,))
                rules = cur.fetchall()
                if not rules:
                    continue
                
                sids = set()
                all_scopes = []
                for r_sids, r_scope in rules:
                    if r_sids:
                        sids.update(r_sids)
                    if r_scope:
                        all_scopes.append(r_scope)
                
                if not sids:
                    continue
                    
                sid_str = ",".join(map(str, sorted(sids)))
                hostname = shared_scope.get('hostname') if shared_scope and isinstance(shared_scope, dict) else None
                
                xml_lines.append(f'  <rule id="{100100 + idx}" level="0">')
                xml_lines.append(f'    <if_sid>{sid_str}</if_sid>')
                if hostname:
                    xml_lines.append(f'    <hostname>{hostname}</hostname>')
                if tenant_id and tenant_id != 'ALL':
                    xml_lines.append(f'    <field name="labels.tenant_id">{tenant_id}</field>')

                # Legacy + Enhanced field collectors
                urls = set()
                users = set()
                ips = set()
                programs = set()
                ioc_hashes = set()
                ioc_domains = set()
                ioa_elements = []

                if shared_scope and isinstance(shared_scope, dict):
                    if shared_scope.get("url"): urls.add(str(shared_scope["url"]))
                    if shared_scope.get("url_path"): urls.add(str(shared_scope["url_path"]))
                    if shared_scope.get("user"): users.add(str(shared_scope["user"]))
                    if shared_scope.get("source_ip"): ips.add(str(shared_scope["source_ip"]))
                    if shared_scope.get("program_name"): programs.add(str(shared_scope["program_name"]))

                for s_def in (all_scopes or []):
                    if not s_def: continue
                    if isinstance(s_def, str):
                        try: s_def = json.loads(s_def)
                        except Exception: continue
                    # Legacy fields
                    if s_def.get("url_path"): urls.add(str(s_def["url_path"]))
                    if s_def.get("url"): urls.add(str(s_def["url"]))
                    if s_def.get("username") and s_def["username"] not in ("All / Internal", "All", ""):
                        users.add(str(s_def["username"]))
                    if s_def.get("source_ip") and s_def["source_ip"] not in ("All / Internal", "All", "") and not str(s_def["source_ip"]).startswith("user:"):
                        ips.add(str(s_def["source_ip"]))
                    if s_def.get("program_name"): programs.add(str(s_def["program_name"]))

                    # IOC indicator extraction
                    for ioc_raw in s_def.get("ioc_indicators", []):
                        if not isinstance(ioc_raw, dict): continue
                        ioc_type = ioc_raw.get("type", "").upper()
                        ioc_val = ioc_raw.get("value", "")
                        if ioc_raw.get("action") == "never_suppress": continue
                        if ioc_type in ("MD5", "SHA256", "SHA1"):
                            ioc_hashes.add(ioc_val)
                        elif ioc_type in ("DOMAIN", "C2_DOMAIN"):
                            ioc_domains.add(ioc_val)
                        elif ioc_type in ("IPV4", "IPV6", "CIDR"):
                            ips.add(ioc_val)

                    # IOA pattern extraction
                    for ioa_raw in s_def.get("ioa_patterns", []):
                        if not isinstance(ioa_raw, dict): continue
                        try:
                            ioa = IoaPattern(**ioa_raw)
                            elem = ioa.to_wazuh_element()
                            if elem and elem not in ioa_elements:
                                ioa_elements.append(elem)
                        except Exception:
                            continue

                # Emit legacy fields
                if urls:
                    xml_lines.append(f'    <field name="url">{"|".join(sorted(urls))}</field>')
                if users:
                    xml_lines.append(f'    <user>{"|".join(sorted(users))}</user>')
                if ips and len(ips) <= 5:
                    xml_lines.append(f'    <srcip>{"|".join(sorted(ips))}</srcip>')
                if programs:
                    xml_lines.append(f'    <program_name>{"|".join(sorted(programs))}</program_name>')

                # Emit IOC-specific Wazuh fields
                if ioc_hashes:
                    xml_lines.append(f'    <field name="data.md5">{"|".join(sorted(ioc_hashes))}</field>')
                if ioc_domains:
                    xml_lines.append(f'    <field name="data.dns.question.name">{"|".join(sorted(ioc_domains))}</field>')

                # Emit IOA pattern elements
                for elem in ioa_elements:
                    xml_lines.append(elem)

                xml_lines.append(f'    <description>ASOC Policy Bundle: {group_name} [{group_id}]</description>')
                xml_lines.append(f'  </rule>')
                
        xml_lines.append('</group>')
        return "\n".join(xml_lines)

    def generate_cdb_lists(self, conn) -> dict:
        """
        Generate CDB list content from shared_value_lists.
        """
        results = {}
        with conn.cursor() as cur:
            cur.execute("""
                SELECT list_name, values 
                FROM suppression.shared_value_lists
                WHERE status = 'ACTIVE'
            """)
            for row in cur.fetchall():
                filename, values = row
                content = []
                if values:
                    for v in values:
                        content.append(f"{v}:")
                results[filename] = "\n".join(content)
        return results

    def get_groups(self, conn, tenant_id=None, group_type=None, status='ACTIVE') -> list:
        """
        Retrieve suppression groups with optional filters, including rule counts and suppressed metrics.
        """
        with conn.cursor() as cur:
            query = """
                SELECT g.group_id, g.tenant_id, g.group_name, g.group_type, g.shared_scope, g.status,
                       COUNT(r.suppression_id) as rule_count,
                       COALESCE(SUM(r.suppressed_count), 0) as suppressed_count
                FROM suppression.suppression_groups g
                LEFT JOIN suppression.suppression_rules r ON r.group_id = g.group_id
                WHERE 1=1
            """
            params = []
            
            if tenant_id:
                query += " AND g.tenant_id = %s"
                params.append(tenant_id)
            if group_type:
                query += " AND g.group_type = %s"
                params.append(group_type)
            if status:
                query += " AND g.status = %s"
                params.append(status)
                
            query += " GROUP BY g.group_id, g.tenant_id, g.group_name, g.group_type, g.shared_scope, g.status"
            
            cur.execute(query, params)
            
            columns = [desc[0] for desc in cur.description]
            groups = []
            for row in cur.fetchall():
                groups.append(dict(zip(columns, row)))
                
            return groups

    def get_group_detail(self, group_id: str, conn) -> dict:
        """
        Retrieve a suppression group's details along with its child rules.
        """
        with conn.cursor() as cur:
            cur.execute("""
                SELECT group_id, tenant_id, group_name, group_type, shared_scope, status
                FROM suppression.suppression_groups
                WHERE group_id = %s
            """, (group_id,))
            
            group_row = cur.fetchone()
            if not group_row:
                return {}
                
            columns = [desc[0] for desc in cur.description]
            group_detail = dict(zip(columns, group_row))
            
            cur.execute("""
                SELECT suppression_id, rule_name, suppression_class, target_rule_ids, status
                FROM suppression.suppression_rules
                WHERE group_id = %s
            """, (group_id,))
            
            rule_cols = [desc[0] for desc in cur.description]
            rules = []
            for row in cur.fetchall():
                rules.append(dict(zip(rule_cols, row)))
                
            group_detail['rules'] = rules
            return group_detail

