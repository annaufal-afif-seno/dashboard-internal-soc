"""
Stage 4: Deterministic Category-Based Priority Engine (P0-P4)
=============================================================
Prioritas tiket ditentukan oleh kategori di aggregate, bukan oleh risk score.
Sesuai PRD Sistem SOC: Alur Alert, Agregasi, Tiket, dan AI Triage.

Risk score dihapus sesuai PRD Section 8 #2. Pengganti = AI triage (ML/LLM local/LLM cloud).
"""
import os
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple
from config.settings import BASE_DIR, DB_HOST, DB_PORT, DB_USER, DB_PASSWORD

logger = logging.getLogger("PriorityEngine")

RECON_CATS = frozenset({
    "DISCOVERY", "WEB_OPERATIONAL", "AUTH_FAILURE",
    "SYSTEM_HEALTH", "CLOUD_CONTAINER", "OTHER"
})
VULN_CATS = frozenset({"VULNERABILITY", "CONFIGURATION_ASSESSMENT"})
ATTACK_CATS = frozenset({"WEB_ATTACK", "EXECUTION", "MALWARE", "CREDENTIAL_ACCESS"})
BREACH_CATS = frozenset({"AUTH_SUCCESS", "INITIAL_ACCESS", "COMMAND_AND_CONTROL"})
POST_EXPLOIT_CATS = frozenset({
    "PRIVILEGE_ESCALATION", "PERSISTENCE", "DEFENSE_EVASION",
    "LATERAL_MOVEMENT", "FILE_INTEGRITY", "EXFILTRATION", "RANSOMWARE"
})

SLA_MATRIX_MINUTES = {
    "P0": 15, "P1": 60, "P2": 240, "P3": 1440, "P4": 10080,
}

CATEGORY_ALIASES = {
    "AUTHENTICATION_FAILED": "AUTH_FAILURE",
    "LOGIN_FAILED": "AUTH_FAILURE",
    "AUTHENTICATION_SUCCESS": "AUTH_SUCCESS",
    "LOGIN_SUCCESS": "AUTH_SUCCESS",
    "SQL_INJECTION": "WEB_ATTACK",
    "SQLI": "WEB_ATTACK",
    "ENCODED_EXECUTION": "EXECUTION",
    "TOOL_TRANSFER_OR_C2": "COMMAND_AND_CONTROL",
    "STAGE_1_INTRUSION": "INITIAL_ACCESS",
    "STAGE_2_EXECUTION_OR_IMPACT": "EXECUTION",
    "MASS_FILE_IMPACT": "RANSOMWARE",
    "NETWORK_WEB": "WEB_OPERATIONAL",
    "LATERAL_ACCESS": "LATERAL_MOVEMENT",
    "DEFENSE_EVASION_TAMPER": "DEFENSE_EVASION",
    "CVE": "VULNERABILITY",
    "SCA": "CONFIGURATION_ASSESSMENT",
    "RECON": "DISCOVERY",
}

PRIORITY_RANK = {"P0": 4, "P1": 3, "P2": 2, "P3": 1, "P4": 0}


def _normalize_category(cat_raw):
    if not cat_raw:
        return "OTHER"
    c = str(cat_raw).strip().upper()
    if c.startswith("BURST_WINDOW_"):
        return "WEB_OPERATIONAL"
    return CATEGORY_ALIASES.get(c, c)


class PriorityEngine:
    """Deterministic Category-Based Priority Engine (P0-P4). PRD Section 5."""

    def __init__(self, db_name: str = "wazuh_soc_db"):
        self.db_name = db_name

    def _fetch_stages_from_db(self, incident_id: str) -> List[str]:
        try:
            import psycopg2
            conn = psycopg2.connect(host=DB_HOST, port=DB_PORT, database=self.db_name,
                                    user=DB_USER, password=DB_PASSWORD, connect_timeout=2)
            stages = []
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT stage_name FROM correlation.incident_stages WHERE incident_id = %s ORDER BY sequence_order ASC;", (incident_id,))
                    for (s_name,) in cur.fetchall():
                        stages.append(s_name)
            finally:
                conn.close()
            return stages
        except Exception:
            return []

    def determine_priority(self, incident: Dict[str, Any]) -> Tuple[str, str, int]:
        """Returns: (soc_priority, justification, sla_minutes)"""
        inc_id = incident.get("incident_id", "")
        cs: List[str] = []
        for st in incident.get("stages", []):
            if isinstance(st, dict):
                cv = st.get("category") or st.get("event_category") or st.get("stage_name")
                if cv:
                    cs.append(_normalize_category(cv))
        if not cs:
            for c in (incident.get("categories") or []):
                if c:
                    cs.append(_normalize_category(c))
        if not cs and incident.get("category"):
            cs.append(_normalize_category(incident["category"]))
        if not cs and inc_id:
            for s in self._fetch_stages_from_db(inc_id):
                cs.append(_normalize_category(s))
        if not cs:
            ts = str(incident.get("target_severity") or incident.get("priority") or "").upper()
            if ts in SLA_MATRIX_MINUTES:
                return ts, f"Inherited severity: {ts}", SLA_MATRIX_MINUTES[ts]
            return "P4", "Reconnaissance / Probe (Default)", SLA_MATRIX_MINUTES["P4"]

        cve_seen, breach_seen, cve_idx, breach_idx = False, False, -1, -1
        attack, post_exploit = False, False
        for idx, cat in enumerate(cs):
            if cat in VULN_CATS and not cve_seen:
                cve_seen, cve_idx = True, idx
            if cat in ATTACK_CATS:
                attack = True
            if cat in BREACH_CATS and not breach_seen:
                breach_seen, breach_idx = True, idx
            if cat in POST_EXPLOIT_CATS:
                post_exploit = True
        n = len(cs)
        if (breach_seen and (n - 1) > breach_idx) or post_exploit:
            return "P0", "Breach diikuti aksi lanjutan / Post-Exploit", SLA_MATRIX_MINUTES["P0"]
        if breach_seen:
            return "P1", "Hacker Berhasil Masuk", SLA_MATRIX_MINUTES["P1"]
        if attack or (cve_seen and (n - 1) > cve_idx):
            r = "Percobaan serangan nyata" if attack else "Target CVE diserang"
            return "P2", r, SLA_MATRIX_MINUTES["P2"]
        if cve_seen:
            return "P3", "Celah CVE Terdeteksi", SLA_MATRIX_MINUTES["P3"]
        return "P4", "Reconnaissance / Probe / Scanning noise", SLA_MATRIX_MINUTES["P4"]

    determine_stateful_priority = determine_priority


    def evaluate_incident(self, incident: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Evaluate priority. Returns (score_record, triage_record)."""
        incident_id = incident["incident_id"]
        soc_priority, reason, sla_mins = self.determine_priority(incident)
        now_utc = datetime.now(timezone.utc)

        first_detected_at = (
            incident.get("first_detected_at")
            or incident.get("first_seen_at")
            or incident.get("created_at")
            or now_utc
        )
        priority_changed_at = (
            incident.get("priority_changed_at")
            or incident.get("priority_established_at")
            or incident.get("last_seen_at")
            or now_utc
        )
        sla_deadline = incident.get("sla_deadline")
        if not sla_deadline and priority_changed_at:
            if isinstance(priority_changed_at, str):
                try:
                    from dateutil import parser as dt_parser
                    p_dt = dt_parser.parse(priority_changed_at)
                    sla_deadline = p_dt + timedelta(minutes=sla_mins)
                except Exception:
                    sla_deadline = now_utc + timedelta(minutes=sla_mins)
            else:
                sla_deadline = priority_changed_at + timedelta(minutes=sla_mins)

        score_record = {
            "incident_id": incident_id, "soc_priority": soc_priority,
            "sla_minutes": sla_mins, "priority_reason": reason,
        }
        triage_record = {
            "triage_id": f"TRG-{incident_id[4:]}" if len(incident_id) > 4 else f"TRG-{incident_id}",
            "incident_id": incident_id, "assigned_analyst": None,
            "priority": soc_priority, "sla_minutes": sla_mins,
            "triage_status": "OPEN", "resolution_outcome": None,
            "false_positive_reason": None,
            "first_detected_at": first_detected_at,
            "priority_changed_at": priority_changed_at,
            "priority_established_at": priority_changed_at,
            "sla_deadline": sla_deadline,
        }
        return score_record, triage_record


class RiskScorer(PriorityEngine):
    """Backward-compatible alias. Risk score dihapus sesuai PRD Section 8 #2."""
    def __init__(self, asset_config_path: Optional[str] = None, db_name: str = "wazuh_soc_db"):
        super().__init__(db_name=db_name)

    def evaluate_incident_risk(self, incident: Dict[str, Any],
                                is_in_maintenance: bool = False,
                                is_approved_scanner: bool = False
                                ) -> Tuple[Dict[str, Any], List[Dict[str, Any]], Dict[str, Any]]:
        """Backward-compatible wrapper. Returns (score_record, factors=[], triage_record)."""
        score_record, triage_record = self.evaluate_incident(incident)
        score_record["total_score"] = 0
        score_record["scoring_version"] = "v5.0_category_only"
        triage_record["mean_time_to_triage_seconds"] = None
        return score_record, [], triage_record
