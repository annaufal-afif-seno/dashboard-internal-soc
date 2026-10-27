"""
Stage 4: Deterministic Category & Subcategory-Based Priority Engine (P0-P4)
==========================================================================
Prioritas tiket ditentukan secara deterministik oleh 6 Kategori Murni & Subkategori Fungsional:
- P0 (15 Menit): Terjadi Breach (Auth Success) diikuti aksi lanjutan apapun, atau Post-Exploit / Privilege Escalation.
- P1 (60 Menit): Terdeteksi keberhasilan masuk perimeter (Auth Success) atau Command & Control.
- P2 (4 Jam): Percobaan serangan nyata (Web Attack, Exploitation / RCE, Malware, Auth Anomaly)
              ATAU target berstatus Vulnerability (P3) ditembak lagi oleh agregat lanjutan apapun.
- P3 (1 Hari): Target terverifikasi memiliki celah (CVE Detected, Missing Patch, SCA Benchmark, FIM).
- P4 (7 Hari): Hanya berisi reconnaissance / probe coba-coba / scanning noise (Web Operational, Service Health, Auth Failure, Recon / Scan).
"""
import os
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple
from config.settings import BASE_DIR, DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD

logger = logging.getLogger("PriorityEngine")

SLA_MATRIX_MINUTES = {
    "P0": 15,
    "P1": 60,
    "P2": 240,       # 4 jam
    "P3": 1440,      # 1 hari
    "P4": 10080,     # 7 hari
}

PRIORITY_RANK = {"P0": 4, "P1": 3, "P2": 2, "P3": 1, "P4": 0}

RECON_SUBCATS = frozenset({
    "Auth Failure", "Recon / Scan", "Web Operational", "Service Health / Error", "Cloud / Container Event"
})
VULN_SUBCATS = frozenset({
    "CVE Detected", "Missing Patch / Outdated", "SCA / CIS Benchmark", "File Integrity (FIM)", "Policy Violation"
})
ATTACK_SUBCATS = frozenset({
    "Web Attack", "Exploitation / RCE", "Lateral Movement", "Auth Anomaly", "Rootkit / Backdoor", "Ransomware", "Virus / Trojan (YARA)"
})
BREACH_SUBCATS = frozenset({
    "Auth Success", "Command & Control", "Privilege Escalation"
})

def _normalize_category(cat_raw, rule_id=None, desc=""):
    if not cat_raw:
        return "System / Availability"
    c = str(cat_raw).strip()
    return c


class PriorityEngine:
    """Deterministic Category & Subcategory-Based Priority Engine (P0-P4)."""

    def __init__(self, db_name: str = DB_NAME):
        self.db_name = db_name

    def determine_priority(self, incident: Dict[str, Any]) -> Tuple[str, str, int]:
        """
        Evaluates stateful attack progression across stages using subcategories.
        Returns: (soc_priority, justification, sla_minutes)
        """
        stages: List[Dict[str, Any]] = []
        for st in incident.get("stages", []):
            if isinstance(st, dict):
                stages.append(st)
            elif isinstance(st, str):
                stages.append({"stage_name": st})

        if not stages and incident.get("primary_category"):
            stages.append({
                "primary_category": incident["primary_category"],
                "subcategory": incident.get("subcategory"),
                "rule_id": incident.get("rule_id"),
                "stage_description": incident.get("rule_description", "")
            })
        elif not stages and incident.get("category"):
            stages.append({
                "primary_category": incident["category"],
                "subcategory": incident.get("subcategory"),
                "rule_id": incident.get("rule_id"),
                "stage_description": incident.get("rule_description", "")
            })

        cve_seen, breach_seen = False, False
        cve_idx, breach_idx = -1, -1
        attack, post_exploit = False, False
        n = len(stages)

        for idx, stg in enumerate(stages):
            pcat = stg.get("primary_category") or stg.get("stage_name") or ""
            subcat = stg.get("subcategory") or ""
            desc = (stg.get("stage_description") or stg.get("description") or "").lower()
            rid = stg.get("rule_id")

            # Resolve subcat fallback if not explicitly provided
            if not subcat:
                if pcat == "Identity / Access":
                    if rid in (5715, 5716, 5501) or ("success" in desc and "fail" not in desc and "invalid" not in desc):
                        subcat = "Auth Success"
                    elif rid in (100001, 5551) or "brute force" in desc:
                        subcat = "Auth Anomaly"
                    elif rid in (5402, 5504, 5902) or "sudo" in desc or "privilege" in desc:
                        subcat = "Privilege Escalation"
                    else:
                        subcat = "Auth Failure"
                elif pcat == "Vulnerability":
                    subcat = "CVE Detected"
                elif pcat == "Configuration / Compliance":
                    subcat = "File Integrity (FIM)" if "syscheck" in desc or "file" in desc else "SCA / CIS Benchmark"
                elif pcat in ("Attack", "Malware"):
                    subcat = "Web Attack" if "sql" in desc or "xss" in desc else "Exploitation / RCE"
                else:
                    subcat = "Web Operational" if "web" in desc or "404" in desc else "Service Health / Error"

            if (subcat in VULN_SUBCATS or pcat in ("Vulnerability", "Configuration / Compliance")) and not cve_seen:
                cve_seen, cve_idx = True, idx
            if subcat in ATTACK_SUBCATS or pcat in ("Attack", "Malware"):
                attack = True
            if (subcat in BREACH_SUBCATS or subcat == "Auth Success") and not breach_seen:
                breach_seen, breach_idx = True, idx
            if subcat in ("Privilege Escalation", "Lateral Movement", "Command & Control") or "privilege" in desc or "persistence" in desc:
                post_exploit = True

        # P0 (15 Menit): Terjadi Breach (AUTH_SUCCESS) diikuti aksi lanjutan apapun, atau Post-Exploit
        if (breach_seen and (n - 1) > breach_idx) or post_exploit:
            return "P0", "Breach (Auth Success) Diikuti Aksi Lanjutan / Post-Exploit", SLA_MATRIX_MINUTES["P0"]

        # P1 (60 Menit): Terdeteksi Keberhasilan Masuk Perimeter
        if breach_seen:
            return "P1", "Keberhasilan Masuk Perimeter (Auth Success)", SLA_MATRIX_MINUTES["P1"]

        # P2 (4 Jam): Percobaan Serangan Nyata ATAU Target Vulnerability Diserang Lanjutan
        if attack or (cve_seen and (n - 1) > cve_idx):
            r = "Percobaan Serangan Nyata (Attack / Malware / Auth Anomaly)" if attack else "Target Berstatus Vulnerability Ditembak Lanjutan"
            return "P2", r, SLA_MATRIX_MINUTES["P2"]

        # P3 (1 Hari): Target Terverifikasi Memiliki Celah
        if cve_seen:
            return "P3", "Target Terverifikasi Memiliki Celah (Vulnerability / Compliance)", SLA_MATRIX_MINUTES["P3"]

        # P4 (7 Hari): Reconnaissance / Probe Coba-coba / Noise
        return "P4", "Reconnaissance / Probe Coba-coba / Scanning Noise", SLA_MATRIX_MINUTES["P4"]

    determine_stateful_priority = determine_priority

    def evaluate_incident(self, incident: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
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
            "incident_id": incident_id,
            "soc_priority": soc_priority,
            "sla_minutes": sla_mins,
            "priority_reason": reason,
        }
        triage_record = {
            "triage_id": f"TRG-{incident_id[4:]}" if len(incident_id) > 4 else f"TRG-{incident_id}",
            "incident_id": incident_id,
            "assigned_analyst": None,
            "priority": soc_priority,
            "sla_minutes": sla_mins,
            "triage_status": "OPEN",
            "resolution_outcome": None,
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
        score_record, triage_record = self.evaluate_incident(incident)
        score_record["total_score"] = 0
        score_record["scoring_version"] = "v5.0_category_subcat"
        triage_record["mean_time_to_triage_seconds"] = None
        return score_record, [], triage_record
