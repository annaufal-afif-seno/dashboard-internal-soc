"""
DFIR-IRIS Adapter Implementation (Mock & Live)
==============================================
Implements IRISAdapterInterface for:
- Escalating actionable security threats into IRIS Cases
- Synchronizing human analyst investigation verdicts back to SOC triage
- Handling offline / not_connected states gracefully
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from pipeline.adapters.base import IRISAdapterInterface, AdapterStatus

logger = logging.getLogger(__name__)


class MockIrisAdapter(IRISAdapterInterface):
    """High-fidelity mock adapter for DFIR-IRIS case management."""

    def __init__(
        self,
        simulate_failure: bool = False,
        simulate_timeout: bool = False
    ):
        self.simulate_failure = simulate_failure
        self.simulate_timeout = simulate_timeout
        self.cases: Dict[str, Dict[str, Any]] = {}
        self._case_seq = 100

    def health_check(self) -> AdapterStatus:
        if self.simulate_failure or self.simulate_timeout:
            return AdapterStatus(
                is_connected=False,
                component="IRIS",
                mode="mock",
                endpoint="mock://iris.soc.local:8443",
                error_message="Simulated connection timeout" if self.simulate_timeout else "Simulated IRIS service unavailable"
            )
        return AdapterStatus(
            is_connected=True,
            component="IRIS",
            mode="mock",
            endpoint="mock://iris.soc.local:8443"
        )

    def create_case(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate creating an investigation case in DFIR-IRIS."""
        if self.simulate_failure:
            return {
                "status": "FAILED",
                "case_id": "",
                "case_title": "",
                "iris_url": "",
                "error": "DFIR-IRIS connection failed: Service down"
            }
        if self.simulate_timeout:
            return {
                "status": "FAILED",
                "case_id": "",
                "case_title": "",
                "iris_url": "",
                "error": "DFIR-IRIS connection timeout (15s exceeded)"
            }

        self._case_seq += 1
        date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
        case_id = f"CASE-{date_str}-{self._case_seq}"
        title = incident.get("title", f"Incident {incident.get('incident_id')}")

        case_record = {
            "case_id": case_id,
            "incident_id": incident.get("incident_id"),
            "tenant_id": incident.get("tenant_id", "DEFAULT"),
            "title": title,
            "severity": incident.get("priority", "P2"),
            "status": "OPEN",
            "verdict": "PENDING",
            "attacker_ip": incident.get("attacker_source_ip"),
            "target_host": incident.get("target_host"),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "resolved_at": None,
            "closing_notes": "",
            "assigned_analyst": "soc_tier2_lead"
        }
        self.cases[case_id] = case_record

        return {
            "status": "SUCCESS",
            "case_id": case_id,
            "case_title": title,
            "iris_url": f"https://iris.soc.local:8443/cases/{case_id}",
            "error": None
        }

    def get_case_resolution(self, case_id: str) -> Dict[str, Any]:
        """Fetch analyst resolution verdict from mock store."""
        case = self.cases.get(case_id)
        if not case:
            return {
                "status": "NOT_FOUND",
                "verdict": "PENDING",
                "closing_notes": "Case does not exist",
                "analyst": "",
                "resolved_at": None
            }
        return {
            "status": case["status"],
            "verdict": case["verdict"],
            "closing_notes": case["closing_notes"],
            "analyst": case["assigned_analyst"],
            "resolved_at": case["resolved_at"]
        }

    def resolve_case_manually(self, case_id: str, verdict: str, notes: str = "", analyst: str = "soc_analyst_1"):
        """Helper for unit tests: simulate analyst closing a case in IRIS."""
        if case_id in self.cases:
            self.cases[case_id]["status"] = "CLOSED"
            self.cases[case_id]["verdict"] = verdict
            self.cases[case_id]["closing_notes"] = notes
            self.cases[case_id]["assigned_analyst"] = analyst
            self.cases[case_id]["resolved_at"] = datetime.now(timezone.utc).isoformat()


class LiveIrisAdapter(IRISAdapterInterface):
    """Production Live Adapter connecting to DFIR-IRIS REST API v2."""

    def __init__(
        self,
        api_url: Optional[str] = None,
        api_key: Optional[str] = None,
        ssl_verify: bool = False
    ):
        self.api_url = (api_url or os.getenv("IRIS_URL", "https://localhost:8443")).rstrip("/")
        self.api_key = api_key or os.getenv("IRIS_API_KEY", "")
        self.ssl_verify = ssl_verify

    def health_check(self) -> AdapterStatus:
        import requests
        headers = {"Authorization": f"Bearer {self.api_key}"}
        try:
            resp = requests.get(f"{self.api_url}/manage/server/status", headers=headers, verify=self.ssl_verify, timeout=5)
            if resp.status_code == 200:
                return AdapterStatus(
                    is_connected=True,
                    component="IRIS",
                    mode="live",
                    endpoint=self.api_url
                )
            return AdapterStatus(
                is_connected=False,
                component="IRIS",
                mode="live",
                endpoint=self.api_url,
                error_message=f"Status code {resp.status_code}"
            )
        except Exception as e:
            return AdapterStatus(
                is_connected=False,
                component="IRIS",
                mode="live",
                endpoint=self.api_url,
                error_message=str(e)
            )

    def create_case(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        import requests
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "case_name": incident.get("title", f"Escalated Incident {incident.get('incident_id')}"),
            "case_description": incident.get("narrative", ""),
            "case_customer": incident.get("tenant_id", "DEFAULT"),
            "case_severity": 1 if incident.get("priority") in ("P0", "P1") else 2,
            "case_soc_id": incident.get("incident_id")
        }
        try:
            resp = requests.post(f"{self.api_url}/manage/cases/add", headers=headers, json=payload, verify=self.ssl_verify, timeout=15)
            if resp.status_code in (200, 201):
                res_data = resp.json().get("data", {})
                cid = str(res_data.get("case_id", "UNKNOWN"))
                return {
                    "status": "SUCCESS",
                    "case_id": cid,
                    "case_title": payload["case_name"],
                    "iris_url": f"{self.api_url}/cases/{cid}",
                    "error": None
                }
            return {
                "status": "FAILED",
                "case_id": "",
                "case_title": "",
                "iris_url": "",
                "error": f"HTTP {resp.status_code} - {resp.text}"
            }
        except Exception as e:
            return {
                "status": "FAILED",
                "case_id": "",
                "case_title": "",
                "iris_url": "",
                "error": str(e)
            }

    def get_case_resolution(self, case_id: str) -> Dict[str, Any]:
        import requests
        headers = {"Authorization": f"Bearer {self.api_key}"}
        try:
            resp = requests.get(f"{self.api_url}/manage/cases/{case_id}", headers=headers, verify=self.ssl_verify, timeout=10)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                state = data.get("case_state", "OPEN")
                raw_verdict = data.get("case_verdict", "PENDING")
                return {
                    "status": state,
                    "verdict": raw_verdict,
                    "closing_notes": data.get("case_closing_notes", ""),
                    "analyst": data.get("case_closed_by", ""),
                    "resolved_at": data.get("case_closed_at")
                }
            return {
                "status": "ERROR",
                "verdict": "PENDING",
                "closing_notes": f"API error {resp.status_code}",
                "analyst": "",
                "resolved_at": None
            }
        except Exception as e:
            return {
                "status": "ERROR",
                "verdict": "PENDING",
                "closing_notes": str(e),
                "analyst": "",
                "resolved_at": None
            }
