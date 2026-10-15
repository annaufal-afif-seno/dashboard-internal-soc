"""
MISP Adapter Implementation (Mock & Live)
==========================================
Implements MISPAdapterInterface for:
- Looking up indicator threat intelligence
- Pushing confirmed threat events and attributes to MISP
- Handling connection states (connected, not_connected, unavailable)
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from pipeline.adapters.base import MISPAdapterInterface, AdapterStatus

logger = logging.getLogger(__name__)


class MockMispAdapter(MISPAdapterInterface):
    """High-fidelity mock adapter for MISP threat intelligence."""

    def __init__(
        self,
        cache_file: Optional[str] = None,
        simulate_failure: bool = False,
        simulate_timeout: bool = False
    ):
        base_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        default_cache = os.path.join(base_root, "data", "cache", "ti_cache.json")
        if not os.path.exists(default_cache):
            default_cache = os.path.join(base_root, "ti_cache.json")
        self.cache_file = cache_file or default_cache
        self.simulate_failure = simulate_failure
        self.simulate_timeout = simulate_timeout
        self.pushed_events: List[Dict[str, Any]] = []
        self._event_counter = 1000

        # Load local cache
        self.cache: Dict[str, Any] = {}
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, "r", encoding="utf-8") as f:
                    self.cache = json.load(f)
            except Exception as e:
                logger.warning(f"MockMispAdapter cache load notice: {e}")

    def health_check(self) -> AdapterStatus:
        if self.simulate_failure or self.simulate_timeout:
            return AdapterStatus(
                is_connected=False,
                component="MISP",
                mode="mock",
                endpoint="mock://misp.internal.local",
                error_message="Simulated timeout" if self.simulate_timeout else "Simulated MISP offline"
            )
        return AdapterStatus(
            is_connected=True,
            component="MISP",
            mode="mock",
            endpoint="mock://misp.internal.local"
        )

    def lookup_ioc(self, indicator: str, indicator_type: str = "ip-src") -> Dict[str, Any]:
        """Lookup IoC from mock cache with error simulation."""
        if self.simulate_failure:
            return {
                "status": "not_connected",
                "indicator": indicator,
                "threat_level": "UNKNOWN",
                "confidence_score": 0,
                "source_feeds": [],
                "tags": [],
                "is_malicious": False,
                "error": "MISP server offline"
            }
        if self.simulate_timeout:
            return {
                "status": "timeout",
                "indicator": indicator,
                "threat_level": "UNKNOWN",
                "confidence_score": 0,
                "source_feeds": [],
                "tags": [],
                "is_malicious": False,
                "error": "MISP connection timeout (10s exceeded)"
            }

        # Check local cache
        data = self.cache.get(indicator)
        if not data:
            return {
                "status": "not_found",
                "indicator": indicator,
                "threat_level": "BENIGN",
                "confidence_score": 0,
                "source_feeds": ["AbuseIPDB Live Cache"],
                "tags": ["tlp:white", "clean"],
                "is_malicious": False
            }

        abuse_score = int(data.get("abuse_score", 0))
        is_mal = abuse_score >= 50
        level = "HIGH" if abuse_score >= 75 else "MEDIUM" if abuse_score >= 25 else "LOW"

        return {
            "status": "connected",
            "indicator": indicator,
            "threat_level": level,
            "confidence_score": abuse_score,
            "source_feeds": ["AbuseIPDB", "Local Telemetry"],
            "tags": [f"country:{data.get('country', 'UNKNOWN')}", f"isp:{data.get('isp', 'UNKNOWN')}"],
            "is_malicious": is_mal,
            "total_reports": data.get("total_reports", 0)
        }

    def push_threat_event(self, incident_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate creating a new threat intelligence event in MISP."""
        if self.simulate_failure or self.simulate_timeout:
            return {
                "status": "FAILED",
                "event_id": "",
                "attribute_count": 0,
                "error": "Failed to push to MISP: Service unreachable"
            }

        self._event_counter += 1
        event_id = f"MISP-EVT-{self._event_counter}"
        
        attributes = []
        if incident_payload.get("attacker_source_ip"):
            attributes.append({"type": "ip-src", "value": incident_payload["attacker_source_ip"]})
        if incident_payload.get("target_host"):
            attributes.append({"type": "hostname", "value": incident_payload["target_host"]})

        record = {
            "event_id": event_id,
            "info": incident_payload.get("title", "Confirmed SOC Incident"),
            "tenant_id": incident_payload.get("tenant_id", "DEFAULT"),
            "attributes": attributes,
            "pushed_at": datetime.now(timezone.utc).isoformat()
        }
        self.pushed_events.append(record)

        return {
            "status": "SUCCESS",
            "event_id": event_id,
            "attribute_count": len(attributes),
            "error": None
        }


class LiveMispAdapter(MISPAdapterInterface):
    """Production Live Adapter connecting to MISP REST API / PyMISP."""

    def __init__(
        self,
        misp_url: Optional[str] = None,
        auth_key: Optional[str] = None,
        ssl_verify: bool = False
    ):
        self.misp_url = (misp_url or os.getenv("MISP_URL", "https://localhost")).rstrip("/")
        self.auth_key = auth_key or os.getenv("MISP_AUTH_KEY", "")
        self.ssl_verify = ssl_verify

    def health_check(self) -> AdapterStatus:
        import requests
        try:
            resp = requests.get(
                f"{self.misp_url}/servers/getVersion",
                headers={"Authorization": self.auth_key, "Accept": "application/json"},
                verify=self.ssl_verify,
                timeout=5
            )
            if resp.status_code == 200:
                return AdapterStatus(
                    is_connected=True,
                    component="MISP",
                    mode="live",
                    endpoint=self.misp_url
                )
            return AdapterStatus(
                is_connected=False,
                component="MISP",
                mode="live",
                endpoint=self.misp_url,
                error_message=f"Status code {resp.status_code}"
            )
        except Exception as e:
            return AdapterStatus(
                is_connected=False,
                component="MISP",
                mode="live",
                endpoint=self.misp_url,
                error_message=str(e)
            )

    def lookup_ioc(self, indicator: str, indicator_type: str = "ip-src") -> Dict[str, Any]:
        import requests
        headers = {
            "Authorization": self.auth_key,
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        payload = {
            "returnFormat": "json",
            "value": indicator,
            "type": indicator_type,
            "limit": 5
        }
        try:
            resp = requests.post(
                f"{self.misp_url}/attributes/restSearch",
                headers=headers,
                json=payload,
                verify=self.ssl_verify,
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json().get("response", {}).get("Attribute", [])
                if not data:
                    return {
                        "status": "not_found",
                        "indicator": indicator,
                        "threat_level": "BENIGN",
                        "confidence_score": 0,
                        "source_feeds": ["MISP"],
                        "tags": [],
                        "is_malicious": False
                    }
                return {
                    "status": "connected",
                    "indicator": indicator,
                    "threat_level": "HIGH",
                    "confidence_score": 85,
                    "source_feeds": ["MISP Live"],
                    "tags": [t.get("name") for item in data for t in item.get("Tag", [])],
                    "is_malicious": True
                }
            return {
                "status": "not_connected",
                "indicator": indicator,
                "threat_level": "UNKNOWN",
                "confidence_score": 0,
                "source_feeds": [],
                "tags": [],
                "is_malicious": False,
                "error": f"MISP API error: {resp.status_code}"
            }
        except Exception as e:
            return {
                "status": "not_connected",
                "indicator": indicator,
                "threat_level": "UNKNOWN",
                "confidence_score": 0,
                "source_feeds": [],
                "tags": [],
                "is_malicious": False,
                "error": str(e)
            }

    def push_threat_event(self, incident_payload: Dict[str, Any]) -> Dict[str, Any]:
        import requests
        headers = {
            "Authorization": self.auth_key,
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        event_body = {
            "Event": {
                "info": incident_payload.get("title", "SOC Incident Escalation"),
                "distribution": "1",  # This community only
                "threat_level_id": "2", # Medium
                "analysis": "2"       # Completed
            }
        }
        try:
            resp = requests.post(
                f"{self.misp_url}/events",
                headers=headers,
                json=event_body,
                verify=self.ssl_verify,
                timeout=15
            )
            if resp.status_code in (200, 201):
                event_data = resp.json().get("Event", {})
                return {
                    "status": "SUCCESS",
                    "event_id": str(event_data.get("id")),
                    "attribute_count": 0,
                    "error": None
                }
            return {
                "status": "FAILED",
                "event_id": "",
                "attribute_count": 0,
                "error": f"HTTP {resp.status_code} - {resp.text}"
            }
        except Exception as e:
            return {
                "status": "FAILED",
                "event_id": "",
                "attribute_count": 0,
                "error": str(e)
            }
