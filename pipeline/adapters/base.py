"""
Pipeline Adapters Layer - Base Interfaces & Data Contracts (Ports and Adapters)
================================================================================
Defines strict abstraction boundaries for Wazuh, MISP, and DFIR-IRIS integrations.
Guarantees that core pipeline logic never directly invokes external HTTP/CLI APIs.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class AdapterStatus:
    is_connected: bool
    component: str  # 'WAZUH', 'MISP', 'IRIS'
    mode: str       # 'mock' or 'live'
    endpoint: str
    last_health_check: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "component": self.component,
            "is_connected": self.is_connected,
            "mode": self.mode,
            "endpoint": self.endpoint,
            "last_health_check": self.last_health_check.isoformat(),
            "error_message": self.error_message,
        }


class WazuhAdapterInterface(ABC):
    """
    Port interface for Wazuh SIEM Manager.
    Capabilities:
    - Pull alerts via streaming cursor
    - Validate rule XML syntax with wazuh-logtest
    - Deploy CDB lists or XML rule overrides per tenant
    - Rollback rules on failure
    """

    @abstractmethod
    def health_check(self) -> AdapterStatus:
        """Check reachability and authentication with Wazuh."""
        pass

    @abstractmethod
    def fetch_alerts(
        self,
        tenant_id: str = "DEFAULT",
        checkpoint_ts: Optional[datetime] = None,
        limit: int = 1000
    ) -> Tuple[List[Dict[str, Any]], Optional[datetime]]:
        """
        Pull raw alerts with cursor/checkpoint support.
        Returns: (alerts_list, latest_checkpoint_timestamp)
        """
        pass

    @abstractmethod
    def test_rule_logtest(self, log_sample: str, rule_xml: str) -> Dict[str, Any]:
        """
        Validate rule behavior via wazuh-logtest.
        Returns: {
            "valid": bool,
            "output_level": int,
            "rule_id": str,
            "matched": bool,
            "error": Optional[str]
        }
        """
        pass

    @abstractmethod
    def deploy_rule_or_cdb(
        self,
        tenant_id: str,
        artifact_type: str,  # 'XML_RULE' or 'CDB_LIST'
        identifier: str,     # Rule ID or List Name
        content: str
    ) -> Dict[str, Any]:
        """
        Deploy suppression rule XML or CDB list to Wazuh cluster.
        Returns: {"status": "SUCCESS" | "FAILED", "revision": str, "error": Optional[str]}
        """
        pass

    @abstractmethod
    def rollback_rule_or_cdb(
        self,
        tenant_id: str,
        artifact_type: str,
        identifier: str,
        target_revision: Optional[str] = None
    ) -> bool:
        """Rollback rule changes to prior state."""
        pass


class MISPAdapterInterface(ABC):
    """
    Port interface for MISP (Malware Information Sharing Platform).
    Capabilities:
    - Lookup IoC (IP, domain, hash) threat intelligence
    - Push confirmed actionable threat incidents and attributes
    """

    @abstractmethod
    def health_check(self) -> AdapterStatus:
        """Check reachability and authentication with MISP."""
        pass

    @abstractmethod
    def lookup_ioc(self, indicator: str, indicator_type: str = "ip-src") -> Dict[str, Any]:
        """
        Query MISP for indicator reputation.
        Returns: {
            "status": "connected" | "not_connected" | "not_found",
            "indicator": str,
            "threat_level": str,   # 'HIGH', 'MEDIUM', 'LOW', 'BENIGN', 'UNKNOWN'
            "confidence_score": int, # 0-100
            "source_feeds": List[str],
            "tags": List[str],
            "is_malicious": bool
        }
        """
        pass

    @abstractmethod
    def push_threat_event(self, incident_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Push confirmed threat IoC and forensic details to MISP.
        Returns: {"status": "SUCCESS" | "FAILED", "event_id": str, "attribute_count": int}
        """
        pass


class IRISAdapterInterface(ABC):
    """
    Port interface for DFIR-IRIS Collaborative Incident Response Platform.
    Capabilities:
    - Escalate actionable incident into DFIR-IRIS Case
    - Synchronize case resolution and human analyst verdict (True Threat vs False Positive)
    """

    @abstractmethod
    def health_check(self) -> AdapterStatus:
        """Check reachability and authentication with DFIR-IRIS."""
        pass

    @abstractmethod
    def create_case(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create new investigation case in DFIR-IRIS.
        Returns: {
            "status": "SUCCESS" | "FAILED",
            "case_id": str,
            "case_title": str,
            "iris_url": str,
            "error": Optional[str]
        }
        """
        pass

    @abstractmethod
    def get_case_resolution(self, case_id: str) -> Dict[str, Any]:
        """
        Poll or fetch analyst resolution verdict from DFIR-IRIS.
        Returns: {
            "status": "OPEN" | "RESOLVED" | "CLOSED",
            "verdict": "TRUE_POSITIVE" | "FALSE_POSITIVE" | "BENIGN" | "PENDING",
            "closing_notes": str,
            "analyst": str,
            "resolved_at": Optional[str]
        }
        """
        pass


class VectorAdapterInterface(ABC):
    """
    Port interface for Vector Pipeline Agent (Wazuh to PostgreSQL).
    Capabilities:
    - Monitor Vector daemon status and health
    - Track checkpoint offsets and buffer capacity
    - Verify ingestion throughput and prevent alert loss
    """

    @abstractmethod
    def health_check(self) -> AdapterStatus:
        """Check reachability and pipeline status of Vector."""
        pass

    @abstractmethod
    def get_ingest_metrics(self) -> Dict[str, Any]:
        """
        Get real-time metrics for Vector ingestion.
        Returns: {
            "events_in": int,
            "events_out": int,
            "buffer_bytes": int,
            "buffer_percent": float,
            "checkpoint_offset": int,
            "is_backpressure": bool
        }
        """
        pass

    @abstractmethod
    def validate_config(self, config_path: str = "vector.toml") -> Dict[str, Any]:
        """
        Validate vector.toml syntax and connectivity.
        Returns: {"valid": bool, "errors": List[str]}
        """
        pass
