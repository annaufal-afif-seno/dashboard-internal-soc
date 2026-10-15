"""
Wazuh Multi-Tenant Suppression Engine & wazuh-logtest Automation
================================================================
Implements closed-loop feedback (Tahap 9 & Loop 3):
1. Translates approved Benign / FP tickets into per-tenant Wazuh XML rules or CDB lists.
2. Executes wazuh-logtest verification before applying changes.
3. Deploys rules per tenant via WazuhAdapter with Git-based revision rollback.
"""

import os
import sys
import logging
import psycopg2
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from config.settings import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD
from pipeline.adapters import get_wazuh_adapter

logger = logging.getLogger(__name__)


class WazuhSuppressionEngine:
    """Manages the lifecycle of Wazuh suppression proposals and enforcement."""

    def __init__(self, wazuh_adapter=None):
        self.adapter = wazuh_adapter or get_wazuh_adapter()

    def generate_cdb_entry(self, ip_address: str, tenant_id: str = "DEFAULT") -> str:
        """Format CDB list entry: {ip_address}:{tenant_id}_suppressed."""
        return f"{ip_address}:{tenant_id}_suppressed\n"

    def generate_xml_rule(
        self,
        base_rule_id: str,
        suppression_rule_id: str,
        tenant_id: str = "DEFAULT",
        src_ip: Optional[str] = None,
        reason: str = "Automated AI Triage False Positive Suppression"
    ) -> str:
        """Generate a valid child Wazuh XML rule (level 0) with tenant boundary."""
        ip_clause = f"    <srcip>{src_ip}</srcip>\n" if src_ip and src_ip != "unknown" else ""
        return (
            f'<!-- Automated Suppression Rule for Tenant: {tenant_id} -->\n'
            f'<group name="tenant_{tenant_id.lower()},suppression,">\n'
            f'  <rule id="{suppression_rule_id}" level="0">\n'
            f'    <if_sid>{base_rule_id}</if_sid>\n'
            f'{ip_clause}'
            f'    <description>{reason}</description>\n'
            f'    <options>no_log</options>\n'
            f'  </rule>\n'
            f'</group>\n'
        )

    def test_and_validate_rule(
        self,
        rule_xml: str,
        log_sample: str = "Sample log triggering base rule"
    ) -> Dict[str, Any]:
        """Validate candidate XML rule via wazuh-logtest."""
        return self.adapter.test_rule_logtest(log_sample, rule_xml)

    def deploy_suppression(
        self,
        tenant_id: str,
        artifact_type: str,
        identifier: str,
        content: str
    ) -> Dict[str, Any]:
        """Deploy rule or CDB list to Wazuh cluster via adapter."""
        return self.adapter.deploy_rule_or_cdb(
            tenant_id=tenant_id,
            artifact_type=artifact_type,
            identifier=identifier,
            content=content
        )

    def rollback_suppression(
        self,
        tenant_id: str,
        artifact_type: str,
        identifier: str
    ) -> bool:
        """Rollback rule changes via adapter."""
        return self.adapter.rollback_rule_or_cdb(
            tenant_id=tenant_id,
            artifact_type=artifact_type,
            identifier=identifier
        )
