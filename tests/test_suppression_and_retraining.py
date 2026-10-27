"""
Tests for Wazuh Suppression Engine & MLOps Retraining Orchestrator
==================================================================
Verifies:
1. XML rule & CDB generation for per-tenant suppression.
2. wazuh-logtest validation integration.
3. Revision tracking & rollback execution.
4. Retraining orchestrator gating safety check logic.
"""

import pytest
from pipeline.suppression_engine import WazuhSuppressionEngine
from pipeline.retraining_orchestrator import RetrainingOrchestrator
from pipeline.adapters import MockWazuhAdapter


class TestSuppressionEngine:
    def test_cdb_entry_format(self):
        engine = WazuhSuppressionEngine()
        entry = engine.generate_cdb_entry("192.168.1.55", tenant_id="TenantC")
        assert entry == "192.168.1.55:TenantC_suppressed\n"

    def test_xml_rule_structure(self):
        engine = WazuhSuppressionEngine()
        xml = engine.generate_xml_rule(
            base_rule_id="31301",
            suppression_rule_id="100501",
            tenant_id="TenantA",
            src_ip="103.19.110.156",
            reason="Authorized Crawler 404 Suppression"
        )
        assert '<rule id="100501" level="0">' in xml
        assert '<if_sid>31301</if_sid>' in xml
        assert '<srcip>103.19.110.156</srcip>' in xml
        assert '<options>no_log</options>' in xml

    def test_logtest_validation_pass(self):
        mock_wazuh = MockWazuhAdapter()
        engine = WazuhSuppressionEngine(wazuh_adapter=mock_wazuh)
        valid_xml = '<rule id="100999" level="0"><if_sid>31301</if_sid></rule>'
        res = engine.test_and_validate_rule(valid_xml, "sample 404 log")
        assert res["valid"] is True
        assert res["output_level"] == 0

    def test_deploy_and_rollback_flow(self):
        mock_wazuh = MockWazuhAdapter()
        engine = WazuhSuppressionEngine(wazuh_adapter=mock_wazuh)
        
        # 1. Deploy
        dep = engine.deploy_suppression(
            tenant_id="TenantA",
            artifact_type="XML_RULE",
            identifier="suppress_31301",
            content="<rule id='100501' level='0'></rule>"
        )
        assert dep["status"] == "SUCCESS"
        assert dep["revision"].startswith("rev_")

        # 2. Rollback
        rb_ok = engine.rollback_suppression(
            tenant_id="TenantA",
            artifact_type="XML_RULE",
            identifier="suppress_31301"
        )
        assert rb_ok is True


class TestRetrainingOrchestrator:
    def test_untrained_samples_count(self):
        orchestrator = RetrainingOrchestrator()
        count = orchestrator.count_new_ground_truth_samples()
        assert isinstance(count, int)
        assert count >= 0
