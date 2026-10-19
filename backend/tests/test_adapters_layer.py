"""
Unit and Integration Tests for Pipeline Adapters Layer (Wazuh, MISP, DFIR-IRIS)
==============================================================================
Verifies contracts, health checks, error simulation, and fail-safe behavior.
"""

import pytest
from datetime import datetime, timezone

from pipeline.adapters import (
    MockWazuhAdapter, MockMispAdapter, MockIrisAdapter,
    get_wazuh_adapter, get_misp_adapter, get_iris_adapter
)


class TestWazuhAdapter:
    def test_mock_wazuh_health_check(self):
        adapter = MockWazuhAdapter()
        status = adapter.health_check()
        assert status.is_connected is True
        assert status.component == "WAZUH"
        assert status.mode == "mock"

    def test_mock_wazuh_logtest_syntax_validation(self):
        adapter = MockWazuhAdapter()
        # Valid XML snippet
        valid_xml = '<rule id="100999" level="0"><description>Test suppression</description></rule>'
        res = adapter.test_rule_logtest("sample apache log 404", valid_xml)
        assert res["valid"] is True
        assert res["output_level"] == 0
        assert res["matched"] is True

        # Invalid XML missing tags
        invalid_xml = 'level="0" description="missing rule tag"'
        res_invalid = adapter.test_rule_logtest("sample log", invalid_xml)
        assert res_invalid["valid"] is False
        assert "XML syntax error" in res_invalid["error"]

    def test_mock_wazuh_deploy_and_rollback(self):
        adapter = MockWazuhAdapter()
        # 1. Deploy rule
        dep_res = adapter.deploy_rule_or_cdb(
            tenant_id="TenantA",
            artifact_type="XML_RULE",
            identifier="rule_100999",
            content="<rule id='100999' level='0'></rule>"
        )
        assert dep_res["status"] == "SUCCESS"
        assert dep_res["revision"].startswith("rev_")

        # 2. Rollback rule
        rb_ok = adapter.rollback_rule_or_cdb(
            tenant_id="TenantA",
            artifact_type="XML_RULE",
            identifier="rule_100999"
        )
        assert rb_ok is True


class TestMISPAdapter:
    def test_mock_misp_lookup_known_ip(self):
        adapter = MockMispAdapter()
        res = adapter.lookup_ioc("185.177.72.51")
        assert res["status"] == "connected"
        assert res["threat_level"] in ("HIGH", "MEDIUM")
        assert res["confidence_score"] > 0
        assert res["is_malicious"] is True

    def test_mock_misp_lookup_clean_ip(self):
        adapter = MockMispAdapter()
        res = adapter.lookup_ioc("103.19.110.156")
        assert res["status"] == "connected"
        assert res["is_malicious"] is False

    def test_mock_misp_offline_error_handling(self):
        adapter = MockMispAdapter(simulate_failure=True)
        res = adapter.lookup_ioc("185.177.72.51")
        assert res["status"] == "not_connected"
        assert res["is_malicious"] is False
        assert "offline" in res["error"]

    def test_mock_misp_push_threat_event(self):
        adapter = MockMispAdapter()
        res = adapter.push_threat_event({
            "title": "Actionable SQL Injection on hportal",
            "attacker_source_ip": "185.177.72.51",
            "target_host": "hportal-prod-159",
            "tenant_id": "TenantA"
        })
        assert res["status"] == "SUCCESS"
        assert res["event_id"].startswith("MISP-EVT-")
        assert res["attribute_count"] >= 1


class TestIRISAdapter:
    def test_mock_iris_create_case(self):
        adapter = MockIrisAdapter()
        res = adapter.create_case({
            "incident_id": "INC-TEST-1234",
            "title": "[P1] Intrusion Chain: SSH Brute Force to Sudo",
            "priority": "P1",
            "attacker_source_ip": "194.26.29.112",
            "target_host": "core-db-01",
            "tenant_id": "TenantB"
        })
        assert res["status"] == "SUCCESS"
        assert res["case_id"].startswith("CASE-")
        assert "cases/" in res["iris_url"]

    def test_mock_iris_get_case_resolution(self):
        adapter = MockIrisAdapter()
        res = adapter.create_case({
            "incident_id": "INC-TEST-5678",
            "title": "Lateral Movement Sweep"
        })
        cid = res["case_id"]

        # Initial state is OPEN / PENDING
        stat = adapter.get_case_resolution(cid)
        assert stat["status"] == "OPEN"
        assert stat["verdict"] == "PENDING"

        # Simulate analyst resolution
        adapter.resolve_case_manually(cid, verdict="TRUE_POSITIVE", notes="Attacker contained")
        updated_stat = adapter.get_case_resolution(cid)
        assert updated_stat["status"] == "CLOSED"
        assert updated_stat["verdict"] == "TRUE_POSITIVE"
        assert updated_stat["closing_notes"] == "Attacker contained"


class TestVectorAdapter:
    def test_mock_vector_health_check(self):
        from pipeline.adapters import MockVectorAdapter
        adapter = MockVectorAdapter()
        status = adapter.health_check()
        assert status.is_connected is True
        assert status.component == "VECTOR"
        assert status.mode == "mock"

    def test_mock_vector_ingest_metrics(self):
        from pipeline.adapters import MockVectorAdapter
        adapter = MockVectorAdapter()
        metrics = adapter.get_ingest_metrics()
        assert metrics["events_in"] > 0
        assert metrics["status"] == "healthy"
        assert metrics["is_backpressure"] is False

    def test_vector_config_validation(self):
        from pipeline.adapters import MockVectorAdapter
        adapter = MockVectorAdapter()
        res = adapter.validate_config("vector.toml")
        assert res["valid"] is True
        assert len(res["errors"]) == 0


class TestAdapterFactory:
    def test_factory_defaults_to_mock(self):
        from pipeline.adapters import get_vector_adapter, MockVectorAdapter
        w_adapter = get_wazuh_adapter()
        m_adapter = get_misp_adapter()
        i_adapter = get_iris_adapter()
        v_adapter = get_vector_adapter()

        assert isinstance(w_adapter, MockWazuhAdapter)
        assert isinstance(m_adapter, MockMispAdapter)
        assert isinstance(i_adapter, MockIrisAdapter)
        assert isinstance(v_adapter, MockVectorAdapter)
