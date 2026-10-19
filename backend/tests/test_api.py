"""
Unit and Integration Tests for FastAPI SOC Dashboard Backend (Package 5)
"""
import pytest
from fastapi.testclient import TestClient
from pipeline.api import app

client = TestClient(app)

def test_api_root():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ONLINE"
    assert "database" in data

def test_api_metrics_overview():
    response = client.get("/api/metrics/overview")
    assert response.status_code == 200
    data = response.json()
    assert "total_raw_events" in data
    assert "noise_reduction_percentage" in data
    assert "priority_distribution" in data
    assert len(data["priority_distribution"]) >= 4
    assert "ticket_overview" in data
    assert "sla_compliance_pct" in data["ticket_overview"]
    assert 0 <= data["ticket_overview"]["sla_compliance_pct"] <= 100

def test_api_triage_queue():
    response = client.get("/api/triage/queue")
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "incidents" in data
    assert isinstance(data["incidents"], list)

def test_api_suppression_rules():
    response = client.get("/api/suppression/rules")
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "rules" in data
    assert isinstance(data["rules"], list)

def test_api_suppression_rule_sla_validation():
    """Verify that suppression rule validity exceeding 180 days is rejected with HTTP 400."""
    response = client.post("/api/suppression/rules", json={
        "name": "Excessive Validity Policy",
        "classification": "KNOWN GOOD",
        "sids": [52002],
        "owner": "secops_analyst",
        "approver": "soc_lead_alice",
        "expiration": "2030-01-01",
        "reason": "Test SLA compliance rejection"
    })
    assert response.status_code == 400
    assert "SLA Governance Breach" in response.json()["detail"]

def test_api_suppression_rule_sod_validation():
    """Verify that author == approver violates Separation of Duties with HTTP 400."""
    response = client.post("/api/suppression/rules", json={
        "name": "SOD Violation Policy",
        "classification": "KNOWN GOOD",
        "sids": [52002],
        "owner": "soc_lead_alice",
        "approver": "soc_lead_alice",
        "expiration": "2026-10-01",
        "reason": "Test SOD rejection"
    })
    assert response.status_code == 400
    assert "Separation of Duties" in response.json()["detail"]

def test_api_export_wazuh_xml():
    """Verify that export endpoint returns valid Wazuh XML snippet."""
    response = client.get("/api/suppression/export/wazuh-xml")
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert "xml" in data
    assert "<group name=" in data["xml"]
    assert "</group>" in data["xml"]
    assert "rule_count" in data


def test_api_export_cdb_lists():
    """Verify that export endpoint returns CDB formatted whitelist files."""
    response = client.get("/api/suppression/export/cdb-lists")
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert "files" in data
    assert "/var/ossec/etc/lists/asoc-whitelist-ips" in data["files"]
    assert "/var/ossec/etc/lists/asoc-whitelist-hosts" in data["files"]


def test_api_suppression_rules_tri_track_fields():
    """Verify that suppression rules endpoint returns tri-track governance attributes."""
    response = client.get("/api/suppression/rules")
    assert response.status_code == 200
    data = response.json()
    assert "rules" in data
    if len(data["rules"]) > 0:
        rule = data["rules"][0]
        assert "enforcementMode" in rule
        assert "wazuhXmlSnippet" in rule
        assert "cdbSnippet" in rule
        assert "status" in rule
        assert rule["enforcementMode"] in ("PIPELINE_MUTE", "WAZUH_XML", "WAZUH_CDB", "HYBRID")

