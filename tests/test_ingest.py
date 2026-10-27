"""
Unit Tests for Streaming Ingestion Engine & Pydantic Data Models (Phase 1)
"""
import os
import pytest
from pipeline.models import WazuhRawAlert, RuleModel, AgentModel, CommonEventModel
from pipeline.ingest import AlertStreamReader
from config.settings import DATA_DIR


def test_wazuh_raw_alert_model():
    sample_data = {
        "_id": "test_123",
        "timestamp": "2026-07-01T12:00:00.000+0000",
        "rule": {
            "id": "52002",
            "level": 3,
            "description": "Apparmor DENIED",
            "groups": ["apparmor", "syslog"]
        },
        "agent": {
            "id": "001",
            "name": "hportal-prod-159",
            "ip": "10.0.0.1"
        },
        "data": {
            "status": "DENIED",
            "extra_data": "profile_name"
        }
    }
    alert = WazuhRawAlert.model_validate(sample_data)
    assert alert.id == "test_123"
    assert alert.rule.id == "52002"
    assert alert.rule.level == 3
    assert alert.agent.name == "hportal-prod-159"


def test_common_event_model_creation():
    cem = CommonEventModel(
        event_id="evt_001",
        timestamp="2026-07-01T12:00:00.000+0000",
        source_ip="192.168.1.100",
        destination_ip="10.0.0.5",
        username="admin",
        agent_id="001",
        agent_name="hportal-prod-159",
        rule_id="31101",
        rule_level=5,
        rule_description="Web server 400 error code.",
        classification_groups=["web", "accesslog"]
    )
    assert cem.event_id == "evt_001"
    assert cem.rule_id == "31101"
    assert cem.rule_level == 5
    assert cem.host_criticality == "STANDARD"


def test_stream_reader_week1_sample():
    week1_file = os.path.join(DATA_DIR, "alerts_raw_week1_20260628_20260704.json")
    if not os.path.exists(week1_file):
        pytest.skip(f"Dataset file not found: {week1_file}")

    reader = AlertStreamReader(week1_file, chunk_size=5000)
    sample_count = 0
    for cem in reader.stream_normalized_events():
        sample_count += 1
        assert cem.event_id is not None
        assert cem.timestamp is not None
        assert cem.rule_id is not None
        if sample_count >= 1000:
            break

    assert sample_count == 1000
    assert reader.total_corrupt_lines == 0
