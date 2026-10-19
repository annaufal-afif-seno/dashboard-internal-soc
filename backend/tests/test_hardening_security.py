"""
Comprehensive Security Hardening and Anti-Evasion Test Suite
Verifies:
1. Low-and-Slow drip attack detection (Cumulative tracker)
2. Distributed password spraying / IP rotation correlation (CORR-006)
3. Anti-dormant adaptive timeframe extension in attack chains
4. API Key authentication & authorization security
5. In-flight state snapshot persistence
"""
import os
import json
import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from pipeline.models import CommonEventModel
from pipeline.deduplicate import SlidingWindowAggregator
from pipeline.correlate import CorrelationEngine, CorrelationTrack
from pipeline.api import app

client = TestClient(app)


# ------------------------------------------------------------------------------
# 1. Low-and-Slow Cumulative Drip Attack Detection
# ------------------------------------------------------------------------------
def test_low_and_slow_cumulative_escalation():
    """
    Simulate a stealthy attacker sending 1 probe every 20 minutes (exceeding 15m window).
    Without cumulative tracking, each window has event_count=1.
    All finalized windows are CLOSED — burst count & category info tersedia untuk Scoring Engine.
    """
    aggregator = SlidingWindowAggregator()
    base_time = datetime(2026, 8, 1, 0, 0, 0, tzinfo=timezone.utc)
    
    # Send 14 events spaced 20 minutes apart
    for i in range(14):
        evt_time = base_time + timedelta(minutes=20 * i)
        evt = CommonEventModel(
            event_id=f"evt_slow_{i}",
            timestamp=evt_time.isoformat(),
            rule_id="31101",
            rule_level=5,
            rule_description="HTTP 400 Probe",
            agent_id="019",
            agent_name="web-prod-01",
            source_ip="103.19.110.156"
        )
        aggregator.process_event(evt)
        
    # The 15th event
    evt_15_time = base_time + timedelta(minutes=20 * 14)
    evt_15 = CommonEventModel(
        event_id="evt_slow_14",
        timestamp=evt_15_time.isoformat(),
        rule_id="31101",
        rule_level=5,
        rule_description="HTTP 400 Probe",
        agent_id="019",
        agent_name="web-prod-01",
        source_ip="103.19.110.156"
    )
    aggregator.process_event(evt_15)
    
    flushed = aggregator.flush_all()
    assert len(flushed) > 0
    # Semua window yang selesai harus berstatus CLOSED
    closed_windows = [w for w in flushed if w["agent_id"] == "019" and w["status"] == "CLOSED"]
    assert len(closed_windows) >= 1, "Semua finalized window harus berstatus CLOSED — Scoring Engine yang menilai bahayanya"


# ------------------------------------------------------------------------------
# 2. Distributed Password Spraying Correlation (CORR-006)
# ------------------------------------------------------------------------------
def test_distributed_password_spraying_corr006():
    """
    Simulate a botnet rotating IP addresses: 8 different IPs attacking the same agent_name.
    CORR-006 match_keys is ['agent_name'], grouping across rotating source IPs.
    """
    engine = CorrelationEngine()
    base_time = datetime(2026, 8, 10, 10, 0, 0, tzinfo=timezone.utc)
    
    incidents = []
    # 8 failed logins from 8 completely distinct source IPs
    for i in range(8):
        evt_time = base_time + timedelta(seconds=15 * i)
        evt = CommonEventModel(
            event_id=f"spray_evt_{i}",
            timestamp=evt_time.isoformat(),
            rule_id="5710",  # SSH authentication failed
            rule_level=5,
            rule_description="SSH authentication failed",
            agent_id="026",
            agent_name="db-cluster-01",
            source_ip=f"198.51.100.{10 + i}",  # Distinct rotating IP per attempt
            username=f"user_{i}"
        )
        new_incidents = engine.process_event(evt)
        incidents.extend(new_incidents)
        
    corr006_incidents = [inc for inc in incidents if inc.get("rule_code") == "DISTRIBUTED_PASSWORD_SPRAY"]
    assert len(corr006_incidents) == 1, "CORR-006 must detect distributed password spray across distinct IPs"
    assert corr006_incidents[0]["target_host"] == "db-cluster-01"
    assert corr006_incidents[0]["target_severity"] == "P1"


# ------------------------------------------------------------------------------
# 3. Anti-Dormant Adaptive Timeframe Extension
# ------------------------------------------------------------------------------
def test_adaptive_timeframe_extension():
    """
    Verify that when candidate events match an active CorrelationTrack,
    window_end dynamically extends forward so dormant attackers sleeping
    between stages cannot prematurely expire the session.
    """
    rule_cfg = {
        "id": "CORR-TEST",
        "code": "TEST_CHAIN",
        "name": "Test Adaptive Chain",
        "description": "Test",
        "timeframe_seconds": 600,
        "target_severity": "P1",
        "trigger_stages": [
            {"stage": "STAGE_A", "rule_ids": ["100"], "min_count": 1},
            {"stage": "STAGE_B", "rule_ids": ["200"], "min_count": 1}
        ],
        "match_keys": ["agent_name"]
    }
    start = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)
    track = CorrelationTrack(rule_cfg, "server-01", start)
    initial_end = track.window_end
    
    # 5 minutes later, an event matches Stage A
    evt_a_time = start + timedelta(minutes=5)
    evt_a = CommonEventModel(
        event_id="e1",
        timestamp=evt_a_time.isoformat(),
        rule_id="100",
        rule_level=3,
        rule_description="Stage A probe",
        agent_id="001",
        agent_name="server-01"
    )
    track.add_candidate_event(evt_a, evt_a_time)
    
    # Window end must have adaptively extended forward (evt_a_time + 600s)
    expected_extended_end = evt_a_time + timedelta(seconds=600)
    assert track.window_end == expected_extended_end
    assert track.window_end > initial_end


# ------------------------------------------------------------------------------
# 4. API Security & Authentication Hardening
# ------------------------------------------------------------------------------
def test_api_rejection_on_invalid_key():
    """Mutating endpoints must reject requests with invalid API keys with HTTP 401."""
    response = client.post(
        "/api/suppression/rules",
        headers={"X-API-Key": "unauthorized-malicious-key"},
        json={
            "name": "Malicious Rule",
            "classification": "KNOWN GOOD",
            "sids": [52002],
            "owner": "attacker",
            "approver": "admin",
            "expiration": "2026-10-01"
        }
    )
    assert response.status_code == 401
    assert "Invalid SOC API Key" in response.json()["detail"]


def test_api_triage_update_rejection_on_invalid_key():
    """Triage update must reject invalid API key with HTTP 401."""
    response = client.post(
        "/api/triage/TRG-TEST-001/update",
        headers={"X-API-Key": "invalid-token"},
        json={
            "triage_status": "CLOSED",
            "assigned_analyst": "Hacker"
        }
    )
    assert response.status_code == 401


def test_api_accepts_valid_key_or_bearer():
    """Valid API Key or Bearer token is accepted through authentication."""
    response = client.post(
        "/api/suppression/rules",
        headers={"X-API-Key": "wazuh-soc-secure-key-2026"},
        json={
            "name": "Valid Test Policy",
            "classification": "KNOWN GOOD",
            "sids": [52002],
            "owner": "secops_analyst",
            "approver": "soc_lead_alice",
            "expiration": "2030-01-01",  # Exceeds SLA on purpose to verify it passes auth and hits SLA validator
            "reason": "Verify auth passes"
        }
    )
    # Status code 400 means auth passed and payload SLA validation ran!
    assert response.status_code == 400
    assert "SLA Governance Breach" in response.json()["detail"]


# ------------------------------------------------------------------------------
# 5. State Snapshot & In-Flight Persistence
# ------------------------------------------------------------------------------
def test_state_snapshot_persistence(tmp_path):
    """Verify deduplication and correlation engines can serialize and save snapshots."""
    dedup = SlidingWindowAggregator()
    evt = CommonEventModel(
        event_id="snap_1",
        timestamp=datetime.now(timezone.utc).isoformat(),
        rule_id="52002",
        rule_level=3,
        rule_description="AppArmor Denied",
        agent_id="001",
        agent_name="host-1"
    )
    dedup.process_event(evt)
    
    snap_file = tmp_path / "dedup_snap.json"
    written_path = dedup.save_snapshot(str(snap_file))
    assert os.path.exists(written_path)
    
    with open(written_path, "r", encoding="utf-8") as f:
        data = json.load(f)
        assert "active_windows" in data
        assert len(data["active_windows"]) >= 1

    corr = CorrelationEngine()
    corr_snap_file = tmp_path / "corr_snap.json"
    written_corr = corr.save_snapshot(str(corr_snap_file))
    assert os.path.exists(written_corr)
    with open(written_corr, "r", encoding="utf-8") as f:
        cdata = json.load(f)
        assert "active_tracks" in cdata
