"""
Unit Tests for Stage 2 Deduplication & Sliding-Window Aggregator (Phase 4)
"""
from datetime import datetime, timezone, timedelta
import json
import os
import tempfile
import pytest
from pipeline.deduplicate import calculate_dedup_key, SlidingWindowAggregator
from pipeline.models import CommonEventModel


def test_calculate_dedup_key_determinism():
    key1 = calculate_dedup_key(rule_id="52002", src_ip="10.0.0.1", dst_ip="10.0.0.2", username="admin")
    key2 = calculate_dedup_key(rule_id="52002", src_ip="10.0.0.1", dst_ip="10.0.0.2", username="admin")
    key3 = calculate_dedup_key(rule_id="52002", src_ip="10.0.0.5", dst_ip="10.0.0.2", username="admin")

    assert key1 == key2, "Deduplication key must be deterministic"
    assert key1 != key3, "Different IP must generate distinct key"


def test_sliding_window_burst_compression():
    aggregator = SlidingWindowAggregator()
    base_time = datetime(2026, 7, 1, 12, 0, 0, tzinfo=timezone.utc)

    # Simulate 500 identical web 400 burst events in a 5-minute window
    for i in range(500):
        evt_time = base_time + timedelta(seconds=i)
        cem = CommonEventModel(
            event_id=f"evt_{i}",
            timestamp=evt_time.isoformat(),
            source_ip="198.51.100.23",
            destination_host="hportal-prod-159",
            rule_id="31101",
            rule_level=5,
            rule_description="Web server 400 error code.",
            agent_id="019",
            agent_name="hportal-prod-159",
            classification_groups=["web", "accesslog"]
        )
        aggregator.process_event(cem)

    flushed = aggregator.flush_all()
    assert len(flushed) == 1, "500 burst events within 15 mins must compress into exactly 1 AggregatedAlert"
    assert flushed[0]["event_count"] == 500
    assert len(flushed[0]["raw_evidence"]) == 500
    assert flushed[0]["status"] == "CLOSED"  # Window selesai = CLOSED. Scoring Engine yang nilai P0-P4.


# ===========================================================================
# Fix C1: Per-rule key fields from aggregation_rules.json are now applied
# ===========================================================================
def test_fix_c1_per_rule_keys_separate_windows_by_destination_host():
    """
    Rule 31101 has keys: ["rule_id","source_ip","destination_host"] in config.
    Two events with same source_ip but DIFFERENT destination_host must produce
    SEPARATE windows (2 aggregated alerts), not be merged into one.
    Before fix: both events shared the same 7-field key → 1 alert (wrong).
    After fix:  different destination_host → different dedup key → 2 alerts (correct).
    """
    # Write a minimal temp config to avoid dependency on real file path
    cfg = {
        "default_window_seconds": 900,
        "rules": {
            "31101": {
                "name": "Web server 400 error code",
                "window_seconds": 900,
                "suppression_class": "S1_KNOWN_GOOD",
                "keys": ["rule_id", "source_ip", "destination_host"],
                "progressive_escalation": True
            }
        }
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(cfg, f)
        tmp_path = f.name

    try:
        aggregator = SlidingWindowAggregator(config_path=tmp_path)
        base_time = datetime(2026, 7, 1, 12, 0, 0, tzinfo=timezone.utc)

        def make_event(idx, dst_host):
            return CommonEventModel(
                event_id=f"evt_{idx}",
                timestamp=(base_time + timedelta(seconds=idx)).isoformat(),
                source_ip="10.1.1.1",
                destination_host=dst_host,
                rule_id="31101",
                rule_level=5,
                rule_description="Web server 400 error code.",
                agent_id="019",
                agent_name="web-server-01",
                classification_groups=["web", "accesslog"]
            )

        aggregator.process_event(make_event(0, "host-A"))
        aggregator.process_event(make_event(1, "host-B"))  # Different destination_host

        flushed = aggregator.flush_all()
        assert len(flushed) == 2, (
            f"[Fix C1] Events to different destination_hosts must produce separate windows. "
            f"Got {len(flushed)} window(s)."
        )
    finally:
        os.unlink(tmp_path)


# ===========================================================================
# Fix C2: Suppression driven by Rule XML, not aggregation layer
# ===========================================================================
def test_fix_c2_suppression_class_s1_known_good_sets_suppressed_status():
    """
    Rule 52002 has suppression_class: "S1_KNOWN_GOOD" in config.
    Finalized window is now always CLOSED — suppression_class is metadata
    for Scoring Engine to consume, not for the aggregation layer to decide.
    """
    cfg = {
        "default_window_seconds": 900,
        "rules": {
            "52002": {
                "name": "Apparmor DENIED",
                "window_seconds": 900,
                "suppression_class": "S1_KNOWN_GOOD",
                "keys": ["rule_id", "agent_id", "source_ip"],
                "progressive_escalation": False
            }
        }
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(cfg, f)
        tmp_path = f.name

    try:
        aggregator = SlidingWindowAggregator(config_path=tmp_path)
        base_time = datetime(2026, 7, 1, 12, 0, 0, tzinfo=timezone.utc)

        cem = CommonEventModel(
            event_id="evt_sup_1",
            timestamp=base_time.isoformat(),
            source_ip="10.0.0.1",
            rule_id="52002",
            rule_level=3,
            rule_description="Apparmor DENIED",
            agent_id="007",
            agent_name="app-server-01",
            classification_groups=["apparmor"]
        )
        aggregator.process_event(cem)
        flushed = aggregator.flush_all()

        assert len(flushed) == 1
        assert flushed[0]["status"] == "CLOSED", (
            f"[Fix C2] Finalized window harus CLOSED. Suppression_class adalah metadata untuk Scoring Engine. "
            f"Got: {flushed[0]['status']}"
        )
    finally:
        os.unlink(tmp_path)


def test_fix_c2_s2_deduplication_class_is_not_suppressed():
    """
    Rule 31101 has suppression_class: "S1_KNOWN_GOOD" (formerly "S2_DEDUPLICATION").
    Finalized window must be CLOSED (not SUPPRESSED — that's not aggregation's job).
    """
    cfg = {
        "default_window_seconds": 900,
        "rules": {
            "31101": {
                "name": "Web server 400 error code",
                "window_seconds": 900,
                "suppression_class": "S1_KNOWN_GOOD",
                "keys": ["rule_id", "source_ip", "destination_host"],
                "progressive_escalation": True
            }
        }
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(cfg, f)
        tmp_path = f.name

    try:
        aggregator = SlidingWindowAggregator(config_path=tmp_path)
        base_time = datetime(2026, 7, 1, 12, 0, 0, tzinfo=timezone.utc)

        cem = CommonEventModel(
            event_id="evt_dedup_1",
            timestamp=base_time.isoformat(),
            source_ip="10.0.0.1",
            destination_host="web-server",
            rule_id="31101",
            rule_level=5,
            rule_description="Web server 400 error code.",
            agent_id="019",
            agent_name="web-server",
            classification_groups=["web"]
        )
        aggregator.process_event(cem)
        flushed = aggregator.flush_all()

        assert len(flushed) == 1
        assert flushed[0]["status"] == "CLOSED", (
            f"[Fix C2] Finalized window harus CLOSED. Got: {flushed[0]['status']}"
        )
    finally:
        os.unlink(tmp_path)


# ===========================================================================
# Fix C3: tenant_id in output record reflects actual event tenant_id
# ===========================================================================
def test_fix_c3_tenant_id_preserved_in_output():
    """
    Events with tenant_id="TENANT_BRAVO" must produce aggregated_alerts
    records with tenant_id="TENANT_BRAVO", not hardcoded "DEFAULT".
    Before fix: _finalize_window() always wrote "tenant_id": "DEFAULT".
    After fix:  window stores tenant_id from event and writes it to output.
    """
    aggregator = SlidingWindowAggregator()
    base_time = datetime(2026, 7, 1, 12, 0, 0, tzinfo=timezone.utc)

    cem = CommonEventModel(
        event_id="evt_tenant_1",
        timestamp=base_time.isoformat(),
        source_ip="10.20.0.5",
        rule_id="100020",
        rule_level=8,
        rule_description="Authentication Failed",
        agent_id="042",
        agent_name="dc-bravo",
        tenant_id="TENANT_BRAVO",
        classification_groups=["authentication_failed"]
    )
    aggregator.process_event(cem)
    flushed = aggregator.flush_all()

    assert len(flushed) == 1
    assert flushed[0]["tenant_id"] == "TENANT_BRAVO", (
        f"[Fix C3] Output tenant_id must reflect the event's actual tenant_id. "
        f"Got: {flushed[0]['tenant_id']!r}"
    )


# ===========================================================================
# Anti-Time-Travel Guard & Strict Window Duration Ceiling Test
# ===========================================================================
def test_anti_time_travel_guard_prevents_stretched_windows():
    """
    Verifies that if an out-of-order event from the past arrives (e.g., July event after August event),
    the aggregator closes the current window rather than stretching it across months.
    Guarantees window duration <= window_duration_seconds.
    """
    aggregator = SlidingWindowAggregator()
    
    # 1. Event from August 31
    august_time = datetime(2026, 8, 31, 15, 0, 0, tzinfo=timezone.utc)
    event_aug = CommonEventModel(
        event_id="evt_aug_1",
        timestamp=august_time.isoformat(),
        source_ip="10.0.0.1",
        destination_host="server-target",
        rule_id="52002",
        rule_level=3,
        rule_description="AppArmor alert",
        agent_id="001",
        agent_name="server-target",
        classification_groups=["apparmor"]
    )
    aggregator.process_event(event_aug)

    # 2. Event from July 1 (2 months in the past - out of order / inverted batch)
    july_time = datetime(2026, 7, 1, 10, 0, 0, tzinfo=timezone.utc)
    event_july = CommonEventModel(
        event_id="evt_july_1",
        timestamp=july_time.isoformat(),
        source_ip="10.0.0.1",
        destination_host="server-target",
        rule_id="52002",
        rule_level=3,
        rule_description="AppArmor alert",
        agent_id="001",
        agent_name="server-target",
        classification_groups=["apparmor"]
    )
    # This must close the August window and create a separate July window
    closed_aug = aggregator.process_event(event_july)
    
    assert closed_aug is not None, "August window must be closed when out-of-order July event arrives"
    assert closed_aug["event_count"] == 1
    # Duration must be <= 900 seconds
    aug_dur = (closed_aug["window_end"] - closed_aug["window_start"]).total_seconds()
    assert aug_dur <= 900
    assert closed_aug["window_duration_seconds"] == 900

    flushed = aggregator.flush_all()
    assert len(flushed) == 1, "July window must be flushed as a separate window"
    assert flushed[0]["event_count"] == 1
    july_dur = (flushed[0]["window_end"] - flushed[0]["window_start"]).total_seconds()
    assert july_dur <= 900
    assert flushed[0]["window_duration_seconds"] == 900


def test_os_platform_differentiates_aggregates():
    """
    Verify that os_platform acts as a first-class differentiator in deduplication:
    Events with identical actor, target, and rule but different os_platform
    must yield distinct canonical keys and separate aggregation windows.
    """
    from pipeline.deduplicate import calculate_canonical_dedup_key, calculate_dedup_key_dynamic

    # 1. Canonical formula verification
    key_linux = calculate_canonical_dedup_key(
        category="AUTH_FAILURE",
        actor="user:admin",
        target="srv-core-01",
        action="99991",
        tenant_id="DEFAULT",
        os_platform="linux"
    )
    key_windows = calculate_canonical_dedup_key(
        category="AUTH_FAILURE",
        actor="user:admin",
        target="srv-core-01",
        action="99991",
        tenant_id="DEFAULT",
        os_platform="windows"
    )
    assert key_linux != key_windows, "Linux and Windows events must produce distinct dedup keys"

    # 2. Dynamic key verification
    base_time = datetime(2026, 7, 1, 10, 0, 0, tzinfo=timezone.utc)
    evt_linux = CommonEventModel(
        event_id="evt_lin_1",
        timestamp=base_time.isoformat(),
        source_ip="10.0.0.1",
        destination_host="srv-core-01",
        rule_id="99991",
        rule_level=5,
        rule_description="sshd: auth failed",
        agent_id="001",
        agent_name="srv-core-01",
        event_category="AUTH_FAILURE",
        dedup_actor="user:admin",
        dedup_target="srv-core-01",
        os_platform="linux"
    )
    evt_windows = CommonEventModel(
        event_id="evt_win_1",
        timestamp=base_time.isoformat(),
        source_ip="10.0.0.1",
        destination_host="srv-core-01",
        rule_id="99991",
        rule_level=5,
        rule_description="sshd: auth failed",
        agent_id="001",
        agent_name="srv-core-01",
        event_category="AUTH_FAILURE",
        dedup_actor="user:admin",
        dedup_target="srv-core-01",
        os_platform="windows"
    )

    dyn_key_lin = calculate_dedup_key_dynamic(evt_linux, ["rule_id", "os_platform"], "99991", None)
    dyn_key_win = calculate_dedup_key_dynamic(evt_windows, ["rule_id", "os_platform"], "99991", None)
    assert dyn_key_lin != dyn_key_win, "Dynamic dedup key must separate events by os_platform"

    # 3. SlidingWindowAggregator separation verification (Canonical flow)
    aggregator = SlidingWindowAggregator()
    aggregator.process_event(evt_linux)
    aggregator.process_event(evt_windows)

    # Must create 2 distinct active windows
    assert len(aggregator.active_windows) == 2, "Events with different OS must form separate aggregation windows"
    
    flushed = aggregator.flush_all()
    assert len(flushed) == 2
    os_set = {f["os_platform"] for f in flushed}
    assert os_set == {"linux", "windows"}

    # 4. SlidingWindowAggregator separation verification (Dynamic rule-based flow with os_platform key)
    cfg = {
        "default_window_seconds": 900,
        "rules": {
            "5710": {
                "name": "sshd: auth failed",
                "window_seconds": 600,
                "keys": ["rule_id", "os_platform"]
            }
        }
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(cfg, f)
        tmp_path = f.name

    try:
        dyn_agg = SlidingWindowAggregator(config_path=tmp_path)
        e_lin = CommonEventModel(
            event_id="e_lin",
            timestamp=base_time.isoformat(),
            source_ip="10.0.0.1",
            rule_id="5710",
            rule_level=5,
            rule_description="sshd: auth failed",
            agent_id="001",
            agent_name="srv-core-01",
            os_platform="linux"
        )
        e_win = CommonEventModel(
            event_id="e_win",
            timestamp=base_time.isoformat(),
            source_ip="10.0.0.1",
            rule_id="5710",
            rule_level=5,
            rule_description="sshd: auth failed",
            agent_id="001",
            agent_name="srv-core-01",
            os_platform="windows"
        )
        dyn_agg.process_event(e_lin)
        dyn_agg.process_event(e_win)
        assert len(dyn_agg.active_windows) == 2, "Dynamic rule with os_platform must separate windows"
    finally:
        os.unlink(tmp_path)

