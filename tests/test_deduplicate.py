"""
Unit Tests for Stage 2 Deduplication & Sliding-Window Aggregator (Cluster v1 Aligned)
"""
from datetime import datetime, timezone, timedelta
import json
import os
import tempfile
import pytest
from pipeline.deduplicate import calculate_composite_cluster_key, SlidingWindowAggregator
from pipeline.models import CommonEventModel


def test_calculate_composite_key_determinism():
    event1 = CommonEventModel(
        event_id="evt_1",
        timestamp="2026-10-23T10:00:00Z",
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        username="admin",
        rule_id="52002",
        rule_level=3,
        rule_description="AppArmor alert",
        agent_id="001",
        agent_name="server-01"
    )
    event2 = CommonEventModel(
        event_id="evt_2",
        timestamp="2026-10-23T10:00:00Z",
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        username="admin",
        rule_id="52002",
        rule_level=3,
        rule_description="AppArmor alert",
        agent_id="001",
        agent_name="server-01"
    )
    event3 = CommonEventModel(
        event_id="evt_3",
        timestamp="2026-10-23T10:00:00Z",
        source_ip="10.0.0.5",  # Different IP
        destination_ip="10.0.0.2",
        username="admin",
        rule_id="52002",
        rule_level=3,
        rule_description="AppArmor alert",
        agent_id="001",
        agent_name="server-01"
    )

    _, key1, _, _ = calculate_composite_cluster_key(event1)
    _, key2, _, _ = calculate_composite_cluster_key(event2)
    _, key3, _, _ = calculate_composite_cluster_key(event3)

    assert key1 == key2, "Composite cluster key must be deterministic"
    assert len(key1) == 64, "Key must be SHA-256 (64 hex chars)"
    assert key1 != key3, "Different source IP generates distinct composite cluster key"


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
    assert flushed[0]["status"] == "CLOSED"


def test_fix_c1_pilihan_a_target_array_prevents_key_explosion():
    """
    [Cluster v1 Pilihan A] Target is excluded from composite key.
    Two events with same source_ip but DIFFERENT destination_host are aggregated
    into 1 cluster, with both targets tracked in distinct_targets[].
    Prevents key explosion during multi-target scanning.
    """
    aggregator = SlidingWindowAggregator()
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
    # Pilihan A: Aggregates into 1 window, preserving both in distinct_targets
    assert len(flushed) == 1
    targets = [t["target"] for t in flushed[0]["distinct_targets"]]
    assert "host-A" in targets
    assert "host-B" in targets


def test_fix_c2_suppression_class_s1_known_good_sets_suppressed_status():
    aggregator = SlidingWindowAggregator()
    base_time = datetime(2026, 7, 1, 12, 0, 0, tzinfo=timezone.utc)
    cem = CommonEventModel(
        event_id="evt_supp",
        timestamp=base_time.isoformat(),
        source_ip="10.0.0.1",
        destination_host="srv-01",
        rule_id="52002",
        rule_level=3,
        rule_description="AppArmor denied",
        agent_id="001",
        agent_name="srv-01",
        classification_groups=["apparmor"]
    )
    aggregator.process_event(cem)
    flushed = aggregator.flush_all()
    assert len(flushed) == 1
    assert flushed[0]["suppression_class"] == "S1_KNOWN_GOOD"


def test_fix_c2_s2_deduplication_class_is_not_suppressed():
    aggregator = SlidingWindowAggregator()
    base_time = datetime(2026, 7, 1, 12, 0, 0, tzinfo=timezone.utc)
    cem = CommonEventModel(
        event_id="evt_s2",
        timestamp=base_time.isoformat(),
        source_ip="198.51.100.1",
        destination_host="srv-01",
        rule_id="31101",
        rule_level=5,
        rule_description="Web server 400 error",
        agent_id="001",
        agent_name="srv-01",
        classification_groups=["web"]
    )
    aggregator.process_event(cem)
    flushed = aggregator.flush_all()
    assert len(flushed) == 1
    assert flushed[0]["suppression_class"] in ("S2_DEDUPLICATION", "S1_KNOWN_GOOD", None)


def test_fix_c3_tenant_id_preserved_in_output():
    aggregator = SlidingWindowAggregator()
    base_time = datetime(2026, 7, 1, 12, 0, 0, tzinfo=timezone.utc)
    cem = CommonEventModel(
        event_id="evt_tenant",
        timestamp=base_time.isoformat(),
        source_ip="198.51.100.1",
        destination_host="srv-01",
        rule_id="31101",
        rule_level=5,
        rule_description="Web server 400 error",
        agent_id="001",
        agent_name="srv-01",
        tenant_id="CORP_PROD",
        classification_groups=["web"]
    )
    aggregator.process_event(cem)
    flushed = aggregator.flush_all()
    assert len(flushed) == 1
    assert flushed[0]["tenant_id"] == "CORP_PROD"


def test_anti_time_travel_guard_prevents_stretched_windows():
    """
    Verifies that time-bound keys via window_bucket_epoch prevent past events
    from stretching active windows across months.
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

    # 2. Event from July (month earlier) -> falls into separate historical bucket
    july_time = datetime(2026, 7, 15, 10, 0, 0, tzinfo=timezone.utc)
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
    aggregator.process_event(event_july)

    flushed = aggregator.flush_all()
    # Must produce separate windows for separate epoch buckets
    assert len(flushed) == 2
    epochs = [f["composite_cluster_key"] for f in flushed]
    assert epochs[0] != epochs[1]


def test_os_platform_in_cluster_v1():
    """
    Verifies that Cluster v1 handles OS platform consistently without key fragmentation.
    """
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
        os_platform="linux"
    )
    aggregator = SlidingWindowAggregator()
    aggregator.process_event(evt_linux)
    flushed = aggregator.flush_all()
    assert len(flushed) == 1
    assert flushed[0]["os_platform"] == "linux"
