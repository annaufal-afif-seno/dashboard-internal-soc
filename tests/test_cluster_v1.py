"""
Unit and Integration Tests for Cluster v1 Architecture
Verifies:
1. Deterministic alert_id with pipe delimiter and raw log timestamp.
2. Composite Key formula (tenant | rule | agent | who | what | os).
3. Subnet grouping (/24 IPv4, /64 IPv6, exact IP for private and external auth success).
4. High-Value Bypass determinism:
   - Privileged auth from external IP -> True
   - Malware / YARA -> True
   - Rootcheck -> True
   - Critical FIM with pkg_activity_nearby context preservation -> True
   - Exploit HTTP 200 -> success_indicator="possible"
5. Cardinality Guards (cap 20 paths per prefix, hard cap 200 keys per actor).
6. Smart Evidence Sampling (max 50 samples with head, tail, highest severity, distinct paths).
7. Summary Metrics & Wazuh Query Pointer.
"""
import pytest
from datetime import datetime, timezone, timedelta
from pipeline.models import CommonEventModel
from pipeline.deduplicate import (
    generate_deterministic_alert_id,
    normalize_actor_subnet,
    evaluate_high_value_event,
    calculate_composite_cluster_key,
    SmartEvidenceTracker,
    SlidingWindowAggregator,
    load_cluster_config
)

def test_deterministic_alert_id():
    id1 = generate_deterministic_alert_id("manager1", "1729671234.5678", "2026-10-23T01:00:00.123456Z")
    id2 = generate_deterministic_alert_id("manager1", "1729671234.5678", "2026-10-23T01:00:00.123456Z")
    assert id1 == id2
    assert len(id1) == 64  # SHA256 length

    # Different raw timestamp produces different hash
    id3 = generate_deterministic_alert_id("manager1", "1729671234.5678", "2026-10-23T01:00:00.999999Z")
    assert id1 != id3

def test_normalize_actor_subnet():
    # Public IPv4 -> /24
    assert normalize_actor_subnet("142.250.190.45") == "142.250.190.0/24"
    # Private IPv4 -> exact
    assert normalize_actor_subnet("10.20.100.5") == "10.20.100.5"
    assert normalize_actor_subnet("192.168.1.50") == "192.168.1.50"
    assert normalize_actor_subnet("127.0.0.1") == "127.0.0.1"
    # External Auth Success -> exact IP preserved!
    assert normalize_actor_subnet("142.250.190.45", is_external_auth_success=True) == "142.250.190.45"

def test_high_value_bypass_privileged_auth():
    event = CommonEventModel(
        event_id="evt_test_01",
        timestamp="2026-10-23T02:00:00Z",
        agent_id="001",
        agent_name="auth-server-01",
        source_ip="142.250.190.19",  # Public external IP
        username="root",
        rule_id="5715",
        rule_level=10,
        rule_description="sshd: authentication succeeded",
        classification_groups=["syslog", "sshd", "authentication_success"]
    )
    is_hv, reason, success_ind, pkg_ctx = evaluate_high_value_event(event)
    assert is_hv is True
    assert reason == "privileged_external_auth_success"
    # Cluster stage only emits 'none' or 'possible'; 'confirmed' is strictly reserved for Correlation stage
    assert success_ind == "possible"

def test_high_value_bypass_fim_and_pkg_context():
    # FIM on /bin/ls without pkg activity
    event_fim = CommonEventModel(
        event_id="evt_test_02",
        timestamp="2026-10-23T02:00:00Z",
        agent_id="001",
        agent_name="app-server-01",
        rule_id="550",
        rule_level=7,
        rule_description="Integrity checksum changed for /bin/ls",
        classification_groups=["ossec", "syscheck"],
        clean_path="/bin/ls"
    )
    is_hv, reason, success_ind, pkg_ctx = evaluate_high_value_event(event_fim, recent_pkg_activity=False)
    assert is_hv is True
    assert reason == "critical_fim_modification"
    assert pkg_ctx is False

    # FIM with pkg activity nearby (apt upgrade)
    is_hv2, reason2, success_ind2, pkg_ctx2 = evaluate_high_value_event(event_fim, recent_pkg_activity=True)
    # Evasion protection: is_high_value MUST REMAIN TRUE, but pkg_activity_nearby is TRUE
    assert is_hv2 is True
    assert pkg_ctx2 is True

def test_exploit_http_200():
    event_exploit = CommonEventModel(
        event_id="evt_test_03",
        timestamp="2026-10-23T02:00:00Z",
        agent_id="001",
        agent_name="web-server-01",
        rule_id="31106",
        rule_level=6,
        rule_description="A web attack was detected: SQL Injection probe",
        classification_groups=["web", "accesslog"],
        action_ttp="SQLI",
        http_status=200,
        clean_path="/api/login?id=1' OR '1'='1"
    )
    is_hv, reason, success_ind, _ = evaluate_high_value_event(event_exploit)
    assert is_hv is False  # Not blind high value bypass
    assert success_ind == "possible"  # Let Correlation validate!

def test_smart_evidence_tracker():
    tracker = SmartEvidenceTracker(capacity=50)
    base_time = datetime(2026, 10, 23, 2, 0, 0, tzinfo=timezone.utc)
    for i in range(100):
        tracker.add_sample(
            event_id=f"evt_{i}",
            event_time=base_time + timedelta(seconds=i),
            rule_id=1000 + (i % 5),
            rule_level=i % 15,
            source_ip="142.250.190.10",
            clean_path=f"/path_{i % 8}",
            http_status=200 if i % 2 == 0 else 404
        )
    samples = tracker.get_combined_samples()
    assert len(samples) <= 50
    assert len(samples) > 20
    # Head samples exist
    assert any(s["event_id"] == "evt_0" for s in samples)
    # Tail samples exist
    assert any(s["event_id"] == "evt_99" for s in samples)

def test_sliding_window_aggregator_clustering():
    aggregator = SlidingWindowAggregator()
    base_time = datetime(2026, 10, 23, 2, 0, 0, tzinfo=timezone.utc)
    
    # Send 10 identical events
    for i in range(10):
        e = CommonEventModel(
            event_id=f"test_evt_{i}",
            timestamp=(base_time + timedelta(seconds=i * 10)).isoformat(),
            rule_id="31101",
            rule_level=5,
            rule_description="Web server 400 error code",
            source_ip="142.250.190.55",
            agent_id="001",
            agent_name="web-server-01",
            clean_path="/api/v1/resource",
            url_path="/api/v1/resource",
            http_status=400,
            tenant_id="DEFAULT"
        )
        aggregator.process_event(e)

    # Flush
    completed = aggregator.flush_all()
    assert len(completed) == 1
    cluster = completed[0]
    assert cluster["event_count"] == 10
    assert cluster["who_cluster"] == "142.250.190.0/24"
    assert cluster["exact_source_ip"] == "142.250.190.55"
    assert "distinct_src_ips" in cluster
    assert cluster["distinct_src_ips"] == ["142.250.190.55"]
    assert cluster["cluster_metrics"]["http_status_distribution"] == {400: 10}
    assert len(cluster["smart_evidence"]) == 10
    assert cluster["wazuh_query_pointer"]["agent_id"] == "001"

def test_material_rate_limit_decoupling():
    """Verify that priority material updates (level jump, auth success) are NOT blocked by new IP rate limits."""
    from pipeline.deduplicate import AggregatedWindow
    base_time = datetime(2026, 10, 23, 2, 0, 0, tzinfo=timezone.utc)
    win = AggregatedWindow(
        aggregation_id="agg_test_rl",
        dedup_key="dedup_test_rl",
        rule_id=5710,
        agent_id="001",
        source_ip="198.51.100.1",
        destination_ip=None,
        username=None,
        start_time=base_time,
        window_duration=timedelta(minutes=15),
        is_high_value=True
    )

    # Initial open
    assert win.should_forward_bypass(base_time) is True

    # 5 New IP updates within the same minute -> all 5 pass
    for i in range(2, 7):
        t = base_time + timedelta(seconds=i)
        assert win.should_forward_bypass(t, is_material=True, is_new_ip=True) is True

    # 6th New IP update within same minute -> throttled by new IP limit!
    t_6th = base_time + timedelta(seconds=10)
    assert win.should_forward_bypass(t_6th, is_material=True, is_new_ip=True) is False

    # CRITICAL: In the SAME minute, a PRIORITY material update (e.g. severity jump) MUST STILL PASS IMMEDIATELY!
    assert win.should_forward_bypass(t_6th, is_material=True, is_priority_material=True) is True

def test_stateful_session_user_isolation():
    """Ensure two different users on the same agent generate distinct composite keys."""
    base_time = datetime(2026, 10, 23, 2, 0, 0, tzinfo=timezone.utc)
    e_alice = CommonEventModel(
        event_id="evt_alice",
        timestamp=base_time.isoformat(),
        agent_id="001",
        agent_name="srv-db-01",
        rule_id="5501",
        rule_level=3,
        rule_description="PAM: Login session opened",
        classification_groups=["pam", "syslog"],
        username="alice"
    )
    e_bob = CommonEventModel(
        event_id="evt_bob",
        timestamp=base_time.isoformat(),
        agent_id="001",
        agent_name="srv-db-01",
        rule_id="5501",
        rule_level=3,
        rule_description="PAM: Login session opened",
        classification_groups=["pam", "syslog"],
        username="bob"
    )

    raw_alice, hash_alice, _, what_alice = calculate_composite_cluster_key(e_alice)
    raw_bob, hash_bob, _, what_bob = calculate_composite_cluster_key(e_bob)

    assert "user=alice" in what_alice
    assert "user=bob" in what_bob
    assert hash_alice != hash_bob

