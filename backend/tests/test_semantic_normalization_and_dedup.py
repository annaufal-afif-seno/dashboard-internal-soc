"""
Unit tests for Semantic Normalization Layer, Canonical Dedup Key,
and Proportional Threshold Escalation with GRC Guardrails.
"""
from datetime import datetime, timezone, timedelta
from pipeline.models import CommonEventModel
from pipeline.ingest import classify_event_archetype
from pipeline.deduplicate import (
    calculate_canonical_dedup_key,
    SlidingWindowAggregator,
    AggregatedWindow
)


def test_classify_event_archetype_auth():
    """Verify SSH / login alerts map to AUTH_FAILURE, FAST (600s), with correct Actor and Target."""
    cat, actor, target, win_class, dur = classify_event_archetype(
        groups=["authentication_failed", "sshd"],
        rule_id="5710",
        rule_level=5,
        source_ip="103.152.24.10",
        destination_host="srv-prod-01",
        destination_ip="192.168.1.10",
        username="root",
        process_name="sshd",
        agent_name="srv-prod-01"
    )
    assert cat == "AUTH_FAILURE"
    assert actor == "user:root"
    assert target == "srv-prod-01"
    assert win_class == "FAST"
    assert dur == 600


def test_classify_event_archetype_network():
    """Verify Web attack / scanner alerts map to DISCOVERY (Tier 0), STANDARD (900s)."""
    cat, actor, target, win_class, dur = classify_event_archetype(
        groups=["web", "accesslog", "attack"],
        rule_id="31101",
        rule_level=6,
        source_ip="185.220.101.5",
        destination_host="portal.domain.com",
        destination_ip="192.168.30.158",
        username=None,
        process_name=None,
        agent_name="web-portal"
    )
    assert cat in ("DISCOVERY", "WEB_ATTACK", "WEB_OPERATIONAL")
    assert actor == "185.220.101.5"
    assert target == "portal.domain.com"
    assert win_class == "STANDARD"
    assert dur == 900


def test_classify_event_archetype_telemetry():
    """
    Rule 52002 (AppArmor DENIED container op) terdaftar di rule_classification_mapping.json
    sebagai cat=PROCESS_EXECUTION → internal_cat=EXECUTION (Tier 0, single source of truth).
    Test ini memverifikasi Tier 0 lookup bekerja dan menghasilkan hasil yang lebih presisi
    daripada fallback lama.
    """
    cat, actor, target, win_class, dur = classify_event_archetype(
        groups=["apparmor", "security"],
        rule_id="52002",
        rule_level=3,
        source_ip=None,
        destination_host=None,
        destination_ip=None,
        username=None,
        process_name="dockerd",
        agent_name="elastic-prod-239"
    )
    # Tier 0 (rule_classification_mapping.json) → PROCESS_EXECUTION → EXECUTION
    assert cat == "EXECUTION"
    assert actor == "proc:dockerd"         # process_name for EXECUTION category
    assert target == "elastic-prod-239"  # agent_name fallback
    assert win_class == "STANDARD"
    assert dur == 900

    # Verify pure VULNERABILITY works for vulnerability rule
    cat2, actor2, target2, win_class2, dur2 = classify_event_archetype(
        groups=["vulnerability-detector"],
        rule_id="99998",              # Not in mapping → falls to Tier 1 VULNERABILITY
        rule_level=3,
        source_ip=None,
        destination_host=None,
        destination_ip=None,
        username=None,
        process_name=None,
        agent_name="host-a"
    )
    assert cat2 == "VULNERABILITY"
    assert win_class2 == "SLOW"
    assert dur2 == 3600


def test_classify_event_archetype_novel_fallback():
    """Verify unexpected/novel alert format safely falls back based on entity presence."""
    cat, actor, target, win_class, dur = classify_event_archetype(
        groups=["unknown_k8s_audit"],
        rule_id="99999",
        rule_level=7,
        source_ip="10.0.0.99",
        destination_host="k8s-api",
        destination_ip=None,
        username=None,
        process_name=None,
        agent_name="k8s-node"
    )
    assert cat == "WEB_OPERATIONAL"
    assert actor == "10.0.0.99"
    assert target == "k8s-api"
    assert dur == 900


def test_canonical_dedup_key_determinism_and_uniqueness():
    """Verify canonical 4-dimensional dedup key is deterministic and separates boundaries."""
    key_auth_root = calculate_canonical_dedup_key("AUTH", "103.152.24.10", "root", "5710")
    key_auth_admin = calculate_canonical_dedup_key("AUTH", "103.152.24.10", "admin", "5710")
    key_auth_root_repeat = calculate_canonical_dedup_key("AUTH", "103.152.24.10", "root", "5710")

    assert key_auth_root == key_auth_root_repeat
    assert key_auth_root != key_auth_admin


def test_finalized_window_always_closed():
    """Verify finalized window status is always CLOSED regardless of event count or category.
    ESCALATED/SUPPRESSED decisions belong to Scoring Engine and Rule XML, not aggregation."""
    agg = SlidingWindowAggregator()
    base_time = datetime(2026, 7, 14, 10, 0, 0, tzinfo=timezone.utc)

    # AUTH window dengan event count besar — tetap CLOSED
    window_auth = AggregatedWindow(
        aggregation_id="test_closed_auth",
        dedup_key="key_closed_auth",
        rule_id=5710,
        agent_id="001",
        source_ip="1.2.3.4",
        destination_ip=None,
        username="root",
        start_time=base_time,
        window_duration=timedelta(seconds=600),
        category="AUTH"
    )
    window_auth.event_count = 200
    res = agg._finalize_window(window_auth)
    assert res["status"] == "CLOSED", "Window yang selesai harus selalu CLOSED"
    assert res["event_count"] == 200, "Event count harus terekam untuk dikonsumsi Scoring Engine"
    assert res["category"] == "AUTH"

    # TELEMETRY window — juga CLOSED, bukan SUPPRESSED
    window_telemetry = AggregatedWindow(
        aggregation_id="test_closed_telem",
        dedup_key="key_closed_telem",
        rule_id=52002,
        agent_id="001",
        source_ip=None,
        destination_ip=None,
        username=None,
        start_time=base_time,
        window_duration=timedelta(seconds=3600),
        category="TELEMETRY"
    )
    window_telemetry.event_count = 500
    res_telem = agg._finalize_window(window_telemetry)
    assert res_telem["status"] == "CLOSED", "TELEMETRY window yang selesai harus CLOSED, bukan SUPPRESSED"
    assert res_telem["event_count"] == 500, "Event count tetap tersimpan untuk referensi Scoring Engine"


def test_aggregated_alert_semantic_readable_fields():
    """Verify category, actor, target, and window_duration_seconds are present and correct in finalized aggregate."""
    agg = SlidingWindowAggregator()
    base_time = datetime(2026, 7, 14, 10, 0, 0, tzinfo=timezone.utc)

    window = AggregatedWindow(
        aggregation_id="test_readability_1",
        dedup_key="key_readability_1",
        rule_id=100020,
        agent_id="019",
        source_ip="198.51.100.44",
        destination_ip=None,
        username="admin",
        start_time=base_time,
        window_duration=timedelta(seconds=600),
        category="AUTH",
        actor="198.51.100.44",
        target="admin"
    )
    res = agg._finalize_window(window)
    assert res["category"] == "AUTH"
    assert res["actor"] == "198.51.100.44"
    assert res["target"] == "admin"
    assert res["window_duration_seconds"] == 600


def test_dedup_save_and_load_snapshot_recovery(tmp_path):
    """Verify 10/10 Crash Recovery: active windows are saved to snapshot and fully restored upon restart."""
    agg1 = SlidingWindowAggregator()
    base_time = datetime(2026, 7, 14, 10, 0, 0, tzinfo=timezone.utc)

    # Ingest 3 events to create active in-flight window
    for i in range(3):
        evt = CommonEventModel(
            event_id=f"snap_evt_{i}",
            timestamp=(base_time + timedelta(seconds=i*10)).isoformat(),
            source_ip="198.51.100.99",
            username="root",
            rule_id="100020",
            rule_level=5,
            rule_description="Failed auth",
            agent_id="019",
            agent_name="server-auth",
            event_category="AUTH",
            dedup_actor="198.51.100.99",
            dedup_target="root"
        )
        agg1.process_event(evt)

    assert len(agg1.active_windows) == 1
    snap_file = str(tmp_path / "test_snapshot.json")
    agg1.save_snapshot(snap_file)

    # Simulate process restart with a fresh aggregator
    agg2 = SlidingWindowAggregator()
    assert len(agg2.active_windows) == 0

    restored_count = agg2.load_snapshot(snap_file)
    assert restored_count == 1
    assert len(agg2.active_windows) == 1

    restored_win = list(agg2.active_windows.values())[0]
    assert restored_win.event_count == 3
    assert restored_win.category == "AUTH"
    assert restored_win.actor == "198.51.100.99"
    assert restored_win.target == "root"


def test_dedup_latency_grace_period_tolerance():
    """Verify watermark tolerance: an event arriving with minor latency (<=15s) does not prematurely bust windows."""
    base_time = datetime(2026, 7, 14, 10, 0, 0, tzinfo=timezone.utc)
    win = AggregatedWindow(
        aggregation_id="win_grace",
        dedup_key="key_grace",
        rule_id=100020,
        agent_id="001",
        source_ip="1.2.3.4",
        destination_ip=None,
        username="admin",
        start_time=base_time,
        window_duration=timedelta(seconds=600),
        category="AUTH"
    )

    # 10s after nominal window_end: within 15s grace period -> NOT expired
    event_at_plus_10s = win.window_end + timedelta(seconds=10)
    assert win.is_expired(event_at_plus_10s, grace_seconds=15) is False

    # 20s after nominal window_end: exceeds grace period -> IS expired
    event_at_plus_20s = win.window_end + timedelta(seconds=20)
    assert win.is_expired(event_at_plus_20s, grace_seconds=15) is True


def test_aggregated_alert_preserves_wazuh_rule_description():
    """Verify rule_description is passed from event to AggregatedWindow to finalized output."""
    agg = SlidingWindowAggregator()
    base_time = datetime(2026, 7, 14, 10, 0, 0, tzinfo=timezone.utc)

    evt = CommonEventModel(
        event_id="evt_desc_test",
        timestamp=base_time.isoformat(),
        source_ip="192.168.1.50",
        username="admin",
        rule_id="5710",
        rule_level=5,
        rule_description="sshd: Attempt to login using non-existent user",
        agent_id="001",
        agent_name="auth-srv",
        event_category="AUTH",
        dedup_actor="192.168.1.50",
        dedup_target="admin"
    )
    agg.process_event(evt)
    flushed = agg.flush_all()

    assert len(flushed) == 1
    assert flushed[0]["rule_description"] == "sshd: Attempt to login using non-existent user"
    assert flushed[0]["category"] == "AUTH"
    assert flushed[0]["actor"] == "192.168.1.50"
    assert flushed[0]["target"] == "admin"


def test_cumulative_alerts_bulk_upsert_tracking():
    """Verify DatabaseManager.bulk_upsert_cumulative_alerts accumulates event counts & burst windows."""
    from pipeline.database import DatabaseManager
    db = DatabaseManager()
    base_time = datetime(2026, 7, 14, 10, 0, 0, tzinfo=timezone.utc)

    test_cum = [
        {
            "cumulative_id": "test_cum_unit_1",
            "deduplication_key": "test_dedup_cum_key_unit",
            "category": "AUTH_FAILURE",
            "rule_id": 5710,
            "rule_description": "sshd: Attempt to login using non-existent user",
            "actor": "192.168.100.99",
            "target": "root",
            "agent_id": "001",
            "event_count": 10,
            "window_start": base_time,
            "window_end": base_time + timedelta(minutes=10),
            "status": "CLOSED"
        }
    ]

    count1 = db.bulk_upsert_cumulative_alerts(test_cum)
    assert count1 == 1

    # Second burst with 15 events
    test_cum[0]["event_count"] = 15
    test_cum[0]["window_end"] = base_time + timedelta(minutes=30)
    count2 = db.bulk_upsert_cumulative_alerts(test_cum)
    assert count2 == 1

    # Verify directly from DB
    with db.get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT total_event_count, total_burst_windows, rule_description
                FROM suppression.cumulative_alerts
                WHERE deduplication_key = 'test_dedup_cum_key_unit';
            """)
            row = cur.fetchone()
            assert row is not None
            assert row[0] >= 25  # 10 + 15
            assert row[1] >= 2   # 2 burst windows
            assert row[2] == "sshd: Attempt to login using non-existent user"

            # Cleanup test record
            cur.execute("DELETE FROM suppression.cumulative_alerts WHERE deduplication_key = 'test_dedup_cum_key_unit';")


def test_ioa_summary_generation_and_pipeline():
    """Verify IOA summary generation across categories and its preservation through aggregation."""
    from pipeline.ingest import generate_ioa_summary

    # 1. Test IOA Generation for Network Web
    ioa_web = generate_ioa_summary(
        category="WEB_OPERATIONAL",
        rule_id="31101",
        rule_description="Web server 400 error code.",
        actor="185.220.101.5",
        target="srv-portal"
    )
    assert "web_scan" in ioa_web or "400" in ioa_web

    # 2. Test IOA Generation for Authentication
    ioa_auth = generate_ioa_summary(
        category="AUTH_FAILURE",
        rule_id="5710",
        rule_description="sshd: Attempt to login using non-existent user",
        actor="user:hacker",
        target="srv-auth"
    )
    assert "auth_type: sshd" in ioa_auth and "user:hacker" in ioa_auth

    # 3. Test IOA Generation for Vulnerability with CVE extraction
    ioa_vuln = generate_ioa_summary(
        category="VULNERABILITY",
        rule_id="23502",
        rule_description="Vulnerability affects pkg bind9 (CVE-2026-1234)",
        actor="pkg:bind9",
        target="srv-dns"
    )
    assert "scanner: vulnerability-detector" in ioa_vuln and "CVE-2026-1234" in ioa_vuln

    # 4. Test IOA In-Memory Window Preservation
    aggregator = SlidingWindowAggregator()
    base_time = datetime(2026, 7, 1, 10, 0, 0, tzinfo=timezone.utc)
    ev1 = CommonEventModel(
        event_id="ev_ioa_1",
        timestamp=base_time.isoformat(),
        source_ip="185.220.101.5",
        agent_id="002",
        agent_name="web-01",
        rule_id="31101",
        rule_level=6,
        rule_description="Web server 400 error code.",
        event_category="WEB_OPERATIONAL",
        dedup_actor="185.220.101.5",
        dedup_target="web-01",
        ioa_summary=ioa_web
    )
    aggregator.process_event(ev1)
    flushed = aggregator.flush_all()
    assert len(flushed) == 1
    assert flushed[0]["ioa_summary"] == ioa_web


def test_ioa_summary_dynamic_and_unseen_rules():
    """Verify that generate_ioa_summary dynamically parses unseen custom rules without hardcoding."""
    from pipeline.ingest import generate_ioa_summary

    # Unseen custom WAF rule (100050)
    ioa_waf = generate_ioa_summary(
        category="WEB_OPERATIONAL",
        rule_id="100050",
        rule_description="Custom WAF detected XSS injection in cookie",
        actor="203.0.113.50",
        target="srv-web",
        data={"status": "403"}
    )
    assert "xss_probe" in ioa_waf
    assert "status: 403" in ioa_waf

    # Unseen Sysmon execution rule (92001) with MITRE
    ioa_sysmon = generate_ioa_summary(
        category="EXECUTION",
        rule_id="92001",
        rule_description="Sysmon Event 1: Process creation powershell.exe detected",
        actor="proc:powershell.exe",
        target="win-srv-01",
        decoder="sysmon",
        mitre_ids=["T1059.001"]
    )
    assert "sec_module: sysmon" in ioa_sysmon
    assert "mitre: T1059.001" in ioa_sysmon
    assert "powershell.exe" in ioa_sysmon

    # Unseen Windows Auth rule (60106)
    ioa_winauth = generate_ioa_summary(
        category="AUTH_SUCCESS",
        rule_id="60106",
        rule_description="Windows audit logon success for user admin",
        actor="user:admin",
        target="win-dc",
        decoder="windows-eventchannel"
    )
    assert "auth_type: windows-eventchannel" in ioa_winauth
    assert "auth_success" in ioa_winauth
    assert "user:admin" in ioa_winauth




