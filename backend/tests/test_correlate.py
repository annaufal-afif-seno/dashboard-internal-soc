"""
Unit Tests for Stage 3 Attack Correlation Engine (Phase 5)
"""
from datetime import datetime, timezone, timedelta
import pytest
from pipeline.correlate import CorrelationEngine
from pipeline.models import CommonEventModel


def test_brute_force_to_successful_login_correlation():
    engine = CorrelationEngine()
    base_time = datetime(2026, 7, 1, 10, 0, 0, tzinfo=timezone.utc)

    # 1. Send 6 failed logins from IP 198.51.100.44 targeting root
    for i in range(6):
        fail_evt = CommonEventModel(
            event_id=f"fail_{i}",
            timestamp=(base_time + timedelta(seconds=i*10)).isoformat(),
            source_ip="198.51.100.44",
            destination_host="hportal-prod-159",
            username="root",
            rule_id="100020",
            rule_level=5,
            rule_description="Single failed authentication",
            agent_id="019",
            agent_name="hportal-prod-159"
        )
        engine.process_event(fail_evt)

    # 2. Send successful login from SAME IP within 5 minutes
    success_evt = CommonEventModel(
        event_id="succ_01",
        timestamp=(base_time + timedelta(seconds=120)).isoformat(),
        source_ip="198.51.100.44",
        destination_host="hportal-prod-159",
        username="root",
        rule_id="100010",
        rule_level=3,
        rule_description="Successful user authentication",
        agent_id="019",
        agent_name="hportal-prod-159"
    )
    incidents = engine.process_event(success_evt)

    assert len(incidents) == 1, "Must generate exactly 1 Correlated Incident for Brute Force -> Success"
    inc = incidents[0]
    assert inc["rule_code"] == "AUTH_BRUTE_FORCE_SUCCESS"
    assert inc["target_host"] == "hportal-prod-159"
    assert inc["attacker_source_ip"] == "198.51.100.44"
    assert len(inc["stages"]) >= 2


def test_cross_host_does_not_falsely_correlate():
    """Verify CORR-001 does not correlate brute force on host A with login on host B."""
    engine = CorrelationEngine()
    base_time = datetime(2026, 7, 1, 10, 0, 0, tzinfo=timezone.utc)

    # Failed logins targeting host A
    for i in range(6):
        fail_evt = CommonEventModel(
            event_id=f"fail_hostA_{i}",
            timestamp=(base_time + timedelta(seconds=i*10)).isoformat(),
            source_ip="198.51.100.44",
            destination_host="server-alpha",
            username="root",
            rule_id="100020",
            rule_level=5,
            rule_description="Single failed authentication",
            agent_id="001",
            agent_name="server-alpha"
        )
        engine.process_event(fail_evt)

    # Login occurs on host B from same IP (valid admin login on different machine)
    login_hostB = CommonEventModel(
        event_id="succ_hostB",
        timestamp=(base_time + timedelta(seconds=120)).isoformat(),
        source_ip="198.51.100.44",
        destination_host="server-beta",
        username="root",
        rule_id="100010",
        rule_level=3,
        rule_description="Successful user authentication",
        agent_id="002",
        agent_name="server-beta"
    )
    incidents = engine.process_event(login_hostB)
    assert len(incidents) == 0, "Should NOT correlate login on host B with brute force on host A"


def test_no_attack_immunity_after_incident_emission():
    """Verify that after incident emission, the track is evicted so a second attack triggers a second incident."""
    engine = CorrelationEngine()
    base_time = datetime(2026, 7, 1, 10, 0, 0, tzinfo=timezone.utc)

    # Attack 1
    for i in range(6):
        engine.process_event(CommonEventModel(
            event_id=f"a1_fail_{i}",
            timestamp=(base_time + timedelta(seconds=i*10)).isoformat(),
            source_ip="198.51.100.99",
            destination_host="host-target",
            username="admin",
            rule_id="100020",
            rule_level=5,
            rule_description="Failed auth",
            agent_id="010",
            agent_name="host-target"
        ))
    inc1 = engine.process_event(CommonEventModel(
        event_id="a1_succ",
        timestamp=(base_time + timedelta(seconds=70)).isoformat(),
        source_ip="198.51.100.99",
        destination_host="host-target",
        username="admin",
        rule_id="100010",
        rule_level=3,
        rule_description="Succ auth",
        agent_id="010",
        agent_name="host-target"
    ))
    assert len(inc1) == 1, "First attack must produce incident"

    # Attack 2 (same attacker, 5 minutes later)
    attack2_time = base_time + timedelta(minutes=5)
    for i in range(6):
        engine.process_event(CommonEventModel(
            event_id=f"a2_fail_{i}",
            timestamp=(attack2_time + timedelta(seconds=i*10)).isoformat(),
            source_ip="198.51.100.99",
            destination_host="host-target",
            username="admin",
            rule_id="100020",
            rule_level=5,
            rule_description="Failed auth",
            agent_id="010",
            agent_name="host-target"
        ))
    inc2 = engine.process_event(CommonEventModel(
        event_id="a2_succ",
        timestamp=(attack2_time + timedelta(seconds=70)).isoformat(),
        source_ip="198.51.100.99",
        destination_host="host-target",
        username="admin",
        rule_id="100010",
        rule_level=3,
        rule_description="Succ auth",
        agent_id="010",
        agent_name="host-target"
    ))
    assert len(inc2) == 1, "Second attack must NOT be swallowed by immunity bug"


def test_semantic_correlation_with_novel_rule_id():
    """
    Verify an attack using an unseen/novel rule_id (e.g. '99999') that is NOT in any
    hardcoded rule list is STILL correlated via semantic categories & groups.
    """
    engine = CorrelationEngine()
    base_time = datetime(2026, 7, 1, 14, 0, 0, tzinfo=timezone.utc)

    # 1. Send 5 failed logins with novel rule_id="99999", category="AUTH", group="authentication_failed"
    for i in range(5):
        engine.process_event(CommonEventModel(
            event_id=f"nov_fail_{i}",
            timestamp=(base_time + timedelta(seconds=i * 10)).isoformat(),
            source_ip="203.0.113.88",
            destination_host="k8s-master",
            username="devops",
            rule_id="99999",  # Novel Rule ID!
            rule_level=6,
            rule_description="Custom novel PAM failure",
            classification_groups=["authentication_failed", "pam_custom"],
            event_category="AUTH",
            agent_id="099",
            agent_name="k8s-master"
        ))

    # 2. Send successful login with novel rule_id="99998", category="AUTH", group="authentication_success"
    incidents = engine.process_event(CommonEventModel(
        event_id="nov_succ",
        timestamp=(base_time + timedelta(seconds=90)).isoformat(),
        source_ip="203.0.113.88",
        destination_host="k8s-master",
        username="devops",
        rule_id="99998",  # Novel Rule ID!
        rule_level=3,
        rule_description="Custom novel PAM success",
        classification_groups=["authentication_success"],
        event_category="AUTH",
        agent_id="099",
        agent_name="k8s-master"
    ))

    assert len(incidents) == 1, "Must generate incident via semantic matching despite novel rule_ids!"
    assert incidents[0]["rule_code"] == "AUTH_BRUTE_FORCE_SUCCESS"
    assert incidents[0]["attacker_source_ip"] == "203.0.113.88"
    assert incidents[0]["target_host"] == "k8s-master"


def test_lateral_movement_cardinality_distinct_targets():
    """
    Verify CORR-004 triggers when 1 single source IP accesses 3 DISTINCT target hosts.
    """
    engine = CorrelationEngine()
    base_time = datetime(2026, 7, 1, 16, 0, 0, tzinfo=timezone.utc)

    targets = ["db-srv-01", "app-srv-02", "ad-dc-03"]
    incidents = []
    for i, tgt in enumerate(targets):
        incs = engine.process_event(CommonEventModel(
            event_id=f"lat_{i}",
            timestamp=(base_time + timedelta(minutes=i * 2)).isoformat(),
            source_ip="192.168.100.55",
            destination_host=tgt,
            username="admin",
            rule_id="106000",
            rule_level=7,
            rule_description="Remote execution via SMB",
            classification_groups=["lateral_movement", "smb"],
            event_category="AUTH",
            agent_id=f"0{i+1}",
            agent_name=tgt
        ))
        incidents.extend(incs)

    assert len(incidents) == 1, "Must trigger exactly 1 Lateral Movement Sweep incident for 3 distinct targets"
    assert incidents[0]["rule_code"] == "LATERAL_MOVEMENT_SWEEP"
    assert incidents[0]["distinct_targets_count"] >= 3


def test_distributed_password_spray_distinct_actors():
    """
    Verify CORR-006 triggers when 5 DISTINCT source IPs target 1 single host.
    """
    engine = CorrelationEngine()
    base_time = datetime(2026, 7, 1, 18, 0, 0, tzinfo=timezone.utc)

    attackers = [f"45.33.32.{10 + i}" for i in range(5)]
    incidents = []
    for i, att_ip in enumerate(attackers):
        incs = engine.process_event(CommonEventModel(
            event_id=f"spray_{i}",
            timestamp=(base_time + timedelta(seconds=i * 20)).isoformat(),
            source_ip=att_ip,
            destination_host="vpn-gateway",
            username=f"user_{i}",
            rule_id="5710",
            rule_level=5,
            rule_description="Failed login spray",
            classification_groups=["authentication_failed"],
            event_category="AUTH",
            agent_id="001",
            agent_name="vpn-gateway"
        ))
        incidents.extend(incs)

    assert len(incidents) == 1, "Must trigger Distributed Password Spray incident for 5 distinct actors"
    assert incidents[0]["rule_code"] == "DISTRIBUTED_PASSWORD_SPRAY"
    assert incidents[0]["distinct_actors_count"] >= 5


def test_threat_intel_subthreshold_escalation():
    """
    Verify when an event has threat_intel_match=True, the brute force threshold is overridden
    down to 1 (enabling detection of 1 failure followed by 1 success without needing 5 failures).
    """
    engine = CorrelationEngine()
    base_time = datetime(2026, 7, 1, 20, 0, 0, tzinfo=timezone.utc)

    # 1 failed login with threat_intel_match=True (from a known malicious scanner IP)
    fail_evt = CommonEventModel(
        event_id="ti_fail_01",
        timestamp=base_time.isoformat(),
        source_ip="185.177.124.99",
        destination_host="crown-jewel-db",
        username="root",
        rule_id="5710",
        rule_level=5,
        rule_description="sshd failure from malicious IP",
        classification_groups=["authentication_failed"],
        event_category="AUTH",
        agent_id="010",
        agent_name="crown-jewel-db"
    )
    # Set threat intel match flag
    fail_evt.threat_intel_match = True
    engine.process_event(fail_evt)

    # 1 successful login right after
    succ_evt = CommonEventModel(
        event_id="ti_succ_01",
        timestamp=(base_time + timedelta(seconds=30)).isoformat(),
        source_ip="185.177.124.99",
        destination_host="crown-jewel-db",
        username="root",
        rule_id="5715",
        rule_level=3,
        rule_description="sshd success from malicious IP",
        classification_groups=["authentication_success"],
        event_category="AUTH",
        agent_id="010",
        agent_name="crown-jewel-db"
    )
    incidents = engine.process_event(succ_evt)

    assert len(incidents) == 1, "Must trigger incident for Threat Intel IP with only 1 failed attempt"
    assert incidents[0]["rule_code"] == "AUTH_BRUTE_FORCE_SUCCESS"
    assert incidents[0]["attacker_source_ip"] == "185.177.124.99"


def test_ransomware_tamper_and_impact_chain():
    """
    Verify CORR-007: Defense Evasion (vssadmin delete shadows) followed by
    Mass File Encryption on the same Windows host generates EXACTLY ONE P0 Incident.
    """
    engine = CorrelationEngine()
    base_time = datetime(2026, 7, 2, 10, 0, 0, tzinfo=timezone.utc)
    target_host = "win-prod-fileserver-01"

    # Stage 1: vssadmin delete shadows (Defense Evasion / Tampering)
    tamper_evt = CommonEventModel(
        event_id="rw_tamper_01",
        timestamp=base_time.isoformat(),
        source_ip="10.0.5.50",
        destination_host=target_host,
        username="administrator",
        rule_id="100500",
        rule_level=9,
        rule_description="vssadmin shadow copy deletion detected",
        classification_groups=["vssadmin", "shadow_copy"],
        mitre_tactics=["Defense Evasion"],
        event_category="HOST",
        agent_id="025",
        agent_name=target_host
    )
    incidents_step1 = engine.process_event(tamper_evt)
    assert len(incidents_step1) == 0, "Stage 1 alone should not trigger an incident yet"

    # Stage 2: Mass File Encryption / Tampering detected 45 seconds later
    encrypt_evt = CommonEventModel(
        event_id="rw_encrypt_02",
        timestamp=(base_time + timedelta(seconds=45)).isoformat(),
        source_ip="10.0.5.50",
        destination_host=target_host,
        username="administrator",
        rule_id="100510",
        rule_level=12,
        rule_description="Mass file modification with known ransomware extension",
        classification_groups=["ransomware", "mass_file_modification"],
        mitre_tactics=["Impact"],
        event_category="HOST",
        agent_id="025",
        agent_name=target_host
    )
    incidents_step2 = engine.process_event(encrypt_evt)

    # Must be resolved into EXACTLY 1 ticket (not 2 separate tickets!)
    assert len(incidents_step2) == 1, f"Expected 1 consolidated incident, got {len(incidents_step2)}"
    rw_incident = incidents_step2[0]

    assert rw_incident["rule_code"] == "RANSOMWARE_TAMPER_AND_IMPACT"
    assert rw_incident["target_severity"] == "P0"
    assert rw_incident["target_host"] == target_host
    assert len(rw_incident["stages"]) == 2
    assert rw_incident["stages"][0]["stage_name"] == "DEFENSE_EVASION_TAMPER"
    assert rw_incident["stages"][1]["stage_name"] == "MASS_FILE_IMPACT"


def test_generic_multi_tactic_safety_net_catches_novel_intrusion():
    """
    Verify CORR-008: An unknown / novel zero-day attack chain (e.g. Web Exploit -> Reverse Shell)
    that doesn't match any specific rule (CORR-001..007) is caught by the Generic Multi-Tactic
    safety net as EXACTLY 1 incident on the target host instead of 2 separate alerts.
    """
    engine = CorrelationEngine()
    base_time = datetime(2026, 7, 3, 14, 0, 0, tzinfo=timezone.utc)
    target_host = "api-gateway-prod-02"

    # Stage 1: Novel web exploit on target host
    exploit_evt = CommonEventModel(
        event_id="novel_exploit_01",
        timestamp=base_time.isoformat(),
        source_ip="194.26.29.11",
        destination_host=target_host,
        username="www-data",
        rule_id="100600",
        rule_level=8,
        rule_description="Novel HTTP request smuggling exploit",
        classification_groups=["web_attack", "exploit"],
        mitre_tactics=["Initial Access"],
        event_category="NETWORK",
        agent_id="030",
        agent_name=target_host
    )
    inc_step1 = engine.process_event(exploit_evt)
    assert len(inc_step1) == 0

    # Stage 2: Reverse shell payload execution 30 seconds later
    shell_evt = CommonEventModel(
        event_id="novel_shell_02",
        timestamp=(base_time + timedelta(seconds=30)).isoformat(),
        source_ip="194.26.29.11",
        destination_host=target_host,
        username="www-data",
        rule_id="100610",
        rule_level=10,
        rule_description="Outbound bash reverse shell connection",
        classification_groups=["reverse_shell", "shell"],
        mitre_tactics=["Execution"],
        event_category="HOST",
        agent_id="030",
        agent_name=target_host
    )
    inc_step2 = engine.process_event(shell_evt)

    assert len(inc_step2) == 1, "Generic safety net must consolidate the attack into 1 ticket"
    generic_inc = inc_step2[0]

    assert generic_inc["rule_code"] == "GENERIC_HOST_MULTI_TACTIC_CHAIN"
    assert generic_inc["target_severity"] == "P0"
    assert generic_inc["target_host"] == target_host
    assert len(generic_inc["stages"]) == 2


# ==============================================================================
# Two-Tier Historical Lookback Tests (Cross-Session / Cross-Day Persistence)
# Simulates: attacker failed for N days, succeeded on day N+1
# Uses unittest.mock to mock DB — no live PostgreSQL required.
# ==============================================================================

from unittest.mock import MagicMock, patch


def _make_auth_success_event(event_id: str, source_ip: str, agent_name: str, timestamp: str) -> CommonEventModel:
    """Helper: create a successful login event that triggers historical lookback."""
    return CommonEventModel(
        event_id=event_id,
        timestamp=timestamp,
        source_ip=source_ip,
        destination_host=agent_name,
        username="victim_user",
        rule_id="5715",
        rule_level=3,
        rule_description="Successful sshd authentication",
        classification_groups=["authentication_success", "login_success"],
        event_category="AUTH",
        agent_id="050",
        agent_name=agent_name
    )


def test_historical_escalation_triggers_on_persistent_attacker():
    """
    Two-Tier Lookback: Attacker failed 15x over 6 days (in cumulative_alerts).
    On day 7, a successful login event arrives.
    Engine MUST emit a HISTORICAL_BRUTE_FORCE_ESCALATION incident.
    """
    mock_db = MagicMock()
    mock_cursor = MagicMock()
    mock_conn = MagicMock()

    # Mock DB return: actor 185.100.200.50 had 15 failures over 6 days
    first_seen = datetime(2026, 7, 1, 8, 0, 0)
    last_failure = datetime(2026, 7, 6, 23, 55, 0)
    mock_cursor.fetchone.return_value = (
        "cum_abc123def456789",  # cumulative_id
        "185.100.200.50",       # actor
        15,                     # total_event_count
        first_seen,             # first_seen_at
        last_failure            # last_seen_at
    )
    mock_cursor.__enter__ = lambda s: s
    mock_cursor.__exit__ = MagicMock(return_value=False)
    mock_conn.cursor.return_value = mock_cursor
    mock_conn.__enter__ = lambda s: s
    mock_conn.__exit__ = MagicMock(return_value=False)
    mock_db.get_connection.return_value = mock_conn

    engine = CorrelationEngine(db_manager=mock_db)

    # Day 7: successful login from the persistent attacker
    success_evt = _make_auth_success_event(
        event_id="day7_success",
        source_ip="185.100.200.50",
        agent_name="crown-jewel-db",
        timestamp=datetime(2026, 7, 7, 9, 0, 0, tzinfo=timezone.utc).isoformat()
    )

    incidents = engine.process_event(success_evt)

    # Must emit exactly 1 historical escalation incident
    hist_incs = [i for i in incidents if i.get("rule_code") == "HISTORICAL_BRUTE_FORCE_ESCALATION"]
    assert len(hist_incs) == 1, (
        f"Must emit 1 historical escalation for persistent attacker, got: {[i['rule_code'] for i in incidents]}"
    )
    inc = hist_incs[0]
    assert inc["attacker_source_ip"] == "185.100.200.50"
    assert inc["target_host"] == "crown-jewel-db"
    assert inc["target_severity"] == "P0"
    assert inc["events_count"] == 16  # 15 historical + 1 success
    assert len(inc["stages"]) == 2
    assert inc["stages"][0]["stage_name"] == "HISTORICAL_AUTH_FAILURES"
    assert inc["stages"][1]["stage_name"] == "SUCCESSFUL_BREACH"
    assert "6" in inc["title"]  # "breached after 6-day persistence"


def test_no_escalation_when_no_historical_failures():
    """
    Two-Tier Lookback: Actor has NO prior failure history in cumulative_alerts.
    Successful login by a new/clean user MUST NOT produce historical escalation.
    """
    mock_db = MagicMock()
    mock_cursor = MagicMock()
    mock_conn = MagicMock()

    # Mock DB return: no rows found (clean actor, no history)
    mock_cursor.fetchone.return_value = None
    mock_cursor.__enter__ = lambda s: s
    mock_cursor.__exit__ = MagicMock(return_value=False)
    mock_conn.cursor.return_value = mock_cursor
    mock_conn.__enter__ = lambda s: s
    mock_conn.__exit__ = MagicMock(return_value=False)
    mock_db.get_connection.return_value = mock_conn

    engine = CorrelationEngine(db_manager=mock_db)

    clean_success = _make_auth_success_event(
        event_id="clean_login",
        source_ip="192.168.1.200",
        agent_name="workstation-dev",
        timestamp=datetime(2026, 7, 8, 10, 0, 0, tzinfo=timezone.utc).isoformat()
    )

    incidents = engine.process_event(clean_success)
    hist_incs = [i for i in incidents if i.get("rule_code") == "HISTORICAL_BRUTE_FORCE_ESCALATION"]
    assert len(hist_incs) == 0, "Clean actor with no history must NOT produce historical escalation"


def test_historical_escalation_graceful_when_db_offline():
    """
    Two-Tier Lookback Resilience: DB raises OperationalError (offline/timeout).
    Engine MUST NOT crash — silently skip historical escalation and return [].
    """
    import psycopg2

    mock_db = MagicMock()
    mock_conn = MagicMock()

    # Simulate DB connection failure at context manager entry
    mock_conn.__enter__ = MagicMock(side_effect=psycopg2.OperationalError("Connection refused"))
    mock_conn.__exit__ = MagicMock(return_value=False)
    mock_db.get_connection.return_value = mock_conn

    engine = CorrelationEngine(db_manager=mock_db)

    success_evt = _make_auth_success_event(
        event_id="offline_test",
        source_ip="10.0.0.99",
        agent_name="any-server",
        timestamp=datetime(2026, 7, 9, 12, 0, 0, tzinfo=timezone.utc).isoformat()
    )

    # Must NOT raise any exception
def test_generic_multi_tactic_safety_net_catches_novel_intrusion():
    """
    Verify CORR-008: An unknown / novel zero-day attack chain (e.g. Web Exploit -> Reverse Shell)
    that doesn't match any specific rule (CORR-001..007) is caught by the Generic Multi-Tactic
    safety net as EXACTLY 1 incident on the target host instead of 2 separate alerts.
    """
    engine = CorrelationEngine()
    base_time = datetime(2026, 7, 3, 14, 0, 0, tzinfo=timezone.utc)
    target_host = "api-gateway-prod-02"

    # Stage 1: Novel web exploit on target host
    exploit_evt = CommonEventModel(
        event_id="novel_exploit_01",
        timestamp=base_time.isoformat(),
        source_ip="194.26.29.11",
        destination_host=target_host,
        username="www-data",
        rule_id="100600",
        rule_level=8,
        rule_description="Novel HTTP request smuggling exploit",
        classification_groups=["web_attack", "exploit"],
        mitre_tactics=["Initial Access"],
        event_category="NETWORK",
        agent_id="030",
        agent_name=target_host
    )
    inc_step1 = engine.process_event(exploit_evt)
    assert len(inc_step1) == 0

    # Stage 2: Reverse shell payload execution 30 seconds later
    shell_evt = CommonEventModel(
        event_id="novel_shell_02",
        timestamp=(base_time + timedelta(seconds=30)).isoformat(),
        source_ip="194.26.29.11",
        destination_host=target_host,
        username="www-data",
        rule_id="100610",
        rule_level=10,
        rule_description="Outbound bash reverse shell connection",
        classification_groups=["reverse_shell", "shell"],
        mitre_tactics=["Execution"],
        event_category="HOST",
        agent_id="030",
        agent_name=target_host
    )
    inc_step2 = engine.process_event(shell_evt)

    assert len(inc_step2) == 1, "Generic safety net must consolidate the attack into 1 ticket"
    generic_inc = inc_step2[0]

    assert generic_inc["rule_code"] == "GENERIC_HOST_MULTI_TACTIC_CHAIN"
    assert generic_inc["target_severity"] == "P0"
    assert generic_inc["target_host"] == target_host
    assert len(generic_inc["stages"]) == 2


# ==============================================================================
# Two-Tier Historical Lookback Tests (Cross-Session / Cross-Day Persistence)
# Simulates: attacker failed for N days, succeeded on day N+1
# Uses unittest.mock to mock DB — no live PostgreSQL required.
# ==============================================================================

from unittest.mock import MagicMock, patch


def _make_auth_success_event(event_id: str, source_ip: str, agent_name: str, timestamp: str) -> CommonEventModel:
    """Helper: create a successful login event that triggers historical lookback."""
    return CommonEventModel(
        event_id=event_id,
        timestamp=timestamp,
        source_ip=source_ip,
        destination_host=agent_name,
        username="victim_user",
        rule_id="5715",
        rule_level=3,
        rule_description="Successful sshd authentication",
        classification_groups=["authentication_success", "login_success"],
        event_category="AUTH",
        agent_id="050",
        agent_name=agent_name
    )


def test_historical_escalation_triggers_on_persistent_attacker():
    """
    Two-Tier Lookback: Attacker failed 15x over 6 days (in cumulative_alerts).
    On day 7, a successful login event arrives.
    Engine MUST emit a HISTORICAL_BRUTE_FORCE_ESCALATION incident.
    """
    mock_db = MagicMock()
    mock_cursor = MagicMock()
    mock_conn = MagicMock()

    # Mock DB return: actor 185.100.200.50 had 15 failures over 6 days
    first_seen = datetime(2026, 7, 1, 8, 0, 0)
    last_failure = datetime(2026, 7, 6, 23, 55, 0)
    mock_cursor.fetchone.return_value = (
        "cum_abc123def456789",  # cumulative_id
        "185.100.200.50",       # actor
        15,                     # total_event_count
        first_seen,             # first_seen_at
        last_failure            # last_seen_at
    )
    mock_cursor.__enter__ = lambda s: s
    mock_cursor.__exit__ = MagicMock(return_value=False)
    mock_conn.cursor.return_value = mock_cursor
    mock_conn.__enter__ = lambda s: s
    mock_conn.__exit__ = MagicMock(return_value=False)
    mock_db.get_connection.return_value = mock_conn

    engine = CorrelationEngine(db_manager=mock_db)

    # Day 7: successful login from the persistent attacker
    success_evt = _make_auth_success_event(
        event_id="day7_success",
        source_ip="185.100.200.50",
        agent_name="crown-jewel-db",
        timestamp=datetime(2026, 7, 7, 9, 0, 0, tzinfo=timezone.utc).isoformat()
    )

    incidents = engine.process_event(success_evt)

    # Must emit exactly 1 historical escalation incident
    hist_incs = [i for i in incidents if i.get("rule_code") == "HISTORICAL_BRUTE_FORCE_ESCALATION"]
    assert len(hist_incs) == 1, (
        f"Must emit 1 historical escalation for persistent attacker, got: {[i['rule_code'] for i in incidents]}"
    )
    inc = hist_incs[0]
    assert inc["attacker_source_ip"] == "185.100.200.50"
    assert inc["target_host"] == "crown-jewel-db"
    assert inc["target_severity"] == "P0"
    assert inc["events_count"] == 16  # 15 historical + 1 success
    assert len(inc["stages"]) == 2
    assert inc["stages"][0]["stage_name"] == "HISTORICAL_AUTH_FAILURES"
    assert inc["stages"][1]["stage_name"] == "SUCCESSFUL_BREACH"
    assert "6" in inc["title"]  # "breached after 6-day persistence"


def test_no_escalation_when_no_historical_failures():
    """
    Two-Tier Lookback: Actor has NO prior failure history in cumulative_alerts.
    Successful login by a new/clean user MUST NOT produce historical escalation.
    """
    mock_db = MagicMock()
    mock_cursor = MagicMock()
    mock_conn = MagicMock()

    # Mock DB return: no rows found (clean actor, no history)
    mock_cursor.fetchone.return_value = None
    mock_cursor.__enter__ = lambda s: s
    mock_cursor.__exit__ = MagicMock(return_value=False)
    mock_conn.cursor.return_value = mock_cursor
    mock_conn.__enter__ = lambda s: s
    mock_conn.__exit__ = MagicMock(return_value=False)
    mock_db.get_connection.return_value = mock_conn

    engine = CorrelationEngine(db_manager=mock_db)

    clean_success = _make_auth_success_event(
        event_id="clean_login",
        source_ip="192.168.1.200",
        agent_name="workstation-dev",
        timestamp=datetime(2026, 7, 8, 10, 0, 0, tzinfo=timezone.utc).isoformat()
    )

    incidents = engine.process_event(clean_success)
    hist_incs = [i for i in incidents if i.get("rule_code") == "HISTORICAL_BRUTE_FORCE_ESCALATION"]
    assert len(hist_incs) == 0, "Clean actor with no history must NOT produce historical escalation"


def test_historical_escalation_graceful_when_db_offline():
    """
    Two-Tier Lookback Resilience: DB raises OperationalError (offline/timeout).
    Engine MUST NOT crash — silently skip historical escalation and return [].
    """
    import psycopg2

    mock_db = MagicMock()
    mock_conn = MagicMock()

    # Simulate DB connection failure at context manager entry
    mock_conn.__enter__ = MagicMock(side_effect=psycopg2.OperationalError("Connection refused"))
    mock_conn.__exit__ = MagicMock(return_value=False)
    mock_db.get_connection.return_value = mock_conn

    engine = CorrelationEngine(db_manager=mock_db)

    success_evt = _make_auth_success_event(
        event_id="offline_test",
        source_ip="10.0.0.99",
        agent_name="any-server",
        timestamp=datetime(2026, 7, 9, 12, 0, 0, tzinfo=timezone.utc).isoformat()
    )

    # Must NOT raise any exception
    try:
        incidents = engine.process_event(success_evt)
    except Exception as e:
        pytest.fail(f"Engine must NOT crash when DB is offline. Got exception: {e}")

    hist_incs = [i for i in incidents if i.get("rule_code") == "HISTORICAL_BRUTE_FORCE_ESCALATION"]
    assert len(hist_incs) == 0, "DB offline must produce 0 historical incidents (graceful degradation)"


def test_no_double_ticket_when_in_session_and_historical_both_match():
    """
    Anti-Double-Ticket Guard:
    Scenario: Attacker 10.0.1.5 has historical failure data in DB (6 days ago),
    AND also has an active in-session CORR-001 track (5+ failures this session).

    When success event arrives:
    - CORR-001 fires first → produces AUTH_BRUTE_FORCE_SUCCESS incident
    - Historical lookback runs AFTER, sees actor already covered → SKIPS

    Result: exactly 1 ticket in SOC queue, not 2.
    """
    mock_db = MagicMock()
    mock_cursor = MagicMock()
    mock_conn = MagicMock()

    # Mock DB: actor has prior history (would normally trigger historical)
    first_seen = datetime(2026, 7, 1, 8, 0, 0)
    last_failure = datetime(2026, 7, 6, 22, 0, 0)
    mock_cursor.fetchone.return_value = (
        "cum_overlap_test_001",
        "10.0.1.5",
        20,           # 20 historical failures
        first_seen,
        last_failure
    )
    mock_cursor.__enter__ = lambda s: s
    mock_cursor.__exit__ = MagicMock(return_value=False)
    mock_conn.cursor.return_value = mock_cursor
    mock_conn.__enter__ = lambda s: s
    mock_conn.__exit__ = MagicMock(return_value=False)
    mock_db.get_connection.return_value = mock_conn

    engine = CorrelationEngine(db_manager=mock_db)
    base_time = datetime(2026, 7, 7, 9, 0, 0, tzinfo=timezone.utc)
    target_host = "crown-jewel-server"

    # Step 1: Send 6 in-session failures (enough to arm CORR-001 track)
    for i in range(6):
        engine.process_event(CommonEventModel(
            event_id=f"insession_fail_{i}",
            timestamp=(base_time + timedelta(seconds=i * 10)).isoformat(),
            source_ip="10.0.1.5",
            destination_host=target_host,
            username="admin",
            rule_id="100020",
            rule_level=5,
            rule_description="Failed auth",
            classification_groups=["authentication_failed"],
            event_category="AUTH",
            agent_id="020",
            agent_name=target_host
        ))

    # Step 2: Success event — both CORR-001 (in-session) and historical should want to fire
    success_evt = CommonEventModel(
        event_id="overlap_success",
        timestamp=(base_time + timedelta(seconds=90)).isoformat(),
        source_ip="10.0.1.5",
        destination_host=target_host,
        username="admin",
        rule_id="100010",
        rule_level=3,
        rule_description="Successful auth",
        classification_groups=["authentication_success", "login_success"],
        event_category="AUTH",
        agent_id="020",
        agent_name=target_host
    )
    incidents = engine.process_event(success_evt)

    # Must produce EXACTLY 1 ticket total — no double-ticket
    assert len(incidents) == 1, (
        f"Anti-double-ticket guard failed: got {len(incidents)} incidents "
        f"({[i['rule_code'] for i in incidents]}), expected exactly 1"
    )
    # The in-session CORR-001 takes priority (it fired first)
    assert incidents[0]["rule_code"] == "AUTH_BRUTE_FORCE_SUCCESS", (
        f"In-session CORR-001 must take priority, got: {incidents[0]['rule_code']}"
    )
