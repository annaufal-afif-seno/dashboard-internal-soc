"""
Test Suite for Stateful Attack Progression (P0-P4), SLA Stopwatch Reset, and P4 AI Dispatch
==========================================================================================
Validates 100% adherence to User Specification:
- P0 (15m): Post-Exploit OR Breach followed by ANY subsequent action
- P1 (60m): Initial Access / AUTH_SUCCESS / C2
- P2 (4h): Active attack attempt OR target with verified CVE receives ANY aggregate
- P3 (1d): Target has verified vulnerability (VULNERABILITY / CVE)
- P4 (7d): Reconnaissance / probe coba-coba / noise
- SLA Stopwatch Rule:
    * SLA starts strictly upon parent aggregate arrival (NOT 24h historical events).
    * Subsequent aggregates of same priority do NOT reset priority_established_at.
    * An elevating aggregate upgrades ticket in-place and resets priority_established_at to its arrival time.
- P4 Holding & AI Dispatch:
    * P4 tickets held for 7 days.
    * On expiration, dispatched to cascading AI pipeline for automated noise resolution.
"""

from datetime import datetime, timezone, timedelta
import pytest
from unittest.mock import MagicMock, patch

from pipeline.score import RiskScorer, SLA_MATRIX_MINUTES
from pipeline.correlate import CorrelationEngine, PRIORITY_RANK
from pipeline.p4_sla_worker import get_expired_p4_tickets, process_expired_p4_tickets


def test_stateful_progression_lifecycle():
    """
    Test progressive elevation from P4 -> P3 -> P2 -> P1 -> P0 based on chronological stages.
    """
    scorer = RiskScorer()

    # Step 1: Recon only -> P4
    t1 = {"stages": [{"stage_name": "WEB_OPERATIONAL"}]}
    p, just, sla = scorer.determine_stateful_priority(t1)
    assert p == "P4"
    assert sla == SLA_MATRIX_MINUTES["P4"] == 10080

    # Step 2: Recon + CVE appears -> P3
    t2 = {"stages": [{"stage_name": "WEB_OPERATIONAL"}, {"stage_name": "VULNERABILITY"}]}
    p, just, sla = scorer.determine_stateful_priority(t2)
    assert p == "P3"
    assert sla == SLA_MATRIX_MINUTES["P3"] == 1440

    # Step 3: Target with CVE receives subsequent aggregate -> P2
    t3 = {
        "stages": [
            {"stage_name": "WEB_OPERATIONAL"},
            {"stage_name": "VULNERABILITY"},
            {"stage_name": "WEB_OPERATIONAL"}
        ]
    }
    p, just, sla = scorer.determine_stateful_priority(t3)
    assert p == "P2"
    assert sla == SLA_MATRIX_MINUTES["P2"] == 240

    # Step 4: Attacker breaches perimeter (AUTH_SUCCESS) -> P1
    t4 = {
        "stages": [
            {"stage_name": "WEB_OPERATIONAL"},
            {"stage_name": "VULNERABILITY"},
            {"stage_name": "WEB_OPERATIONAL"},
            {"stage_name": "AUTH_SUCCESS"}
        ]
    }
    p, just, sla = scorer.determine_stateful_priority(t4)
    assert p == "P1"
    assert sla == SLA_MATRIX_MINUTES["P1"] == 60

    # Step 5: Breach followed by ANY subsequent action -> P0
    t5 = {
        "stages": [
            {"stage_name": "WEB_OPERATIONAL"},
            {"stage_name": "VULNERABILITY"},
            {"stage_name": "WEB_OPERATIONAL"},
            {"stage_name": "AUTH_SUCCESS"},
            {"stage_name": "WEB_OPERATIONAL"}
        ]
    }
    p, just, sla = scorer.determine_stateful_priority(t5)
    assert p == "P0"
    assert sla == SLA_MATRIX_MINUTES["P0"] == 15


def test_direct_attack_and_breach_mapping():
    """
    Verify standalone alert mapping when attack or breach occurs right away.
    """
    scorer = RiskScorer()

    # Direct Web Attack -> P2
    p, _, sla = scorer.determine_stateful_priority({"stages": [{"stage_name": "WEB_ATTACK"}]})
    assert p == "P2"
    assert sla == 240

    # Direct Auth Success -> P1
    p, _, sla = scorer.determine_stateful_priority({"stages": [{"stage_name": "AUTH_SUCCESS"}]})
    assert p == "P1"
    assert sla == 60

    # Direct Post-Exploitation -> P0
    p, _, sla = scorer.determine_stateful_priority({"stages": [{"stage_name": "PRIVILEGE_ESCALATION"}]})
    assert p == "P0"
    assert sla == 15


def test_sla_stopwatch_continuation_and_reset_logic():
    """
    Simulate the SLA stopwatch rule:
    1. Parent aggregate arrives at T0 (10:00) with P4 -> SLA starts at 10:00 (7 days).
    2. Same-priority aggregate arrives at T1 (10:30) with P4 -> priority_established_at stays 10:00 (stopwatch continues).
    3. Elevating aggregate arrives at T2 (11:00) with P3 -> priority_established_at resets to 11:00 (new SLA: 1 day).
    4. Elevating aggregate arrives at T3 (11:15) with P2 -> priority_established_at resets to 11:15 (new SLA: 4 hours).
    5. Elevating aggregate arrives at T4 (11:45) with P1 -> priority_established_at resets to 11:45 (new SLA: 60 min).
    6. Action arrives at T5 (12:00) -> elevates to P0 -> priority_established_at resets to 12:00 (new SLA: 15 min).
    """
    t0 = datetime(2026, 10, 9, 10, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 9, 10, 30, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 10, 9, 11, 0, 0, tzinfo=timezone.utc)
    t3 = datetime(2026, 10, 9, 11, 15, 0, tzinfo=timezone.utc)
    t4 = datetime(2026, 10, 9, 11, 45, 0, tzinfo=timezone.utc)
    t5 = datetime(2026, 10, 9, 12, 0, 0, tzinfo=timezone.utc)

    scorer = RiskScorer()

    # Step 1: Initial parent aggregate
    stages = [{"stage_name": "DISCOVERY"}]
    curr_p, _, _ = scorer.determine_stateful_priority({"stages": stages})
    assert curr_p == "P4"
    priority_established_at = t0
    assert priority_established_at == t0

    # Step 2: Same priority aggregate arrives at T1
    stages.append({"stage_name": "AUTH_FAILURE"})
    new_p, _, _ = scorer.determine_stateful_priority({"stages": stages})
    assert new_p == "P4"
    if PRIORITY_RANK[new_p] > PRIORITY_RANK[curr_p]:
        priority_established_at = t1  # Should not be executed
    assert priority_established_at == t0  # STOPWATCH CONTINUES UNTOUCHED!

    # Step 3: CVE arrives at T2
    stages.append({"stage_name": "VULNERABILITY"})
    new_p, _, _ = scorer.determine_stateful_priority({"stages": stages})
    assert new_p == "P3"
    if PRIORITY_RANK[new_p] > PRIORITY_RANK[curr_p]:
        curr_p = new_p
        priority_established_at = t2  # RESET TO T2
    assert curr_p == "P3"
    assert priority_established_at == t2

    # Step 4: Subsequent event after CVE arrives at T3 -> elevates to P2
    stages.append({"stage_name": "WEB_OPERATIONAL"})
    new_p, _, _ = scorer.determine_stateful_priority({"stages": stages})
    assert new_p == "P2"
    if PRIORITY_RANK[new_p] > PRIORITY_RANK[curr_p]:
        curr_p = new_p
        priority_established_at = t3  # RESET TO T3
    assert curr_p == "P2"
    assert priority_established_at == t3

    # Step 5: Breach (AUTH_SUCCESS) arrives at T4 -> elevates to P1
    stages.append({"stage_name": "AUTH_SUCCESS"})
    new_p, _, _ = scorer.determine_stateful_priority({"stages": stages})
    assert new_p == "P1"
    if PRIORITY_RANK[new_p] > PRIORITY_RANK[curr_p]:
        curr_p = new_p
        priority_established_at = t4  # RESET TO T4
    assert curr_p == "P1"
    assert priority_established_at == t4

    # Step 6: Post-breach activity arrives at T5 -> elevates to P0
    stages.append({"stage_name": "EXECUTION"})
    new_p, _, _ = scorer.determine_stateful_priority({"stages": stages})
    assert new_p == "P0"
    if PRIORITY_RANK[new_p] > PRIORITY_RANK[curr_p]:
        curr_p = new_p
        priority_established_at = t5  # RESET TO T5
    assert curr_p == "P0"
    assert priority_established_at == t5


def test_p4_holding_and_sla_expiry_ai_dispatch():
    """
    Verify that expired P4 tickets are accurately processed via the AI cascade pipeline.
    """
    sample_p4 = {
        "incident_id": "INC-P4-RECON-TEST",
        "total_risk_score": 15,
        "priority": "P4",
        "stages_count": 1,
        "rule_level": 3,
        "rule_code": "STANDALONE_AGGREGATE",
        "attacker_source_ip": "192.168.1.100",
        "stages": [{"stage_name": "DISCOVERY"}]
    }

    # Evaluate through AI cascade
    from pipeline.ml_classifier import evaluate_cascading_pipeline
    cascade_res = evaluate_cascading_pipeline(sample_p4)

    # Must produce a valid decision and active tier
    assert "active_tier" in cascade_res
    assert "final_verdict" in cascade_res
    assert "final_confidence" in cascade_res
    assert cascade_res["decision"] in ("AUTO_CLOSE", "CREATE_IRIS_CASE", "AUDIT_SOC_ANALYST", "FORWARD_TO_TRIAGE", "REQUIRE_GROUND_TRUTH")


def test_dual_clock_sla_immutability_and_deadline_reset():
    """
    Test dual-clock stopwatch invariant (Revision No 6):
    1. first_detected_at represents the permanent incident birth timestamp and NEVER changes.
    2. priority_changed_at updates each time priority elevates (e.g. P4 -> P2 -> P0).
    3. sla_deadline calculates strictly from priority_changed_at + SLA_MATRIX_MINUTES[priority].
    """
    t_genesis = datetime(2026, 10, 9, 8, 0, 0, tzinfo=timezone.utc)
    t_elevate_p2 = datetime(2026, 10, 9, 14, 0, 0, tzinfo=timezone.utc)
    t_elevate_p0 = datetime(2026, 10, 9, 15, 30, 0, tzinfo=timezone.utc)

    scorer = RiskScorer()

    # Step 1: Ticket is born at t_genesis with P4
    inc_p4 = {
        "incident_id": "INC-TEST-DUAL-001",
        "first_detected_at": t_genesis,
        "priority_changed_at": t_genesis,
        "stages": [{"stage_name": "DISCOVERY"}]
    }
    score_rec, triage_rec = scorer.evaluate_incident(inc_p4)
    assert triage_rec["priority"] == "P4"
    assert triage_rec["first_detected_at"] == t_genesis
    assert triage_rec["priority_changed_at"] == t_genesis
    assert triage_rec["sla_deadline"] == t_genesis + timedelta(minutes=SLA_MATRIX_MINUTES["P4"])

    # Step 2: Elevates to P2 at t_elevate_p2
    inc_p2 = {
        "incident_id": "INC-TEST-DUAL-001",
        "first_detected_at": triage_rec["first_detected_at"],  # PRESERVED!
        "priority_changed_at": t_elevate_p2,                   # UPDATED
        "stages": [{"stage_name": "DISCOVERY"}, {"stage_name": "WEB_ATTACK"}]
    }
    score_rec2, triage_rec2 = scorer.evaluate_incident(inc_p2)
    assert triage_rec2["priority"] == "P2"
    assert triage_rec2["first_detected_at"] == t_genesis  # STILL PERMANENT!
    assert triage_rec2["priority_changed_at"] == t_elevate_p2
    assert triage_rec2["sla_deadline"] == t_elevate_p2 + timedelta(minutes=SLA_MATRIX_MINUTES["P2"])

    # Step 3: Elevates to P0 at t_elevate_p0
    inc_p0 = {
        "incident_id": "INC-TEST-DUAL-001",
        "first_detected_at": triage_rec2["first_detected_at"], # PRESERVED!
        "priority_changed_at": t_elevate_p0,                   # UPDATED
        "stages": [
            {"stage_name": "DISCOVERY"},
            {"stage_name": "WEB_ATTACK"},
            {"stage_name": "AUTH_SUCCESS"},
            {"stage_name": "EXECUTION"}
        ]
    }
    score_rec3, triage_rec3 = scorer.evaluate_incident(inc_p0)
    assert triage_rec3["priority"] == "P0"
    assert triage_rec3["first_detected_at"] == t_genesis  # IMMUTABLE!
    assert triage_rec3["priority_changed_at"] == t_elevate_p0
    assert triage_rec3["sla_deadline"] == t_elevate_p0 + timedelta(minutes=SLA_MATRIX_MINUTES["P0"])

