"""
Unit Tests for Stage 4 Stateful Attack Progression Priority Engine (Version 4.0)
================================================================================
Verifies:
  1. P0: Post-Exploitation / Breach followed by subsequent actions (SLA: 15m)
  2. P1: Initial Access / Breach Confirmed (SLA: 60m)
  3. P2: Active Exploit Attempt OR Target with CVE attacked (SLA: 4h / 240m)
  4. P3: Vulnerability / CVE Exposure Discovered (SLA: 1d / 1440m)
  5. P4: Reconnaissance / Noise Coba-coba (SLA: 7d / 10080m)
  6. Continuous Risk Score (0-100) & Deductions
"""
import pytest
from pipeline.score import RiskScorer, SLA_MATRIX_MINUTES


def test_risk_scorer_p0_post_exploitation_sla15m():
    """
    P0 Invariant:
    Attacker breached (AUTH_SUCCESS) and then executed subsequent actions (PRIVILEGE_ESCALATION)
    Must be P0 with SLA 15 minutes.
    """
    scorer = RiskScorer()
    sample_incident = {
        "incident_id": "INC-TEST-P0",
        "rule_level": 14,
        "categories": ["DISCOVERY", "AUTH_SUCCESS", "PRIVILEGE_ESCALATION"],
        "target_host": "dc-01.prod.local",
        "compromised_account": "root",
        "threat_intel_match": True,
        "threat_intel_status": "MALICIOUS",
        "threat_intel_confidence": 95,
        "stages": [
            {"stage_name": "DISCOVERY"},
            {"stage_name": "AUTH_SUCCESS"},
            {"stage_name": "PRIVILEGE_ESCALATION"},
        ],
    }

    score_rec, factors, triage = scorer.evaluate_incident_risk(sample_incident)
    assert score_rec["soc_priority"] == "P0"
    assert triage["priority"] == "P0"
    assert score_rec["sla_minutes"] == 15
    assert triage["sla_minutes"] == 15
    assert score_rec["scoring_version"] == "v5.0_category_only"


def test_risk_scorer_p1_initial_access_breach_sla60m():
    """
    P1 Invariant:
    Attacker succeeded in Initial Access (AUTH_SUCCESS) without subsequent post-exploitation yet.
    Must be P1 with SLA 60 minutes.
    """
    scorer = RiskScorer()
    sample_incident = {
        "incident_id": "INC-TEST-P1",
        "rule_level": 10,
        "categories": ["AUTH_FAILURE", "AUTH_SUCCESS"],
        "target_host": "vpn-gw.prod.local",
        "compromised_account": "analyst01",
        "threat_intel_status": "SUSPICIOUS",
        "stages": [
            {"stage_name": "AUTH_FAILURE"},
            {"stage_name": "AUTH_SUCCESS"},
        ],
    }

    score_rec, factors, triage = scorer.evaluate_incident_risk(sample_incident)
    assert score_rec["soc_priority"] == "P1"
    assert triage["priority"] == "P1"
    assert score_rec["sla_minutes"] == 60
    assert triage["sla_minutes"] == 60


def test_risk_scorer_p2_active_exploit_attempt_sla4h():
    """
    P2 Invariant A:
    Active attack attempt (SQL Injection / WEB_ATTACK) on target.
    Must be P2 with SLA 4 hours (240 minutes).
    """
    scorer = RiskScorer()
    sample_incident = {
        "incident_id": "INC-TEST-P2-ATTACK",
        "rule_level": 8,
        "categories": ["WEB_OPERATIONAL", "WEB_ATTACK"],
        "target_host": "portal.prod.local",
        "compromised_account": None,
        "stages": [
            {"stage_name": "WEB_OPERATIONAL"},
            {"stage_name": "WEB_ATTACK"},
        ],
    }

    score_rec, factors, triage = scorer.evaluate_incident_risk(sample_incident)
    assert score_rec["soc_priority"] == "P2"
    assert triage["priority"] == "P2"
    assert score_rec["sla_minutes"] == 240


def test_risk_scorer_p2_activity_after_cve_sla4h():
    """
    P2 Invariant B:
    Target host has CVE (P3), and after CVE is detected, ANY new activity appears (even web probe).
    Must escalate to P2 with SLA 4 hours.
    """
    scorer = RiskScorer()
    sample_incident = {
        "incident_id": "INC-TEST-P2-CVE-ATTACK",
        "rule_level": 7,
        "categories": ["WEB_OPERATIONAL", "VULNERABILITY", "WEB_OPERATIONAL"],
        "target_host": "app-server-02",
        "stages": [
            {"stage_name": "WEB_OPERATIONAL"},
            {"stage_name": "VULNERABILITY"},
            {"stage_name": "WEB_OPERATIONAL"},
        ],
    }

    score_rec, factors, triage = scorer.evaluate_incident_risk(sample_incident)
    assert score_rec["soc_priority"] == "P2"
    assert triage["priority"] == "P2"
    assert score_rec["sla_minutes"] == 240


def test_risk_scorer_p3_vulnerability_exposure_sla1d():
    """
    P3 Invariant:
    Target host has verified CVE / Vulnerability without subsequent attacks yet.
    Must be P3 with SLA 24 hours (1440 minutes).
    """
    scorer = RiskScorer()
    sample_incident = {
        "incident_id": "INC-TEST-P3",
        "rule_level": 7,
        "categories": ["WEB_OPERATIONAL", "VULNERABILITY"],
        "target_host": "db-server-01",
        "stages": [
            {"stage_name": "WEB_OPERATIONAL"},
            {"stage_name": "VULNERABILITY"},
        ],
    }

    score_rec, factors, triage = scorer.evaluate_incident_risk(sample_incident)
    assert score_rec["soc_priority"] == "P3"
    assert triage["priority"] == "P3"
    assert score_rec["sla_minutes"] == 1440


def test_risk_scorer_p4_recon_noise_sla7d():
    """
    P4 Invariant:
    Only reconnaissance / probe coba-coba / web 404 noise.
    Must be P4 with SLA 7 days (10080 minutes).
    """
    scorer = RiskScorer()
    sample_incident = {
        "incident_id": "INC-TEST-P4",
        "rule_level": 4,
        "categories": ["WEB_OPERATIONAL", "DISCOVERY"],
        "target_host": "web-static-01",
        "stages": [
            {"stage_name": "WEB_OPERATIONAL"},
            {"stage_name": "DISCOVERY"},
        ],
    }

    score_rec, factors, triage = scorer.evaluate_incident_risk(sample_incident)
    assert score_rec["soc_priority"] == "P4"
    assert triage["priority"] == "P4"
    assert score_rec["sla_minutes"] == 10080


def test_risk_scorer_known_good_deduction():
    """
    PRD Section 8 #2: Risk score dihapus. Maintenance window tidak lagi
    mengurangi score. Test ini memverifikasi bahwa priority tetap ditentukan
    oleh kategori, bukan score.
    """
    scorer = RiskScorer()
    sample_incident = {
        "incident_id": "INC-TEST-MAINT",
        "rule_level": 10,
        "categories": ["AUTH_FAILURE", "CREDENTIAL_ACCESS"],
        "target_host": "hportal-prod-159",
        "compromised_account": "dimas_analyst",
        "threat_intel_status": "SUSPICIOUS",
        "stages": [{"stage_name": "AUTH_FAILURE"}, {"stage_name": "CREDENTIAL_ACCESS"}],
    }

    score_std, _, _ = scorer.evaluate_incident_risk(sample_incident, is_in_maintenance=False)
    score_maint, factors, triage = scorer.evaluate_incident_risk(sample_incident, is_in_maintenance=True)

    # Priority tetap sama (ditentukan kategori, bukan score)
    assert score_std["soc_priority"] == score_maint["soc_priority"]
    # Score selalu 0 karena risk score dihapus (PRD Section 8 #2)
    assert score_std["total_score"] == 0
    assert score_maint["total_score"] == 0
    # Tidak ada risk factors lagi
    assert factors == []
