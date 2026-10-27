"""
Unit Tests for Stage 2 & 7 Suppression Governance, SLA Expirations & Metrics (Phase 6)
"""
from datetime import date, timedelta
import pytest
from pipeline.governance import SuppressionGovernanceManager


def test_separation_of_duties_enforcement():
    gov = SuppressionGovernanceManager()

    # Self-approval must fail
    with pytest.raises(ValueError, match="Separation of Duties violation"):
        gov.create_rule(
            suppression_id="SUP-TEST-FAIL",
            rule_name="Invalid Self Approval",
            suppression_class="S1_KNOWN_GOOD",
            target_rule_ids=[31101],
            author="analyst_dimas",
            approver="analyst_dimas",  # Same person!
            ticket_id="CRQ-001",
            business_reason="Testing",
            scope_definition={},
            expires_date=date.today() + timedelta(days=30)
        )


def test_automated_rule_expiration_audit():
    gov = SuppressionGovernanceManager()

    # Create a rule that expired yesterday
    past_date = date(2026, 6, 30)
    gov.rules["SUP-EXPIRED-TEST"] = gov.create_rule(
        suppression_id="SUP-EXPIRED-TEST",
        rule_name="Temporary Migration Rule",
        suppression_class="S3_MAINTENANCE",
        target_rule_ids=[52002],
        author="sec_eng_john",
        approver="soc_lead_alice",
        ticket_id="CRQ-MIGRATE",
        business_reason="App migration",
        scope_definition={"host": "old-srv"},
        expires_date=date.today() + timedelta(days=1)
    )
    # Manually set expires_date to past for audit simulation
    gov.rules["SUP-EXPIRED-TEST"].expires_date = date(2026, 6, 1)

    expired = gov.audit_expirations(current_date=date(2026, 7, 1))
    assert "SUP-EXPIRED-TEST" in expired
    assert gov.rules["SUP-EXPIRED-TEST"].status == "EXPIRED"

    # Verify audit log recorded
    actions = [log.action for log in gov.audit_logs if log.suppression_id == "SUP-EXPIRED-TEST"]
    assert "EXPIRED" in actions


def test_suppression_escape_detection():
    gov = SuppressionGovernanceManager()

    suppressed_ips = {"10.10.50.20", "198.51.100.99"}
    sample_incidents = [
        {
            "incident_id": "INC-001",
            "title": "Confirmed Brute Force Attack",
            "target_severity": "P0",
            "attacker_source_ip": "198.51.100.99",
            "target_host": "prod-db-01",
            "compromised_account": "root",
            "last_seen_at": "2026-07-01T12:00:00Z"
        },
        {
            "incident_id": "INC-002",
            "title": "Low Priority Web Scan",
            "target_severity": "P3",
            "attacker_source_ip": "10.10.50.20",
            "target_host": "web-dmz-01",
            "compromised_account": None,
            "last_seen_at": "2026-07-01T12:05:00Z"
        }
    ]

    escapes = gov.check_suppression_escape(suppressed_ips, sample_incidents)
    assert len(escapes) == 1, "Must detect exactly 1 suppression escape matching P0 incident"
    assert escapes[0]["incident_id"] == "INC-001"
    assert "Source IP: 198.51.100.99" in escapes[0]["matched_entities"]


def test_daily_operational_metrics_calculation():
    gov = SuppressionGovernanceManager()
    metrics = gov.generate_daily_metrics(
        metric_date=date(2026, 7, 1),
        raw_count=121317,
        wazuh_alerts_count=121317,
        suppressed_count=115000,
        aggregated_count=2800,
        correlated_count=2,
        analyst_reviewed_count=2,
        true_positives_count=2,
        suppression_escapes_count=0
    )
    assert metrics.raw_events_count == 121317
    assert metrics.alert_reduction_percentage >= 95.0
    assert metrics.actionable_incidents_count == 2


def test_calculate_drift_sigma():
    gov = SuppressionGovernanceManager()
    # Explicitly set baseline for SUP-2026-001 to 5,000 for deterministic unit testing
    gov.rules["SUP-2026-001"].drift_baseline_count = 5000
    # Current is 5,200 (> 5,000). Std_dev is sqrt(5000) ~= 70.7 -> sigma > 0
    sigma = gov.calculate_drift_sigma("SUP-2026-001", current_count=5200)
    assert sigma > 0
    # Rule with current count far above baseline triggers high sigma
    high_sigma = gov.calculate_drift_sigma("SUP-2026-001", current_count=15000)
    assert high_sigma >= 3.0
