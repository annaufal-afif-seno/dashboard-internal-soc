"""
Unit Tests for 19-Table Pydantic Database Models & Validation Invariants
"""
from datetime import datetime, date
import pytest
from pipeline.models import (
    AssetInventoryContextDB,
    IdentityContextDB,
    ThreatIntelligenceIoCDB,
    MaintenanceWindowDB,
    SuppressionRuleDB,
    AggregatedAlertDB,
    CorrelationRuleDB,
    CorrelatedIncidentDB,
    IncidentStageDB,
    RiskScoringFactorDB,
    CalculatedRiskScoreDB,
    SocTriageQueueDB,
    IncidentInvestigationNoteDB,
    IncidentResponseActionDB,
    OperationalMetricsDailyDB,
    CommonEventModel
)


def test_asset_inventory_context_model():
    asset = AssetInventoryContextDB(
        asset_id="AST-001",
        hostname="dc-01.prod.local",
        ip_address="10.0.0.10",
        asset_type="DOMAIN_CONTROLLER",
        criticality_tier="CROWN_JEWEL",
        criticality_score=25,
        environment="PRODUCTION",
        is_internet_exposed=False
    )
    assert asset.asset_id == "AST-001"
    assert asset.criticality_score == 25


def test_calculated_risk_score_invariants():
    # Valid P0 (score 85)
    score_p0 = CalculatedRiskScoreDB(
        incident_id="INC-001",
        total_score=85,
        soc_priority="P0"
    )
    assert score_p0.soc_priority == "P0"

    # PRD Section 8 #9: Score-to-priority constraint removed.
    # Any score with any priority is now valid.
    score_mixed = CalculatedRiskScoreDB(
        incident_id="INC-002",
        total_score=30,
        soc_priority="P0"
    )
    assert score_mixed.soc_priority == "P0"


def test_soc_triage_queue_model():
    queue_item = SocTriageQueueDB(
        triage_id="TRG-001",
        incident_id="INC-001",
        assigned_analyst="analyst_dimas",
        priority="P0",
        triage_status="INVESTIGATING",
        resolution_outcome="TRUE_POSITIVE_ACTIONABLE"
    )
    assert queue_item.priority == "P0"
    assert queue_item.triage_status == "INVESTIGATING"


def test_suppression_rule_model():
    suppression = SuppressionRuleDB(
        suppression_id="SUP-2026-001",
        rule_name="Approved Vulnerability Scanner",
        suppression_class="S1_KNOWN_GOOD",
        target_rule_ids=[5710, 31101],
        author="sec_eng_john",
        approver="soc_lead_alice",
        ticket_id="CRQ-2026-9901",
        business_reason="Scheduled nessus scan",
        scope_definition={"source_ips": ["10.10.50.20", "10.10.50.21"]},
        created_date=date(2026, 7, 1),
        expires_date=date(2026, 9, 30)
    )
    assert suppression.author != suppression.approver
    assert suppression.suppression_class == "S1_KNOWN_GOOD"


def test_operational_metrics_daily_model():
    metrics = OperationalMetricsDailyDB(
        metric_date=date(2026, 7, 1),
        raw_events_count=121317,
        wazuh_alerts_count=121317,
        suppressed_events_count=110000,
        aggregated_alerts_count=1200,
        correlated_incidents_count=45,
        analyst_reviewed_count=45,
        true_positives_count=5
    )
    assert metrics.raw_events_count == 121317
    assert metrics.true_positives_count == 5
