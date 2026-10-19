"""
Unit Tests for False Positive Suppression Workflow (CEM v3.0 Locked Specification)
Covers:
1. 4-Eyes Governance & Separation of Duties (Author != Approver)
2. In-Memory Hot-Reload & Dynamic Rule Registration
3. Proactive Suppression Interception on Aggregated Alerts (Rule ID, Host, Actor)
4. Safety Ceiling Enforcement: Volume Breach (max_count) & Risk Breach (max_risk_score)
5. Pydantic Request Models for 4-Section Suppression Schema
"""
from datetime import date, timedelta
from decimal import Decimal
import pytest

from pipeline.governance import SuppressionGovernanceManager
from pipeline.models import SuppressionRuleDB
from pipeline.api import NewSuppressionRuleRequest, RuleApprovalRequest


def test_separation_of_duties_at_creation_and_approval():
    gov = SuppressionGovernanceManager()

    # Self-approval during creation must raise ValueError
    with pytest.raises(ValueError, match="Separation of Duties violation"):
        gov.create_rule(
            suppression_id="SUP-SOD-001",
            rule_name="Self Approval Attempt",
            suppression_class="S2_FALSE_POSITIVE",
            target_rule_ids=[31101],
            author="analyst_bob",
            approver="analyst_bob",
            ticket_id="CRQ-SOD-1",
            business_reason="Testing SOD",
            scope_definition={},
            expires_date=date.today() + timedelta(days=30)
        )


def test_in_memory_hot_reload_and_registration():
    gov = SuppressionGovernanceManager()
    initial_rule_count = len(gov.rules)

    new_rule = SuppressionRuleDB(
        suppression_id="SUP-TEST-HOTRELOAD",
        rule_name="Hot Reload Test Rule",
        suppression_class="S2_FALSE_POSITIVE",
        target_rule_ids=[550, 554],
        author="analyst_alice",
        approver="lead_carol",
        ticket_id="CRQ-HR-01",
        business_reason="Legitimate backup agent polling",
        scope_definition={
            "match_sids": [550, 554],
            "target_host": "backup-srv-01",
            "source_ip": "10.0.0.99",
            "max_count": 500,
            "max_risk_score": 60
        },
        status="ACTIVE",
        created_date=date.today(),
        expires_date=date.today() + timedelta(days=60),
        review_cycle="QUARTERLY",
        drift_baseline_count=0,
        current_drift_sigma=Decimal("0.00")
    )

    # Register rule dynamically into in-memory manager
    gov.register_rule(new_rule)
    assert len(gov.rules) == initial_rule_count + 1
    assert "SUP-TEST-HOTRELOAD" in gov.rules
    assert gov.rules["SUP-TEST-HOTRELOAD"].status == "ACTIVE"


def test_suppression_evaluation_exact_match():
    gov = SuppressionGovernanceManager()
    
    rule = SuppressionRuleDB(
        suppression_id="SUP-FP-WEB-001",
        rule_name="Suppress Nessus Scanner",
        suppression_class="S1_KNOWN_GOOD",
        target_rule_ids=[99900],
        author="analyst_dan",
        approver="lead_eve",
        ticket_id="CRQ-SCAN-01",
        business_reason="Scheduled security vulnerability scanning",
        scope_definition={
            "match_sids": [99900],
            "target_host": "web-prod-01",
            "source_ip": "10.10.10.50",
            "max_count": 500,
            "max_risk_score": 60
        },
        status="ACTIVE",
        created_date=date.today(),
        expires_date=date.today() + timedelta(days=90),
        review_cycle="QUARTERLY",
        drift_baseline_count=0,
        current_drift_sigma=Decimal("0.00")
    )
    gov.register_rule(rule)

    # Aggregate alert matching rule criteria within safety ceiling
    agg = {
        "aggregation_id": "AGG-TEST-001",
        "category": "web_attack",
        "rule_id": 99900,
        "rule_description": "Web application attack detected",
        "actor": "10.10.10.50",
        "source_ip": "10.10.10.50",
        "target": "web-prod-01",
        "event_count": 45,
        "max_inline_risk_score": 50
    }

    is_supp, supp_id, reason = gov.evaluate_aggregate_suppression(agg)
    assert is_supp is True
    assert supp_id == "SUP-FP-WEB-001"
    assert reason == "Scheduled security vulnerability scanning"


def test_safety_ceiling_breach_volume():
    gov = SuppressionGovernanceManager()

    rule = SuppressionRuleDB(
        suppression_id="SUP-FP-VOL-001",
        rule_name="Suppress High Volume with Ceiling",
        suppression_class="S2_FALSE_POSITIVE",
        target_rule_ids=[99901],
        author="analyst_dan",
        approver="lead_eve",
        ticket_id="CRQ-VOL-01",
        business_reason="Noisy service check",
        scope_definition={
            "match_sids": [99901],
            "target_host": "db-prod-01",
            "source_ip": "10.10.10.20",
            "max_count": 200,
            "max_risk_score": 60
        },
        status="ACTIVE",
        created_date=date.today(),
        expires_date=date.today() + timedelta(days=90),
        review_cycle="QUARTERLY",
        drift_baseline_count=0,
        current_drift_sigma=Decimal("0.00")
    )
    gov.register_rule(rule)

    # Aggregate alert exceeding max_count (350 > 200) -> Safety ceiling breached!
    agg = {
        "aggregation_id": "AGG-VOL-BREACH",
        "category": "authentication_failure",
        "rule_id": 99901,
        "rule_description": "sshd: illegal user attempt",
        "actor": "10.10.10.20",
        "source_ip": "10.10.10.20",
        "target": "db-prod-01",
        "event_count": 350,
        "max_inline_risk_score": 40
    }

    is_supp, supp_id, reason = gov.evaluate_aggregate_suppression(agg)
    assert is_supp is False
    assert supp_id == "SUP-FP-VOL-001"
    assert "exceeded suppression threshold 200" in reason


def test_safety_ceiling_breach_risk_score():
    gov = SuppressionGovernanceManager()

    rule = SuppressionRuleDB(
        suppression_id="SUP-FP-RISK-001",
        rule_name="Suppress Low Risk with Risk Ceiling",
        suppression_class="S2_FALSE_POSITIVE",
        target_rule_ids=[99902],
        author="analyst_dan",
        approver="lead_eve",
        ticket_id="CRQ-RISK-01",
        business_reason="Maintenance service",
        scope_definition={
            "match_sids": [99902],
            "target_host": "app-srv-01",
            "source_ip": "10.10.10.30",
            "max_count": 500,
            "max_risk_score": 60
        },
        status="ACTIVE",
        created_date=date.today(),
        expires_date=date.today() + timedelta(days=90),
        review_cycle="QUARTERLY",
        drift_baseline_count=0,
        current_drift_sigma=Decimal("0.00")
    )
    gov.register_rule(rule)

    # Aggregate alert exceeding max_risk_score (85 > 60) -> Critical escalation!
    agg = {
        "aggregation_id": "AGG-RISK-BREACH",
        "category": "authentication_failure",
        "rule_id": 99902,
        "rule_description": "sshd: Multiple successful authentications after failure",
        "actor": "10.10.10.30",
        "source_ip": "10.10.10.30",
        "target": "app-srv-01",
        "event_count": 20,
        "max_inline_risk_score": 85
    }

    is_supp, supp_id, reason = gov.evaluate_aggregate_suppression(agg)
    assert is_supp is False
    assert supp_id == "SUP-FP-RISK-001"
    assert "exceeded maximum allowed suppression risk 60" in reason


def test_api_schema_models_validation():
    # Valid 4-section request
    req = NewSuppressionRuleRequest(
        name="FP Supresi Web Scanner",
        classification="FALSE POSITIVE",
        sids=[31101, 31102],
        owner="analyst_tier1",
        approver="soc_lead_alice",
        expiration="2026-12-31",
        reason="Penyetelan rutin scanner internal",
        referenced_ticket_id="TCK-2026-001",
        aggregation_id="AGG-2026-999",
        event_category="web_attack",
        scope_definition={
            "match_sids": [31101, 31102],
            "target_host": "web-prod-01",
            "source_ip": "10.0.0.5",
            "max_count": 500,
            "max_risk_score": 60
        },
        status="ACTIVE"
    )
    assert req.referenced_ticket_id == "TCK-2026-001"
    assert req.aggregation_id == "AGG-2026-999"
    assert req.scope_definition["max_count"] == 500
    assert req.scope_definition["max_risk_score"] == 60

    # Approval model
    appr = RuleApprovalRequest(
        approver="soc_lead_alice",
        notes="Approved after forensic review"
    )
    assert appr.approver == "soc_lead_alice"


# ============================================================================
# ENHANCED TESTS: IOC/IOA Enriched Suppression, Never-Suppress Blacklist,
# Multi-Dimensional Auto-Clustering
# ============================================================================

def test_ioc_indicator_model_validation():
    """Verify IocIndicator Pydantic model validates type and action correctly."""
    from pipeline.models import IocIndicator

    # Valid IOC
    ioc = IocIndicator(type="md5", value="abc123def456", direction="any", action="suppress")
    assert ioc.type == "MD5"
    assert ioc.action == "suppress"

    # Invalid type should fail
    with pytest.raises(Exception):
        IocIndicator(type="INVALID_TYPE", value="xxx", action="suppress")

    # Invalid action should fail
    with pytest.raises(Exception):
        IocIndicator(type="SHA256", value="abc", action="block")


def test_ioa_pattern_model_and_wazuh_conversion():
    """Verify IoaPattern model validation and to_wazuh_element() output."""
    from pipeline.models import IoaPattern

    # Regex pattern for command_line -> should emit <regex>
    ioa = IoaPattern(field="command_line", operator="regex", value="powershell.*-enc")
    assert ioa.operator == "regex"
    xml = ioa.to_wazuh_element()
    assert "<regex>" in xml
    assert "powershell.*-enc" in xml

    # Contains pattern for data.dns.question.name -> should emit <field name="...">
    ioa2 = IoaPattern(field="data.dns.question.name", operator="contains", value="evil.com")
    xml2 = ioa2.to_wazuh_element()
    assert 'field name="data.dns.question.name"' in xml2
    assert "evil.com" in xml2

    # Startswith for process_path
    ioa3 = IoaPattern(field="process_path", operator="startswith", value="/tmp/")
    xml3 = ioa3.to_wazuh_element()
    assert "^/tmp/" in xml3

    # Invalid operator
    with pytest.raises(Exception):
        IoaPattern(field="url", operator="LIKE", value="test")


def test_never_suppress_guard_model():
    """Verify NeverSuppressGuard model and risk score validation."""
    from pipeline.models import NeverSuppressGuard

    guard = NeverSuppressGuard(
        threat_intel_match=True,
        min_risk_score_override=85,
        ioc_blacklist_types=["MD5", "SHA256", "C2_DOMAIN"]
    )
    assert guard.min_risk_score_override == 85
    assert "C2_DOMAIN" in guard.ioc_blacklist_types

    # Risk score out of range
    with pytest.raises(Exception):
        NeverSuppressGuard(min_risk_score_override=150)


def test_suppression_rule_ioc_accessors():
    """Verify SuppressionRuleDB IOC/IOA accessor methods parse scope_definition correctly."""
    rule = SuppressionRuleDB(
        suppression_id="SUP-IOC-001",
        rule_name="IOC Enriched Rule",
        suppression_class="S2_FALSE_POSITIVE",
        target_rule_ids=[31101],
        author="analyst_a", approver="lead_b",
        ticket_id="CRQ-IOC-01",
        business_reason="Known benign hash",
        scope_definition={
            "match_sids": [31101], "max_count": 500, "max_risk_score": 60,
            "ioc_indicators": [
                {"type": "MD5", "value": "d41d8cd98f00b204e9800998ecf8427e", "action": "suppress"},
                {"type": "C2_DOMAIN", "value": "evil.example.com", "action": "never_suppress"}
            ],
            "ioa_patterns": [
                {"field": "command_line", "operator": "contains", "value": "curl -s"},
                {"field": "data.dns.question.name", "operator": "equals", "value": "benign.internal.corp"}
            ],
            "never_suppress_if": {
                "threat_intel_match": True,
                "min_risk_score_override": 80,
                "ioc_blacklist_types": ["MD5", "SHA256", "C2_DOMAIN"]
            }
        },
        status="ACTIVE", created_date=date.today(),
        expires_date=date.today() + timedelta(days=90),
        review_cycle="QUARTERLY",
        drift_baseline_count=0, current_drift_sigma=Decimal("0.00")
    )
    iocs = rule.get_ioc_indicators()
    assert len(iocs) == 2
    assert iocs[0].type == "MD5"
    assert iocs[1].action == "never_suppress"


def test_ioa_command_line_matching():
    """IOA pattern: suppress when ALL patterns match (AND logic)."""
    from pipeline.governance import SuppressionGovernanceManager
    gov = SuppressionGovernanceManager()
    rule = SuppressionRuleDB(
        suppression_id="SUP-IOA-CMD-001",
        rule_name="Suppress Known Admin Script",
        suppression_class="S5_CONDITIONAL",
        target_rule_ids=[55502],
        author="analyst_a", approver="lead_b",
        ticket_id="CRQ-CMD-01",
        business_reason="Scheduled admin maintenance script",
        scope_definition={
            "match_sids": [55502], "max_count": 500, "max_risk_score": 60,
            "ioa_patterns": [
                {"field": "command_line", "operator": "contains",
                 "value": "ansible-playbook"},
                {"field": "username", "operator": "equals",
                 "value": "admin_ops"}
            ]
        },
        status="ACTIVE", created_date=date.today(),
        expires_date=date.today() + timedelta(days=60),
        review_cycle="QUARTERLY",
        drift_baseline_count=0, current_drift_sigma=Decimal("0.00")
    )
    gov.register_rule(rule)
    # Both match -> suppressed
    agg = {"rule_id": 55502, "actor": "10.0.0.1", "source_ip": "10.0.0.1",
           "target": "srv-01", "event_count": 3, "max_inline_risk_score": 25,
           "command_line": "/usr/bin/ansible-playbook deploy.yml",
           "username": "admin_ops"}
    ok, sid, _ = gov.evaluate_aggregate_suppression(agg)
    assert ok is True and sid == "SUP-IOA-CMD-001"
    # One mismatch -> NOT suppressed (AND logic)
    agg2 = dict(agg, username="hacker_user")


def test_never_suppress_blacklist_override():
    """Never-suppress guard blocks suppression for high risk."""
    from pipeline.governance import SuppressionGovernanceManager
    gov = SuppressionGovernanceManager()
    rule = SuppressionRuleDB(
        suppression_id="SUP-GUARD-001",
        rule_name="Suppress with Guard",
        suppression_class="S2_FALSE_POSITIVE",
        target_rule_ids=[55503],
        author="analyst_a", approver="lead_b",
        ticket_id="CRQ-GUARD-01",
        business_reason="Low-noise endpoint telemetry",
        scope_definition={
            "match_sids": [55503], "max_count": 500, "max_risk_score": 60,
            "ioc_indicators": [
                {"type": "C2_DOMAIN", "value": "malware-c2.evil.com",
                 "action": "never_suppress"}
            ],
            "never_suppress_if": {
                "threat_intel_match": True,
                "min_risk_score_override": 80,
                "ioc_blacklist_types": ["C2_DOMAIN"]
            }
        },
        status="ACTIVE", created_date=date.today(),
        expires_date=date.today() + timedelta(days=90),
        review_cycle="QUARTERLY",
        drift_baseline_count=0, current_drift_sigma=Decimal("0.00")
    )
    gov.register_rule(rule)
    # High risk -> guard blocks
    agg = {"rule_id": 55503, "actor": "10.0.0.1", "source_ip": "10.0.0.1",
           "target": "srv-01", "event_count": 5, "max_inline_risk_score": 90}
    ok, _, _ = gov.evaluate_aggregate_suppression(agg)
    assert ok is False
    # Blacklisted C2 domain -> guard blocks
    agg2 = {"rule_id": 55503, "actor": "10.0.0.1", "source_ip": "10.0.0.1",
            "target": "srv-01", "event_count": 5, "max_inline_risk_score": 20,
            "dns_query": "malware-c2.evil.com"}
    ok2, _, _ = gov.evaluate_aggregate_suppression(agg2)
    assert ok2 is False


def test_match_ioa_operator_static():
    """Unit test for _match_ioa_operator static helper."""
    from pipeline.governance import SuppressionGovernanceManager
    m = SuppressionGovernanceManager._match_ioa_operator
    assert m("equals", "admin", "admin") is True
    assert m("equals", "admin", "Admin") is True
    assert m("equals", "admin", "admin_ops") is False
    assert m("not_equals", "admin", "root") is True
    assert m("contains", "power", "powershell.exe -enc") is True
    assert m("not_contains", "power", "bash -c ls") is True
    assert m("startswith", "/tmp/", "/tmp/malware.sh") is True
    assert m("endswith", ".exe", "calc.exe") is True
    assert m("regex", r"powershell.*-enc", "powershell.exe -enc b64") is True
    assert m("regex", r"powershell.*-enc", "bash -c ls") is False
    assert m("not_regex", r"^safe_", "dangerous_script") is True
    assert m("equals", "test", "") is False


def test_ioc_hash_matching_in_suppression():
    """IOC hash matching: suppression triggers when file hash matches MD5."""
    from pipeline.governance import SuppressionGovernanceManager
    gov = SuppressionGovernanceManager()
    rule = SuppressionRuleDB(
        suppression_id="SUP-IOC-HASH-001",
        rule_name="Suppress Known Benign Hash",
        suppression_class="S1_KNOWN_GOOD",
        target_rule_ids=[55501],
        author="analyst_a", approver="lead_b",
        ticket_id="CRQ-HASH-01",
        business_reason="Known legitimate updater binary",
        scope_definition={
            "match_sids": [55501], "max_count": 500, "max_risk_score": 60,
            "ioc_indicators": [
                {"type": "MD5", "value": "d41d8cd98f00b204e9800998ecf8427e",
                 "action": "suppress"}
            ]
        },
        status="ACTIVE", created_date=date.today(),
        expires_date=date.today() + timedelta(days=90),
        review_cycle="QUARTERLY",
        drift_baseline_count=0, current_drift_sigma=Decimal("0.00")
    )
    gov.register_rule(rule)
    # Match
    agg = {"rule_id": 55501, "actor": "10.0.0.1", "source_ip": "10.0.0.1",
           "target": "srv-01", "event_count": 5, "max_inline_risk_score": 20,
           "file_hash": "d41d8cd98f00b204e9800998ecf8427e"}
    ok, sid, _ = gov.evaluate_aggregate_suppression(agg)
    assert ok is True and sid == "SUP-IOC-HASH-001"
    # No match
    agg2 = dict(agg, file_hash="aaaa1111bbbb2222cccc3333dddd4444")
    ok2, _, _ = gov.evaluate_aggregate_suppression(agg2)
    assert ok2 is False

