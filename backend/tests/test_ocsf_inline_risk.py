"""
Test Suite: OCSF Fields, MITRE Community Supplement, and Inline Risk Score
Verifies the 97-98/100 normalization upgrade components.
"""
import sys
import os
import json
import pytest
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from pipeline.normalization_plugins import (
    OCSFFieldMapperPlugin,
    MITRECommunitySupplementPlugin,
    InlineRiskScorerPlugin,
    run_plugin_chain,
)
from pipeline.models import CommonEventModel


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def make_cem(**overrides) -> CommonEventModel:
    """Build a minimal valid CommonEventModel for testing."""
    defaults = dict(
        event_id="test-evt-001",
        timestamp="2026-09-21T10:00:00+07:00",
        agent_id="001",
        agent_name="test-host",
        rule_id="5715",
        rule_level=5,
        rule_description="sshd: authentication success",
        event_category="AUTH_FAILURE",
        host_criticality="STANDARD",
        is_internet_exposed=False,
        is_privileged_user=False,
        is_service_account=False,
        threat_intel_match=False,
        mitre_tactics=[],
        mitre_attack_ids=[],
        mitre_techniques=[],
    )
    defaults.update(overrides)
    return CommonEventModel(**defaults)


def make_raw_stub():
    """Minimal raw alert stub (not used by current plugins but required by interface)."""
    class _Stub:
        rule = type("r", (), {"id": "5715", "level": 5, "groups": []})()
        agent = type("a", (), {"id": "001", "name": "test-host", "ip": None})()
        data = {}
    return _Stub()


# ---------------------------------------------------------------------------
# Test 1: OCSFFieldMapperPlugin — correct class_uid / category_uid
# ---------------------------------------------------------------------------
class TestOCSFFieldMapper:

    def test_auth_event_gets_correct_ocsf_fields(self):
        """SSH auth failure event must map to OCSF class_uid=3002 (Authentication)."""
        plugin = OCSFFieldMapperPlugin()
        cem = make_cem(event_category="AUTH_FAILURE", rule_level=5)
        result = plugin.enrich(cem, make_raw_stub())

        assert result.ocsf_class_uid == 3002, "Auth class_uid must be 3002"
        assert result.ocsf_category_uid == 3, "Auth category_uid must be 3 (IAM)"
        assert result.ocsf_activity_id == 2, "Auth activity_id must be 2 (Logon Failed)"
        assert result.ocsf_severity_id == 3, "Rule level 5 must map to ocsf_severity_id=3 (Medium)"

    def test_network_web_event_gets_correct_ocsf_fields(self):
        """HTTP scan event must map to OCSF class_uid=4001 (Network Activity)."""
        plugin = OCSFFieldMapperPlugin()
        cem = make_cem(event_category="WEB_OPERATIONAL", rule_level=3)
        result = plugin.enrich(cem, make_raw_stub())

        assert result.ocsf_class_uid == 4001, "Network class_uid must be 4001"
        assert result.ocsf_category_uid == 4, "Network category_uid must be 4"

    def test_malware_event_gets_severity_bias(self):
        """Malware category must apply severity_bias=+2 (raises Medium → High)."""
        plugin = OCSFFieldMapperPlugin()
        # Rule level 5 = ocsf_severity_id 3 (Medium) → MALWARE adds +2 → 5 (Critical)
        cem = make_cem(event_category="MALWARE", rule_level=5)
        result = plugin.enrich(cem, make_raw_stub())

        assert result.ocsf_class_uid == 2004, "Malware class_uid must be 2004"
        assert result.ocsf_severity_id == 5, "Malware bias +2 on level-5 must give severity_id=5 (Critical)"

    def test_unknown_category_returns_none_gracefully(self):
        """Completely unknown category must not crash — all OCSF fields stay None."""
        plugin = OCSFFieldMapperPlugin()
        cem = make_cem(event_category="TOTALLY_NEW_FUTURE_CATEGORY", rule_level=7)
        result = plugin.enrich(cem, make_raw_stub())

        assert result.ocsf_class_uid is None, "Unknown category must not assign class_uid"
        assert result.ocsf_category_uid is None

    def test_all_22_categories_produce_non_none_class_uid(self):
        """Every one of the 22 universal Sweet Spot categories must have a valid OCSF mapping."""
        plugin = OCSFFieldMapperPlugin()
        categories = [
            "AUTH_FAILURE", "AUTH_SUCCESS", "CREDENTIAL_ACCESS",
            "LATERAL_MOVEMENT", "PRIVILEGE_ESCALATION", "EXECUTION",
            "PERSISTENCE", "DEFENSE_EVASION", "DISCOVERY", "INITIAL_ACCESS",
            "EXFILTRATION", "WEB_ATTACK", "WEB_OPERATIONAL",
            "MALWARE", "RANSOMWARE", "VULNERABILITY", "FILE_INTEGRITY",
            "CLOUD_CONTAINER", "SYSTEM_HEALTH", "CONFIGURATION_ASSESSMENT",
            "OTHER", "COMPLIANCE", "TELEMETRY"
        ]
        missing = []
        for cat in categories:
            cem = make_cem(event_category=cat, rule_level=5)
            result = plugin.enrich(cem, make_raw_stub())
            if result.ocsf_class_uid is None:
                missing.append(cat)

        assert not missing, f"These categories lack OCSF class_uid mapping: {missing}"


# ---------------------------------------------------------------------------
# Test 2: MITRECommunitySupplementPlugin
# ---------------------------------------------------------------------------
class TestMITRECommunitySupplement:

    def test_rule_without_upstream_mitre_gets_supplement(self):
        """Rule 533 (syscollector) has no upstream MITRE → supplement provides T1049."""
        plugin = MITRECommunitySupplementPlugin()
        cem = make_cem(rule_id="533", mitre_tactics=[], mitre_attack_ids=[])
        result = plugin.enrich(cem, make_raw_stub())

        assert "discovery" in result.mitre_tactics, "Rule 533 supplement must provide 'discovery' tactic"
        assert "T1049" in result.mitre_attack_ids, "Rule 533 supplement must provide T1049"

    def test_rule_with_existing_mitre_is_not_overwritten(self):
        """If upstream MITRE data exists, supplement must NOT overwrite it."""
        plugin = MITRECommunitySupplementPlugin()
        cem = make_cem(
            rule_id="533",
            mitre_tactics=["initial-access"],   # already set
            mitre_attack_ids=["T1190"]           # already set
        )
        result = plugin.enrich(cem, make_raw_stub())

        assert result.mitre_tactics == ["initial-access"], "Existing MITRE tactic must not be overwritten"
        assert result.mitre_attack_ids == ["T1190"], "Existing MITRE technique must not be overwritten"

    def test_unknown_rule_does_not_crash_supplement(self):
        """A rule ID not in supplement returns CEM unchanged without error."""
        plugin = MITRECommunitySupplementPlugin()
        cem = make_cem(rule_id="999999", mitre_tactics=[], mitre_attack_ids=[])
        result = plugin.enrich(cem, make_raw_stub())

        assert result.mitre_tactics == [], "Unknown rule must leave mitre_tactics empty"


# ---------------------------------------------------------------------------
# Test 3: InlineRiskScorerPlugin
# ---------------------------------------------------------------------------
class TestInlineRiskScorer:

    def test_base_score_calculation(self):
        """Standard host, rule level 5 → score = floor(5*6.0) + 5 = 35."""
        plugin = InlineRiskScorerPlugin()
        cem = make_cem(rule_level=5, host_criticality="STANDARD", event_category="AUTH_FAILURE")
        result = plugin.enrich(cem, make_raw_stub())

        assert result.inline_risk_score is not None, "inline_risk_score must not be None"
        assert result.inline_risk_score >= 30, f"Expected >= 30, got {result.inline_risk_score}"
        assert result.inline_risk_score <= 50, f"Expected <= 50, got {result.inline_risk_score}"

    def test_crown_jewel_asset_raises_score(self):
        """CROWN_JEWEL asset must produce higher score than STANDARD for same rule."""
        plugin = InlineRiskScorerPlugin()
        cem_std = make_cem(rule_level=5, host_criticality="STANDARD", event_category="AUTH_FAILURE")
        cem_cj  = make_cem(rule_level=5, host_criticality="CROWN_JEWEL", event_category="AUTH_FAILURE")

        std_score = plugin.enrich(cem_std, make_raw_stub()).inline_risk_score
        cj_score  = plugin.enrich(cem_cj, make_raw_stub()).inline_risk_score

        assert cj_score > std_score, f"CROWN_JEWEL ({cj_score}) must exceed STANDARD ({std_score})"

    def test_threat_intel_match_bonus(self):
        """threat_intel_match=True must add bonus (default +20) to score."""
        plugin = InlineRiskScorerPlugin()
        cem_no  = make_cem(rule_level=5, host_criticality="STANDARD", threat_intel_match=False)
        cem_yes = make_cem(rule_level=5, host_criticality="STANDARD", threat_intel_match=True)

        score_no  = plugin.enrich(cem_no, make_raw_stub()).inline_risk_score
        score_yes = plugin.enrich(cem_yes, make_raw_stub()).inline_risk_score

        assert score_yes > score_no, f"Threat-intel score ({score_yes}) must exceed no-intel ({score_no})"
        assert score_yes - score_no >= 15, "Threat intel bonus must be at least 15 points"

    def test_score_is_capped_at_100(self):
        """Maximum possible score must never exceed 100."""
        plugin = InlineRiskScorerPlugin()
        cem = make_cem(
            rule_level=15,
            host_criticality="CROWN_JEWEL",
            event_category="MALWARE",
            threat_intel_match=True,
            is_internet_exposed=True,
            is_privileged_user=True,
            is_service_account=True,
        )
        result = plugin.enrich(cem, make_raw_stub())
        assert result.inline_risk_score <= 100, f"Score must be capped at 100, got {result.inline_risk_score}"
        assert result.inline_risk_score == 100, f"Max conditions must hit cap=100, got {result.inline_risk_score}"

    def test_score_is_never_negative(self):
        """Score must always be >= 0 even for unknown categories."""
        plugin = InlineRiskScorerPlugin()
        cem = make_cem(rule_level=0, host_criticality="LAB", event_category="SYSTEM_HEALTH")
        result = plugin.enrich(cem, make_raw_stub())
        assert result.inline_risk_score >= 0, f"Score must be >= 0, got {result.inline_risk_score}"


# ---------------------------------------------------------------------------
# Test 4: Full Plugin Chain
# ---------------------------------------------------------------------------
class TestFullPluginChain:

    def test_full_chain_populates_all_new_fields(self):
        """After full plugin chain: all 5 new CEM fields must be set (not None)."""
        cem = make_cem(rule_level=7, event_category="AUTH_FAILURE", host_criticality="HIGH")
        result = run_plugin_chain(cem, make_raw_stub())

        assert result.ocsf_class_uid is not None, "ocsf_class_uid must be set by chain"
        assert result.ocsf_category_uid is not None, "ocsf_category_uid must be set by chain"
        assert result.ocsf_activity_id is not None, "ocsf_activity_id must be set by chain"
        assert result.ocsf_severity_id is not None, "ocsf_severity_id must be set by chain"
        assert result.inline_risk_score is not None, "inline_risk_score must be set by chain"

    def test_full_chain_ssh_auth_scenario(self):
        """
        Real scenario: SSH auth success, rule 5715, level 5, STANDARD host.
        Expected: OCSF class 3002 (Auth), severity Medium (3), risk_score ~35
        """
        cem = make_cem(
            rule_id="5715",
            rule_level=5,
            event_category="AUTH_FAILURE",
            host_criticality="STANDARD",
            username="ubuntu",
            source_ip="192.168.30.114",
        )
        result = run_plugin_chain(cem, make_raw_stub())

        assert result.ocsf_class_uid == 3002
        assert result.ocsf_severity_id == 3
        assert 25 <= result.inline_risk_score <= 55

    def test_full_chain_is_fast(self):
        """Plugin chain must complete 10,000 events in < 2 seconds (same O(1) guarantee)."""
        cem_template = make_cem(rule_level=5, event_category="AUTH_FAILURE")
        raw = make_raw_stub()

        t0 = time.perf_counter()
        for _ in range(10_000):
            import copy
            cem = copy.copy(cem_template)
            run_plugin_chain(cem, raw)
        elapsed = time.perf_counter() - t0

        assert elapsed < 2.0, f"10,000 plugin chain calls took {elapsed:.2f}s — must be < 2.0s"
        print(f"\n  [perf] 10,000 chain calls: {elapsed:.3f}s ({10000/elapsed:,.0f} events/sec)")

    def test_chain_survives_minimal_cem(self):
        """Plugin chain must not crash on minimal CEM with many None fields."""
        cem = make_cem(
            rule_level=1,
            event_category="SYSTEM_HEALTH",
            host_criticality="LAB",
            source_ip=None,
            username=None,
            process_name=None,
        )
        # Should not raise
        result = run_plugin_chain(cem, make_raw_stub())
        assert result is not None
        assert result.inline_risk_score is not None


# ---------------------------------------------------------------------------
# Test 5: Config Files Exist and Are Valid JSON
# ---------------------------------------------------------------------------
class TestConfigFiles:

    CONFIG_DIR = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "config"
    )

    def test_ocsf_mapping_json_is_valid(self):
        path = os.path.join(self.CONFIG_DIR, "ocsf_mapping.json")
        assert os.path.exists(path), "ocsf_mapping.json must exist"
        with open(path) as f:
            data = json.load(f)
        assert "categories" in data
        assert "severity_map" in data
        assert len(data["categories"]) >= 9

    def test_mitre_supplement_json_is_valid(self):
        path = os.path.join(self.CONFIG_DIR, "mitre_community_supplement.json")
        assert os.path.exists(path), "mitre_community_supplement.json must exist"
        with open(path) as f:
            data = json.load(f)
        assert "supplement" in data
        assert len(data["supplement"]) >= 30

    def test_inline_risk_weights_json_is_valid(self):
        path = os.path.join(self.CONFIG_DIR, "inline_risk_weights.json")
        assert os.path.exists(path), "inline_risk_weights.json must exist"
        with open(path) as f:
            data = json.load(f)
        assert "formula" in data
        assert "asset_criticality_scores" in data
        assert "bonuses" in data
        assert data["formula"]["cap"] == 100
