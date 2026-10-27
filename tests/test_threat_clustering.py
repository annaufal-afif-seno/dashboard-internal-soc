"""
Unit Tests for Threat Campaign & Multi-Layer Attack Graph Clustering Engine
===========================================================================
Tests Layer 1 (Spatial Graph), Layer 2 (Temporal DAG), Layer 3 (Cumulative Context),
and Retrospective Alert Unmasking without disrupting any existing features.
"""

import pytest
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from unittest.mock import MagicMock, patch

from pipeline.models import (
    ThreatCampaignClusterDB, ClusterMemberDB, ClusterCausalityEdgeDB
)
from pipeline.campaign_clustering import ThreatCampaignClusterer
from fastapi.testclient import TestClient
from pipeline.api import app


def test_models_instantiation():
    """Verify that new Pydantic clustering models instantiate cleanly with valid fields."""
    now = datetime.now(timezone.utc)
    cluster = ThreatCampaignClusterDB(
        cluster_id="CAMP-20261017-001",
        pivot_incident_id="INC-B5A8566B0DDA6307",
        pivot_triage_id="TRG-001",
        tenant_id="DEFAULT",
        target_host="srv-prod-db01",
        compromised_account="admin",
        campaign_title="Coordinated Recon and SSH Intrusion",
        campaign_risk_score=95,
        priority="P0",
        mitre_tactics_chain=["Reconnaissance", "Credential Access", "Initial Access"],
        first_activity_at=now - timedelta(hours=18),
        last_activity_at=now,
        total_distinct_actors=3,
        total_aggregates_count=7,
        total_raw_events_count=520,
        causality_dag={"stages": []},
        cluster_status="CONFIRMED_THREAT"
    )
    assert cluster.cluster_id == "CAMP-20261017-001"
    assert cluster.priority == "P0"
    assert cluster.campaign_risk_score == 95
    assert len(cluster.mitre_tactics_chain) == 3

    member = ClusterMemberDB(
        cluster_id="CAMP-20261017-001",
        aggregation_id="AGG-RECON-01",
        layer_stage=1,
        entity_role="PRECURSOR_RECON",
        actor_entity="198.51.100.14",
        target_entity="srv-prod-db01",
        rule_id=100002,
        event_timestamp=now - timedelta(hours=18),
        temporal_offset_seconds=-64800,
        confidence_weight=Decimal("0.850"),
        prior_status="AUTO_CLOSED",
        evidence_summary="Port scan detected"
    )
    assert member.entity_role == "PRECURSOR_RECON"
    assert member.prior_status == "AUTO_CLOSED"

    edge = ClusterCausalityEdgeDB(
        cluster_id="CAMP-20261017-001",
        source_node="actor:198.51.100.14",
        target_node="host:srv-prod-db01",
        relation_type="PRECURSOR_RECON",
        weight=Decimal("0.850"),
        evidence_timestamp=now
    )
    assert edge.source_node == "actor:198.51.100.14"


def test_classify_event_role():
    """Verify kill-chain role classification based on categories and rule descriptions."""
    clusterer = ThreatCampaignClusterer()

    recon_agg = {"category": "DISCOVERY", "rule_description": "Nmap Port Scan", "rule_id": 100002}
    assert clusterer._classify_event_role(recon_agg, is_pivot=False) == "PRECURSOR_RECON"

    spray_agg = {"category": "AUTH_FAILURE", "rule_description": "SSH Failed Auth", "rule_id": 5716}
    assert clusterer._classify_event_role(spray_agg, is_pivot=False) == "BRUTE_FORCE_SPRAY"

    pivot_agg = {"category": "AUTH_SUCCESS", "rule_description": "SSH Login Success", "rule_id": 5715}
    assert clusterer._classify_event_role(pivot_agg, is_pivot=True) == "PIVOT_COMPROMISE"

    lateral_agg = {"category": "LATERAL_MOVEMENT", "rule_description": "PsExec execution"}
    assert clusterer._classify_event_role(lateral_agg, is_pivot=False) == "LATERAL_MOVE"

    c2_agg = {"category": "COMMAND_AND_CONTROL", "rule_description": "Beaconing to external IP"}
    assert clusterer._classify_event_role(c2_agg, is_pivot=False) == "C2_EXFIL"


def test_campaign_clustering_mock_pipeline():
    """
    Test end-to-end campaign clustering logic with multiple actors and
    previously closed precursor tickets.
    """
    now = datetime.now(timezone.utc)
    mock_db = MagicMock()

    # Create mock candidate aggregates representing:
    # 1. Recon IP 198.51.100.14 (18h ago, previously AUTO_CLOSED)
    # 2. Spray IP 203.0.113.88 (6h ago, previously WAITING_SLA)
    # 3. Pivot IP 45.33.32.156 (now, P0 Breach)
    candidate_data = [
        {
            "aggregation_id": "AGG-RECON-001",
            "rule_id": 100002,
            "actor": "198.51.100.14",
            "target": "srv-prod-db01",
            "category": "DISCOVERY",
            "window_start": now - timedelta(hours=18),
            "window_end": now - timedelta(hours=17, minutes=45),
            "event_count": 45,
            "rule_description": "Web Directory Fuzzing",
            "status": "AUTO_CLOSED",
            "mitre_tactics": ["Reconnaissance"],
            "distinct_ioas": [],
            "distinct_iocs": ["198.51.100.14"],
            "triage_id": "TRG-001",
            "triage_status": "AUTO_CLOSED",
            "resolution_outcome": "BENIGN"
        },
        {
            "aggregation_id": "AGG-SPRAY-002",
            "rule_id": 5716,
            "actor": "203.0.113.88",
            "target": "srv-prod-db01",
            "category": "AUTH_FAILURE",
            "window_start": now - timedelta(hours=6),
            "window_end": now - timedelta(hours=5, minutes=45),
            "event_count": 500,
            "rule_description": "SSH Authentication Failed",
            "status": "CLOSED",
            "mitre_tactics": ["Credential Access"],
            "distinct_ioas": [],
            "distinct_iocs": ["203.0.113.88"],
            "triage_id": "TRG-002",
            "triage_status": "WAITING_SLA",
            "resolution_outcome": None
        },
        {
            "aggregation_id": "AGG-PIVOT-003",
            "rule_id": 5715,
            "actor": "45.33.32.156",
            "target": "srv-prod-db01",
            "category": "AUTH_SUCCESS",
            "window_start": now - timedelta(minutes=5),
            "window_end": now,
            "event_count": 1,
            "rule_description": "SSH Authentication Succeeded",
            "status": "OPEN",
            "mitre_tactics": ["Initial Access"],
            "distinct_ioas": [],
            "distinct_iocs": ["45.33.32.156"],
            "triage_id": "TRG-003",
            "triage_status": "INVESTIGATE",
            "resolution_outcome": "TRUE_POSITIVE_ACTIONABLE"
        }
    ]

    clusterer = ThreatCampaignClusterer(db_manager=mock_db, default_lookback_hours=72)

    with patch.object(clusterer, "_fetch_candidate_aggregates", return_value=candidate_data), \
         patch.object(clusterer, "_fetch_cumulative_context", return_value={"max_sightings": 15, "dormant_actors": ["203.0.113.88"]}), \
         patch.object(clusterer, "_fetch_analyst_precedent", return_value={"has_true_positive_precedent": True, "precedent_confidence": 95.0}), \
         patch.object(clusterer, "_persist_campaign", return_value=None), \
         patch.object(clusterer, "_reclassify_precursor_tickets", return_value=None):

        pivot_incident = {
            "incident_id": "INC-B5A8566B0DDA6307",
            "triage_id": "TRG-003",
            "tenant_id": "DEFAULT",
            "target_host": "srv-prod-db01",
            "attacker_source_ip": "45.33.32.156",
            "compromised_account": "admin",
            "priority": "P0",
            "last_seen_at": now
        }

        res = clusterer.cluster_threat_campaign(pivot_incident)

        assert res["cluster_id"].startswith("CAMP-")
        assert res["target_host"] == "srv-prod-db01"
        assert res["priority"] == "P0"  # Invariant: Inherits highest priority P0
        assert res["total_distinct_actors"] == 3
        assert "198.51.100.14" in res["causality_dag"]["distinct_actors"]
        assert "203.0.113.88" in res["causality_dag"]["distinct_actors"]
        assert "45.33.32.156" in res["causality_dag"]["distinct_actors"]

        stages = res["causality_dag"]["stages"]
        assert len(stages) == 3
        # Monotonic time ordering: Recon -> Spray -> Pivot
        assert stages[0]["role"] == "PRECURSOR_RECON"
        assert stages[0]["prior_status"] == "AUTO_CLOSED"  # Unmasked!
        assert stages[1]["role"] == "BRUTE_FORCE_SPRAY"
        assert stages[2]["role"] == "PIVOT_COMPROMISE"

        # CRI Risk Score should reflect multi-IP coordination and high severity
        assert res["campaign_risk_score"] >= 90


def test_api_campaign_cluster_endpoints():
    """Verify that FastAPI REST API endpoints for threat campaigns return valid responses."""
    client = TestClient(app)

    # 1. GET /api/campaign-clusters
    response = client.get("/api/campaign-clusters")
    assert response.status_code == 200
    data = response.json()
    assert data.get("status") == "success"
    assert "data" in data

    # 2. GET /api/campaign-clusters/CAMP-NONEXISTENT should 404 cleanly
    resp_404 = client.get("/api/campaign-clusters/CAMP-NONEXISTENT")
    assert resp_404.status_code == 404
