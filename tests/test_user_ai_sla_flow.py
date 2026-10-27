import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone, timedelta

from pipeline.ml_classifier import evaluate_cascading_pipeline

def test_ml_high_confidence_benign_auto_close():
    """ML >= 85% Benign -> AUTO_CLOSE"""
    incident = {
        "incident_id": "INC-TEST-001",
        "title": "Port Scan Noise",
        "priority": "P4",
        "stages_count": 1,
        "total_risk_score": 10.0,
        "rule_level": 3,
        "threat_intel_match": 0,
        "is_internet_exposed": 1,
    }
    with patch("pipeline.ml_classifier.LightGBMIncidentClassifier.predict_incident") as mock_ml:
        mock_ml.return_value = {
            "verdict": "BENIGN",
            "confidence": 92.5,
            "predicted_label": 0,
            "decision": "AUTO_CLOSE"
        }
        res = evaluate_cascading_pipeline(incident)
        assert res["active_tier"] == "Tier-1 ML"
        assert res["decision"] == "AUTO_CLOSE"
        assert res["final_verdict"] == "BENIGN"
        assert res["final_confidence"] == 92.5
        assert res["needs_ground_truth"] is False


def test_ml_high_confidence_threat_create_iris_case():
    """ML >= 85% Threat -> CREATE_IRIS_CASE"""
    incident = {
        "incident_id": "INC-TEST-002",
        "title": "Severe Exploit",
        "priority": "P0",
        "stages_count": 3,
        "total_risk_score": 85.0,
        "rule_level": 12,
        "threat_intel_match": 1,
    }
    with patch("pipeline.ml_classifier.LightGBMIncidentClassifier.predict_incident") as mock_ml:
        mock_ml.return_value = {
            "verdict": "THREAT",
            "confidence": 95.0,
            "predicted_label": 1,
            "decision": "FORWARD_TO_TRIAGE"
        }
        res = evaluate_cascading_pipeline(incident)
        assert res["active_tier"] == "Tier-1 ML"
        assert res["decision"] == "CREATE_IRIS_CASE"
        assert res["final_verdict"] == "THREAT"


def test_local_llm_high_confidence_creates_groundtruth_for_ml():
    """ML < 85%, Local LLM >= 85% -> Decision executed + Ground Truth created for ML retraining"""
    incident = {
        "incident_id": "INC-TEST-003",
        "title": "Ambiguous Probe",
        "priority": "P4",
        "total_risk_score": 40.0,
    }
    with patch("pipeline.ml_classifier.LightGBMIncidentClassifier.predict_incident") as mock_ml, \
         patch("pipeline.local_llm.LocalLLMTriageClient.is_available", return_value=True), \
         patch("pipeline.local_llm.LocalLLMTriageClient.evaluate_incident") as mock_local:
        
        mock_ml.return_value = {
            "verdict": "BENIGN",
            "confidence": 70.0,
            "predicted_label": 0,
        }
        mock_local.return_value = {
            "verdict": "BENIGN",
            "confidence": 88.0,
            "reasoning": "Standard routine health check probe."
        }
        res = evaluate_cascading_pipeline(incident)
        assert res["active_tier"] == "Tier-2 Local LLM"
        assert res["decision"] == "AUTO_CLOSE"
        assert res["needs_ground_truth"] is True
        assert res["ground_truth_target"] == "ML"


def test_soft_voting_formula_benign_auto_close():
    """
    ML < 85, Local < 85 -> Cloud LLM with selective masking & Soft Voting.
    Formula: Local(0.4 * [1 - conf/100 if Benign]) + Cloud(0.6 * [1 - conf/100 if Benign])
    Contoh:
    Local: 80% Benign -> threat score = 1 - 0.8 = 0.2 -> weighted = 0.4 * 0.2 = 0.08
    Cloud: 90% Benign -> threat score = 1 - 0.9 = 0.1 -> weighted = 0.6 * 0.1 = 0.06
    Total threat = 0.14 -> Benign = 1 - 0.14 = 86% (>= 85%) -> AUTO_CLOSE
    """
    incident = {
        "incident_id": "INC-TEST-004",
        "title": "Borderline Activity",
        "priority": "P4",
    }
    with patch("pipeline.ml_classifier.LightGBMIncidentClassifier.predict_incident") as mock_ml, \
         patch("pipeline.local_llm.LocalLLMTriageClient.is_available", return_value=True), \
         patch("pipeline.local_llm.LocalLLMTriageClient.evaluate_incident") as mock_local, \
         patch("pipeline.cloud_llm.CloudLLMTriageClient.is_available", return_value=True), \
         patch("pipeline.cloud_llm.CloudLLMTriageClient.sanitize_incident", side_effect=lambda x: x), \
         patch("pipeline.cloud_llm.CloudLLMTriageClient.evaluate_incident") as mock_cloud:
        
        mock_ml.return_value = {"verdict": "BENIGN", "confidence": 60.0}
        mock_local.return_value = {"verdict": "BENIGN", "confidence": 80.0}
        mock_cloud.return_value = {"verdict": "BENIGN", "confidence": 90.0}

        res = evaluate_cascading_pipeline(incident)
        assert "Tier-3 Cloud LLM (Soft Voting" in res["active_tier"]
        assert res["decision"] == "AUTO_CLOSE"
        assert res["final_verdict"] == "BENIGN"
        assert res["final_confidence"] == 86.0  # 1 - 0.14 = 0.86


def test_soft_voting_formula_threat_create_iris_case():
    """
    Local: 80% Threat -> threat score = 0.8 -> weighted = 0.4 * 0.8 = 0.32
    Cloud: 90% Threat -> threat score = 0.9 -> weighted = 0.6 * 0.9 = 0.54
    Total threat = 0.86 -> 86% (>= 85%) -> CREATE_IRIS_CASE
    """
    incident = {
        "incident_id": "INC-TEST-005",
        "title": "Subtle Intrusion",
        "priority": "P4",
    }
    with patch("pipeline.ml_classifier.LightGBMIncidentClassifier.predict_incident") as mock_ml, \
         patch("pipeline.local_llm.LocalLLMTriageClient.is_available", return_value=True), \
         patch("pipeline.local_llm.LocalLLMTriageClient.evaluate_incident") as mock_local, \
         patch("pipeline.cloud_llm.CloudLLMTriageClient.is_available", return_value=True), \
         patch("pipeline.cloud_llm.CloudLLMTriageClient.sanitize_incident", side_effect=lambda x: x), \
         patch("pipeline.cloud_llm.CloudLLMTriageClient.evaluate_incident") as mock_cloud:
        
        mock_ml.return_value = {"verdict": "THREAT", "confidence": 65.0}
        mock_local.return_value = {"verdict": "THREAT", "confidence": 80.0}
        mock_cloud.return_value = {"verdict": "THREAT", "confidence": 90.0}

        res = evaluate_cascading_pipeline(incident)
        assert res["decision"] == "CREATE_IRIS_CASE"
        assert res["final_verdict"] == "THREAT"
        assert res["final_confidence"] == 86.0


def test_soft_voting_formula_inconclusive_audit_soc_analyst():
    """
    Local: 70% Benign -> threat = 0.3 -> weighted = 0.4 * 0.3 = 0.12
    Cloud: 70% Threat -> threat = 0.7 -> weighted = 0.6 * 0.7 = 0.42
    Total threat = 0.54 -> neither Benign (>= 85%) nor Threat (>= 85%)
    Result -> AUDIT_SOC_ANALYST, ground truth created for Local LLM and ML retraining!
    """
    incident = {
        "incident_id": "INC-TEST-006",
        "title": "Highly Ambiguous Anomaly",
        "priority": "P4",
    }
    with patch("pipeline.ml_classifier.LightGBMIncidentClassifier.predict_incident") as mock_ml, \
         patch("pipeline.local_llm.LocalLLMTriageClient.is_available", return_value=True), \
         patch("pipeline.local_llm.LocalLLMTriageClient.evaluate_incident") as mock_local, \
         patch("pipeline.cloud_llm.CloudLLMTriageClient.is_available", return_value=True), \
         patch("pipeline.cloud_llm.CloudLLMTriageClient.sanitize_incident", side_effect=lambda x: x), \
         patch("pipeline.cloud_llm.CloudLLMTriageClient.evaluate_incident") as mock_cloud:
        
        mock_ml.return_value = {"verdict": "BENIGN", "confidence": 55.0}
        mock_local.return_value = {"verdict": "BENIGN", "confidence": 70.0}
        mock_cloud.return_value = {"verdict": "THREAT", "confidence": 70.0}

        res = evaluate_cascading_pipeline(incident)
        assert res["decision"] == "AUDIT_SOC_ANALYST"
        assert res["final_verdict"] == "AMBIGUOUS"
        assert res["needs_ground_truth"] is True
        assert res["ground_truth_target"] == "LOCAL_LLM_AND_ML"
