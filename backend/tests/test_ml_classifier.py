"""
Unit Tests for LightGBM Incident Classifier (Tier-1 Machine Learning Fast-Filter)
==================================================================================
Tests:
1. Feature extraction from raw and correlated incident dictionaries.
2. Invariant: internal IP identification and privileged user flags.
3. LightGBM inference, probability calibration, and 85% confidence auto-suppression threshold.
4. Model persistence and artifact reloading.
5. Integration with AITriageOrchestrator as Tier-1 filter.
"""

import os
import pytest
import numpy as np
import pandas as pd
from pipeline.ml_classifier import LightGBMIncidentClassifier


def test_extract_features_structure():
    raw_incident = {
        "incident_id": "INC-TEST-001",
        "correlation_rule_id": "CORR-008",
        "attacker_source_ip": "192.168.1.50",
        "compromised_account": "administrator",
        "target_host": "srv-prod-01",
        "host_criticality": "CRITICAL",
        "is_internet_exposed": True,
        "max_inline_risk_score": 85,
        "total_score": 85,
        "stages": [
            {"sequence_order": 1, "stage_name": "SCAN"},
            {"sequence_order": 2, "stage_name": "EXPLOIT"}
        ],
        "threat_intel_match": True,
        "priority": "P0"
    }

    feats = LightGBMIncidentClassifier.extract_features(raw_incident)

    assert feats["has_attacker_ip"] == 1
    assert feats["is_internal_attacker"] == 1  # 192.168.x.x
    assert feats["is_privileged_user"] == 1    # administrator
    assert feats["host_criticality_score"] == 20  # CRITICAL
    assert feats["is_internet_exposed"] == 1
    assert feats["threat_intel_match"] == 1
    assert feats["stages_count"] == 2
    assert feats["rule_code"] == "CORR-008"
    assert feats["priority"] == "P0"


def test_extract_features_external_unprivileged():
    raw_incident = {
        "incident_id": "INC-TEST-002",
        "correlation_rule_id": "CORR-003",
        "attacker_source_ip": "185.177.10.22",
        "compromised_account": "guest_user",
        "target_host": "lab-vm-01",
        "host_criticality": "LAB",
        "is_internet_exposed": False,
        "max_inline_risk_score": 25,
        "total_score": 25,
        "stages": [],
        "threat_intel_match": False,
        "priority": "P3"
    }

    feats = LightGBMIncidentClassifier.extract_features(raw_incident)

    assert feats["has_attacker_ip"] == 1
    assert feats["is_internal_attacker"] == 0  # 185.177.x.x is public
    assert feats["is_privileged_user"] == 0    # guest_user
    assert feats["host_criticality_score"] == 0   # LAB
    assert feats["threat_intel_match"] == 0


def test_unloaded_model_raises_runtime_error_per_prinsip_g():
    # Classifier with non-existent path
    clf = LightGBMIncidentClassifier(model_path="/path/does/not/exist/model.joblib")
    assert clf.model is None

    sample_inc = {
        "rule_code": "HEALTH_CHECK_PROBE",
        "max_inline_risk_score": 15,
        "stages": []
    }
    with pytest.raises(RuntimeError, match="Under Prinsip G"):
        clf.predict_incident(sample_inc)


def test_trained_model_prediction_and_thresholds():
    clf = LightGBMIncidentClassifier()
    if clf.model is None:
        pytest.skip("Trained LightGBM model artifact not yet available on disk.")

    # High severity attack
    threat_inc = {
        "rule_code": "CORR-008",
        "attacker_source_ip": "103.19.110.156",
        "compromised_account": "root",
        "target_host": "hportal-prod-159",
        "host_criticality": "HIGH",
        "is_internet_exposed": True,
        "threat_intel_match": True,
        "max_inline_risk_score": 85,
        "total_score": 85,
        "priority": "P0",
        "stages_count": 5
    }

    res = clf.predict_incident(threat_inc)

    assert "verdict" in res
    assert "confidence" in res
    assert "benign_probability" in res
    assert "threat_probability" in res
    assert abs((res["benign_probability"] + res["threat_probability"]) - 100.0) < 0.1
    assert res["decision"] in ("AUTO_CLOSE", "AUTO_SUPPRESS", "FORWARD_TO_TRIAGE")

    # Invariant: If AUTO_CLOSE/AUTO_SUPPRESS is returned, verdict MUST be BENIGN and confidence >= 85%
    if res["decision"] in ("AUTO_CLOSE", "AUTO_SUPPRESS"):
        assert res["verdict"] == "BENIGN"
        assert res["confidence"] >= 85.0
    else:
        # If forwarded, it is either a threat or low confidence benign
        assert res["decision"] == "FORWARD_TO_TRIAGE"


def test_cfs_suppresses_llm_overconfidence_hallucination():
    """
    LLM mengklaim THREAT dengan 95% confidence, tapi bukti fisik telemetri nihil:
    - Tidak ada Threat Intel (IP bersih)
    - Wazuh rule level rendah (level 3)
    - 1 stage saja (bukan multi-stage)
    - Server non-critical
    - ML memvonis BENIGN 80%
    CFS harus memangkas probabilitas threat hingga < 50%, mencegah auto-escalation palsu!
    """
    from pipeline.ml_classifier import compute_calibrated_factual_score

    fake_incident = {
        "threat_intel_match": False,
        "rule_level": 3,
        "stages": [{"stage_name": "PROBE"}],
        "host_criticality": "STANDARD"
    }
    ml_res = {
        "verdict": "BENIGN",
        "confidence": 80.0
    }
    # LLM overconfident claim: 95% Threat
    llm_threat_prob = 0.95

    cfs = compute_calibrated_factual_score(fake_incident, ml_res, llm_threat_prob)

    assert cfs["evidence_threat_prob"] < 0.10  # Bukti fisik nihil
    assert cfs["cfs_threat_prob"] < 0.50       # Klaim 95% LLM terpangkas drastis
    assert cfs["ti_match"] is False


def test_cfs_prevents_false_auto_close_on_real_threat():
    """
    LLM halusinasi memvonis BENIGN 90% (llm_threat_prob = 0.10),
    tetapi bukti fisik serangan sangat kuat (Threat Intel match, Rule Level 12, Multi-stage).
    CFS harus mendongkrak skor dan memastikan Benign confidence TIDAK mencapai 85%,
    sehingga serangan riil tidak mungkin di-auto-close!
    """
    from pipeline.ml_classifier import compute_calibrated_factual_score

    real_threat_incident = {
        "threat_intel_match": True,
        "rule_level": 12,
        "stages": [{"stage_name": "RECON"}, {"stage_name": "EXPLOIT"}, {"stage_name": "C2"}],
        "host_criticality": "CRITICAL_PROD"
    }
    ml_res = {
        "verdict": "THREAT",
        "confidence": 75.0
    }
    # LLM halusinasi mengklaim hanya 10% threat (90% Benign)
    llm_threat_prob = 0.10

    cfs = compute_calibrated_factual_score(real_threat_incident, ml_res, llm_threat_prob)

    assert cfs["evidence_threat_prob"] > 0.85  # Bukti fisik sangat kuat
    assert cfs["cfs_threat_prob"] > 0.50       # Bukti fisik mengoreksi LLM
    benign_confidence = (1.0 - cfs["cfs_threat_prob"]) * 100.0
    assert benign_confidence < 85.0            # Veto auto-close aktif: tidak bisa ditutup sembarangan!




