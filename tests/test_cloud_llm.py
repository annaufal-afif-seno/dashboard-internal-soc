"""
Unit Tests for Tier-3 Cloud LLM (Gemini) Client
================================================
"""

import pytest
from pipeline.cloud_llm import CloudLLMTriageClient

def test_cloud_llm_client_initialization():
    client = CloudLLMTriageClient()
    assert "gemini" in client.model
    assert client.threshold == 85.0
    assert "generativelanguage.googleapis.com" in client.endpoint_url

def test_data_sanitization_privacy():
    client = CloudLLMTriageClient()
    raw_incident = {
        "incident_id": "INC-TEST-PRIVACY",
        "attacker_source_ip": "192.168.1.163",  # Internal private IP
        "narrative": "User login with password=SecretAdmin123! token=abc999xyz"
    }
    sanitized = client.sanitize_incident(raw_incident)
    
    # Internal IP must be masked
    assert "192.168.1.163" not in sanitized["attacker_source_ip"]
    assert "INTERNAL_SUBNET_NODE" in sanitized["attacker_source_ip"]
    assert sanitized["ip_locality"] == "INTERNAL_PRIVATE_RFC1918"
    
    # Passwords and tokens must be redacted
    assert "SecretAdmin123!" not in sanitized["narrative"]
    assert "REDACTED" in sanitized["narrative"]

def test_prompt_structure_contains_sanitized_data():
    client = CloudLLMTriageClient()
    sample = {
        "incident_id": "INC-TEST-002",
        "title": "Encoded PowerShell",
        "target_host": "srv-prod",
        "host_criticality": "HIGH",
        "attacker_source_ip": "10.0.0.55",
        "total_risk_score": 80,
        "priority": "P1"
    }
    prompt = client.build_prompt(sample)
    assert "INC-TEST-002" in prompt
    assert "srv-prod" in prompt
    assert "10.0.0.55" not in prompt  # Masked!
    assert "INTERNAL_SUBNET_NODE" in prompt
    assert "OUTPUT FORMAT" in prompt

def test_evaluate_fallback_when_no_key():
    client = CloudLLMTriageClient(api_key="")
    res = client.evaluate_incident({"incident_id": "INC-NO-KEY"})
    assert res["status"] == "ERROR_NO_API_KEY"
    assert res["decision"] == "REQUIRE_GROUND_TRUTH"
