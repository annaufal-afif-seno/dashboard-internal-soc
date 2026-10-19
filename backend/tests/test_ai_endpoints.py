"""
Test AI Triage & Ground Truth FastAPI Endpoints
"""
import pytest
from fastapi.testclient import TestClient
from pipeline.api import app

@pytest.fixture(scope="module")
def client():
    return TestClient(app)

def test_api_confusion_matrix(client):
    response = client.get("/api/ai/confusion-matrix")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "benchmark" in data
    # Must contain benchmarks for Local LLM and Cloud LLM
    tiers = [row["model_tier"] for row in data["benchmark"]]
    assert "Local LLM" in tiers
    assert "Cloud LLM" in tiers

def test_api_ground_truth_stats(client):
    response = client.get("/api/ai/ground-truth-stats")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "stats" in data
    assert "total_samples" in data["stats"]
    assert "retraining_ready" in data

def test_api_train_ml(client):
    response = client.post("/api/ai/train-ml")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "metrics" in data
    assert "accuracy" in data["metrics"]
    assert "roc_auc" in data["metrics"]
    assert "feature_importances" in data["metrics"]
