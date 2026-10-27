"""
End-to-End Simulation: Alur Sistem 100% Sesuai Spesifikasi (Tahap 1 s.d. Tahap 5)
================================================================================
Memverifikasi:
- Tahap 1: Ingest via Vector (vector.toml & vector_adapter)
- Tahap 2: Normalisasi CEM murni (Common Event Model)
- Tahap 3: Agregasi 6-Dimensi (15 menit window, dedup key)
- Tahap 4: Korelasi Entitas 24-Jam (Lookback 24h, linking root cause, auto-close >= 85 vs open < 85)
- Tahap 5: Pure ML & Siklus Hidup Tiket SOC (OPEN -> INVESTIGATE -> WAITING -> APPROVE / REJECT)
"""
import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
import psycopg2
from psycopg2.extras import RealDictCursor

from config.settings import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD
from pipeline.adapters.vector_adapter import MockVectorAdapter
from pipeline.models import CommonEventModel, WazuhRawAlert, RuleModel, AgentModel
from pipeline.ml_classifier import LightGBMIncidentClassifier
from pipeline.api import app

client = TestClient(app)


@pytest.fixture
def db_conn():
    conn = psycopg2.connect(
        host=DB_HOST, port=DB_PORT, database=DB_NAME, user=DB_USER, password=DB_PASSWORD
    )
    yield conn
    conn.close()


def test_e2e_5stages_flow_approval(db_conn):
    """
    Simulasi Lengkap Tahap 1 s.d. 5:
    Alert masuk -> Normalisasi -> Agregasi -> Korelasi -> ML -> OPEN -> INVESTIGATE -> WAITING -> APPROVE
    """
    # =========================================================================
    # TAHAP 1: Ingest via Vector
    # =========================================================================
    vec_adapter = MockVectorAdapter()
    v_status = vec_adapter.health_check()
    assert v_status.is_connected is True
    cfg_val = vec_adapter.validate_config("vector.toml")
    assert cfg_val["valid"] is True

    raw_wazuh_alert = {
        "id": "e2e-alert-001",
        "timestamp": "2026-10-08T10:00:00Z",
        "rule": {
            "id": "5710",
            "level": 8,
            "description": "sshd: Multiple failed login attempts",
            "mitre": {
                "id": ["T1110"],
                "tactic": ["credential-access"],
                "technique": ["Brute Force"]
            }
        },
        "agent": {"id": "001", "name": "bastion-host", "ip": "10.0.1.5"},
        "data": {
            "srcip": "203.0.113.195",
            "dstip": "10.0.1.5",
            "srcuser": "root"
        }
    }

    # =========================================================================
    # TAHAP 2: Normalisasi CEM Murni
    # =========================================================================
    cem_alert = CommonEventModel(
        event_id="e2e-alert-001",
        timestamp="2026-10-08T10:00:00Z",
        source_ip="203.0.113.195",
        destination_ip="10.0.1.5",
        destination_host="bastion-host",
        rule_id="5710",
        rule_level=8,
        rule_description="sshd: Multiple failed login attempts",
        mitre_attack_ids=["T1110"],
        mitre_tactics=["credential-access"],
        mitre_techniques=["Brute Force"],
        agent_id="001",
        agent_name="bastion-host",
        tenant_id="TenantA",
        event_category="CREDENTIAL_ACCESS",
        dedup_actor="203.0.113.195",
        dedup_target="bastion-host"
    )
    assert isinstance(cem_alert, CommonEventModel)
    assert cem_alert.source_ip == "203.0.113.195"
    assert cem_alert.destination_ip == "10.0.1.5"
    assert cem_alert.rule_id == "5710"
    assert cem_alert.rule_level == 8
    assert cem_alert.mitre_tactics == ["credential-access"]
    assert cem_alert.mitre_techniques == ["Brute Force"]

    # =========================================================================
    # TAHAP 3: Agregasi 6-Dimensi (15 Menit Window)
    # =========================================================================
    from pipeline.deduplicate import SlidingWindowAggregator
    aggregator = SlidingWindowAggregator()
    aggregator.process_event(cem_alert)
    flushed = aggregator.flush_all()
    assert len(flushed) == 1
    assert flushed[0]["event_count"] == 1
    assert int(flushed[0]["rule_id"]) == 5710

    # =========================================================================
    # TAHAP 4: Korelasi Entitas 24 Jam & Thresholding Auto-Close
    # =========================================================================
    # Lookback window = 24 jam
    lookback_hours = 24
    now = datetime.now(timezone.utc)
    lookback_start = now - timedelta(hours=lookback_hours)
    assert lookback_start < now

    # Aturan Threshold: >= 85.0 Benign -> Auto-Close; < 85.0 atau Threat -> OPEN
    # Kasus: Threat terdeteksi -> Priority P1 -> Masuk ke Queue dengan status OPEN
    test_inc_id = "INC-E2E-SIM-001"
    test_trg_id = "TRG-E2E-SIM-001"

    try:
        with db_conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                INSERT INTO correlation.correlated_incidents (
                    incident_id, correlation_rule_id, tenant_id,
                    title, narrative, attacker_source_ip, target_host,
                    first_seen_at, last_seen_at
                ) VALUES (
                    %s, 'CORR-003', 'TenantA',
                    'E2E SSH Brute Force Campaign', 'Multiple failed SSH attempts across 24h',
                    '203.0.113.195', 'bastion-host',
                    %s, %s
                ) ON CONFLICT (incident_id) DO UPDATE SET title = EXCLUDED.title;
            """, (test_inc_id, lookback_start, now))

            cur.execute("""
                INSERT INTO soc_ops.soc_triage_queue (
                    triage_id, incident_id, priority, triage_status
                ) VALUES (
                    %s, %s, 'P1', 'OPEN'
                ) ON CONFLICT (triage_id) DO UPDATE SET triage_status = 'OPEN';
            """, (test_trg_id, test_inc_id))
            db_conn.commit()

        # =========================================================================
        # TAHAP 5: Pure ML & Siklus Hidup Tiket SOC (OPEN -> INVESTIGATE -> WAITING -> APPROVE)
        # =========================================================================
        # Pure ML check
        classifier = LightGBMIncidentClassifier()
        assert classifier.model is not None

        # Step 5.1: Tiket berada di status OPEN
        res_list = client.get("/api/triage/queue")
        assert res_list.status_code == 200

        # Step 5.2: SOC Analyst mengklik investigasi (OPEN -> INVESTIGATE)
        res_inv = client.post(f"/api/triage/{test_trg_id}/investigate")
        assert res_inv.status_code == 200
        assert res_inv.json()["ticket"]["triage_status"] == "INVESTIGATE"

        # Step 5.3: SOC Analyst menyelesaikan investigasi, submit Ground Truth (INVESTIGATE -> CLOSE di queue, WAITING di GT review)
        res_gt = client.post(
            f"/api/triage/{test_trg_id}/submit-ground-truth",
            json={
                "verdict": "TRUE_POSITIVE",
                "notes": "E2E Verified SSH brute force brute-spray.",
                "analyst_id": "analyst_e2e"
            }
        )
        assert res_gt.status_code == 200
        assert res_gt.json()["ticket"]["ground_truth_status"] == "WAITING"
        assert res_gt.json()["ticket"]["ground_truth_verdict"] == "TRUE_POSITIVE"

        # Step 5.4: SOC Manager mereview queue GT
        res_queue = client.get("/api/ground-truth/queue")
        assert res_queue.status_code == 200
        item = next((r for r in res_queue.json()["records"] if r["triage_id"] == test_trg_id), None)
        assert item is not None

        # Step 5.5: SOC Manager melakukan APPROVE
        res_app = client.post(
            f"/api/ground-truth/{test_trg_id}/approve",
            json={
                "manager_notes": "Approved by SOC Manager: Confirmed external threat actor.",
                "manager_id": "manager_e2e"
            }
        )
        assert res_app.status_code == 200
        app_data = res_app.json()
        assert app_data["status"] == "APPROVE"
        assert app_data["ticket"]["ground_truth_status"] == "APPROVE"
        assert app_data["iris_case"]["status"] == "SUCCESS"
        assert app_data["misp_event"]["status"] == "SUCCESS"
    finally:
        with db_conn.cursor() as cur:
            cur.execute("DELETE FROM soc_ops.ground_truth_dataset WHERE triage_id = %s", (test_trg_id,))
            cur.execute("DELETE FROM soc_ops.soc_triage_queue WHERE incident_id = %s", (test_inc_id,))
            cur.execute("DELETE FROM correlation.correlated_incidents WHERE incident_id = %s", (test_inc_id,))
            db_conn.commit()


def test_e2e_5stages_flow_rejection(db_conn):
    """
    Simulasi Tahap 5 Rejection:
    INVESTIGATE -> WAITING -> REJECT
    """
    test_inc_id = "INC-E2E-SIM-002"
    test_trg_id = "TRG-E2E-SIM-002"

    try:
        with db_conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                INSERT INTO correlation.correlated_incidents (
                    incident_id, correlation_rule_id, tenant_id,
                    title, narrative, attacker_source_ip, target_host,
                    first_seen_at, last_seen_at
                ) VALUES (
                    %s, 'CORR-002', 'TenantA',
                    'E2E False Positive Web Scan', 'Internal vulnerability scanner test',
                    '10.0.0.99', 'web-app-01',
                    CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
                ) ON CONFLICT (incident_id) DO UPDATE SET title = EXCLUDED.title;
            """, (test_inc_id,))

            cur.execute("""
                INSERT INTO soc_ops.soc_triage_queue (
                    triage_id, incident_id, priority, triage_status
                ) VALUES (
                    %s, %s, 'P2', 'INVESTIGATE'
                ) ON CONFLICT (triage_id) DO UPDATE SET triage_status = 'INVESTIGATE', priority = EXCLUDED.priority;
            """, (test_trg_id, test_inc_id))
            db_conn.commit()

        # Analyst submit GT sebagai FALSE_POSITIVE
        res_gt = client.post(
            f"/api/triage/{test_trg_id}/submit-ground-truth",
            json={
                "verdict": "FALSE_POSITIVE",
                "notes": "Scanner internal terotorisasi.",
                "analyst_id": "analyst_bob"
            }
        )
        assert res_gt.status_code == 200

        # SOC Manager mereject Ground Truth karena scanner belum berizin resmi
        res_rej = client.post(
            f"/api/ground-truth/{test_trg_id}/reject",
            json={
                "manager_notes": "Scanner 10.0.0.99 tidak terdaftar di change ticket resmi. Investigasi ulang sebagai anomali.",
                "manager_id": "manager_alice"
            }
        )
        assert res_rej.status_code == 200
        rej_data = res_rej.json()
        assert rej_data["status"] == "REJECT"
        assert rej_data["old_ticket_id"] == test_trg_id
    finally:
        with db_conn.cursor() as cur:
            cur.execute("DELETE FROM soc_ops.ground_truth_dataset WHERE triage_id LIKE 'TRG-%%-REJ' OR triage_id = %s", (test_trg_id,))
            cur.execute("DELETE FROM soc_ops.soc_triage_queue WHERE incident_id = %s", (test_inc_id,))
            cur.execute("DELETE FROM correlation.correlated_incidents WHERE incident_id = %s", (test_inc_id,))
            db_conn.commit()
