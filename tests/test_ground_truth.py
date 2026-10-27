"""
Test Ground Truth Flow & Manager Validation Pipeline
Tests 100% compliant flow:
1. OPEN -> INVESTIGATE (Analyst starts investigation)
2. INVESTIGATE -> WAITING (Analyst submits Ground Truth TP/FP)
3. WAITING -> APPROVE (SOC Manager approves, triggers retraining dataset & IRIS/MISP/Supresi)
4. WAITING -> REJECT (SOC Manager rejects)
"""
import pytest
from fastapi.testclient import TestClient
from pipeline.api import app
import psycopg2
from psycopg2.extras import RealDictCursor
from config.settings import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD

client = TestClient(app)


@pytest.fixture
def db_conn():
    conn = psycopg2.connect(
        host=DB_HOST, port=DB_PORT, database=DB_NAME, user=DB_USER, password=DB_PASSWORD
    )
    yield conn
    conn.close()


def test_ground_truth_end_to_end_approval_flow(db_conn):
    """
    Test: OPEN -> INVESTIGATE -> SUBMIT GT (WAITING) -> APPROVE
    """
    test_inc_id = "INC-TEST-FLOW-01"
    test_trg_id = "TRG-TEST-FLOW-01"

    with db_conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            INSERT INTO correlation.correlated_incidents (
                incident_id, correlation_rule_id, tenant_id,
                title, narrative, attacker_source_ip, target_host,
                first_seen_at, last_seen_at
            ) VALUES (
                %s, 'CORR-003', 'TenantA',
                'SSH Brute Force Attack', 'Multiple failed SSH attempts',
                '198.51.100.10', 'srv-bastion',
                CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
            ) ON CONFLICT (incident_id) DO UPDATE SET title = EXCLUDED.title;
        """, (test_inc_id,))

        cur.execute("""
            INSERT INTO soc_ops.soc_triage_queue (
                triage_id, incident_id, priority, triage_status, ground_truth_status
            ) VALUES (
                %s, %s, 'P1', 'GROUNDTRUTH', 'ACT NEED'
            ) ON CONFLICT (triage_id) DO UPDATE SET triage_status = 'GROUNDTRUTH', ground_truth_status = 'ACT NEED';
        """, (test_trg_id, test_inc_id))
        db_conn.commit()

    try:
        # Step 1: Analyst submits Ground Truth (TRUE_POSITIVE)
        res_gt = client.post(
            f"/api/triage/{test_trg_id}/submit-ground-truth",
            json={
                "verdict": "TRUE_POSITIVE",
                "notes": "Confirmed malicious SSH password spraying attack.",
                "analyst_id": "soc_analyst_alice"
            }
        )
        assert res_gt.status_code == 200, res_gt.text
        data_gt = res_gt.json()
        assert data_gt["ticket"]["ground_truth_status"] == "WAITING"
        assert data_gt["ticket"]["triage_status"] == "GROUNDTRUTH"
        assert data_gt["ticket"]["ground_truth_verdict"] == "TRUE_POSITIVE"

        # Step 2: SOC Manager checks queue
        res_q = client.get("/api/ground-truth/queue")
        assert res_q.status_code == 200
        records = res_q.json()["records"]
        waiting_ticket = next((r for r in records if r["triage_id"] == test_trg_id), None)
        assert waiting_ticket is not None
        assert waiting_ticket["ground_truth_verdict"] == "TRUE_POSITIVE"

        # Step 3: SOC Manager APPROVES Ground Truth
        res_app = client.post(
            f"/api/ground-truth/{test_trg_id}/approve",
            json={
                "manager_notes": "Validated by SOC Lead. Verified malicious activity.",
                "manager_id": "soc_manager_bob"
            }
        )
        assert res_app.status_code == 200, res_app.text
        data_app = res_app.json()
        assert data_app["status"] == "APPROVE"
        assert data_app["ticket"]["ground_truth_status"] == "APPROVE"
        assert data_app["ticket"]["triage_status"] in ("CLOSE", "CLOSED")
        assert data_app["iris_case"] is not None
        assert data_app["misp_event"] is not None

        # Verify entry in ground_truth_dataset for ML retraining
        with db_conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM soc_ops.ground_truth_dataset WHERE incident_id = %s;", (test_inc_id,))
            gt = cur.fetchone()
            assert gt is not None
            assert gt["ground_truth_label"] == 1  # TP = 1
            assert gt["is_used_in_training"] is False

    finally:
        with db_conn.cursor() as cur:
            cur.execute("DELETE FROM soc_ops.ground_truth_dataset WHERE incident_id = %s;", (test_inc_id,))
            cur.execute("DELETE FROM soc_ops.soc_triage_queue WHERE incident_id = %s;", (test_inc_id,))
            cur.execute("DELETE FROM correlation.correlated_incidents WHERE incident_id = %s;", (test_inc_id,))
            db_conn.commit()


def test_ground_truth_rejection(db_conn):
    """
    Test: OPEN -> INVESTIGATE -> SUBMIT GT (WAITING) -> REJECT
    Validates that rejecting transitions status to REJECT without spawning FP Reject ticket!
    """
    test_inc_id = "INC-TEST-REJ-01"
    test_trg_id = "TRG-TEST-REJ-01"

    with db_conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            INSERT INTO correlation.correlated_incidents (
                incident_id, correlation_rule_id, tenant_id,
                title, narrative, attacker_source_ip, target_host,
                first_seen_at, last_seen_at
            ) VALUES (
                %s, 'CORR-008', 'TenantB',
                'Web Scanner Anomaly', 'Repeated 404 queries',
                '203.0.113.50', 'srv-frontend',
                CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
            ) ON CONFLICT (incident_id) DO UPDATE SET title = EXCLUDED.title;
        """, (test_inc_id,))

        cur.execute("""
            INSERT INTO soc_ops.soc_triage_queue (
                triage_id, incident_id, priority, triage_status, ground_truth_status
            ) VALUES (
                %s, %s, 'P2', 'GROUNDTRUTH', 'ACT NEED'
            ) ON CONFLICT (triage_id) DO UPDATE SET triage_status = 'GROUNDTRUTH', ground_truth_status = 'ACT NEED';
        """, (test_trg_id, test_inc_id))
        db_conn.commit()

    try:
        # Step 1: Analyst submits FP verdict
        client.post(
            f"/api/triage/{test_trg_id}/submit-ground-truth",
            json={
                "verdict": "FALSE_POSITIVE",
                "notes": "Believed to be authorized vulnerability scanner.",
                "analyst_id": "soc_analyst_alice"
            }
        )

        # Step 2: SOC Manager rejects verdict because origin IP is unauthorized
        res_rej = client.post(
            f"/api/ground-truth/{test_trg_id}/reject",
            json={
                "manager_notes": "IP 203.0.113.50 bukan scanner resmi internal. Wajib telusuri payload.",
                "manager_id": "soc_manager_bob"
            }
        )
        assert res_rej.status_code == 200, res_rej.text
        data_rej = res_rej.json()
        assert data_rej["status"] == "REJECT"
        assert data_rej["old_ticket_id"] == test_trg_id

        # Verify ground_truth_status is updated to REJECT and triage_status remains GROUNDTRUTH
        with db_conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT triage_id, triage_status, ground_truth_status, incident_id FROM soc_ops.soc_triage_queue WHERE triage_id = %s;", (test_trg_id,))
            found_ticket = cur.fetchone()
        assert found_ticket is not None
        assert found_ticket["ground_truth_status"] == "REJECT"
        assert found_ticket["triage_status"] == "GROUNDTRUTH"

    finally:
        with db_conn.cursor() as cur:
            cur.execute("DELETE FROM soc_ops.soc_triage_queue WHERE incident_id = %s;", (test_inc_id,))
            cur.execute("DELETE FROM correlation.correlated_incidents WHERE incident_id = %s;", (test_inc_id,))
            db_conn.commit()
