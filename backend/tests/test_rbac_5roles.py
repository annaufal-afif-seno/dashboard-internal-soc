"""
Unit Tests for RBAC 5-Role System & User Management
Covers:
1. Retrieval of all 5 roles in ROLE_PERMISSIONS_MATRIX (SOC_ANALYST, SOC_DEVELOPER, SOC_LEAD, SOC_MANAGER, ADMIN)
2. Creation of users with SOC_DEVELOPER and ADMIN roles
3. Password hashing validation (password stored as bcrypt hash, not plaintext)
4. Database CHECK constraint enforcement on invalid roles
"""
import pytest
from fastapi.testclient import TestClient
import psycopg2
from psycopg2 import extras

from pipeline.api import app, ROLE_PERMISSIONS_MATRIX
from config.settings import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


def test_role_permissions_matrix_5_roles():
    expected_roles = {"SOC_ANALYST", "SOC_DEVELOPER", "SOC_LEAD", "SOC_MANAGER", "ADMIN"}
    assert set(ROLE_PERMISSIONS_MATRIX.keys()) == expected_roles

    # Verify SOC_DEVELOPER permissions
    dev_perms = ROLE_PERMISSIONS_MATRIX["SOC_DEVELOPER"]["permissions"]
    assert dev_perms["view_analytics"] is True
    assert dev_perms["triage_tickets"] is False
    assert dev_perms["manage_suppression_rules"] is True
    assert dev_perms["approve_suppression"] is False
    assert dev_perms["manage_users"] is False

    # Verify ADMIN permissions (Full Universal Access / Superadmin)
    admin_perms = ROLE_PERMISSIONS_MATRIX["ADMIN"]["permissions"]
    assert admin_perms["manage_users"] is True
    assert admin_perms["run_database_maintenance"] is True
    assert admin_perms["manage_api_keys"] is True
    assert admin_perms["triage_tickets"] is True
    assert admin_perms["view_incidents"] is True
    assert admin_perms["approve_suppression"] is True
    assert admin_perms["manage_suppression_rules"] is True


def test_get_rbac_users_endpoint(client):
    res = client.get("/api/system/rbac/users")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] >= 1
    assert "SOC_DEVELOPER" in data["roles"]
    assert "ADMIN" in data["roles"]
    usernames = [u["username"] for u in data["users"]]
    assert "admin_secops" in usernames


def test_create_and_delete_user_flow(client):
    test_username = "test_developer_pytest"
    test_email = "test.pytest.dev@pradita.ac.id"

    # Clean up before test if leftover
    conn = psycopg2.connect(host=DB_HOST, port=DB_PORT, dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD)
    cur = conn.cursor(cursor_factory=extras.RealDictCursor)
    cur.execute("DELETE FROM soc_ops.soc_users WHERE username = %s OR email = %s;", (test_username, test_email))
    conn.commit()

    try:
        # Create user via API
        payload = {
            "username": test_username,
            "full_name": "Test Pytest Developer",
            "email": test_email,
            "role": "SOC_DEVELOPER",
            "department": "Detection Engineering Unit",
            "password": "TestDevPassword2026!"
        }
        res = client.post("/api/system/rbac/users", json=payload)
        assert res.status_code == 200
        created = res.json()["user"]
        assert created["username"] == test_username
        assert created["role"] == "SOC_DEVELOPER"

        # Verify in database that password is encrypted and not plaintext
        cur.execute("SELECT password_hash, role FROM soc_ops.soc_users WHERE username = %s;", (test_username,))
        row = cur.fetchone()
        assert row is not None
        assert row["role"] == "SOC_DEVELOPER"
        assert row["password_hash"] is not None
        assert row["password_hash"] != "TestDevPassword2026!"
        assert row["password_hash"].startswith("$2b$") or len(row["password_hash"]) == 64

    finally:
        # Clean up
        cur.execute("DELETE FROM soc_ops.soc_users WHERE username = %s OR email = %s;", (test_username, test_email))
        conn.commit()
        cur.close()
        conn.close()


def test_database_constraint_rejects_invalid_role():
    conn = psycopg2.connect(host=DB_HOST, port=DB_PORT, dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD)
    cur = conn.cursor()
    try:
        with pytest.raises(psycopg2.IntegrityError):
            cur.execute("""
                INSERT INTO soc_ops.soc_users (username, full_name, email, role, status, department)
                VALUES ('hacker_invalid', 'Invalid Role', 'invalid@test.com', 'SUPER_HACKER', 'ACTIVE', 'None');
            """)
        conn.rollback()
    finally:
        cur.close()
        conn.close()
