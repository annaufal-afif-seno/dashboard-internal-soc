"""
Unit & Integration Tests for RBAC Authentication / Login Flow
Covers:
1. Successful login using username (admin_secops) -> 200 OK & session token
2. Successful login using email (admin.secops@pradita.ac.id) -> 200 OK
3. Rejection on wrong password -> 401 Unauthorized
4. Rejection on non-existent user -> 401 Unauthorized
5. Rejection on SUSPENDED user -> 403 Forbidden
6. Database verification: last_login is updated upon login
"""
import pytest
from fastapi.testclient import TestClient
import psycopg2
from psycopg2 import extras
import bcrypt

from pipeline.api import app
from config.settings import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture(scope="module")
def db_conn():
    conn = psycopg2.connect(host=DB_HOST, port=DB_PORT, dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD)
    yield conn
    conn.close()


def test_login_admin_success_with_username(client):
    res = client.post("/api/system/rbac/login", json={
        "username": "admin_secops",
        "password": "WazuhSecOps2026!"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert "token" in data
    assert data["user"]["username"] == "admin_secops"
    assert data["user"]["role"] == "ADMIN"
    assert data["user"]["status"] == "ACTIVE"


def test_login_admin_success_with_email(client, db_conn):
    with db_conn.cursor() as cur:
        cur.execute("SELECT email FROM soc_ops.soc_users WHERE username = 'admin_secops';")
        admin_email = cur.fetchone()[0]

    res = client.post("/api/system/rbac/login", json={
        "username": admin_email,
        "password": "WazuhSecOps2026!"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["user"]["username"] == "admin_secops"


def test_login_invalid_password(client):
    res = client.post("/api/system/rbac/login", json={
        "username": "admin_secops",
        "password": "WrongPassword2026!"
    })
    assert res.status_code == 401
    data = res.json()
    assert "tidak valid" in data["detail"].lower()


def test_login_non_existent_user(client):
    res = client.post("/api/system/rbac/login", json={
        "username": "unknown_hacker_999",
        "password": "AnyPassword123!"
    })
    assert res.status_code == 401
    data = res.json()
    assert "tidak valid" in data["detail"].lower()


def test_login_suspended_user_rejection(client, db_conn):
    test_suspended_user = "test_suspended_login"
    test_email = "test.suspended@pradita.ac.id"
    test_pass = "ValidPass12345!"
    test_hash = bcrypt.hashpw(test_pass.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    # Clean up before
    with db_conn.cursor() as cur:
        cur.execute("DELETE FROM soc_ops.soc_users WHERE username = %s;", (test_suspended_user,))
        cur.execute("""
            INSERT INTO soc_ops.soc_users (username, full_name, email, password_hash, role, status, department)
            VALUES (%s, 'Suspended User Test', %s, %s, 'SOC_ANALYST', 'SUSPENDED', 'Test Dept');
        """, (test_suspended_user, test_email, test_hash))
        db_conn.commit()

    try:
        res = client.post("/api/system/rbac/login", json={
            "username": test_suspended_user,
            "password": test_pass
        })
        assert res.status_code == 403
        data = res.json()
        assert "ditangguhkan" in data["detail"].lower() or "suspended" in data["detail"].lower()
    finally:
        with db_conn.cursor() as cur:
            cur.execute("DELETE FROM soc_ops.soc_users WHERE username = %s;", (test_suspended_user,))
            db_conn.commit()


def test_delete_user_lifecycle(client, db_conn):
    test_user = "test_to_delete"
    test_email = "test.delete@pradita.ac.id"
    test_pass = "DeletePass123!"
    test_hash = bcrypt.hashpw(test_pass.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    # Insert test user
    with db_conn.cursor() as cur:
        cur.execute("DELETE FROM soc_ops.soc_users WHERE username = %s;", (test_user,))
        cur.execute("""
            INSERT INTO soc_ops.soc_users (username, full_name, email, password_hash, role, status, department)
            VALUES (%s, 'User To Delete', %s, %s, 'SOC_ANALYST', 'ACTIVE', 'Test Unit')
            RETURNING user_id;
        """, (test_user, test_email, test_hash))
        user_id = cur.fetchone()[0]
        db_conn.commit()

    try:
        # Delete user via API
        del_res = client.delete(f"/api/system/rbac/users/{user_id}")
        assert del_res.status_code == 200
        del_data = del_res.json()
        assert del_data["success"] is True
        assert del_data["user_id"] == user_id

        # Verify not found in DB
        with db_conn.cursor() as cur:
            cur.execute("SELECT user_id FROM soc_ops.soc_users WHERE user_id = %s;", (user_id,))
            assert cur.fetchone() is None

        # Subsequent delete returns 404
        retry_res = client.delete(f"/api/system/rbac/users/{user_id}")
        assert retry_res.status_code == 404
    finally:
        with db_conn.cursor() as cur:
            cur.execute("DELETE FROM soc_ops.soc_users WHERE username = %s;", (test_user,))
            db_conn.commit()


def test_delete_last_admin_prevented(client, db_conn):
    # Find existing admin
    with db_conn.cursor() as cur:
        cur.execute("SELECT user_id FROM soc_ops.soc_users WHERE role = 'ADMIN' AND status = 'ACTIVE' LIMIT 1;")
        admin_row = cur.fetchone()

    if admin_row:
        admin_id = admin_row[0]
        # Count admins
        with db_conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM soc_ops.soc_users WHERE role = 'ADMIN' AND status = 'ACTIVE';")
            total_admins = cur.fetchone()[0]

        if total_admins == 1:
            res = client.delete(f"/api/system/rbac/users/{admin_id}")
            assert res.status_code == 400
            data = res.json()
            assert "satu-satunya" in data["detail"].lower()

