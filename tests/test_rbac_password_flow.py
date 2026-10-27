"""
Unit & Integration Tests for Self-Service Password Change and Admin Profile / Password Reset Flow
Covers:
1. Self-service password change (/api/system/rbac/change-password):
   - Rejection on invalid current password (400)
   - Rejection on passwords shorter than 8 characters (422)
   - Rejection on non-existent users (404)
   - Successful password update with bcrypt re-hashing (200)
2. Admin User Update & Emergency Reset (/api/system/rbac/users/{user_id}):
   - Profile update (full_name, email, role, department, status)
   - Admin override password with custom value
   - Admin reset password to platform default (WazuhSecOps2026!)
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


def test_self_change_password_flow(client, db_conn):
    test_user = "test_user_pwd_flow"
    test_email = "test.pwd.flow@pradita.ac.id"
    initial_pass = "InitialPass2026!"
    updated_pass = "UpdatedPass2026!XYZ"

    # Cleanup before test
    with db_conn.cursor() as cur:
        cur.execute("DELETE FROM soc_ops.soc_users WHERE username = %s OR email = %s;", (test_user, test_email))
        db_conn.commit()

    # 1. Create user via API
    create_res = client.post("/api/system/rbac/users", json={
        "username": test_user,
        "full_name": "Test User Password Flow",
        "email": test_email,
        "password": initial_pass,
        "role": "SOC_ANALYST",
        "department": "Triage Testing"
    })
    assert create_res.status_code == 200
    user_id = create_res.json()["user"]["user_id"]

    try:
        # 2. Try changing with wrong current password -> 400
        fail_res = client.post("/api/system/rbac/change-password", json={
            "username": test_user,
            "current_password": "WrongPassword123!",
            "new_password": updated_pass
        })
        assert fail_res.status_code == 400
        assert "salah" in fail_res.json()["detail"].lower()

        # 3. Change password successfully -> 200
        succ_res = client.post("/api/system/rbac/change-password", json={
            "username": test_user,
            "current_password": initial_pass,
            "new_password": updated_pass
        })
        assert succ_res.status_code == 200
        assert "berhasil diubah" in succ_res.json()["message"]

        # 4. Verify in DB that new hash works with updated_pass
        with db_conn.cursor(cursor_factory=extras.RealDictCursor) as cur:
            cur.execute("SELECT password_hash FROM soc_ops.soc_users WHERE user_id = %s;", (user_id,))
            row = cur.fetchone()
            assert row is not None
            assert bcrypt.checkpw(updated_pass.encode('utf-8'), row["password_hash"].encode('utf-8'))
            assert not bcrypt.checkpw(initial_pass.encode('utf-8'), row["password_hash"].encode('utf-8'))

        # 5. Subsequent change using the new password works
        final_pass = "FinalSecuredPass2026!"
        second_res = client.post("/api/system/rbac/change-password", json={
            "username": test_user,
            "current_password": updated_pass,
            "new_password": final_pass
        })
        assert second_res.status_code == 200

    finally:
        # Cleanup
        with db_conn.cursor() as cur:
            cur.execute("DELETE FROM soc_ops.soc_users WHERE user_id = %s;", (user_id,))
            db_conn.commit()


def test_self_change_password_validations(client):
    # Password too short (< 8 chars) -> 400
    short_res = client.post("/api/system/rbac/change-password", json={
        "username": "admin_secops",
        "current_password": "WazuhSecOps2026!",
        "new_password": "short"
    })
    assert short_res.status_code == 400
    assert "minimal harus 8 karakter" in short_res.json()["detail"]

    # Non-existent user -> 404
    missing_res = client.post("/api/system/rbac/change-password", json={
        "username": "non_existent_soc_user_9999",
        "current_password": "AnyPassword123!",
        "new_password": "ValidNewPassword2026!"
    })
    assert missing_res.status_code == 404


def test_admin_update_profile_and_emergency_reset(client, db_conn):
    test_user = "test_admin_reset_user"
    test_email = "test.admin.reset@pradita.ac.id"

    # Cleanup before test
    with db_conn.cursor() as cur:
        cur.execute("DELETE FROM soc_ops.soc_users WHERE username = %s OR email = %s;", (test_user, test_email))
        db_conn.commit()

    # Create user
    create_res = client.post("/api/system/rbac/users", json={
        "username": test_user,
        "full_name": "Before Admin Update",
        "email": test_email,
        "password": "InitialPass12345!",
        "role": "SOC_ANALYST",
        "department": "Engineering"
    })
    assert create_res.status_code == 200
    user_id = create_res.json()["user"]["user_id"]

    try:
        # Admin updates profile and overrides password
        admin_new_pass = "AdminAssignedPass2026!"
        update_res = client.put(f"/api/system/rbac/users/{user_id}", json={
            "username": "test_admin_reset_user_mod",
            "full_name": "After Admin Update",
            "email": "test.admin.mod@pradita.ac.id",
            "role": "SOC_DEVELOPER",
            "department": "Threat Detection Engineering",
            "status": "SUSPENDED",
            "new_password": admin_new_pass
        })
        assert update_res.status_code == 200
        update_data = update_res.json()["user"]
        assert update_data["username"] == "test_admin_reset_user_mod"
        assert update_data["role"] == "SOC_DEVELOPER"
        assert update_data["status"] == "SUSPENDED"

        # Verify password hash in DB matches admin_new_pass
        with db_conn.cursor(cursor_factory=extras.RealDictCursor) as cur:
            cur.execute("SELECT password_hash FROM soc_ops.soc_users WHERE user_id = %s;", (user_id,))
            row = cur.fetchone()
            assert bcrypt.checkpw(admin_new_pass.encode('utf-8'), row["password_hash"].encode('utf-8'))

        # Admin resets password to default
        reset_res = client.put(f"/api/system/rbac/users/{user_id}", json={
            "reset_to_default": True
        })
        assert reset_res.status_code == 200

        with db_conn.cursor(cursor_factory=extras.RealDictCursor) as cur:
            cur.execute("SELECT password_hash FROM soc_ops.soc_users WHERE user_id = %s;", (user_id,))
            row = cur.fetchone()
            assert bcrypt.checkpw("WazuhSecOps2026!".encode('utf-8'), row["password_hash"].encode('utf-8'))

    finally:
        # Cleanup
        with db_conn.cursor() as cur:
            cur.execute("DELETE FROM soc_ops.soc_users WHERE user_id = %s;", (user_id,))
            db_conn.commit()
