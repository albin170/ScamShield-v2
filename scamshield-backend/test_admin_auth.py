"""
Tests for ScamShield Authentication and Admin Routes
"""
import pytest
from fastapi.testclient import TestClient
import main
from database import get_db

client = TestClient(main.app)

def test_login_invalid_credentials():
    resp = client.post("/auth/login", json={"username": "albin", "password": "wrongpassword"})
    assert resp.status_code == 401
    assert "Invalid username or password" in resp.json()["detail"]

def test_login_superadmin_and_me():
    # Login as bootstrapped superadmin
    resp = client.post("/auth/login", json={"username": "albin", "password": "evengely"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["username"] == "albin"
    assert data["role"] == "superadmin"
    assert "access_token" in resp.cookies

    # Test /auth/me
    me_resp = client.get("/auth/me")
    assert me_resp.status_code == 200
    assert me_resp.json()["username"] == "albin"
    assert me_resp.json()["role"] == "superadmin"

def test_superadmin_stats_and_settings():
    # Login first
    client.post("/auth/login", json={"username": "albin", "password": "evengely"})

    # Stats
    stats_resp = client.get("/superadmin/stats")
    assert stats_resp.status_code == 200
    stats = stats_resp.json()
    assert "scans" in stats
    assert "users" in stats

    # Get Theme Settings
    settings_resp = client.get("/superadmin/settings")
    assert settings_resp.status_code == 200
    assert "themes" in settings_resp.json()

def test_public_theme_settings():
    resp = client.get("/settings/theme")
    assert resp.status_code == 200
    data = resp.json()
    assert "active_theme" in data

def test_logout():
    # Login
    client.post("/auth/login", json={"username": "albin", "password": "evengely"})
    # Logout
    logout_resp = client.post("/auth/logout")
    assert logout_resp.status_code == 200
    
    # After logout, accessing protected route with deleted cookie should fail
    resp = client.get("/auth/me")
    assert resp.status_code == 401

def test_superadmin_system_health():
    client.post("/auth/login", json={"username": "albin", "password": "evengely"})
    resp = client.get("/superadmin/system-health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] in ("operational", "degraded")
    assert "detection_models" in data
    assert "url_analyzer" in data["detection_models"]
    assert "message_analyzer" in data["detection_models"]
    assert "database" in data

def test_superadmin_integrations_and_features():
    client.post("/auth/login", json={"username": "albin", "password": "evengely"})
    # Get integrations
    resp = client.get("/superadmin/integrations")
    assert resp.status_code == 200
    # Patch feature
    feat_resp = client.patch("/superadmin/features", json={"rate_limiting": True, "public_scans": True})
    assert feat_resp.status_code == 200
    assert feat_resp.json()["features"]["rate_limiting"] is True

def test_superadmin_admin_lifecycle_and_rbac():
    # Login as superadmin
    client.post("/auth/login", json={"username": "albin", "password": "evengely"})

    # 1. Create a regular admin
    test_username = "test_sec_officer"
    create_resp = client.post("/superadmin/users", json={
        "username": test_username,
        "password": "TemporaryPassword123!",
        "email": "officer@scamshield.local",
        "permissions": ["view_stats", "view_history"]
    })
    assert create_resp.status_code == 200
    user_id = create_resp.json()["id"]

    # 2. Verify in list
    users_resp = client.get("/superadmin/users")
    assert users_resp.status_code == 200
    usernames = [u["username"] for u in users_resp.json()]
    assert test_username in usernames

    # 3. Update admin (suspend)
    patch_resp = client.patch(f"/superadmin/users/{user_id}", json={"is_suspended": True})
    assert patch_resp.status_code == 200

    # 4. Unsuspend
    patch_resp2 = client.patch(f"/superadmin/users/{user_id}", json={"is_suspended": False})
    assert patch_resp2.status_code == 200

    # 5. Reset admin password
    reset_resp = client.post(f"/superadmin/users/{user_id}/reset-password")
    assert reset_resp.status_code == 200
    assert "temp_password" in reset_resp.json()
    new_temp_pw = reset_resp.json()["temp_password"]

    # 6. Test RBAC: login as the new regular admin
    client.post("/auth/logout")
    admin_login_resp = client.post("/auth/login", json={"username": test_username, "password": new_temp_pw})
    assert admin_login_resp.status_code == 200
    assert admin_login_resp.json()["role"] == "admin"
    assert admin_login_resp.json()["must_change_password"] is True

    # Regular admin CANNOT access superadmin routes (must return 403 Forbidden!)
    forbidden_resp = client.get("/superadmin/stats")
    assert forbidden_resp.status_code == 403
    assert "Super Admin access required" in forbidden_resp.json()["detail"]

    forbidden_users = client.get("/superadmin/users")
    assert forbidden_users.status_code == 403

    # Regular admin CAN access permitted admin routes
    admin_stats_resp = client.get("/admin/dashboard-stats")
    assert admin_stats_resp.status_code == 200

    # 7. Cleanup: login back as superadmin and delete the test admin
    client.post("/auth/logout")
    client.post("/auth/login", json={"username": "albin", "password": "evengely"})
    del_resp = client.delete(f"/superadmin/users/{user_id}")
    assert del_resp.status_code == 200

def test_superadmin_bootstrap_persistence():
    from database import bootstrap_superadmin, get_db
    # Call bootstrap again
    bootstrap_superadmin()
    # Verify account still exists and password is NOT corrupted or changed
    with get_db() as conn:
        count = conn.execute("SELECT COUNT(*) FROM users WHERE username='albin'").fetchone()[0]
        assert count == 1

