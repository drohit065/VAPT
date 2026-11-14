"""API tests for login, roles, user management and the audit log (temporary SQLite database)."""
import os

import pytest

os.environ.update({
    "DATABASE_URL": "sqlite:////tmp/vapt-test-users.db",
    "ADMIN_USERNAME": "admin",
    "ADMIN_PASSWORD": "builtin-admin-password-123",
    "JWT_SECRET": "x" * 40,
    "TOKEN_ENCRYPTION_KEY": "",
})


@pytest.fixture(scope="module")
def client():
    if os.path.exists("/tmp/vapt-test-users.db"):
        os.remove("/tmp/vapt-test-users.db")
    from app.config import get_settings
    get_settings.cache_clear()
    from fastapi.testclient import TestClient

    from app.main import app
    with TestClient(app) as c:
        yield c


def login(client, user, pw):
    r = client.post("/api/auth/login", json={"username": user, "password": pw})
    return r


def hdr(token):
    return {"Authorization": f"Bearer {token}"}


def test_password_hashing():
    from app.auth import check_password, hash_password
    h = hash_password("correct horse battery")
    assert h.startswith("scrypt$") and check_password("correct horse battery", h)
    assert not check_password("wrong", h) and not check_password("x", "garbage")


def test_roles_and_user_management(client):
    r = login(client, "admin", "builtin-admin-password-123")
    assert r.status_code == 200 and r.json()["role"] == "admin"
    admin = hdr(r.json()["access_token"])

    # create an analyst and a viewer
    assert client.post("/api/users", headers=admin, json={"username": "ana", "password": "short", "role": "analyst"}).status_code == 400
    assert client.post("/api/users", headers=admin, json={"username": "admin", "password": "x" * 12}).status_code == 400
    ana = client.post("/api/users", headers=admin, json={"username": "ana", "password": "analyst-password-1", "role": "analyst"})
    assert ana.status_code == 200
    viewer = client.post("/api/users", headers=admin, json={"username": "vic", "password": "viewer-password-12", "role": "viewer"}).json()
    assert client.post("/api/users", headers=admin, json={"username": "vic", "password": "viewer-password-12"}).status_code == 409

    v = hdr(login(client, "vic", "viewer-password-12").json()["access_token"])
    a = hdr(login(client, "ana", "analyst-password-1").json()["access_token"])
    assert client.get("/api/auth/me", headers=v).json()["role"] == "viewer"

    # viewer: read yes, write no, admin no
    assert client.get("/api/projects", headers=v).status_code == 200
    assert client.post("/api/scans", headers=v, data={"source_type": "git", "repo_url": "https://github.com/x/y"}).status_code == 403
    assert client.patch("/api/findings/1", headers=v, json={"status": "open"}).status_code == 403
    assert client.get("/api/users", headers=v).status_code == 403
    assert client.get("/api/audit", headers=a).status_code == 403
    # analyst passes the role check (finding does not exist)
    assert client.patch("/api/findings/999", headers=a, json={"status": "open"}).status_code == 404

    # deactivating ends the viewer's existing session at once
    assert client.patch(f"/api/users/{viewer['id']}", headers=admin, json={"active": False}).status_code == 200
    assert client.get("/api/projects", headers=v).status_code == 401
    assert login(client, "vic", "viewer-password-12").status_code == 401

    # password reset invalidates old tokens
    ana_id = ana.json()["id"]
    assert client.patch(f"/api/users/{ana_id}", headers=admin, json={"password": "new-analyst-pass-2"}).status_code == 200
    assert client.get("/api/projects", headers=a).status_code == 401
    assert login(client, "ana", "new-analyst-pass-2").status_code == 200

    # audit log has the trail and no passwords
    log = client.get("/api/audit", headers=admin).json()
    actions = [e["action"] for e in log]
    for expected in ("login", "login_failed", "user_created", "user_updated"):
        assert expected in actions
    assert "analyst-password" not in str(log) and "new-analyst-pass" not in str(log)

    assert client.delete(f"/api/users/{viewer['id']}", headers=admin).status_code == 200
    assert client.get("/api/users", headers=admin).json()["builtin_admin"] == "admin"


def test_unknown_user_and_bad_token(client):
    assert login(client, "nobody", "whatever-password").status_code == 401
    assert client.get("/api/projects", headers=hdr("not-a-jwt")).status_code == 401
    assert client.get("/api/projects").status_code == 401
