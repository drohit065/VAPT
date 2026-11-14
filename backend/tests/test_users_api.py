"""API tests for login, roles, user management and the audit log (temporary SQLite database)."""
import os

import pytest

os.environ.update({
    "DATABASE_URL": "sqlite:////tmp/vapt-test-users.db",
    "ADMIN_USERNAME": "admin",
    "ADMIN_PASSWORD": "builtin-admin-password-123",
    "JWT_SECRET": "x" * 40,
    "TOKEN_ENCRYPTION_KEY": "kL5f4pXJ0rZ3m2s3qF8m3b5xQ0rN3c2vY6h1t9u8w7E=",
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


def test_logout_revokes_token(client):
    t = login(client, "admin", "builtin-admin-password-123").json()["access_token"]
    assert client.get("/api/projects", headers=hdr(t)).status_code == 200
    assert client.post("/api/auth/logout", headers=hdr(t)).status_code == 200
    assert client.get("/api/projects", headers=hdr(t)).status_code == 401
    # a fresh login still works
    t2 = login(client, "admin", "builtin-admin-password-123").json()["access_token"]
    assert client.get("/api/projects", headers=hdr(t2)).status_code == 200


def test_notification_settings_secrets_are_write_only(client):
    admin = hdr(login(client, "admin", "builtin-admin-password-123").json()["access_token"])
    body = {"enabled": True, "email_to": ["sec@example.com"], "smtp_host": "smtp.example.com",
            "smtp_user": "mailer", "smtp_password": "super-secret-smtp-pw"}
    r = client.put("/api/settings/notifications", headers=admin, json=body)
    assert r.status_code == 200, r.text
    got = client.get("/api/settings/notifications", headers=admin).json()
    assert got["smtp_password_set"] is True and got["email_to"] == ["sec@example.com"]
    assert "super-secret-smtp-pw" not in str(got)
    # saving again without the password keeps it; 'clear' removes it
    assert client.put("/api/settings/notifications", headers=admin, json={**body, "smtp_password": ""}).json()["smtp_password_set"]
    assert not client.put("/api/settings/notifications", headers=admin,
                          json={**body, "smtp_password": "", "clear": ["smtp_password"]}).json()["smtp_password_set"]
    assert client.put("/api/settings/notifications", headers=admin, json={**body, "email_to": ["nope"]}).status_code == 400
    assert client.put("/api/settings/notifications", headers=admin,
                      json={**body, "slack_url": "http://insecure.example.com/x"}).status_code == 400


def test_api_keys_and_gate(client):
    admin = hdr(login(client, "admin", "builtin-admin-password-123").json()["access_token"])
    assert client.post("/api/api-keys", headers=admin, json={"name": "ci", "role": "admin"}).status_code == 400
    r = client.post("/api/api-keys", headers=admin, json={"name": "github-ci", "role": "analyst", "expires_days": 30})
    assert r.status_code == 200
    key = r.json()["key"]
    assert key.startswith("vapt_") and r.json()["prefix"] == key[:12]
    k = hdr(key)
    assert client.get("/api/projects", headers=k).status_code == 200
    assert client.get("/api/users", headers=k).status_code == 403          # analyst role, not admin
    assert client.get("/api/scans/999/gate", headers=k).status_code == 404
    listed = client.get("/api/api-keys", headers=admin).json()
    assert key not in str(listed) and listed[0]["last_used_at"]
    assert client.delete(f"/api/api-keys/{listed[0]['id']}", headers=admin).json()["revoked"] is True
    assert client.get("/api/projects", headers=k).status_code == 401
    assert client.get("/api/projects", headers=hdr("vapt_not-a-real-key")).status_code == 401
    log = client.get("/api/audit", headers=admin).json()
    assert "api_key_created" in [e["action"] for e in log] and key not in str(log)


def test_gate_logic():
    from types import SimpleNamespace

    from app.routers import scans as s
    from app.db import SessionLocal
    from app.models import Finding, Project, Scan
    db = SessionLocal()
    p = Project(name="gate", source_type="zip", source="gate.zip")
    db.add(p)
    db.flush()
    sc = Scan(project_id=p.id, status="completed", counts={"Critical": 0, "High": 1, "Medium": 1, "Low": 0})
    db.add(sc)
    db.flush()
    for sev, new, st in (("High", False, "open"), ("Medium", True, "open"), ("Critical", True, "false_positive")):
        db.add(Finding(scan_id=sc.id, severity=sev, title=f"{sev} issue", file_path="a.py", check="code",
                       snippet="", description="", exploitation="", recommendation="", scanners=["semgrep"],
                       is_new=new, status=st))
    db.commit()
    assert s.quality_gate(sc.id, "High", False, db)["passed"] is False      # the open High blocks
    assert s.quality_gate(sc.id, "High", True, db)["passed"] is True        # new-only: High is not new
    assert s.quality_gate(sc.id, "Medium", True, db)["blocking"] == 1       # the new Medium blocks
    assert s.quality_gate(sc.id, "none", False, db)["passed"] is True
    db.close()
    assert SimpleNamespace


def test_schedule_credentials_write_only(client):
    from app.db import SessionLocal
    from app.models import Project, Scan
    admin = hdr(login(client, "admin", "builtin-admin-password-123").json()["access_token"])
    db = SessionLocal()
    p = Project(name="private-repo", source_type="git", source="https://github.com/acme/private")
    db.add(p)
    db.flush()
    db.add(Scan(project_id=p.id, status="completed", checks={"code": True}, branch="main"))
    db.commit()
    pid = p.id
    db.close()
    r = client.put(f"/api/projects/{pid}/schedule", headers=admin,
                   json={"schedule": "daily", "hour_utc": 3, "git_token": "ghp_secretvalue123"})
    assert r.status_code == 200 and r.json()["schedule_has_credentials"] is True
    assert "ghp_secretvalue123" not in r.text
    r = client.put(f"/api/projects/{pid}/schedule", headers=admin, json={"schedule": "daily", "hour_utc": 3})
    assert r.json()["schedule_has_credentials"] is True          # kept when not re-entered
    r = client.put(f"/api/projects/{pid}/schedule", headers=admin,
                   json={"schedule": "daily", "hour_utc": 3, "clear_credentials": True})
    assert r.json()["schedule_has_credentials"] is False
    assert "ghp_secretvalue123" not in str(client.get("/api/audit", headers=admin).json())
