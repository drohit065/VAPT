"""Admin settings: notifications (and, later, integrations)."""
import re

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from ..auth import CurrentUser, audit, client_ip, require_role
from ..db import get_db
from ..notifier import DEFAULTS, deliver, validate_webhook
from ..security import ValidationError
from ..settings_store import load, merge_secrets, save

router = APIRouter(prefix="/api/settings", tags=["settings"])
admin_only = require_role("admin")
_EMAIL = re.compile(r"^[^@\s,;]+@[^@\s,;]+\.[^@\s,;]+$")


class NotificationsIn(BaseModel):
    enabled: bool = False
    on_completed: bool = False
    on_failed: bool = True
    on_new_findings: bool = True
    min_severity: str = "High"
    email_to: list[str] = Field(default_factory=list, max_length=20)
    smtp_host: str = Field(default="", max_length=255)
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_user: str = Field(default="", max_length=255)
    smtp_from: str = Field(default="", max_length=255)
    smtp_tls: str = "starttls"
    # write-only secrets: empty = keep the stored value
    slack_url: str = Field(default="", max_length=1000)
    teams_url: str = Field(default="", max_length=2000)
    smtp_password: str = Field(default="", max_length=500)
    clear: list[str] = Field(default_factory=list)


def _public(cfg: dict, secrets: dict) -> dict:
    return {**DEFAULTS, **cfg, "slack_configured": bool(secrets.get("slack_url")),
            "teams_configured": bool(secrets.get("teams_url")),
            "smtp_password_set": bool(secrets.get("smtp_password"))}


@router.get("/notifications")
def get_notifications(db: Session = Depends(get_db), _: CurrentUser = Depends(admin_only)):
    cfg, secrets = load(db, "notifications")
    return _public(cfg, secrets)


@router.put("/notifications")
async def put_notifications(body: NotificationsIn, request: Request, db: Session = Depends(get_db),
                            me: CurrentUser = Depends(admin_only)):
    if body.min_severity not in ("Critical", "High", "Medium", "Low"):
        raise HTTPException(400, "min_severity must be Critical, High, Medium or Low")
    if body.smtp_tls not in ("starttls", "ssl", "none"):
        raise HTTPException(400, "smtp_tls must be starttls, ssl or none")
    emails = [e.strip() for e in body.email_to if e.strip()]
    bad = [e for e in emails if not _EMAIL.match(e)]
    if bad:
        raise HTTPException(400, f"Invalid email address: {bad[0][:100]}")
    try:
        for url in (body.slack_url, body.teams_url):
            if url:
                await run_in_threadpool(validate_webhook, url)
    except (ValidationError, ValueError) as e:
        raise HTTPException(400, f"Webhook URL rejected: {e}")
    cfg_old, secrets_old = load(db, "notifications")
    cfg = {k: getattr(body, k) for k in DEFAULTS} | {"email_to": emails}
    secrets = merge_secrets(secrets_old, {"slack_url": body.slack_url, "teams_url": body.teams_url,
                                          "smtp_password": body.smtp_password},
                            [c for c in body.clear if c in ("slack_url", "teams_url", "smtp_password")])
    try:
        save(db, "notifications", cfg, secrets)
    except RuntimeError:
        raise HTTPException(500, "Server is missing TOKEN_ENCRYPTION_KEY; cannot store secrets.")
    audit(me.username, "settings_changed", "notifications",
          {"enabled": cfg["enabled"], "channels": [c for c in ("slack_url", "teams_url") if secrets.get(c)]
           + (["email"] if emails else [])}, client_ip(request))
    return _public(cfg, secrets)


@router.post("/notifications/test")
async def test_notifications(db: Session = Depends(get_db), me: CurrentUser = Depends(admin_only)):
    cfg, secrets = load(db, "notifications")
    cfg = {**DEFAULTS, **cfg}
    if not (secrets.get("slack_url") or secrets.get("teams_url") or (cfg.get("email_to") and cfg.get("smtp_host"))):
        raise HTTPException(400, "Configure at least one channel first.")
    errors = await run_in_threadpool(deliver, cfg, secrets, "[VAPT] Test notification",
                                     f"This is a test message sent by {me.username} from VAPT Scanner.")
    return {"ok": not errors, "errors": errors}


# ---------------------------------------------------------------- ticketing (Jira / GitHub Issues)

from ..ticketing import DEFAULTS as TICKET_DEFAULTS  # noqa: E402
from ..ticketing import TicketError, test_connection, validate_config  # noqa: E402


class TicketingIn(BaseModel):
    provider: str = "none"
    jira_url: str = Field(default="", max_length=300)
    jira_email: str = Field(default="", max_length=255)
    jira_project: str = Field(default="", max_length=20)
    jira_issue_type: str = Field(default="Bug", max_length=50)
    github_repo: str = Field(default="", max_length=201)
    labels: list[str] = Field(default_factory=lambda: ["security", "vapt"], max_length=10)
    jira_token: str = Field(default="", max_length=1000)
    github_token: str = Field(default="", max_length=1000)
    clear: list[str] = Field(default_factory=list)


def _ticket_public(cfg: dict, secrets: dict) -> dict:
    return {**TICKET_DEFAULTS, **cfg, "jira_token_set": bool(secrets.get("jira_token")),
            "github_token_set": bool(secrets.get("github_token"))}


@router.get("/ticketing")
def get_ticketing(db: Session = Depends(get_db), _: CurrentUser = Depends(admin_only)):
    cfg, secrets = load(db, "ticketing")
    return _ticket_public(cfg, secrets)


@router.put("/ticketing")
def put_ticketing(body: TicketingIn, request: Request, db: Session = Depends(get_db),
                  me: CurrentUser = Depends(admin_only)):
    cfg = {k: getattr(body, k) for k in TICKET_DEFAULTS}
    cfg["jira_url"] = cfg["jira_url"].strip().rstrip("/")
    cfg["jira_project"] = cfg["jira_project"].strip().upper()
    try:
        validate_config(cfg)
    except (ValidationError, ValueError) as e:
        raise HTTPException(400, str(e))
    _, secrets_old = load(db, "ticketing")
    secrets = merge_secrets(secrets_old, {"jira_token": body.jira_token, "github_token": body.github_token},
                            [c for c in body.clear if c in ("jira_token", "github_token")])
    try:
        save(db, "ticketing", cfg, secrets)
    except RuntimeError:
        raise HTTPException(500, "Server is missing TOKEN_ENCRYPTION_KEY; cannot store secrets.")
    audit(me.username, "settings_changed", "ticketing", {"provider": cfg["provider"]}, client_ip(request))
    return _ticket_public(cfg, secrets)


@router.post("/ticketing/test")
async def test_ticketing(db: Session = Depends(get_db), _: CurrentUser = Depends(admin_only)):
    cfg, secrets = load(db, "ticketing")
    cfg = {**TICKET_DEFAULTS, **cfg}
    try:
        return {"ok": True, "message": await run_in_threadpool(test_connection, cfg, secrets)}
    except (TicketError, ValidationError, OSError) as e:
        return {"ok": False, "message": str(e)[:300]}
