from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from ..auth import CurrentUser, audit, client_ip, require_role, require_user
from ..db import get_db
from ..models import Project
from ..schedules import RESCHEDULABLE, SCHEDULES, config_from_scan, next_run
from ..summary import project_summary, scan_brief

router = APIRouter(prefix="/api/projects", tags=["projects"], dependencies=[Depends(require_user)])


@router.get("")
def list_projects(db: Session = Depends(get_db)):
    projects = db.scalars(select(Project).options(selectinload(Project.scans))).all()
    items = [project_summary(p) for p in projects]

    def last_time(item):
        s = item["latest_scan"]
        return (s["created_at"] if s else item["created_at"]).timestamp()

    items.sort(key=last_time, reverse=True)
    return items


@router.get("/{project_id}")
def get_project(project_id: int, db: Session = Depends(get_db)):
    p = db.get(Project, project_id)
    if not p:
        raise HTTPException(404, "Project not found")
    data = project_summary(p)
    data["scans"] = [scan_brief(s) for s in sorted(p.scans, key=lambda s: s.id, reverse=True)]
    return data


class ScheduleIn(BaseModel):
    schedule: str
    hour_utc: int = Field(default=2, ge=0, le=23)
    # Optional credentials for scheduled runs (write-only). Which fields apply depends on the project type:
    git_token: str = Field(default="", max_length=1000)          # git
    auth_a: str = Field(default="", max_length=20000)            # url: user A headers
    auth_b: str = Field(default="", max_length=20000)            # url: user B headers
    registry_user: str = Field(default="", max_length=200)       # image
    registry_password: str = Field(default="", max_length=4000)  # image
    clear_credentials: bool = False


def _creds_payload(p: Project, body: ScheduleIn) -> str | None:
    """The same encrypted payload format a manual scan of this project type uses, or None."""
    import json

    from ..security import ValidationError, parse_auth_headers
    if p.source_type == "git" and body.git_token.strip():
        return body.git_token.strip()
    if p.source_type == "url" and body.auth_a.strip():
        try:
            return json.dumps({"a": parse_auth_headers(body.auth_a), "b": parse_auth_headers(body.auth_b)})
        except (ValidationError, ValueError) as e:
            raise HTTPException(400, str(e))
    if p.source_type == "image" and body.registry_user.strip():
        if not body.registry_password.strip():
            raise HTTPException(400, "Enter the registry password / token too.")
        return json.dumps({"u": body.registry_user.strip(), "p": body.registry_password.strip()})
    return None


@router.put("/{project_id}/schedule")
def set_schedule(project_id: int, body: ScheduleIn, request: Request, db: Session = Depends(get_db),
                 user: CurrentUser = Depends(require_role("analyst"))):
    if body.schedule not in SCHEDULES:
        raise HTTPException(400, f"schedule must be one of: {', '.join(SCHEDULES)}")
    p = db.get(Project, project_id)
    if not p:
        raise HTTPException(404, "Project not found")
    if body.schedule != "none":
        if p.source_type not in RESCHEDULABLE:
            raise HTTPException(400, "Zip uploads cannot be re-scanned automatically: upload a new zip instead.")
        last = next((s for s in sorted(p.scans, key=lambda s: s.id, reverse=True) if s.checks), None)
        if not last:
            raise HTTPException(400, "Run one scan of this project first; the schedule repeats its settings.")
        p.schedule_config = config_from_scan(last)
    creds_action = None
    payload = _creds_payload(p, body)
    if body.clear_credentials or body.schedule == "none":
        creds_action = "removed" if p.schedule_creds_enc else None
        p.schedule_creds_enc = None
    if payload and body.schedule != "none":
        from ..security import encrypt_token
        try:
            p.schedule_creds_enc = encrypt_token(payload)
        except RuntimeError:
            raise HTTPException(500, "Server is missing TOKEN_ENCRYPTION_KEY; cannot store credentials.")
        creds_action = "saved"
    p.schedule, p.schedule_hour = body.schedule, body.hour_utc
    p.next_run_at = next_run(body.schedule, body.hour_utc)
    db.commit()
    audit(user.username, "schedule_changed", p.name, {"schedule": body.schedule, "hour_utc": body.hour_utc}
          | ({"credentials": creds_action} if creds_action else {}), client_ip(request))
    return project_summary(p)


@router.delete("/{project_id}")
def delete_project(project_id: int, request: Request, db: Session = Depends(get_db),
                   user: CurrentUser = Depends(require_role("admin"))):
    import os
    p = db.get(Project, project_id)
    if not p:
        raise HTTPException(404, "Project not found")
    if any(s.status == "running" for s in p.scans):
        raise HTTPException(409, "A scan of this project is running; delete it when the scan has finished.")
    for s in p.scans:
        if s.upload_path and os.path.exists(s.upload_path):
            os.remove(s.upload_path)
    name, n = p.name, len(p.scans)
    db.delete(p)
    db.commit()
    audit(user.username, "project_deleted", name, {"scans": n}, client_ip(request))
    return {"deleted": project_id}
