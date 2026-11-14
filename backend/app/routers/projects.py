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
    p.schedule, p.schedule_hour = body.schedule, body.hour_utc
    p.next_run_at = next_run(body.schedule, body.hour_utc)
    db.commit()
    audit(user.username, "schedule_changed", p.name, {"schedule": body.schedule, "hour_utc": body.hour_utc},
          client_ip(request))
    return project_summary(p)
