from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from ..auth import require_user
from ..db import get_db
from ..models import Project
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
