"""Scheduled re-scans: next-run calculation and queueing due projects (used by the worker)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from .models import Project, Scan

SCHEDULES = ("none", "daily", "weekly")
RESCHEDULABLE = ("git", "url", "image")  # zip uploads have no source to fetch again


def next_run(schedule: str, hour: int, now: datetime | None = None, weekday: int | None = None) -> datetime | None:
    """Next run strictly after `now` at `hour`:00 UTC (weekly: on `weekday`, default today's weekday)."""
    if schedule not in ("daily", "weekly"):
        return None
    now = now or datetime.now(timezone.utc)
    candidate = now.replace(hour=hour, minute=0, second=0, microsecond=0)
    if schedule == "daily":
        return candidate if candidate > now else candidate + timedelta(days=1)
    weekday = now.weekday() if weekday is None else weekday
    candidate += timedelta(days=(weekday - now.weekday()) % 7)
    return candidate if candidate > now else candidate + timedelta(days=7)


def config_from_scan(scan: Scan) -> dict:
    """What a scheduled scan repeats. Secrets (tokens, auth headers) are never kept."""
    opts = dict(scan.options or {})
    opts.pop("auth_a", None)
    opts.pop("auth_b", None)
    checks = dict(scan.checks or {})
    checks.pop("authz", None)  # needs credentials, which are not kept
    return {"checks": checks, "branch": scan.branch, "options": opts}


def enqueue_due(db, now: datetime | None = None) -> list[int]:
    """Queue a scan for every project whose schedule is due. Returns the new scan ids."""
    now = now or datetime.now(timezone.utc)
    due = db.scalars(
        select(Project).where(Project.schedule != "none", Project.next_run_at.is_not(None),
                              Project.next_run_at <= now).with_for_update(skip_locked=True)
    ).all()
    created = []
    for p in due:
        p.next_run_at = next_run(p.schedule, p.schedule_hour, now,
                                 weekday=p.next_run_at.weekday() if p.next_run_at else None)
        busy = db.scalar(select(Scan.id).where(Scan.project_id == p.id, Scan.status.in_(("queued", "running"))))
        cfg = p.schedule_config or {}
        if busy or not cfg.get("checks"):
            continue
        scan = Scan(project_id=p.id, status="queued", checks=cfg["checks"], branch=cfg.get("branch"),
                    options=cfg.get("options") or {},
                    notes=[f"Scheduled {p.schedule} scan (credentials are not stored, so it runs without "
                           "access tokens or login headers)."])
        db.add(scan)
        db.flush()
        created.append(scan.id)
    db.commit()
    return created
