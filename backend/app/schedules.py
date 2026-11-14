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
    authz = bool(checks.pop("authz", None))  # needs credentials: only re-enabled when they are saved
    return {"checks": checks, "branch": scan.branch, "options": opts, "authz_with_creds": authz}


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
        checks = dict(cfg["checks"])
        options = dict(cfg.get("options") or {})
        if p.schedule_creds_enc:
            note = f"Scheduled {p.schedule} scan with the project's saved credentials."
            if p.source_type == "url" and cfg.get("authz_with_creds"):
                checks["authz"] = True
                options["auth_a"] = True
        else:
            note = (f"Scheduled {p.schedule} scan without credentials (none are saved for this project, so "
                    "private repositories, logged-in pages or private images are not reachable).")
        scan = Scan(project_id=p.id, status="queued", checks=checks, branch=cfg.get("branch"), options=options,
                    git_token_enc=p.schedule_creds_enc, notes=[note])
        db.add(scan)
        db.flush()
        created.append(scan.id)
    db.commit()
    return created
