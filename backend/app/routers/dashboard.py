"""Portfolio dashboard: open risk across projects, trend, top risky projects, recent activity."""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from ..auth import require_user
from ..db import get_db
from ..findings_mgmt import SUPPRESSED
from ..models import Finding, Project, Scan
from ..summary import SEVERITIES, risk_level

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"], dependencies=[Depends(require_user)])
WEIGHT = {"Critical": 10, "High": 5, "Medium": 2, "Low": 1}
CHECK_NAMES = {"code": "Code flaws", "deps": "Dependencies", "secrets": "Secrets", "iac": "Docker / Terraform",
               "web": "Web checks", "nuclei": "Known CVEs (Nuclei)", "zap": "OWASP ZAP", "authz": "Access control",
               "tls": "TLS", "ports": "Open ports", "image": "Container image"}


def _aware(dt):
    return dt.replace(tzinfo=timezone.utc) if dt is not None and dt.tzinfo is None else dt


def _empty() -> dict:
    return {s: 0 for s in SEVERITIES}


@router.get("")
def dashboard(weeks: int = 12, db: Session = Depends(get_db)):
    weeks = max(4, min(weeks, 52))
    now = datetime.now(timezone.utc)
    projects = db.scalars(select(Project).options(selectinload(Project.scans))).all()

    latest: dict[int, Scan] = {}
    for p in projects:
        done = [s for s in p.scans if s.status == "completed"]
        if done:
            latest[p.id] = max(done, key=lambda s: s.id)

    totals = _empty()
    for s in latest.values():
        for sev in SEVERITIES:
            totals[sev] += (s.counts or {}).get(sev, 0)

    # Trend: at the end of each week, the open counts of every project's latest completed scan so far.
    trend = []
    all_done = sorted((s for p in projects for s in p.scans if s.status == "completed" and s.finished_at),
                      key=lambda s: _aware(s.finished_at))
    for i in range(weeks - 1, -1, -1):
        end = now - timedelta(days=7 * i)
        snap: dict[int, Scan] = {}
        for s in all_done:
            if _aware(s.finished_at) <= end:
                snap[s.project_id] = s
        week = _empty()
        for s in snap.values():
            for sev in SEVERITIES:
                week[sev] += (s.counts or {}).get(sev, 0)
        trend.append({"week_end": end.date().isoformat(), **week})

    by_project = []
    for p in projects:
        s = latest.get(p.id)
        counts = {**_empty(), **((s.counts or {}) if s else {})}
        by_project.append({"id": p.id, "name": p.name, "source_type": p.source_type, "scan_id": s.id if s else None,
                           "counts": counts, "risk": risk_level(counts) if s else None,
                           "score": sum(WEIGHT[k] * counts[k] for k in SEVERITIES),
                           "last_scan_at": s.finished_at if s else None,
                           "new": (s.diff or {}).get("new", 0) if s else 0,
                           "fixed": (s.diff or {}).get("fixed", 0) if s else 0})
    top = sorted((x for x in by_project if x["score"]), key=lambda x: -x["score"])[:6]

    by_check = {}
    if latest:
        rows = db.execute(
            select(Finding.check, Finding.severity, func.count()).where(
                Finding.scan_id.in_([s.id for s in latest.values()]), Finding.status.not_in(SUPPRESSED)
            ).group_by(Finding.check, Finding.severity)
        ).all()
        for check, sev, n in rows:
            by_check.setdefault(check, _empty())[sev] = n
    categories = sorted(({"check": k, "label": CHECK_NAMES.get(k, k), **v} for k, v in by_check.items()),
                        key=lambda x: -sum(x[s] for s in SEVERITIES))

    month_ago = now - timedelta(days=30)
    recent_scans = db.scalars(select(Scan).options(selectinload(Scan.project)).order_by(Scan.id.desc()).limit(8)).all()
    scans_30d = [s for p in projects for s in p.scans if _aware(s.created_at) and _aware(s.created_at) >= month_ago]
    triaged = db.scalar(select(func.count()).select_from(Finding).where(
        Finding.scan_id.in_([s.id for s in latest.values()] or [-1]), Finding.status.in_(SUPPRESSED))) or 0

    return {
        "totals": totals,
        "risk": risk_level(totals) if latest else None,
        "kpis": {
            "projects": len(projects),
            "scanned_projects": len(latest),
            "scans_30d": len(scans_30d),
            "active_scans": sum(1 for p in projects for s in p.scans if s.status in ("queued", "running")),
            "failed_30d": sum(1 for s in scans_30d if s.status == "failed"),
            "fixed_30d": sum((s.diff or {}).get("fixed", 0) for s in scans_30d if s.status == "completed"),
            "new_30d": sum((s.diff or {}).get("new", 0) for s in scans_30d if s.status == "completed"),
            "triaged": triaged,
            "scheduled": sum(1 for p in projects if (p.schedule or "none") != "none"),
        },
        "trend": trend,
        "top_projects": top,
        "categories": categories,
        "recent": [{"id": s.id, "project": s.project.name, "project_id": s.project_id, "status": s.status,
                    "created_at": s.created_at, "finished_at": s.finished_at,
                    "counts": {**_empty(), **(s.counts or {})}} for s in recent_scans],
    }
