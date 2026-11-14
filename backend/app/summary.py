"""Shared helpers to describe scans and projects for the API (never exposes tokens)."""
from .models import Project, Scan

SEVERITIES = ["Critical", "High", "Medium", "Low"]


def empty_counts() -> dict:
    return {s: 0 for s in SEVERITIES}


def risk_level(counts: dict | None) -> str:
    counts = counts or {}
    for sev in SEVERITIES:
        if counts.get(sev, 0) > 0:
            return sev
    return "None"


def scan_brief(scan: Scan) -> dict:
    counts = {**empty_counts(), **(scan.counts or {})}
    return {
        "id": scan.id,
        "status": scan.status,
        "branch": scan.branch,
        "commit_sha": scan.commit_sha,
        "created_at": scan.created_at,
        "started_at": scan.started_at,
        "finished_at": scan.finished_at,
        "counts": counts,
        "total": sum(counts.values()),
        "risk": risk_level(counts) if scan.status == "completed" else None,
    }


def project_summary(p: Project) -> dict:
    scans = sorted(p.scans, key=lambda s: s.id, reverse=True)
    latest = scans[0] if scans else None
    latest_done = next((s for s in scans if s.status == "completed"), None)
    return {
        "id": p.id,
        "name": p.name,
        "source_type": p.source_type,
        "source": p.source,
        "created_at": p.created_at,
        "scan_count": len(scans),
        "latest_scan": scan_brief(latest) if latest else None,
        "latest_completed_scan": scan_brief(latest_done) if latest_done else None,
        "schedule": p.schedule or "none",
        "schedule_hour": p.schedule_hour if p.schedule_hour is not None else 2,
        "next_run_at": p.next_run_at,
    }
