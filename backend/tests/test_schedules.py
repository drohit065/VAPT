"""Tests for scheduled re-scans."""
from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.models import Project, Scan
from app.schedules import config_from_scan, enqueue_due, next_run

T = datetime(2026, 11, 14, 10, 30, tzinfo=timezone.utc)  # a Saturday


def test_next_run_daily_and_weekly():
    assert next_run("daily", 2, T) == datetime(2026, 11, 15, 2, 0, tzinfo=timezone.utc)
    assert next_run("daily", 23, T) == datetime(2026, 11, 14, 23, 0, tzinfo=timezone.utc)
    assert next_run("weekly", 2, T) == datetime(2026, 11, 21, 2, 0, tzinfo=timezone.utc)
    assert next_run("weekly", 12, T) == datetime(2026, 11, 14, 12, 0, tzinfo=timezone.utc)
    assert next_run("weekly", 2, T, weekday=0) == datetime(2026, 11, 16, 2, 0, tzinfo=timezone.utc)
    assert next_run("none", 2, T) is None


def test_config_drops_secrets_and_authz():
    s = Scan(checks={"web": True, "authz": True}, branch="main",
             options={"endpoints": ["https://a.example.com/x"], "auth_a": True, "auth_b": True})
    cfg = config_from_scan(s)
    assert cfg == {"checks": {"web": True}, "branch": "main", "options": {"endpoints": ["https://a.example.com/x"]}}


def _db():
    eng = create_engine("sqlite://")
    Base.metadata.create_all(eng)
    return sessionmaker(bind=eng, expire_on_commit=False)()


def test_enqueue_due_creates_scan_and_advances():
    db = _db()
    due = Project(name="a", source_type="git", source="https://g.example.com/a", schedule="daily", schedule_hour=2,
                  next_run_at=datetime(2026, 11, 14, 2, 0, tzinfo=timezone.utc),
                  schedule_config={"checks": {"code": True}, "branch": "main", "options": {}})
    later = Project(name="b", source_type="git", source="https://g.example.com/b", schedule="daily", schedule_hour=2,
                    next_run_at=datetime(2026, 11, 15, 2, 0, tzinfo=timezone.utc),
                    schedule_config={"checks": {"code": True}})
    off = Project(name="c", source_type="git", source="https://g.example.com/c", schedule="none")
    db.add_all([due, later, off])
    db.commit()

    ids = enqueue_due(db, now=T)
    assert len(ids) == 1
    scan = db.get(Scan, ids[0])
    assert scan.project_id == due.id and scan.status == "queued" and scan.branch == "main"
    assert scan.checks == {"code": True} and "Scheduled daily scan" in scan.notes[0]
    assert due.next_run_at.replace(tzinfo=timezone.utc) == datetime(2026, 11, 15, 2, 0, tzinfo=timezone.utc)

    # a project that already has a queued scan is not queued twice
    due.next_run_at = datetime(2026, 11, 14, 2, 0, tzinfo=timezone.utc)
    db.commit()
    assert enqueue_due(db, now=T) == []
