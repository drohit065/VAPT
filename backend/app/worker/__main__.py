"""Background worker: polls PostgreSQL for queued scans and runs them one at a time."""
import logging
import os
import shutil
import time
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.exc import OperationalError

from ..db import SessionLocal, init_db
from ..findings_mgmt import fingerprint
from ..models import Finding, Scan
from .pipeline import WORK_ROOT, run_scan

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("vapt.worker")
POLL_SECONDS = 2


def recover() -> None:
    """Scans left 'running' by a crashed worker are failed and their secrets wiped."""
    db = SessionLocal()
    try:
        for scan in db.scalars(select(Scan).where(Scan.status == "running")):
            scan.status = "failed"
            scan.error = "The worker restarted while this scan was running. Start the scan again."
            scan.finished_at = datetime.now(timezone.utc)
            scan.git_token_enc = None
            if scan.upload_path and os.path.exists(scan.upload_path):
                os.remove(scan.upload_path)
            scan.upload_path = None
        db.commit()
    finally:
        db.close()
    if os.path.isdir(WORK_ROOT):
        for entry in os.listdir(WORK_ROOT):
            shutil.rmtree(os.path.join(WORK_ROOT, entry), ignore_errors=True)


def backfill_fingerprints() -> None:
    """Findings stored before finding management existed get a fingerprint once."""
    db = SessionLocal()
    try:
        rows = db.scalars(select(Finding).where(Finding.fingerprint.is_(None)).limit(50000)).all()
        for f in rows:
            f.fingerprint = fingerprint({"check": f.check, "rule_id": f.rule_id, "file_path": f.file_path,
                                         "snippet": f.snippet, "line": f.line, "title": f.title})
        if rows:
            db.commit()
            log.info("backfilled fingerprints for %s finding(s)", len(rows))
    finally:
        db.close()


def claim_next() -> int | None:
    db = SessionLocal()
    try:
        scan = db.scalars(
            select(Scan).where(Scan.status == "queued").order_by(Scan.id).limit(1).with_for_update(skip_locked=True)
        ).first()
        if scan is None:
            db.rollback()
            return None
        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        db.commit()
        return scan.id
    finally:
        db.close()


def main() -> None:
    for _ in range(30):
        try:
            init_db()
            break
        except OperationalError as e:
            log.warning("Database not ready: %s", str(e.orig or e).strip().splitlines()[0])
            time.sleep(2)
    recover()
    backfill_fingerprints()
    log.info("worker ready")
    while True:
        try:
            scan_id = claim_next()
        except OperationalError:
            time.sleep(5)
            continue
        if scan_id is None:
            time.sleep(POLL_SECONDS)
            continue
        log.info("scan %s started", scan_id)
        run_scan(scan_id)


if __name__ == "__main__":
    main()
