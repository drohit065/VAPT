import json
import os
import re
import uuid
import zipfile
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, Form, HTTPException, Response, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import require_user
from ..config import get_settings
from ..db import get_db
from ..models import Finding, Project, Scan
from ..security import (
    ValidationError,
    assert_public_host,
    assert_public_target,
    canonical_repo_source,
    encrypt_token,
    project_name_from_url,
    parse_auth_headers,
    target_project_name,
    validate_branch,
    validate_endpoints,
    validate_git_url,
    validate_targets,
)
from ..findings_mgmt import STATUSES, open_counts
from ..summary import scan_brief

router = APIRouter(prefix="/api", tags=["scans"], dependencies=[Depends(require_user)])

CHECKS = {
    "code": "Code flaws (Semgrep)",
    "deps": "Vulnerable dependencies (Trivy)",
    "secrets": "Hardcoded secrets (Gitleaks, incl. Git history)",
    "iac": "Docker and Terraform files (Trivy config)",
    "web": "Web security checks: headers, TLS, cookies, CORS, exposed files",
    "nuclei": "Known vulnerabilities and misconfigurations (Nuclei templates)",
    "authz": "Access control: compare no login / user A / user B (needs authentication below)",
    "ai": "AI review (Claude)",
}
DEFAULT_CHECKS = {"code": True, "deps": True, "secrets": True, "iac": True,
                  "web": True, "nuclei": True, "authz": True, "ai": False}
CODE_SOURCES = ["git", "zip"]
# Which inputs each check applies to.
CHECK_SOURCES = {"code": CODE_SOURCES, "deps": CODE_SOURCES, "secrets": CODE_SOURCES, "iac": CODE_SOURCES,
                 "ai": CODE_SOURCES, "web": ["url"], "nuclei": ["url"], "authz": ["url"]}


@router.get("/meta")
def meta():
    s = get_settings()
    return {
        "checks": [{"key": k, "label": v, "default": DEFAULT_CHECKS[k], "sources": CHECK_SOURCES[k]}
                   for k, v in CHECKS.items()],
        "ai_available": s.ai_enabled,
        "ai_model": s.anthropic_model if s.ai_enabled else None,
        "ai_unavailable_reason": None if s.ai_enabled else "ANTHROPIC_API_KEY is not set on the server.",
        "max_upload_mb": s.max_upload_mb,
    }


def _parse_checks(raw: str | None, source_type: str) -> tuple[dict, list[str]]:
    notes = []
    try:
        data = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        raise HTTPException(400, "Invalid checks value")
    if not isinstance(data, dict):
        raise HTTPException(400, "Invalid checks value")
    checks = {k: bool(data.get(k, DEFAULT_CHECKS[k])) for k in CHECKS if source_type in CHECK_SOURCES[k]}
    if checks.get("ai") and not get_settings().ai_enabled:
        checks["ai"] = False
        notes.append("AI review was requested but is disabled: ANTHROPIC_API_KEY is not set.")
    if not any(checks.values()):
        raise HTTPException(400, "Switch on at least one check.")
    return checks, notes


def _get_or_create_project(db: Session, source_type: str, source: str, name: str) -> Project:
    p = db.scalar(select(Project).where(Project.source_type == source_type, Project.source == source))
    if not p:
        p = Project(name=name[:255], source_type=source_type, source=source[:1000])
        db.add(p)
        db.flush()
    return p


def _safe_zip_name(filename: str | None) -> str:
    base = os.path.basename((filename or "upload.zip").replace("\\", "/"))
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base)[:200] or "upload.zip"
    return base


@router.post("/scans")
async def create_scan(
    source_type: str = Form(...),
    repo_url: str | None = Form(None),
    branch: str | None = Form(None),
    token: str | None = Form(None),
    target_urls: str | None = Form(None),
    authorized: str | None = Form(None),
    auth_a: str | None = Form(None),
    auth_b: str | None = Form(None),
    endpoints: str | None = Form(None),
    checks: str | None = Form(None),
    file: UploadFile | None = File(None),
    db: Session = Depends(get_db),
):
    s = get_settings()
    if source_type not in ("git", "zip", "url"):
        raise HTTPException(400, "source_type must be 'git', 'zip' or 'url'")
    check_cfg, notes = _parse_checks(checks, source_type)

    if source_type == "url":
        if (authorized or "").lower() not in ("true", "1", "yes", "on"):
            raise HTTPException(400, "Confirm that you own these targets or have permission to test them.")
        try:
            urls = validate_targets(target_urls)
            for u in urls:
                assert_public_target(u)
            headers_a = parse_auth_headers(auth_a)
            headers_b = parse_auth_headers(auth_b)
            eps = validate_endpoints(endpoints, urls)
        except (ValidationError, ValueError) as e:
            raise HTTPException(400, str(e) or "Invalid URL")
        if headers_b and not headers_a:
            raise HTTPException(400, "Enter user A's authentication before user B's.")
        source = "\n".join(urls)
        if len(source) > 1000:
            raise HTTPException(400, "The URLs are too long in total (1000 characters max).")
        if check_cfg.get("authz") and not headers_a:
            check_cfg["authz"] = False
            notes.append("Access control check skipped: it needs user A's authentication headers.")
            if not any(check_cfg.values()):
                raise HTTPException(400, "Switch on at least one check.")
        creds_enc = None
        if headers_a:
            try:
                creds_enc = encrypt_token(json.dumps({"a": headers_a, "b": headers_b}))
            except RuntimeError:
                raise HTTPException(500, "Server is missing TOKEN_ENCRYPTION_KEY; cannot accept credentials.")
        project = _get_or_create_project(db, "url", source, target_project_name(urls))
        notes.append("The operator confirmed being authorised to test these targets.")
        if headers_a:
            notes.append("Authenticated scan as user A" + (" with user B for comparison" if headers_b else "")
                         + f" (header names: {', '.join(headers_a)}; values are never stored).")
        options = {"endpoints": eps, "auth_a": bool(headers_a), "auth_b": bool(headers_b)}
        scan = Scan(project_id=project.id, checks=check_cfg, notes=notes, status="queued",
                    git_token_enc=creds_enc, options=options)
        db.add(scan)
        db.commit()
        return {"id": scan.id, "project_id": project.id}

    if source_type == "git":
        try:
            url = validate_git_url(repo_url or "")
            assert_public_host(url)
            br = validate_branch(branch)
        except (ValidationError, ValueError) as e:
            raise HTTPException(400, str(e) or "Invalid Git URL")
        token_enc = None
        if token and token.strip():
            if len(token) > 1000:
                raise HTTPException(400, "Access token is too long")
            try:
                token_enc = encrypt_token(token.strip())
            except RuntimeError:
                raise HTTPException(500, "Server is missing TOKEN_ENCRYPTION_KEY; cannot accept tokens.")
        source = canonical_repo_source(url)
        project = _get_or_create_project(db, "git", source, project_name_from_url(url))
        scan = Scan(
            project_id=project.id, branch=br, checks=check_cfg, notes=notes,
            git_token_enc=token_enc, status="queued",
        )
        db.add(scan)
        db.commit()
        return {"id": scan.id, "project_id": project.id}

    if source_type == "zip":
        if file is None:
            raise HTTPException(400, "Choose a .zip file to upload.")
        name = _safe_zip_name(file.filename)
        if not name.lower().endswith(".zip"):
            raise HTTPException(400, "Only .zip uploads are supported.")
        upload_dir = os.path.join(s.data_dir, "uploads")
        os.makedirs(upload_dir, exist_ok=True)
        dest = os.path.join(upload_dir, f"{uuid.uuid4().hex}.zip")
        limit = s.max_upload_mb * 1024 * 1024
        written = 0
        try:
            with open(dest, "wb") as out:
                while chunk := await file.read(1024 * 1024):
                    written += len(chunk)
                    if written > limit:
                        raise HTTPException(413, f"Upload is larger than {s.max_upload_mb} MB.")
                    out.write(chunk)
            if not zipfile.is_zipfile(dest):
                raise HTTPException(400, "The file is not a valid zip archive.")
        except BaseException:
            if os.path.exists(dest):
                os.remove(dest)
            raise
        stem = name[:-4] or "upload"
        project = _get_or_create_project(db, "zip", name, stem)
        scan = Scan(project_id=project.id, checks=check_cfg, notes=notes, upload_path=dest, status="queued")
        db.add(scan)
        db.commit()
        return {"id": scan.id, "project_id": project.id}

    raise HTTPException(400, "source_type must be 'git', 'zip' or 'url'")


def _scan_detail(scan: Scan) -> dict:
    data = scan_brief(scan)
    data.update(
        project={"id": scan.project.id, "name": scan.project.name,
                 "source_type": scan.project.source_type, "source": scan.project.source},
        checks=scan.checks,
        steps=scan.steps,
        languages=scan.languages,
        frameworks=scan.frameworks,
        notes=scan.notes,
        error=scan.error,
        ai_summary=scan.ai_summary,
        diff=scan.diff or {},
        options=scan.options or {},
        statuses=STATUSES,
        suppressed={k: sum(1 for f in scan.findings if f.status == k)
                    for k in ("false_positive", "accepted_risk", "fixed")},
    )
    return data


@router.get("/scans/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return _scan_detail(scan)


def finding_dict(f: Finding) -> dict:
    return {
        "id": f.id, "severity": f.severity, "title": f.title, "file_path": f.file_path,
        "line": f.line, "snippet": f.snippet, "description": f.description,
        "exploitation": f.exploitation, "recommendation": f.recommendation, "cwe": f.cwe,
        "owasp": f.owasp, "scanners": f.scanners, "rule_id": f.rule_id, "check": f.check,
        "ai_verdict": f.ai_verdict, "ai_notes": f.ai_notes,
        "fingerprint": f.fingerprint, "status": f.status or "open", "status_note": f.status_note,
        "status_updated_at": f.status_updated_at, "is_new": f.is_new,
        "cvss_score": f.cvss_score, "cvss_vector": f.cvss_vector, "cvss_source": f.cvss_source,
    }


@router.get("/scans/{scan_id}/findings")
def get_findings(scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    from ..normalize import sort_key

    items = [finding_dict(f) for f in scan.findings]
    items.sort(key=sort_key)
    return items


class FindingStatusIn(BaseModel):
    status: str
    note: str | None = Field(default=None, max_length=2000)


@router.patch("/findings/{finding_id}")
def update_finding(finding_id: int, body: FindingStatusIn, db: Session = Depends(get_db)):
    if body.status not in STATUSES:
        raise HTTPException(400, f"status must be one of: {', '.join(STATUSES)}")
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(404, "Finding not found")
    f.status = body.status
    f.status_note = (body.note or "").strip() or None
    f.status_updated_at = datetime.now(timezone.utc)
    f.scan.counts = open_counts(f.scan.findings)
    db.commit()
    return finding_dict(f) | {"scan_counts": f.scan.counts}


def _sorted_findings(scan: Scan) -> list[dict]:
    from ..normalize import sort_key
    return sorted((finding_dict(f) for f in scan.findings), key=sort_key)


def _export_name(scan: Scan, ext: str) -> str:
    name = re.sub(r"[^A-Za-z0-9._-]", "_", scan.project.name)[:80] or "project"
    return f"vapt-{name}-scan{scan.id}.{ext}"


def _completed_scan(db: Session, scan_id: int) -> Scan:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.status != "completed":
        raise HTTPException(409, "Exports are available when the scan has completed.")
    return scan


@router.get("/scans/{scan_id}/export.csv")
def export_csv(scan_id: int, db: Session = Depends(get_db)):
    from ..exports import to_csv
    scan = _completed_scan(db, scan_id)
    return Response(content="﻿" + to_csv(_sorted_findings(scan)), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{_export_name(scan, "csv")}"',
                             "Cache-Control": "no-store"})


@router.get("/scans/{scan_id}/export.sarif")
def export_sarif(scan_id: int, db: Session = Depends(get_db)):
    from ..exports import to_sarif
    scan = _completed_scan(db, scan_id)
    body = json.dumps(to_sarif(_scan_detail(scan), _sorted_findings(scan)), indent=2, default=str)
    return Response(content=body, media_type="application/sarif+json",
                    headers={"Content-Disposition": f'attachment; filename="{_export_name(scan, "sarif")}"',
                             "Cache-Control": "no-store"})


@router.get("/scans/{scan_id}/report.pdf")
def get_report_pdf(scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.status != "completed":
        raise HTTPException(409, "The report is available when the scan has completed.")
    from ..normalize import sort_key
    from ..pdf_report import build_pdf

    items = sorted((finding_dict(f) for f in scan.findings), key=sort_key)
    pdf = build_pdf(_scan_detail(scan), items)
    name = re.sub(r"[^A-Za-z0-9._-]", "_", scan.project.name)[:80] or "project"
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="vapt-report-{name}-scan{scan.id}.pdf"',
            "Cache-Control": "no-store",
        },
    )
