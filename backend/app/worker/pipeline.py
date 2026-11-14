"""Scan pipeline: fetch -> detect -> enabled checks -> report.

Security rules enforced here:
- Code is only read. Scanners are static analysers; nothing from the repository is built or run.
- Each scan works in its own temporary folder, deleted in `finally`.
- The Git token is decrypted only for the clone, then wiped from the database.
- Scanner processes get a minimal environment (no DB password, no API keys, no tokens) and
  are started with an argument list, never a shell string.
"""
import json
import logging
import os
import subprocess
import tempfile
import time
from datetime import datetime, timezone

from sqlalchemy.orm.attributes import flag_modified

from ..config import get_settings
from ..db import SessionLocal
from ..models import Finding, Scan
from ..normalize import (
    count_by_severity,
    dedupe,
    parse_gitleaks,
    parse_nuclei,
    parse_semgrep,
    parse_trivy_config,
    parse_trivy_vulns,
    redact_findings,
    secret_values,
)
from sqlalchemy import select

from ..findings_mgmt import apply_history, open_counts
from ..security import decrypt_token, scrub
from . import dast
from . import detect as detect_mod
from .fetch import FetchError, clone, extract_zip, remove_tree, single_top_dir

log = logging.getLogger("vapt.worker")

WORK_ROOT = os.environ.get("VAPT_WORK_DIR", "/work")
CACHE_DIR = os.environ.get("VAPT_CACHE_DIR", "/cache")

CHECK_STEPS = [
    ("code", "Code flaws (Semgrep)"),
    ("deps", "Vulnerable dependencies (Trivy)"),
    ("secrets", "Hardcoded secrets (Gitleaks)"),
    ("iac", "Docker and Terraform files (Trivy config)"),
    ("web", "Web security checks (headers, TLS, cookies, CORS, exposed files)"),
    ("nuclei", "Known vulnerabilities and misconfigurations (Nuclei)"),
    ("ai", "AI review (Claude)"),
]
NUCLEI_TEMPLATES = os.path.join(CACHE_DIR, "nuclei-templates")


def now():
    return datetime.now(timezone.utc).isoformat()


class Steps:
    def __init__(self, db, scan: Scan):
        self.db, self.scan = db, scan

    def init(self, keys_labels):
        self.scan.steps = [{"key": k, "label": l, "status": "pending", "detail": None,
                            "started_at": None, "finished_at": None} for k, l in keys_labels]
        self._save()

    def _get(self, key):
        return next(s for s in self.scan.steps if s["key"] == key)

    def start(self, key, detail=None):
        s = self._get(key)
        s.update(status="running", started_at=now(), detail=detail)
        self._save()

    def finish(self, key, status="done", detail=None):
        s = self._get(key)
        s.update(status=status, finished_at=now())
        if detail is not None:
            s["detail"] = detail
        self._save()

    def fail_running(self, detail):
        for s in self.scan.steps:
            if s["status"] == "running":
                s.update(status="failed", finished_at=now(), detail=detail)
            elif s["status"] == "pending":
                s.update(status="skipped")
        self._save()

    def _save(self):
        flag_modified(self.scan, "steps")
        self.db.commit()


def tool_env(home: str) -> dict:
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": home,
        "LANG": "C.UTF-8",
        "TRIVY_CACHE_DIR": os.path.join(CACHE_DIR, "trivy"),
        "SEMGREP_ENABLE_VERSION_CHECK": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }
    for k in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy"):
        if os.environ.get(k):
            env[k] = os.environ[k]
    return env


def run_tool(cmd: list[str], cwd: str, home: str, timeout: float) -> subprocess.CompletedProcess:
    if timeout <= 5:
        raise TimeoutError("Scan time limit reached")
    try:
        return subprocess.run(cmd, cwd=cwd, env=tool_env(home), capture_output=True, text=True,
                              timeout=timeout)
    except subprocess.TimeoutExpired:
        raise TimeoutError(f"{cmd[0]} exceeded the time limit")


def _load_json(path: str):
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return None
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return json.load(fh)


def _tail(text: str, n=300) -> str:
    text = (text or "").strip()
    return text[-n:] if text else ""


# ---------------------------------------------------------------- checks


def check_code(src, out_dir, home, budget):
    out = os.path.join(out_dir, "semgrep.json")
    cmd = ["semgrep", "scan", "--config", "auto", "--json", "--output", out,
           "--disable-version-check", "--timeout", "30", "--max-target-bytes", "2000000",
           "--jobs", "2", "--quiet", src]
    proc = run_tool(cmd, out_dir, home, budget)
    data = _load_json(out)
    if data is None:
        raise RuntimeError(f"Semgrep failed: {_tail(proc.stderr)}")
    findings = parse_semgrep(data, src)
    errs = len(data.get("errors") or [])
    detail = f"{len(findings)} issue(s)" + (f", {errs} file(s) could not be parsed" if errs else "")
    return findings, detail


def check_deps(src, out_dir, home, budget):
    out = os.path.join(out_dir, "trivy-fs.json")
    cmd = ["trivy", "fs", "--scanners", "vuln", "--format", "json", "--output", out, "--quiet",
           "--timeout", f"{int(budget)}s", src]
    proc = run_tool(cmd, out_dir, home, budget)
    data = _load_json(out)
    if data is None or proc.returncode != 0:
        raise RuntimeError(f"Trivy failed: {_tail(proc.stderr)}")
    findings = parse_trivy_vulns(data)
    targets = [r.get("Target") for r in data.get("Results") or []]
    detail = f"{len(findings)} vulnerable package(s) in {len(targets)} manifest(s)"
    if not targets:
        detail = "No supported lockfiles or manifests found"
    return findings, detail


def check_secrets(src, out_dir, home, budget, has_git: bool):
    out = os.path.join(out_dir, "gitleaks.json")
    mode = "git" if has_git else "dir"
    # Not --redact: the raw values are needed (in memory only) to mask them in every other
    # finding's snippet. The report file sits in the scan's temp folder, deleted at the end.
    cmd = ["gitleaks", mode, "--report-format", "json", "--report-path", out,
           "--exit-code", "0", "--no-banner", "--log-level", "error", src]
    proc = run_tool(cmd, out_dir, home, budget)
    data = _load_json(out)
    if data is None:
        if proc.returncode == 0:
            data = []
        else:
            raise RuntimeError(f"Gitleaks failed: {_tail(proc.stderr)}")
    findings = parse_gitleaks(data, src)
    secrets = secret_values(data)
    os.remove(out)
    scope = "files and full Git history" if has_git else "files (zip uploads have no Git history)"
    return findings, f"{len(data)} raw match(es) in {scope}", secrets


def check_iac(src, out_dir, home, budget):
    out = os.path.join(out_dir, "trivy-config.json")
    cmd = ["trivy", "config", "--format", "json", "--output", out, "--quiet",
           "--misconfig-scanners", "dockerfile,terraform", "--timeout", f"{int(budget)}s", src]
    proc = run_tool(cmd, out_dir, home, budget)
    data = _load_json(out)
    if data is None or proc.returncode != 0:
        raise RuntimeError(f"Trivy config failed: {_tail(proc.stderr)}")
    findings = parse_trivy_config(data, src)
    files = len(data.get("Results") or [])
    return findings, (f"{len(findings)} misconfiguration(s) in {files} file(s)" if files
                      else "No Dockerfiles or Terraform files found")


def ensure_nuclei_templates(out_dir, home, budget) -> str:
    """Download / refresh the Nuclei templates at most once a day into the shared cache."""
    marker = os.path.join(NUCLEI_TEMPLATES, ".vapt-updated")
    if os.path.exists(marker) and time.time() - os.path.getmtime(marker) < 86400:
        return ""
    have_old = os.path.isdir(os.path.join(NUCLEI_TEMPLATES, "http"))
    try:
        proc = run_tool(["nuclei", "-update-templates", "-update-template-dir", NUCLEI_TEMPLATES,
                         "-silent", "-nc"], out_dir, home, min(budget, 900))
        ok = proc.returncode == 0 and os.path.isdir(os.path.join(NUCLEI_TEMPLATES, "http"))
        err = _tail(proc.stderr or proc.stdout)
    except TimeoutError as e:
        ok, err = False, str(e)
    if ok:
        with open(marker, "w") as fh:
            fh.write(str(time.time()))
        return ""
    if have_old:
        return " (templates could not be updated; cached templates were used)"
    raise RuntimeError(f"Could not download Nuclei templates: {err}")


def check_nuclei(urls, out_dir, home, budget):
    started = time.monotonic()
    note = ensure_nuclei_templates(out_dir, home, budget)
    budget -= time.monotonic() - started
    targets = os.path.join(out_dir, "targets.txt")
    with open(targets, "w") as fh:
        fh.write("\n".join(urls) + "\n")
    out = os.path.join(out_dir, "nuclei.jsonl")
    cmd = ["nuclei", "-l", targets, "-t", NUCLEI_TEMPLATES,
           "-pt", "http,ssl",                     # web templates only: no network/code/file/headless
           "-s", "low,medium,high,critical",
           "-etags", "dos,fuzz,intrusive,bruteforce,brute-force,osint,headless",
           "-ni",                                 # no interactsh: never call out to third-party OAST servers
           "-dr",                                 # never follow redirects (could point at internal hosts)
           "-duc", "-nc", "-silent", "-or", "-jsonl", "-o", out,
           "-timeout", "10", "-retries", "1", "-rl", "30", "-c", "10", "-bs", "10",
           "-H", f"User-Agent: {dast.USER_AGENT}"]
    timed_out = False
    proc = None
    try:
        proc = run_tool(cmd, out_dir, home, budget - 5)
    except TimeoutError:
        timed_out = True
    results = []
    if os.path.exists(out):
        with open(out, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        results.append(json.loads(line))
                    except ValueError:
                        pass
    if proc is not None and proc.returncode != 0 and not results:
        raise RuntimeError(f"Nuclei failed: {_tail(proc.stderr)}")
    findings = parse_nuclei(results)
    detail = f"{len(findings)} issue(s) on {len(urls)} target(s)" + note
    if timed_out:
        detail += " (stopped at the time limit; results are partial)"
    return findings, detail


# ---------------------------------------------------------------- main entry


def run_scan(scan_id: int) -> None:
    s = get_settings()
    db = SessionLocal()
    scan = db.get(Scan, scan_id)
    if scan is None:
        db.close()
        return
    os.makedirs(WORK_ROOT, exist_ok=True)
    workdir = tempfile.mkdtemp(prefix=f"scan-{scan_id}-", dir=WORK_ROOT)
    src_dir = os.path.join(workdir, "src")
    out_dir = os.path.join(workdir, "out")
    home = os.path.join(workdir, "home")
    for d in (src_dir, out_dir, home):
        os.makedirs(d, mode=0o700)
    token = None
    deadline = time.monotonic() + s.scan_timeout_seconds
    steps = Steps(db, scan)
    notes = list(scan.notes or [])

    def budget():
        return deadline - time.monotonic()

    try:
        checks = scan.checks or {}
        is_url = scan.project.source_type == "url"
        plan = [("fetch", "Connecting to targets" if is_url else "Fetching code")]
        if not is_url:
            plan.append(("detect", "Detecting languages and frameworks"))
        plan += [(k, l) for k, l in CHECK_STEPS if checks.get(k)]
        plan += [("report", "Building report")]
        steps.init(plan)

        # 1. fetch
        project = scan.project
        if project.source_type == "git":
            steps.start("fetch", "Cloning repository")
            if scan.git_token_enc:
                token = decrypt_token(scan.git_token_enc)
            info = clone(project.source, scan.branch, token, src_dir, home, timeout=max(30, min(900, budget())))
            # Token no longer needed: wipe it from memory and the database right away.
            token = None
            scan.git_token_enc = None
            scan.commit_sha, scan.branch = info["commit"], info["branch"]
            db.commit()
            scan_root = src_dir
            has_git = True
            steps.finish("fetch", detail=f"Cloned {info['branch'] or 'default branch'} @ {(info['commit'] or '')[:12]}")
        elif is_url:
            steps.start("fetch", "Resolving and connecting to targets")
            targets = []
            for u in project.source.splitlines():
                try:
                    targets.append(dast.probe(u))
                except dast.TargetError as e:
                    notes.append(f"Skipped target: {e}")
            if not targets:
                raise FetchError("None of the targets could be reached. " + " ".join(notes[-5:]))
            scan.languages = []
            scan.frameworks = sorted({x for t in targets for x in dast.detect_tech(t.resp)})
            db.commit()
            scan_root, has_git = None, False
            steps.finish("fetch", detail="; ".join(f"{t.url} -> HTTP {t.resp.status}" for t in targets)[:500])
        else:
            steps.start("fetch", "Extracting archive")
            if not scan.upload_path or not os.path.isfile(scan.upload_path):
                raise FetchError("Uploaded archive is missing.")
            info = extract_zip(scan.upload_path, src_dir)
            os.remove(scan.upload_path)
            scan_root = single_top_dir(src_dir)
            has_git = False
            detail = f"Extracted {info['files']} file(s)"
            if info["skipped_symlinks"]:
                detail += f", skipped {info['skipped_symlinks']} symlink(s)"
            steps.finish("fetch", detail=detail)

        # 2. detect
        if not is_url:
            steps.start("detect")
            found = detect_mod.detect(scan_root)
            scan.languages, scan.frameworks = found["languages"], found["frameworks"]
            db.commit()
            langs = ", ".join(l["name"] for l in found["languages"][:6]) or "none recognised"
            steps.finish("detect", detail=langs)

        # 3. checks
        all_findings: list[dict] = []
        secrets: list[str] = []
        runners = {
            "code": lambda: check_code(scan_root, out_dir, home, budget()),
            "deps": lambda: check_deps(scan_root, out_dir, home, budget()),
            "secrets": lambda: check_secrets(scan_root, out_dir, home, budget(), has_git),
            "iac": lambda: check_iac(scan_root, out_dir, home, budget()),
            "web": lambda: (lambda f: (f, f"{len(f)} issue(s) on {len(targets)} target(s)"))(
                dast.run_web_checks(targets, budget)),
            "nuclei": lambda: check_nuclei([t.url for t in targets], out_dir, home, budget()),
        }
        for key, _label in CHECK_STEPS:
            if not checks.get(key):
                continue
            steps.start(key)
            if key == "ai":
                steps.finish(key, "skipped", "AI review is added in Phase 4")
                continue
            try:
                result = runners[key]()
                found_items, detail = result[0], result[1]
                if len(result) > 2:
                    secrets = result[2]
                all_findings.extend(found_items)
                steps.finish(key, detail=detail)
            except TimeoutError as e:
                steps.finish(key, "failed", str(e))
                notes.append(f"{_label} did not finish: {e}. Results may be incomplete.")
            except Exception as e:  # one scanner failing must not lose the others
                msg = scrub(str(e))[:500]
                log.warning("scan %s: check %s failed: %s", scan_id, key, msg)
                steps.finish(key, "failed", msg)
                notes.append(f"{_label} failed: {msg}")

        # 4. report
        steps.start("report")
        redact_findings(all_findings, secrets)
        secrets = []
        final = dedupe(all_findings)
        previous = db.scalars(
            select(Scan).where(Scan.project_id == scan.project_id, Scan.status == "completed",
                               Scan.id != scan.id).order_by(Scan.id.desc()).limit(1)
        ).first()
        diff = apply_history(final, previous.findings if previous else [])
        diff["previous_scan_id"] = previous.id if previous else None
        scan.diff = diff
        for f in final:
            db.add(Finding(scan_id=scan.id, **{k: v for k, v in f.items() if not k.startswith("_")}))
        scan.counts = open_counts(final)
        scan.notes = notes
        removed = len(all_findings) - len(final)
        detail = f"{len(final)} finding(s)" + (f", {removed} duplicate(s) merged" if removed else "")
        if previous:
            detail += f"; vs scan #{previous.id}: {diff['new']} new, {diff['fixed']} fixed"
        steps.finish("report", detail=detail)
        scan.status = "completed"
        scan.finished_at = datetime.now(timezone.utc)
        db.commit()
        log.info("scan %s completed with %s findings", scan_id, len(final))
    except Exception as e:
        db.rollback()
        msg = scrub(str(e), token)[:1000] or e.__class__.__name__
        log.warning("scan %s failed: %s", scan_id, msg)
        scan = db.get(Scan, scan_id)
        steps.scan = scan
        steps.fail_running(msg)
        scan.status = "failed"
        scan.error = msg
        scan.notes = notes
        scan.finished_at = datetime.now(timezone.utc)
        db.commit()
    finally:
        token = None
        remove_tree(workdir)
        try:
            scan = db.get(Scan, scan_id)
            if scan.upload_path and os.path.exists(scan.upload_path):
                os.remove(scan.upload_path)
            scan.upload_path = None
            scan.git_token_enc = None
            db.commit()
        finally:
            db.close()
