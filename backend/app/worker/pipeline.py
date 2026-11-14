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

from urllib.parse import urlsplit

from sqlalchemy.orm.attributes import flag_modified

from ..config import get_settings
from ..db import SessionLocal
from ..models import Finding, Scan
from ..normalize import (
    count_by_severity,
    dedupe,
    parse_gitleaks,
    make_finding,
    parse_trivy_secrets,
    parse_nuclei,
    parse_semgrep,
    parse_trivy_config,
    parse_trivy_vulns,
    redact_findings,
    secret_values,
)
from sqlalchemy import select

from ..findings_mgmt import apply_history, open_counts
from ..security import assert_public_registry, decrypt_token, parse_image_ref, scrub
from . import dast
from . import infra
from . import zap as zap_mod
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
    ("image", "Container image: vulnerabilities, secrets, misconfigurations (Trivy image)"),
    ("tls", "TLS protocols and ciphers (nmap)"),
    ("ports", "Open ports and exposed services (nmap)"),
    ("zap", "OWASP ZAP: crawl, passive scan and OpenAPI import"),
    ("authz", "Access control (no login / user A / user B)"),
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


def run_tool(cmd: list[str], cwd: str, home: str, timeout: float,
             extra_env: dict | None = None) -> subprocess.CompletedProcess:
    """extra_env carries per-call secrets (e.g. registry login) via the environment, never argv."""
    if timeout <= 5:
        raise TimeoutError("Scan time limit reached")
    try:
        return subprocess.run(cmd, cwd=cwd, env={**tool_env(home), **(extra_env or {})}, capture_output=True,
                              text=True, timeout=timeout)
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


def check_image(info, creds, out_dir, home, budget):
    out = os.path.join(out_dir, "trivy-image.json")
    cmd = ["trivy", "image", "--image-src", "remote", "--scanners", "vuln,secret,misconfig",
           "--image-config-scanners", "misconfig,secret", "--format", "json", "--output", out, "--quiet",
           "--timeout", f"{int(budget)}s", "--", info["ref"]]
    proc = run_tool(cmd, out_dir, home, budget, extra_env=creds)
    data = _load_json(out)
    if data is None or proc.returncode != 0:
        err = _tail(proc.stderr, 400)
        if "UNAUTHORIZED" in err or "authentication required" in err or "denied" in err.lower():
            raise RuntimeError("The registry refused access: check the image name and the registry login.")
        if "MANIFEST_UNKNOWN" in err or "not found" in err.lower():
            raise RuntimeError(f"Image {info['ref']} was not found in the registry.")
        raise RuntimeError(f"Trivy image failed: {err}")
    findings = parse_trivy_vulns(data) + parse_trivy_secrets(data) + parse_trivy_config(data, None)
    meta = data.get("Metadata") or {}
    os_info = meta.get("OS") or {}
    image_meta = {
        "os": " ".join(x for x in (os_info.get("Family"), os_info.get("Name")) if x),
        "digest": next((d.split("@", 1)[-1] for d in meta.get("RepoDigests") or [] if "@" in d), None),
        "eosl": bool(os_info.get("EOSL")),
    }
    if image_meta["eosl"]:
        findings.append(make_finding(
            severity="High", title=f"Base image OS is end-of-life ({image_meta['os']})", file_path=info["ref"],
            line=None, snippet=image_meta["os"], check="image", scanner="trivy", rule_id="image.eosl",
            cwe="CWE-1104", owasp="A06:2021 - Vulnerable and Outdated Components",
            description="The operating system in this image no longer receives security updates.",
            exploitation="New vulnerabilities in the OS packages will never be fixed, so the image accumulates "
                         "exploitable flaws over time.",
            recommendation="Rebuild on a supported base image version (e.g. a current Debian, Alpine or "
                           "distroless release) and rebuild regularly."))
    counts = {"vuln": sum(1 for f in findings if f["check"] == "deps"),
              "secret": sum(1 for f in findings if f["check"] == "secrets"),
              "config": sum(1 for f in findings if f["check"] == "iac")}
    detail = (f"{counts['vuln']} vulnerable package(s), {counts['secret']} secret(s), "
              f"{counts['config']} misconfiguration(s)" + (f" · {image_meta['os']}" if image_meta["os"] else ""))
    return findings, detail, image_meta


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


def check_nuclei(urls, out_dir, home, budget, auth: dict | None = None):
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
    if auth:
        # Credentials go through a 0600 file, never on the command line.
        hdr_file = os.path.join(out_dir, "auth-headers.txt")
        fd = os.open(hdr_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write("".join(f"{k}: {v}\n" for k, v in auth.items()))
        cmd += ["-H", hdr_file]
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
    auth_a: dict = {}
    auth_b: dict = {}
    secret_values_auth: list[str] = []
    registry_creds: dict = {}
    image_info: dict = {}
    deadline = time.monotonic() + s.scan_timeout_seconds
    steps = Steps(db, scan)
    notes = list(scan.notes or [])

    def budget():
        return deadline - time.monotonic()

    try:
        checks = scan.checks or {}
        is_url = scan.project.source_type == "url"
        is_image = scan.project.source_type == "image"
        no_source = is_url or is_image  # nothing is downloaded to disk for these
        plan = [("fetch", "Connecting to targets" if is_url else "Checking image reference" if is_image
                 else "Fetching code")]
        if not no_source:
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
            if scan.git_token_enc:
                creds = json.loads(decrypt_token(scan.git_token_enc))
                auth_a, auth_b = creds.get("a") or {}, creds.get("b") or {}
                secret_values_auth = [v for h in (auth_a, auth_b) for v in h.values()]
                scan.git_token_enc = None  # wiped from the database right away; kept in memory only
                db.commit()
            targets = []
            for u in project.source.splitlines():
                try:
                    targets.append(dast.probe(u, auth_a))
                except dast.TargetError as e:
                    notes.append(f"Skipped target: {e}")
            if not targets:
                raise FetchError("None of the targets could be reached. " + " ".join(notes[-5:]))
            scan.languages = []
            scan.frameworks = sorted({x for t in targets for x in dast.detect_tech(t.resp)})
            db.commit()
            scan_root, has_git = None, False
            netlocs = {urlsplit(t.url).netloc for t in targets}
            specs = dast.discover_specs(targets, auth_a, (scan.options or {}).get("specs") or [])
            spec_endpoints = [u for su, doc in specs for u in dast.spec_get_endpoints(doc, su, netlocs)]
            if specs:
                notes.append("OpenAPI spec found: " + ", ".join(su for su, _ in specs)
                             + f" ({len(spec_endpoints)} GET endpoint(s) without path parameters).")
            detail = "; ".join(f"{t.url} -> HTTP {t.resp.status}" for t in targets)
            if specs:
                detail += f"; {len(specs)} OpenAPI spec(s) found"
            steps.finish("fetch", detail=detail[:500])
        elif is_image:
            steps.start("fetch", "Validating image reference and registry")
            image_info = parse_image_ref(project.source)
            assert_public_registry(image_info)
            if scan.git_token_enc:
                reg = json.loads(decrypt_token(scan.git_token_enc))
                registry_creds = {"TRIVY_USERNAME": reg.get("u") or "", "TRIVY_PASSWORD": reg.get("p") or ""}
                secret_values_auth = [v for v in registry_creds.values() if v]
                scan.git_token_enc = None
                db.commit()
            scan_root, has_git = None, False
            steps.finish("fetch", detail=f"{image_info['registry']}/{image_info['repo']}"
                         + (f":{image_info['tag']}" if image_info["tag"] else "")
                         + (" (registry login provided)" if registry_creds else ""))
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
        if not no_source:
            steps.start("detect")
            found = detect_mod.detect(scan_root)
            scan.languages, scan.frameworks = found["languages"], found["frameworks"]
            db.commit()
            langs = ", ".join(l["name"] for l in found["languages"][:6]) or "none recognised"
            steps.finish("detect", detail=langs)

        # 3. checks
        all_findings: list[dict] = []
        secrets: list[str] = []

        def run_zap():
            found, detail, zap_notes = zap_mod.run(
                [t.url for t in targets], [su for su, _ in specs], auth_a, bool(checks.get("zap_active")),
                budget, skip_covered=bool(checks.get("web")), scan_id=scan.id)
            notes.extend(zap_notes)
            return found, detail

        def run_image():
            found, detail, meta = check_image(image_info, registry_creds, out_dir, home, budget())
            scan.languages = []
            scan.frameworks = [x for x in (meta.get("os"),) if x]
            if meta.get("digest"):
                scan.commit_sha = meta["digest"].replace("sha256:", "")[:64]
            scan.branch = image_info.get("tag") or None
            db.commit()
            return found, detail

        def run_ports():
            found, detail, port_notes = infra.run_ports(targets, out_dir, home, budget, run_tool)
            notes.extend(port_notes)
            return found, detail
        runners = {
            "code": lambda: check_code(scan_root, out_dir, home, budget()),
            "deps": lambda: check_deps(scan_root, out_dir, home, budget()),
            "secrets": lambda: check_secrets(scan_root, out_dir, home, budget(), has_git),
            "iac": lambda: check_iac(scan_root, out_dir, home, budget()),
            "web": lambda: (lambda f: (f, f"{len(f)} issue(s) on {len(targets)} target(s)"))(
                dast.run_web_checks(targets, budget, auth_a)),
            "nuclei": lambda: check_nuclei([t.url for t in targets], out_dir, home, budget(), auth_a),
            "zap": lambda: run_zap(),
            "tls": lambda: infra.run_tls(targets, out_dir, home, budget, run_tool),
            "ports": lambda: run_ports(),
            "image": lambda: run_image(),
            "authz": lambda: dast.run_authz(
                (scan.options or {}).get("endpoints") or (spec_endpoints + [t.url for t in targets])[:50],
                {urlsplit(t.url).netloc: t.ip for t in targets},
                {urlsplit(t.url).netloc: t.verify for t in targets},
                budget, auth_a, auth_b or None),
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
                msg = scrub(str(e), *secret_values_auth)[:500]
                log.warning("scan %s: check %s failed: %s", scan_id, key, msg)
                steps.finish(key, "failed", msg)
                notes.append(f"{_label} failed: {msg}")

        # 4. report
        steps.start("report")
        redact_findings(all_findings, secrets + sorted(secret_values_auth, key=len, reverse=True))
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
        msg = scrub(str(e), token, *secret_values_auth)[:1000] or e.__class__.__name__
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
        auth_a, auth_b, secret_values_auth = {}, {}, []
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
