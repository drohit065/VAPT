"""Normalise Semgrep, Trivy and Gitleaks output into one finding format, then de-duplicate.

Pure functions (no DB, no subprocess) so they are easy to unit test.

Normalised finding (dict):
    severity        Critical | High | Medium | Low
    title           short name
    file_path       path relative to the scanned root
    line            int | None
    snippet         code excerpt (secrets are redacted)
    description     what is wrong
    exploitation    how it could be exploited
    recommendation  recommended fix (text only)
    cwe             e.g. "CWE-89: Improper Neutralization ..." | None
    owasp           e.g. "A03:2021 - Injection" | None
    scanners        list of scanner names that reported it
    rule_id         scanner rule / advisory ID
    check           code | deps | secrets | iac
"""
from __future__ import annotations

import os
import re

from .knowledge import cwe_number, lookup

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
MAX_TEXT = 4000
MAX_SNIPPET_LINES = 15
MAX_SNIPPET_FILE_BYTES = 5 * 1024 * 1024

# Gitleaks rules whose leaks typically grant direct access to cloud / SCM / payment systems.
CRITICAL_SECRET_PREFIXES = (
    "aws", "private-key", "gcp", "github", "gitlab", "azure", "stripe", "slack", "twilio",
    "sendgrid", "openai", "anthropic", "heroku", "digitalocean", "npm-access-token",
    "pypi", "shopify", "square", "hashicorp", "vault", "databricks", "doppler",
)


# ---------------------------------------------------------------- helpers


def _clip(text, limit=MAX_TEXT) -> str:
    text = (text or "").strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def rel_path(path: str, root: str | None) -> str:
    path = (path or "").replace("\\", "/")
    if root:
        r = root.rstrip("/").replace("\\", "/")
        if path == r:
            return "."
        if path.startswith(r + "/"):
            path = path[len(r) + 1:]
    while path.startswith("./"):
        path = path[2:]
    return path.lstrip("/")


def read_snippet(root: str | None, rel: str, start: int | None, end: int | None = None, context: int = 2) -> str:
    """Read a few numbered lines around a finding. Refuses paths that escape the root
    (including through symlinks) so a malicious repo cannot make us leak worker files."""
    if not root or not rel or not start:
        return ""
    base = os.path.realpath(root)
    full = os.path.realpath(os.path.join(base, rel))
    if not full.startswith(base + os.sep) or not os.path.isfile(full):
        return ""
    try:
        if os.path.getsize(full) > MAX_SNIPPET_FILE_BYTES:
            return ""
        with open(full, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return ""
    end = end or start
    lo = max(1, start - context)
    hi = min(len(lines), max(end, start) + context, lo + MAX_SNIPPET_LINES - 1)
    width = len(str(hi))
    return "\n".join(f"{n:>{width}} | {lines[n - 1][:300]}" for n in range(lo, hi + 1))


def _first(value):
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _owasp_2021(value) -> str | None:
    items = value if isinstance(value, list) else [value] if value else []
    for item in items:
        if isinstance(item, str) and "2021" in item:
            m = re.match(r"\s*(A\d{2}):2021\s*[-–]?\s*(.*)", item)
            return f"{m.group(1)}:2021 - {m.group(2).strip()}" if m and m.group(2) else item.strip()
    return None


ESTIMATED_CVSS = {"Critical": 9.1, "High": 7.5, "Medium": 5.3, "Low": 3.1}


def _cvss_fields(severity, score, vector) -> dict:
    try:
        score = float(score) if score not in (None, "") else None
    except (TypeError, ValueError):
        score = None
    if score is not None and 0 <= score <= 10:
        return {"cvss_score": round(score, 1), "cvss_vector": _clip(vector, 200) or None, "cvss_source": "scanner"}
    sev = severity if severity in SEVERITY_ORDER else "Low"
    return {"cvss_score": ESTIMATED_CVSS[sev], "cvss_vector": None, "cvss_source": "estimated"}


def make_finding(*, severity, title, file_path, line, snippet, description, check, scanner,
                 rule_id=None, cwe=None, owasp=None, exploitation=None, recommendation=None,
                 cvss_score=None, cvss_vector=None) -> dict:
    kb_owasp, kb_exploit, kb_fix = lookup(cwe, check)
    return _cvss_fields(severity, cvss_score, cvss_vector) | {
        "severity": severity if severity in SEVERITY_ORDER else "Low",
        "title": _clip(title, 500) or "Untitled finding",
        "file_path": file_path or "(repository)",
        "line": int(line) if isinstance(line, int) or (isinstance(line, str) and line.isdigit()) else None,
        "snippet": _clip(snippet, 6000),
        "description": _clip(description),
        "exploitation": _clip(exploitation) or kb_exploit,
        "recommendation": _clip(recommendation) or kb_fix,
        "cwe": _clip(cwe, 100) or None,
        "owasp": owasp or kb_owasp,
        "scanners": [scanner],
        "rule_id": _clip(rule_id, 500) or None,
        "check": check,
    }


# ---------------------------------------------------------------- Semgrep


def semgrep_severity(extra: dict) -> str:
    sev = str(extra.get("severity", "")).upper()
    meta = extra.get("metadata") or {}
    impact = str(meta.get("impact", "")).upper()
    likelihood = str(meta.get("likelihood", "")).upper()
    if sev == "CRITICAL":
        return "Critical"
    if sev in ("ERROR", "HIGH"):
        return "Critical" if impact == "HIGH" and likelihood == "HIGH" else "High"
    if sev in ("WARNING", "MEDIUM"):
        return "Medium"
    return "Low"


def parse_semgrep(data: dict, root: str | None = None) -> list[dict]:
    out = []
    for r in (data or {}).get("results", []) or []:
        extra = r.get("extra") or {}
        meta = extra.get("metadata") or {}
        path = rel_path(r.get("path", ""), root)
        start = (r.get("start") or {}).get("line")
        end = (r.get("end") or {}).get("line")
        check_id = r.get("check_id") or ""
        short = check_id.rsplit(".", 1)[-1].replace("-", " ").replace("_", " ").strip()
        message = extra.get("message") or ""
        refs = meta.get("references") or []
        if isinstance(refs, str):
            refs = [refs]
        desc = message + ("\n\nReferences:\n" + "\n".join(f"- {x}" for x in refs[:5]) if refs else "")
        fix = extra.get("fix")
        recommendation = None
        if fix:
            # Show suggested replacement as text only. It is never applied.
            recommendation = f"Suggested change (not applied automatically):\n{fix}"
            recommendation = lookup(_first(meta.get("cwe")), "code")[2] + "\n\n" + recommendation
        out.append(make_finding(
            severity=semgrep_severity(extra),
            title=short[:1].upper() + short[1:] if short else "Semgrep finding",
            file_path=path,
            line=start,
            snippet=read_snippet(root, path, start, end),
            description=desc,
            check="code",
            scanner="semgrep",
            rule_id=check_id,
            cwe=_first(meta.get("cwe")),
            owasp=_owasp_2021(meta.get("owasp")),
            recommendation=recommendation,
        ))
    return out


# ---------------------------------------------------------------- Trivy

TRIVY_SEV = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "UNKNOWN": "Low"}


def parse_trivy_vulns(data: dict) -> list[dict]:
    out = []
    for res in (data or {}).get("Results", []) or []:
        target = rel_path(res.get("Target", ""), None)
        for v in res.get("Vulnerabilities", []) or []:
            vid = v.get("VulnerabilityID", "")
            pkg = v.get("PkgName", "")
            installed = v.get("InstalledVersion", "")
            fixed = v.get("FixedVersion") or ""
            cwe = _first(v.get("CweIDs"))
            desc = v.get("Description") or v.get("Title") or ""
            if v.get("PrimaryURL"):
                desc += f"\n\nAdvisory: {v['PrimaryURL']}"
            if fixed:
                rec = (f"Upgrade {pkg} from {installed} to {fixed} or later (declared in {target}), "
                       "regenerate the lockfile and re-run your tests.")
            else:
                rec = (f"No fixed version of {pkg} is published yet. Check whether the vulnerable "
                       "function is used, apply vendor mitigations, or replace the package.")
            exploit = lookup(cwe, "deps")[1] if cwe_number(cwe) else None
            cvss = v.get("CVSS") or {}
            src = next((cvss[k] for k in ("nvd", "ghsa", "redhat") if isinstance(cvss.get(k), dict)
                        and cvss[k].get("V3Score") is not None), None) or {}
            line = None
            locs = v.get("Locations") or []
            if locs and isinstance(locs, list):
                line = (locs[0] or {}).get("StartLine")
            out.append(make_finding(
                severity=TRIVY_SEV.get(str(v.get("Severity", "")).upper(), "Low"),
                title=f"{vid} in {pkg} {installed}" + (f": {v['Title']}" if v.get("Title") else ""),
                file_path=target,
                line=line,
                snippet=f"{pkg}@{installed}" + (f"  ->  fixed in {fixed}" if fixed else "  (no fix available)"),
                description=desc,
                check="deps",
                scanner="trivy",
                rule_id=vid,
                cwe=cwe,
                owasp="A06:2021 - Vulnerable and Outdated Components",
                exploitation=(f"{pkg} {installed} is affected by the publicly known vulnerability {vid}. "
                              + (exploit or lookup(None, "deps")[1])),
                recommendation=rec,
                cvss_score=src.get("V3Score"),
                cvss_vector=src.get("V3Vector"),
            ))
    return out


def parse_trivy_config(data: dict, root: str | None = None) -> list[dict]:
    out = []
    for res in (data or {}).get("Results", []) or []:
        target = rel_path(res.get("Target", ""), root)
        for m in res.get("Misconfigurations", []) or []:
            if str(m.get("Status", "FAIL")).upper() != "FAIL":
                continue
            cause = m.get("CauseMetadata") or {}
            start = cause.get("StartLine")
            end = cause.get("EndLine")
            code_lines = ((cause.get("Code") or {}).get("Lines")) or []
            snippet = "\n".join(
                f"{ln.get('Number')} | {ln.get('Content', '')}" for ln in code_lines[:MAX_SNIPPET_LINES]
                if ln.get("Content") is not None
            ) or read_snippet(root, target, start, end)
            desc = m.get("Description") or ""
            if m.get("Message"):
                desc = f"{m['Message']}\n\n{desc}".strip()
            refs = m.get("References") or []
            if refs:
                desc += "\n\nReferences:\n" + "\n".join(f"- {x}" for x in refs[:3])
            out.append(make_finding(
                severity=TRIVY_SEV.get(str(m.get("Severity", "")).upper(), "Low"),
                title=m.get("Title") or m.get("ID") or "Misconfiguration",
                file_path=target,
                line=start,
                snippet=snippet,
                description=desc,
                check="iac",
                scanner="trivy",
                rule_id=m.get("AVDID") or m.get("ID"),
                cwe=None,
                owasp="A05:2021 - Security Misconfiguration",
                recommendation=m.get("Resolution"),
            ))
    return out


# ---------------------------------------------------------------- Gitleaks


def gitleaks_severity(rule_id: str) -> str:
    rid = (rule_id or "").lower()
    return "Critical" if rid.startswith(CRITICAL_SECRET_PREFIXES) else "High"


def secret_values(data: list) -> list[str]:
    """Raw secret strings from an un-redacted Gitleaks report (kept in memory only)."""
    vals = {str(g.get("Secret") or "") for g in data or []}
    return sorted((v for v in vals if len(v) >= 4 and v != "REDACTED"), key=len, reverse=True)


def redact(text: str, secrets: list[str]) -> str:
    for v in secrets:
        if v and v in (text or ""):
            text = text.replace(v, "REDACTED")
    return text


_SECRET_NAME = r"(?:\w*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential)\w*)"
# NAME = "literal"   /  "name": "literal"   /  name => 'literal'
_QUOTED_RE = re.compile(_SECRET_NAME + r"""(["']?\s*(?:=|:|=>)\s*)(["'])([^"'\n]{4,})\2""", re.I)
# NAME=value (env files, Dockerfile ENV, shell): no spaces around '='
_ENV_RE = re.compile(r"(\b" + _SECRET_NAME + r"=)([^\s\"']{4,})", re.I)
_URL_CRED_RE = re.compile(r"(://[^/\s:@]+:)([^@\s/]+)(@)")


def mask_assignments(text: str) -> str:
    """Heuristic: hide literal values assigned to secret-looking names, and passwords in URLs.
    Code such as `password = request.form["password"]` is left readable."""
    if not text:
        return text
    text = _URL_CRED_RE.sub(r"\1REDACTED\3", text)
    text = _QUOTED_RE.sub(lambda m: m.group(0)[: m.start(3) - m.start(0)] + "REDACTED" + m.group(2), text)
    return _ENV_RE.sub(lambda m: m.group(1) + "REDACTED", text)


def redact_findings(findings: list[dict], secrets: list[str]) -> None:
    """Mask secret values wherever they appear in any finding: exact values found by
    Gitleaks, plus a heuristic for secret-looking assignments in snippets."""
    for f in findings:
        for field in ("snippet", "description", "title", "recommendation"):
            if f.get(field):
                f[field] = redact(f[field], secrets)
        if f.get("snippet"):
            f["snippet"] = mask_assignments(f["snippet"])


def _rule_label(rule: str) -> str:
    return rule.replace("-", " ").strip().capitalize() if rule else "Secret"


def parse_gitleaks(data: list, root: str | None = None) -> list[dict]:
    """Secrets are always redacted in the output, whether or not Gitleaks ran with --redact."""
    secrets = secret_values(data)
    out = []
    for g in data or []:
        rule = g.get("RuleID", "")
        path = rel_path(g.get("File", ""), root)
        commit = (g.get("Commit") or "")[:12]
        where = (f"Found in Git history, commit {commit}"
                 + (f" ({g['Date'][:10]})" if g.get("Date") else "") + "."
                 if commit else "Found in the current files.")
        match = redact(g.get("Match") or "", secrets)
        desc = (g.get("Description") or "").strip()
        out.append(make_finding(
            severity=gitleaks_severity(rule),
            title=f"Hardcoded secret: {_rule_label(rule)}",
            file_path=path,
            line=g.get("StartLine"),
            snippet=f"{g.get('StartLine', '?')} | {match}" if match else "",
            description=((desc + "\n\n") if desc else "")
            + f"A value matching the '{rule}' pattern is committed to the repository. {where} "
              "The secret value is redacted in this report.",
            check="secrets",
            scanner="gitleaks",
            rule_id=rule,
            cwe="CWE-798: Use of Hard-coded Credentials",
            owasp="A07:2021 - Identification and Authentication Failures",
        ) | {"_commit": commit})
    return out


# ---------------------------------------------------------------- Trivy secrets (container images)


def parse_trivy_secrets(data: dict) -> list[dict]:
    """Secrets Trivy found inside image layers. Trivy masks the value (****); we mask again anyway."""
    out = []
    for res in (data or {}).get("Results", []) or []:
        target = rel_path(res.get("Target", ""), None)
        for s in res.get("Secrets", []) or []:
            rule = s.get("RuleID") or "secret"
            match = mask_assignments(str(s.get("Match") or ""))
            out.append(make_finding(
                severity=TRIVY_SEV.get(str(s.get("Severity", "")).upper(), "High"),
                title=f"Secret in image: {s.get('Title') or _rule_label(rule)}",
                file_path=target, line=s.get("StartLine"),
                snippet=f"{s.get('StartLine', '?')} | {match}"[:600] if match else "",
                description=(f"A value matching '{rule}' ({s.get('Category') or 'secret'}) is stored in a file "
                             "inside the image. Anyone who can pull the image can read it. "
                             "The value is masked in this report."),
                check="secrets", scanner="trivy", rule_id=f"trivy-secret.{rule}",
                cwe="CWE-798: Use of Hard-coded Credentials",
                owasp="A07:2021 - Identification and Authentication Failures",
            ))
    return out


# ---------------------------------------------------------------- Nuclei (live URLs)

NUCLEI_SEV = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}


def _mask_extracted(value: str) -> str:
    """Extracted values can be tokens or keys from an exposed file: keep only a short prefix."""
    value = str(value).strip()
    return value if len(value) <= 16 else value[:4] + "…(redacted)"


def parse_nuclei(results: list[dict]) -> list[dict]:
    """Nuclei JSONL records -> findings. 'info' and unknown severities are skipped."""
    out = []
    for r in results or []:
        if not isinstance(r, dict):
            continue
        info = r.get("info") or {}
        sev = NUCLEI_SEV.get(str(info.get("severity", "")).lower())
        if sev is None:
            continue
        cls = info.get("classification") or {}
        cwe_raw = _first(cls.get("cwe-id"))
        cwe = f"CWE-{cwe_number(cwe_raw)}" if cwe_number(cwe_raw) is not None else None
        cve = _first(cls.get("cve-id"))
        template = r.get("template-id") or ""
        name = info.get("name") or template or "Nuclei finding"
        title = name + (f" ({str(cve).upper()})" if cve and str(cve).upper() not in name.upper() else "")
        matched = r.get("matched-at") or r.get("host") or r.get("url") or ""
        evidence = [f"Matched at: {matched}"]
        if r.get("matcher-name"):
            evidence.append(f"Matcher: {r['matcher-name']}")
        extracted = r.get("extracted-results") or []
        if extracted:
            evidence.append("Extracted: " + ", ".join(_mask_extracted(x) for x in extracted[:5]))
        refs = info.get("reference") or []
        if isinstance(refs, str):
            refs = [refs]
        desc = (info.get("description") or "").strip() or f"The target matched the Nuclei template '{template}'."
        if refs:
            desc += "\n\nReferences:\n" + "\n".join(f"- {x}" for x in refs[:5])
        out.append(make_finding(
            severity=sev,
            title=title,
            file_path=matched,
            line=None,
            snippet=mask_assignments("\n".join(evidence)),
            description=desc,
            check="nuclei",
            scanner="nuclei",
            rule_id=template or None,
            cwe=cwe,
            recommendation=info.get("remediation"),
            cvss_score=cls.get("cvss-score"),
            cvss_vector=cls.get("cvss-metrics"),
        ))
    return out


# ---------------------------------------------------------------- de-duplication


def dedupe_key(f: dict) -> tuple:
    if f["check"] == "deps":
        return ("deps", f["file_path"], f.get("rule_id"), f["title"].split(":")[0])
    n = cwe_number(f.get("cwe"))
    ident = f"CWE-{n}" if n is not None else (f.get("rule_id") or f["title"]).lower()
    return ("loc", f["file_path"], f.get("line"), ident)


def dedupe(findings: list[dict]) -> list[dict]:
    """Merge findings that describe the same issue at the same place.

    Keeps the most severe version, unions the scanner list, and for secrets found in
    several commits lists the commits once.
    """
    merged: dict[tuple, dict] = {}
    for f in findings:
        key = dedupe_key(f)
        commit = f.pop("_commit", None)
        cur = merged.get(key)
        if cur is None:
            f = dict(f)
            f["_commits"] = [commit] if commit else []
            merged[key] = f
            continue
        if commit and commit not in cur["_commits"]:
            cur["_commits"].append(commit)
        for s in f["scanners"]:
            if s not in cur["scanners"]:
                cur["scanners"].append(s)
        if SEVERITY_ORDER[f["severity"]] < SEVERITY_ORDER[cur["severity"]]:
            keep_scanners, keep_commits = cur["scanners"], cur["_commits"]
            cur.clear()
            cur.update(f, scanners=keep_scanners, _commits=keep_commits)
        else:
            for field in ("snippet", "cwe", "owasp", "description"):
                if not cur.get(field) and f.get(field):
                    cur[field] = f[field]
    result = []
    for f in merged.values():
        commits = f.pop("_commits", [])
        if len(commits) > 1:
            shown = ", ".join(commits[:5]) + (f" and {len(commits) - 5} more" if len(commits) > 5 else "")
            f["description"] += f"\n\nThe same secret appears in {len(commits)} commits: {shown}."
        result.append(f)
    result.sort(key=sort_key)
    return result


def sort_key(f: dict):
    return (SEVERITY_ORDER.get(f["severity"], 9), f.get("file_path") or "", f.get("line") or 0)


def count_by_severity(findings: list[dict]) -> dict:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return counts
