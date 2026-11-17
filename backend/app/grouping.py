"""Grouping of raw scanner findings into one finding per real issue.

* Secrets: one finding per unique credential (the HMAC fingerprint of its value), with every
  location listed. Several rules matching the same value become one finding with the most specific
  title. AWS access key IDs are rated by whether a secret access key sits next to them.
  A committed GCP service-account key file is one finding.
* Dependencies: one finding per vulnerable package, listing its CVEs and the single minimum
  version that fixes all of them on the installed major version line.
* Docker: the same problem reported by Trivy and Semgrep becomes one finding.

Runs in the worker after masking and de-duplication; raw secret values are never needed here
(parsers attach only the fingerprint and a few non-secret features as `_secret_*` keys).
"""
from __future__ import annotations

import json
import os
import re

from .normalize import SEVERITY_ORDER, sort_key
from .remediation import ECOSYSTEM_FIX, ecosystem as _ecosystem, secret_fix


def ecosystem(f_or_path) -> str:
    if isinstance(f_or_path, dict):
        return f_or_path.get("_eco") or _ecosystem(f_or_path.get("file_path") or "")
    return _ecosystem(f_or_path)
from .secret_display import fingerprint as value_fingerprint

# ---------------------------------------------------------------- secret features (worker, pre-masking)

_AWS_SECRET_SHAPE = re.compile(r"[A-Za-z0-9/+]{40}")
_PLACEHOLDER = re.compile(r"^\$\{[^}]*\}$|^%\([^)]*\)s$|^<[^>]+>$|^\{\{[^}]*\}\}$")
_ASSIGNED = re.compile(r"""([A-Za-z_][\w.\-]*)["']?\s*(?:=|:|=>)\s*["']?([^"'\s#,;]{6,})""")


def secret_features(raw: str, name: str = "") -> dict:
    """Non-secret facts about a raw secret value: fingerprint, whether it looks like an AWS secret
    access key, and the name it was assigned to. The raw value itself is not kept."""
    return {"_secret_fp": value_fingerprint(raw),
            "_secret_aws40": bool(_AWS_SECRET_SHAPE.fullmatch(raw or "")),
            "_secret_name": (name or "")[:120]}


def name_before(match: str, raw: str) -> str:
    """The key a secret is assigned to, e.g. 'AWS_S3_SECRET_KEY' in "AWS_S3_SECRET_KEY: 'abc'"."""
    head = (match or "").split(raw, 1)[0] if raw and raw in (match or "") else ""
    names = re.findall(r"[A-Za-z_][\w.\-]*", head)
    return names[-1] if names else ""


def annotate_line_secret(f: dict, known_values: list[str]) -> None:
    """For secret-type findings without a value fingerprint (e.g. Semgrep secret rules): take the
    value on the flagged line, preferring a value Gitleaks already identified."""
    if f.get("_secret_fp") or not f.get("line"):
        return
    code = ""
    for raw_line in (f.get("snippet") or "").splitlines():
        num, sep, rest = raw_line.partition(" | ")
        if sep and num.strip() == str(f["line"]):
            code = rest
            break
    if not code:
        return
    for v in sorted(known_values, key=len, reverse=True):
        if v and v in code:
            f.update(secret_features(v, name_before(code, v)))
            return
    matches = [m for m in _ASSIGNED.finditer(code) if not _PLACEHOLDER.match(m.group(2))]
    if matches:
        m = matches[-1]
        f.update(secret_features(m.group(2), m.group(1)))


def is_secret_finding(f: dict) -> bool:
    return f.get("check") == "secrets" or (f.get("check") == "code" and "798" in (f.get("cwe") or ""))


# ---------------------------------------------------------------- secret grouping

# kind -> (specificity rank: lower is more specific, label)
KINDS = {
    "gcp_sa": (0, "GCP service account key file"),
    "aws_secret": (1, "AWS secret access key"),
    "aws_key_id": (1, "AWS access key ID"),
    "private_key": (1, "Private key"),
    "gcp_api_key": (1, "Google API key"),
    "azure_secret": (1, "Azure AD client secret"),
    "openai": (1, "OpenAI API key"),
    "anthropic": (1, "Anthropic API key"),
    "slack": (1, "Slack token"),
    "github": (1, "GitHub token"),
    "stripe": (1, "Stripe key"),
    "jwt": (2, "JSON Web Token"),
    "password_hash": (3, "Password hash"),
    "password": (3.5, "Password"),
    "generic": (4, "Hardcoded secret"),
}
_RULE_KIND = [
    ("aws-secret-access-key", "aws_secret"), ("aws-access-token", "aws_key_id"), ("aws-access-key", "aws_key_id"),
    ("private-key", "private_key"), ("gcp-api-key", "gcp_api_key"), ("google-api-key", "gcp_api_key"),
    ("azure-ad-client-secret", "azure_secret"), ("openai", "openai"), ("slack", "slack"),
    ("github", "github"), ("stripe", "stripe"), ("jwt", "jwt"), ("bcrypt", "password_hash"),
    ("argon2", "password_hash"), ("anthropic", "anthropic"), ("vapt-config-password", "password"),
]


def secret_kind(f: dict) -> str:
    rid = (f.get("rule_id") or "").lower()
    for needle, kind in _RULE_KIND:
        if needle in rid:
            return kind
    if f.get("_secret_aws40") and "secret" in (f.get("_secret_name") or "").lower():
        return "aws_secret"
    return "generic"


def _service_account(root: str | None, rel: str) -> dict | None:
    """client_email / project_id of a committed GCP service-account key file, else None."""
    if not root or not rel.lower().endswith(".json"):
        return None
    path = os.path.realpath(os.path.join(root, rel))
    if not path.startswith(os.path.realpath(root) + os.sep) or not os.path.isfile(path):
        return None
    try:
        if os.path.getsize(path) > 100_000:
            return None
        with open(path, encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    if isinstance(data, dict) and data.get("type") == "service_account" and data.get("private_key"):
        return {"client_email": str(data.get("client_email") or "")[:200],
                "project_id": str(data.get("project_id") or "")[:200]}
    return None


def _loc(f: dict) -> tuple[str, int | None]:
    return (f.get("file_path") or "", f.get("line"))


def _fmt_loc(loc: tuple) -> str:
    return loc[0] + (f":{loc[1]}" if loc[1] else "")


def _first_para(text: str) -> str:
    return (text or "").split("\n\n", 1)[0].strip()


def group_secrets(findings: list[dict], root: str | None) -> list[dict]:
    secret = [f for f in findings if is_secret_finding(f) and f.get("_secret_fp")]
    if not secret:
        return findings
    rest = [f for f in findings if not (is_secret_finding(f) and f.get("_secret_fp"))]

    sa_info = {}
    for f in secret:
        p = f.get("file_path") or ""
        if p not in sa_info:
            sa_info[p] = _service_account(root, p)
    key_of_fp = {f["_secret_fp"]: "sa:" + f["file_path"] for f in secret if sa_info.get(f["file_path"])}

    groups: dict[str, list[dict]] = {}
    for f in secret:
        key = "sa:" + f["file_path"] if sa_info.get(f["file_path"]) else key_of_fp.get(f["_secret_fp"], f["_secret_fp"])
        groups.setdefault(key, []).append(f)

    def group_kind(key: str, items: list[dict]) -> str:
        if key.startswith("sa:"):
            return "gcp_sa"
        return min((secret_kind(x) for x in items), key=lambda k: KINDS[k][0])

    # Where AWS secret access keys are, to rate access key IDs.
    aws_secret_at: dict[str, list[tuple[int, str]]] = {}
    for key, items in groups.items():
        if group_kind(key, items) == "aws_secret":
            for x in items:
                if x.get("line"):
                    aws_secret_at.setdefault(x["file_path"], []).append((x["line"], x["_secret_fp"]))

    out = []
    for key, items in groups.items():
        kind = group_kind(key, items)
        rep = min(items, key=lambda x: (KINDS[secret_kind(x)][0], SEVERITY_ORDER[x["severity"]], _loc(x)))
        locs = sorted({_loc(x) for x in items}, key=lambda l: (l[0], l[1] or 0))
        first = _loc(rep)
        locs.remove(first)
        locs.insert(0, first)
        scanners = sorted({s for x in items for s in x.get("scanners") or []})
        rules = sorted({r for x in items for r in ([x.get("rule_id")] + list(x.get("_rules") or [])) if r})
        in_history = any(x.get("_in_history") for x in items)
        fp = rep["_secret_fp"]
        severity = min((x["severity"] for x in items), key=lambda s: SEVERITY_ORDER[s])
        notes = []

        if kind == "gcp_sa":
            info = sa_info[key[3:]]
            title = f"GCP service account key file committed: {key[3:]}"
            severity = "Critical"
            what = ("A Google Cloud service-account key file (JSON with a private key) is committed to the "
                    f"repository. Account: {info['client_email'] or 'unknown'}"
                    + (f", project: {info['project_id']}" if info["project_id"] else "") + ". "
                    "Anyone with the file can act as this service account with all of its permissions.")
            fix = ("Rotate immediately: delete this key in Google Cloud (IAM > Service accounts > "
                   f"{info['client_email'] or 'the account'} > Keys), create a new key only if one is really "
                   "needed, and load it at runtime (workload identity, a secrets manager or a mounted file "
                   "outside the repository). Remove the file from the code")
        else:
            label = KINDS[kind][1]
            title = (label if label.startswith("Hardcoded") else "Hardcoded " + label[0].lower() + label[1:]
                     if kind in ("password_hash", "password") else "Hardcoded " + label) + f" ({fp})"
            if kind == "aws_secret":
                severity = "Critical"
            elif kind == "aws_key_id":
                pairs = []
                for loc in locs:  # the nearest secret within 3 lines (a tie goes to the line below)
                    near = [(abs(l - loc[1]), l < loc[1], l, s) for (l, s) in aws_secret_at.get(loc[0], [])
                            if loc[1] and abs(l - loc[1]) <= 3]
                    if near:
                        pairs.append(min(near)[2:])
                if pairs:
                    severity = "Critical"
                    notes.append("A secret access key (" + ", ".join(sorted({s for _, s in pairs}))
                                 + ") is stored right next to this key ID, so together they grant access to AWS.")
                else:
                    severity = "Medium"
                    notes.append("No secret access key was found next to this key ID. An access key ID alone does "
                                 "not grant access, but it identifies the AWS account and user and is usually "
                                 "paired with a secret stored elsewhere.")
            what = _first_para(rep.get("description")) or f"A {label.lower()} is committed to the repository."
            fix = None
        n = len(locs)
        where = f"Found in {n} location{'s' if n != 1 else ''}" + (" (including Git history)." if in_history else ".")
        desc = "\n\n".join(p for p in [
            what, *notes, where,
            "The value is never shown in full: values of 20+ characters show only their first and last 4 "
            f"characters, and the fingerprint {fp} is the same wherever this credential appears.",
            ("Matched rules: " + ", ".join(rules)) if len(rules) > 1 else "",
        ] if p)
        config_keys = [(x["_secret_config_key"], bool(x.get("_secret_fallback"))) for x in items
                       if x.get("_secret_config_key")]
        if kind == "gcp_sa":
            fix += ((f" at all {n} locations listed" if n > 1 else "")
                    + ", and load it from a secrets manager or environment variables.")
            if in_history:
                fix += (" It is also in the Git history: after rotating, purge it from history "
                        "(git filter-repo or BFG) and force-push, and ask everyone to re-clone.")
        else:
            fix = secret_fix(kind, locs, in_history, config_keys)
        g = dict(rep)
        g.update(
            title=title, severity=severity, scanners=scanners, description=desc, recommendation=fix,
            exploitation=("Anyone who can read this code - developers, CI systems, anyone it is shared with - "
                          "can use the credential directly against the service it belongs to."),
            locations=[{"file": l[0], "line": l[1]} for l in locs] if n > 1 else None,
            _in_history=in_history,
            _fp_key=f"secret|{fp if kind != 'gcp_sa' else key}",
        )
        if severity != rep["severity"]:
            g["cvss_score"], g["cvss_source"], g["cvss_vector"] = (
                {"Critical": 9.1, "High": 7.5, "Medium": 5.3, "Low": 3.1}[severity], "estimated", None)
        out.append(g)
    return rest + out


# ---------------------------------------------------------------- dependency grouping

_VTOK = re.compile(r"\d+|[A-Za-z]+")


def vkey(v: str) -> tuple:
    """Sortable version key; pre-release tags (rc, beta...) sort before the release."""
    out = []
    for p in _VTOK.findall(v or ""):
        out.append((1, int(p), "") if p.isdigit() else (0, 0, p.lower()))
    return tuple(out) + ((1, -1, ""),)


def _nums(v: str) -> list[int]:
    return [int(x) for x in re.findall(r"\d+", v or "")]


def _branch(v: str) -> tuple:
    return tuple(_nums(v)[:2])


def split_fixed(fixed: str) -> list[str]:
    return [x.strip() for x in (fixed or "").split(",") if x.strip()]


def fixes_cve(version: str, fixes: list[str]) -> bool:
    """True if `version` contains the fix: it is at or above a fix on its own minor line, or at or
    above every listed fix."""
    if not fixes:
        return False
    if any(_branch(f) == _branch(version) and vkey(version) >= vkey(f) for f in fixes):
        return True
    return all(vkey(version) >= vkey(f) for f in fixes)


def minimum_fix(installed: str, cves: list[list[str]]) -> tuple[str | None, bool]:
    """Smallest version that fixes every CVE that has a fix. Prefers the installed major version
    line (another major can be a different artifact, e.g. jackson 3.x is tools.jackson.core).
    Returns (version, same_major)."""
    with_fix = [c for c in cves if c]
    if not with_fix:
        return None, True
    cands = sorted({v for c in with_fix for v in c if vkey(v) > vkey(installed)}, key=vkey)
    major = _nums(installed)[:1]
    single = len(_nums(installed)) < 2  # date-style versions (org.json 20210307): one line only
    same = [v for v in cands if single or _nums(v)[:1] == major]
    for pool, same_major in ((same, True), (cands, False)):
        for v in pool:
            if all(fixes_cve(v, c) for c in with_fix):
                return v, same_major
    return None, True


# A version as advisories write it: dotted (2.13.4.1) or date-style (20230227).
_VER = r"(?:\d+(?:\.\d+)+(?:[.-]?(?:rc|beta|alpha|m|cr)\d*)?|\d{6,})(?!\.?[A-Za-z0-9])"
_VLIST = _VER + r"(?:\s*(?:,\s*and|,|and|or)\s*" + _VER + r")*"
_BOUND_EXCL = re.compile(r"\b(?:before|prior to|earlier than|lower than|older than|below)\s+(?:versions?\s+|v)?("
                         + _VLIST + ")", re.I)
_BOUND_INCL = re.compile(r"\b(?:through|up to(?: and including)?)\s+(?:versions?\s+|v)?(" + _VLIST + ")"
                         r"|\b(" + _VLIST + r")\s+(?:and|or)\s+(?:earlier|prior|below|older|lower)\b", re.I)


def _bounds(text: str) -> list[tuple[str, bool]]:
    """(version, inclusive) upper bounds of the affected range stated in advisory text."""
    out = []
    for m in _BOUND_EXCL.finditer(text or ""):
        out += [(v, False) for v in re.findall(_VER, m.group(1))]
    for m in _BOUND_INCL.finditer(text or ""):
        out += [(v, True) for v in re.findall(_VER, m.group(1) or m.group(2))]
    return out


def advisory_check(installed: str, fixed: list[str], text: str) -> str | None:
    """A 'Verify' note when the advisory's own data says the installed version may not be affected.
    The finding is never dropped: the scanner's range data can be newer than the advisory text."""
    if fixed and fixes_cve(installed, fixed):
        return (f"advisory data is inconsistent: it lists {', '.join(fixed)} as fixed and {installed} is "
                "already at or above that on its version line. Verify manually.")
    single = len(_nums(installed)) < 2
    mine = [(v, inc) for v, inc in _bounds(text)
            if (len(_nums(v)) < 2) == single and (single or _nums(v)[:1] == _nums(installed)[:1])]
    if mine and all(vkey(installed) > vkey(v) if inc else vkey(installed) >= vkey(v) for v, inc in mine):
        stated = ", ".join(("through " if inc else "before ") + v for v, inc in mine)
        return (f"the advisory text describes affected versions as {stated}; {installed} may be outside "
                "that range. Verify against the vendor advisory.")
    return None


# Artifacts that moved to new coordinates: the old name never gets a fixed release.
# old -> (new coordinates, minimum safe version or None, why)
RELOCATED = {
    "mysql:mysql-connector-java": (
        "com.mysql:mysql-connector-j", "8.2.0",
        "Oracle moved MySQL Connector/J to new Maven coordinates in 8.0.31; the old artifact gets no new "
        "releases, so no fixed version will ever be published under its old name."),
    "org.bouncycastle:bcprov-jdk15on": (
        "org.bouncycastle:bcprov-jdk18on", None,
        "The jdk15on artifacts stopped at 1.70; newer Bouncy Castle releases are published as jdk18on."),
    "log4j:log4j": (
        "org.apache.logging.log4j:log4j-core", None,
        "Log4j 1.x reached end of life in 2015 and gets no fixes; migrate to Log4j 2 (log4j-1.2-api can "
        "bridge existing code)."),
}


def group_deps(findings: list[dict]) -> list[dict]:
    deps = [f for f in findings if f.get("check") == "deps" and f.get("_pkg")]
    if not deps:
        return findings
    rest = [f for f in findings if not (f.get("check") == "deps" and f.get("_pkg"))]
    groups: dict[tuple, list[dict]] = {}
    for f in deps:
        groups.setdefault((f["file_path"], f["_pkg"], f["_installed"]), []).append(f)
    out = []
    for (path, pkg, installed), items in groups.items():
        items.sort(key=lambda x: (SEVERITY_ORDER[x["severity"]], -(x.get("cvss_score") or 0), x.get("rule_id") or ""))
        rep = items[0]
        n = len(items)
        fix, same_major = minimum_fix(installed, [split_fixed(x.get("_fixed")) for x in items])
        unfixed = [x["rule_id"] for x in items if not split_fixed(x.get("_fixed"))]
        verify = {x["rule_id"]: advisory_check(installed, split_fixed(x.get("_fixed")), x.get("_vdesc") or "")
                  for x in items}
        lines = []
        for x in items:
            score = f"CVSS {x['cvss_score']:.1f}" if x.get("cvss_score") is not None else "CVSS n/a"
            lines.append(f"{x['rule_id']}  {x['severity']:<8} {score}  {x.get('_vtitle') or ''}".rstrip()
                         + (f"  (fixed in {x['_fixed']})" if x.get("_fixed") else "  (no fix published)")
                         + ("  [verify]" if verify[x["rule_id"]] else ""))
        title = f"{pkg} {installed}: {n} known vulnerabilit{'y' if n == 1 else 'ies'}"
        if all(verify.values()):
            title += " (verify: may not be affected)"
        desc_lines = [f"{pkg} {installed}, declared in {path}, is affected by {n} publicly known "
                      f"vulnerabilit{'y' if n == 1 else 'ies'}:"]
        for x in items:
            rating = x["severity"]
            if x.get("cvss_score") is not None:
                rating += f", CVSS {x['cvss_score']:.1f}" + (f" {x['_cvss_src']}" if x.get("_cvss_src") else "")
            if x.get("_vendor_sev"):
                rating += f"; vendor rated {x['_vendor_sev']}"
            desc_lines.append(f"- {x['rule_id']} ({rating}): {x.get('_vtitle') or 'see advisory'}"
                              + (f" - {x['_url']}" if x.get("_url") else "")
                              + (f"\n  Verify: {verify[x['rule_id']]}" if verify[x["rule_id"]] else ""))
        if any(x.get("_vendor_sev") for x in items):
            desc_lines.append("\nSeverity follows the CVSS score shown (9.0+ Critical, 7.0+ High, 4.0+ Medium); "
                              "where the vendor's own rating differs it is noted.")
        flagged = sum(1 for v in verify.values() if v)
        if flagged:
            desc_lines.append(f"\n{flagged} of {n} need manual verification (see 'Verify' above). They are kept "
                              "in the report and the totals until confirmed not to apply.")
        if rep.get("_rel") == "direct":
            desc_lines.append(f"\n{pkg} is declared directly in {path}.")
        elif rep.get("_rel") == "indirect":
            via = ", ".join(rep.get("_via") or []) or "another dependency"
            desc_lines.append(f"\n{pkg} is a transitive dependency: it is not declared in {path} but pulled in "
                              f"by {via}.")
        moved = RELOCATED.get(pkg)
        if moved:
            new_pkg, min_v, why = moved
            fix = None
            unfixed = []
            rec = (f"{pkg} has moved: {why} Replace the dependency with {new_pkg} "
                   + (f"{min_v} or later, which fixes the listed vulnerabilit{'y' if n == 1 else 'ies'}."
                      if min_v else "at its latest release, then re-scan to confirm."))
        elif fix:
            rec = (f"Upgrade {pkg} from {installed} to {fix} or later: this one version fixes "
                   + ("all" if not unfixed else f"{n - len(unfixed)} of the")
                   + f" {n} listed vulnerabilit{'y' if n == 1 else 'ies'}.")
            if not same_major:
                rec += (" No fix exists on the installed major version line, so this is a major upgrade: "
                        "check the release notes for breaking changes.")
        else:
            rec = f"No fixed version of {pkg} is published for these vulnerabilities."
        if unfixed:
            rec += (f" No fix is published for {', '.join(unfixed)}: check whether the vulnerable function "
                    "is used, apply vendor mitigations, or replace the package.")
        if rep.get("_rel") == "indirect":
            via = ", ".join(rep.get("_via") or []) or "the dependency that pulls it in"
            rec += (f" It is a transitive dependency (via {via}): first check whether a newer {via} already "
                    f"uses a fixed {pkg}; otherwise pin {pkg}"
                    + (f" {fix}" if fix else "") + " in "
                    + ("<dependencyManagement> in pom.xml" if ecosystem(rep) == "maven" else
                       "a dependency constraint / override" if ecosystem(rep) != "npm" else "`overrides` in package.json")
                    + ".")
        if moved:
            rec += (f" Change the groupId and artifactId (and version) in {path} or the BOM that manages it, "
                    "rebuild and re-run your tests.")
        else:
            rec += " " + ECOSYSTEM_FIX[ecosystem(rep)]
        g = dict(rep)
        g.update(
            title=title,
            snippet="\n".join(lines),
            description="\n".join(desc_lines),
            exploitation=(f"The most severe is {rep['rule_id']}"
                          + (f" ({rep['_vtitle']})" if rep.get("_vtitle") else "") + ". "
                          "Each vulnerability is exploitable only if the application reaches the affected "
                          "code path; see each advisory for the conditions."),
            recommendation=rec,
            rule_id=f"pkg:{pkg}",
            scanners=sorted({s for x in items for s in x.get("scanners") or []}),
            _fp_key=f"deps|{path}|{pkg}",
        )
        out.append(g)
    return rest + out


# ---------------------------------------------------------------- Dockerfile duplicates across tools

_CONCEPTS = [
    ("container-root-user", re.compile(r"^AVD-DS-0002$|missing-user(-entrypoint)?$", re.I),
     "Container runs as root (no non-root USER instruction)"),
    ("csrf-disabled", re.compile(r"^(spring-)?csrf-disabled$", re.I), "CSRF protection disabled in Spring Security"),
]


def merge_concepts(findings: list[dict]) -> list[dict]:
    groups: dict[tuple, list[dict]] = {}
    rest = []
    for f in findings:
        rid = (f.get("rule_id") or "").rsplit(".", 1)[-1] if f.get("check") == "code" else (f.get("rule_id") or "")
        concept = next(((name, title) for name, rx, title in _CONCEPTS if rx.search(rid)), None)
        if concept:
            groups.setdefault((f.get("file_path"), concept), []).append(f)
        else:
            rest.append(f)
    for (path, (name, title)), items in groups.items():
        if len(items) == 1:
            rest.extend(items)
            continue
        items.sort(key=lambda x: (SEVERITY_ORDER[x["severity"]], x.get("line") is None, not x.get("snippet")))
        rep = dict(items[0])
        rep.update(
            title=title,
            line=next((x["line"] for x in items if x.get("line")), None),
            snippet=next((x["snippet"] for x in items if x.get("snippet")), ""),
            scanners=sorted({s for x in items for s in x.get("scanners") or []}),
            description=rep.get("description", "") + "\n\nReported by several rules: "
            + ", ".join(sorted({x.get("rule_id") or "" for x in items})),
            _fp_key=f"concept|{path}|{name}",
        )
        rest.append(rep)
    return rest


def group_findings(findings: list[dict], root: str | None = None) -> list[dict]:
    out = merge_concepts(group_deps(group_secrets(findings, root)))
    out.sort(key=sort_key)
    return out
