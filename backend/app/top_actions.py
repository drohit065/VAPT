"""'Top actions': at most 10 concrete steps that resolve the most important findings, for the
executive summary. Built in the worker from the grouped findings (structured data such as a
package's fix version is still available there) and stored on the scan with the fingerprints each
action covers, so a report can drop an action once all of its findings are triaged away.
"""
from __future__ import annotations

import re
from collections import Counter

from .normalize import SEVERITY_ORDER

MAX_ACTIONS = 10
SUPPRESSED = {"false_positive", "accepted_risk", "fixed"}

_SECRET_LABEL = {
    "aws_secret": ("AWS secret access key", "AWS secret access keys"),
    "aws_key_id": ("AWS access key ID", "AWS access key IDs"),
    "aws_smtp": ("AWS SES SMTP login", "AWS SES SMTP logins"),
    "private_key": ("private key", "private keys"),
    "gcp_api_key": ("Google API key", "Google API keys"),
    "gcp_sa": ("GCP service account key", "GCP service account keys"),
    "azure_secret": ("Azure AD client secret", "Azure AD client secrets"),
    "openai": ("OpenAI API key", "OpenAI API keys"),
    "anthropic": ("Anthropic API key", "Anthropic API keys"),
    "slack": ("Slack token", "Slack tokens"),
    "github": ("GitHub token", "GitHub tokens"),
    "stripe": ("Stripe key", "Stripe keys"),
    "jwt": ("JSON Web Token", "JSON Web Tokens"),
    "password_hash": ("password hash", "password hashes"),
    "password": ("password", "passwords"),
    "signing_key": ("JWT signing secret", "JWT signing secrets"),
    "api_key": ("API key", "API keys"),
    "token": ("access token", "access tokens"),
    "generic": ("other secret", "other secrets"),
}

# rule id (last dotted part) -> how to phrase the action
_CODE_ACTIONS = [
    (re.compile(r"spel-injection$"), "Stop evaluating SpEL with the full context: use SimpleEvaluationContext or "
                                     "fixed rules"),
    (re.compile(r"cbc-padding-oracle$|(^|[-_.])cbc([-_.]|$)"), "Replace AES-CBC with AES-GCM"),
    (re.compile(r"^AVD-DS-0002$|missing-user(-entrypoint)?$"), "Run the container as a non-root user"),
    (re.compile(r"csrf-disabled$"), "Re-enable CSRF protection (or confirm only header-based auth is used)"),
    (re.compile(r"actuator-exposed$|actuator-security-off$"), "Restrict Spring Boot Actuator endpoints"),
    (re.compile(r"h2-console$"), "Disable the H2 console"),
    (re.compile(r"permit-all-everything$"), "Require authentication by default in Spring Security"),
    (re.compile(r"db-no-tls$"), "Enable TLS for database connections"),
]


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else (many or one + 's')}"


def _files(fs: list[dict], cap: int = 2) -> str:
    names = []
    for f in fs:
        for loc in [{"file": f.get("file_path")}] + list(f.get("locations") or []):
            name = (loc.get("file") or "").rsplit("/", 1)[-1]
            if name and name not in names:
                names.append(name)
    shown = ", ".join(names[:cap])
    return shown + (f" and {len(names) - cap} more file(s)" if len(names) > cap else "")


def _short_pkg(pkg: str) -> str:
    """'com.fasterxml.jackson.core:jackson-databind' -> 'jackson-databind'; keeps the group when the
    artifact name alone says little ('org.json:json')."""
    short = pkg.rsplit(":", 1)[-1] if ":" in pkg else pkg
    return pkg if len(short) <= 5 else short


def _secret_kind(f: dict) -> str:
    if (f.get("title") or "").startswith("Hardcoded AWS access key pair"):
        return "aws_pair"
    if (f.get("title") or "").startswith("Hardcoded AWS SES SMTP"):
        return "aws_smtp"
    kind = f.get("_secret_kind") or "generic"
    return "generic" if kind == "config_secret" else kind


def _secret_actions(fs: list[dict]) -> list[tuple]:
    out = []
    tiers = [("Critical",), ("High",), ("Medium",), ("Low",)]
    for tier in tiers:
        items = [f for f in fs if f["severity"] in tier]
        if not items:
            continue
        kinds = Counter(_secret_kind(f) for f in items)
        parts = []
        for kind, n in sorted(kinds.items(), key=lambda kv: (-kv[1], kv[0])):
            if kind == "aws_pair":
                parts.append(_plural(n, "AWS access key pair"))
            else:
                one, many = _SECRET_LABEL.get(kind, _SECRET_LABEL["generic"])
                parts.append(_plural(n, one, many))
        n = len(items)
        sev = min((f["severity"] for f in items), key=SEVERITY_ORDER.get)
        lead = (f"Rotate {_plural(n, 'exposed credential')}" if tier[0] != "Low" else
                f"Change {_plural(n, 'credential')} in test configuration")
        text = (f"{lead} ({', '.join(parts)}) and load {'it' if n == 1 else 'them'} from a secrets manager or "
                "environment variables")
        out.append((sev, 0, -n, text, items))
    return out


def _dep_action(f: dict) -> tuple:
    pkg = (f.get("rule_id") or "").removeprefix("pkg:") or f.get("title")
    n = f.get("_cve_count") or 1
    cves = _plural(n, "CVE")
    moved = f.get("_moved_to")
    fix = f.get("_fix_version")
    if moved:
        text = f"Replace {pkg} with {moved[0]}" + (f" {moved[1]} or later" if moved[1] else "") + f" (fixes {cves})"
    elif fix:
        text = f"Upgrade {_short_pkg(pkg)} to {fix} (fixes {cves if f.get('_fixes_all') else 'some of ' + cves})"
    else:
        text = f"Mitigate or replace {_short_pkg(pkg)}: no fixed version is published ({cves})"
    if f.get("_major_upgrade"):
        text += " (major version upgrade: check for breaking changes)"
    if "(verify: may not be affected)" in (f.get("title") or ""):
        text += " after verifying the advisories apply"
    return (f["severity"], 1, -n, text, [f])


BOOT = "org.springframework.boot:"


def _boot_managed(f: dict) -> bool:
    """A vulnerable library whose version comes from Spring Boot (a Boot artifact, or pulled in
    through a Boot starter, whose dependency management sets the version)."""
    pkg = (f.get("rule_id") or "").removeprefix("pkg:")
    return pkg.startswith(BOOT) or any(v.startswith(BOOT) for v in f.get("_via") or [])


def _boot_action(fs: list[dict]) -> tuple:
    """One 'upgrade Spring Boot' step instead of a separate step per library it manages."""
    version = next((f.get("_installed") for f in fs if (f.get("rule_id") or "").startswith("pkg:" + BOOT)
                    and f.get("_installed")), None)
    fs = sorted(fs, key=lambda f: (SEVERITY_ORDER[f["severity"]], -(f.get("_cve_count") or 0)))
    cves = sum(f.get("_cve_count") or 0 for f in fs)
    names = list(dict.fromkeys(_short_pkg((f.get("rule_id") or "").removeprefix("pkg:")) for f in fs))
    shown = ", ".join(names[:3]) + (f" and {len(names) - 3} more" if len(names) > 3 else "")
    line = f"{version.split('.')[0]}.x " if version and version[:1].isdigit() else ""
    text = (f"Upgrade Spring Boot{' from ' + version if version else ''} to its latest {line}release: it sets "
            f"the versions of {len(fs)} vulnerable libraries ({shown}; {cves} CVEs). Re-scan afterwards and pin "
            "any library that is still flagged")
    if any(f.get("_major_upgrade") for f in fs):
        text += "; some fixes exist only in a newer major version"
    return (fs[0]["severity"], 1, -cves, text, fs)


def _code_actions(fs: list[dict]) -> list[tuple]:
    groups: dict[str, list[dict]] = {}
    for f in fs:
        tail = (f.get("rule_id") or "").rsplit(".", 1)[-1] if f.get("check") == "code" else (f.get("rule_id") or "")
        phrase = next((p for rx, p in _CODE_ACTIONS if rx.search(tail)), None) or f"Fix: {f['title']}"
        groups.setdefault(phrase, []).append(f)
    out = []
    for phrase, items in groups.items():
        sev = min((f["severity"] for f in items), key=SEVERITY_ORDER.get)
        n = len(items)
        where = _files(items)
        if n > 1:
            text = f"{phrase} ({n} places" + (f" in {where})" if where else ")")
        else:
            text = phrase + (f" in {where}" if where else "")
        out.append((sev, 2, -n, text, items))
    return out


def build_top_actions(findings: list[dict], limit: int = MAX_ACTIONS) -> list[dict]:
    """[{"severity", "text", "fingerprints"}] for open findings, most important first."""
    open_fs = [f for f in findings if f.get("status", "open") not in SUPPRESSED and f.get("severity") != "Info"]
    candidates = _secret_actions([f for f in open_fs if f.get("check") == "secrets"])
    deps = [f for f in open_fs if f.get("check") == "deps" and f.get("_cve_count")]
    boot = [f for f in deps if _boot_managed(f)]
    if len(boot) >= 2:
        candidates.append(_boot_action(boot))
        deps = [f for f in deps if f not in boot]
    candidates += [_dep_action(f) for f in deps]
    candidates += _code_actions([f for f in open_fs if f.get("check") not in ("secrets", "deps")
                                 or (f.get("check") == "deps" and not f.get("_cve_count"))])
    candidates.sort(key=lambda c: (SEVERITY_ORDER[c[0]], c[1], c[2]))
    return [{"severity": sev, "text": text, "fingerprints": [f.get("fingerprint") for f in items]}
            for sev, _, _, text, items in candidates[:limit]]


def current_actions(actions: list[dict] | None, status_by_fp: dict[str, str]) -> list[dict]:
    """Stored actions minus those whose findings have all been triaged away since the scan."""
    keep = []
    for a in actions or []:
        fps = [fp for fp in a.get("fingerprints") or [] if fp]
        if fps and all(status_by_fp.get(fp) in SUPPRESSED for fp in fps):
            continue
        keep.append(a)
    return keep
