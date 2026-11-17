"""Severity corrections for rules whose scanner default does not match their real impact.

Applied after grouping. Every change is written into the finding's description (so the report
explains it) and returned for the scan log. Pure function: no DB, no I/O.
"""
from __future__ import annotations

import re

from .normalize import ESTIMATED_CVSS, SEVERITY_ORDER

# (rule pattern, severity, reason). Matched against the rule ID, or its last dotted part for Semgrep.
OVERRIDES: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"^AVD-DS-0022$"), "Info",
     "MAINTAINER is deprecated Dockerfile syntax with no security impact. Reported for completeness "
     "only and not counted in the totals."),
    (re.compile(r"^AVD-DS-0002$|missing-user(-entrypoint)?$"), "Medium",
     "Running as root is not exploitable by itself. It makes any other flaw worse, because an attacker "
     "who gets code execution in the container gets root there too."),
    (re.compile(r"spel-injection$"), "High",
     "Evaluating a SpEL expression built from input can lead to remote code execution. Raise this to "
     "Critical if the expression can contain request data; lower it if it only uses constants."),
    (re.compile(r"weak-random$"), "Low",
     "java.util.Random is only a problem when its output must be unpredictable. Raise this to High if "
     "it is used for tokens, passwords, session IDs, OTPs or keys."),
]


def _rule_tail(f: dict) -> str:
    rid = f.get("rule_id") or ""
    return rid.rsplit(".", 1)[-1] if f.get("check") == "code" else rid


def apply_policy(findings: list[dict]) -> list[str]:
    """Adjust severities in place; returns one log line per change."""
    log = []
    for f in findings:
        rid = _rule_tail(f)
        rule = next(((sev, why) for rx, sev, why in OVERRIDES if rx.search(rid)), None)
        if not rule or rule[0] == f.get("severity"):
            continue
        new, why = rule
        old = f.get("severity")
        f["severity"] = new
        if f.get("cvss_source") == "estimated":
            f["cvss_score"] = ESTIMATED_CVSS[new]
        note = f"Severity set to {new} (scanner default: {old}). {why}"
        f["description"] = ((f.get("description") or "").rstrip() + "\n\n" + note).strip()
        log.append(f"{f.get('rule_id')} at {f.get('file_path')}: {old} -> {new}")
    return log


assert all(sev in SEVERITY_ORDER for _, sev, _ in OVERRIDES)
