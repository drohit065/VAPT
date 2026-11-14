"""Finding management: fingerprints, status carry-over between scans and scan-to-scan comparison."""
from __future__ import annotations

import hashlib
import re

from .normalize import SEVERITY_ORDER

STATUSES = {
    "open": "Open",
    "false_positive": "False positive",
    "accepted_risk": "Accepted risk",
    "fixed": "Fixed",
}
# Statuses a user sets that should stick to the same issue in later scans.
STICKY = {"false_positive", "accepted_risk"}
# Statuses excluded from risk counts.
SUPPRESSED = {"false_positive", "accepted_risk", "fixed"}

_LINE_PREFIX = re.compile(r"^\s*\d+\s*\|\s?")
_DIGITS = re.compile(r"\d+")


def _code_line(snippet: str, line: int | None) -> str:
    """The flagged source line from a numbered snippet, whitespace-normalised."""
    for raw in (snippet or "").splitlines():
        m = re.match(r"^\s*(\d+)\s*\|", raw)
        if m and line and int(m.group(1)) == line:
            return " ".join(_LINE_PREFIX.sub("", raw).split())
    return ""


def fingerprint(f: dict) -> str:
    """Stable identity of an issue across scans. Line numbers are left out (code moves);
    for code findings the flagged source line is used instead."""
    check = f.get("check") or ""
    rule = (f.get("rule_id") or "").lower()
    path = f.get("file_path") or ""
    if check == "code":
        extra = _code_line(f.get("snippet") or "", f.get("line")) or str(f.get("line") or "")
    elif check == "deps":
        # "CVE-X in pkg 1.2.3: title" -> package name, so an upgrade that stays vulnerable still matches
        m = re.match(r"\S+ in (\S+)", f.get("title") or "")
        extra = m.group(1) if m else ""
    elif check == "secrets":
        extra = str(f.get("line") or "")
    else:
        extra = _DIGITS.sub("#", (f.get("title") or "").lower())
    raw = "|".join([check, rule, path, extra])
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()


def open_counts(findings) -> dict:
    """Severity counts of findings that still need attention (attribute or dict access)."""
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        status = f["status"] if isinstance(f, dict) else f.status
        sev = f["severity"] if isinstance(f, dict) else f.severity
        if status not in SUPPRESSED:
            counts[sev] = counts.get(sev, 0) + 1
    return counts


def apply_history(final: list[dict], previous: list) -> dict:
    """Set fingerprint / status / is_new on each new finding dict using the previous completed
    scan's findings (ORM objects or dicts) and return the diff summary."""
    prev_by_fp = {}
    for p in previous:
        fp = p["fingerprint"] if isinstance(p, dict) else p.fingerprint
        if fp:
            prev_by_fp[fp] = p

    def get(p, k):
        return p[k] if isinstance(p, dict) else getattr(p, k)

    current = set()
    for f in final:
        fp = fingerprint(f)
        f["fingerprint"] = fp
        current.add(fp)
        p = prev_by_fp.get(fp)
        f["is_new"] = p is None
        f["status"] = "open"
        f["status_note"] = None
        if p is not None:
            st = get(p, "status")
            if st in STICKY:
                f["status"] = st
                f["status_note"] = get(p, "status_note")
            elif st == "fixed":
                f["status_note"] = "Marked fixed in an earlier scan but found again."
    fixed = [p for fp, p in prev_by_fp.items() if fp not in current and get(p, "status") not in STICKY]
    fixed.sort(key=lambda p: SEVERITY_ORDER.get(get(p, "severity"), 9))
    return {
        "new": sum(1 for f in final if f["is_new"]),
        "recurring": sum(1 for f in final if not f["is_new"]),
        "fixed": len(fixed),
        "fixed_items": [{"severity": get(p, "severity"), "title": get(p, "title"),
                         "file_path": get(p, "file_path"), "line": get(p, "line")} for p in fixed[:200]],
    }
