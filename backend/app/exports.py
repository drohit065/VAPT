"""CSV and SARIF 2.1.0 exports of a scan's findings."""
from __future__ import annotations

import csv
import io

from .findings_mgmt import STATUSES

CSV_FIELDS = ["severity", "cvss_score", "cvss_source", "status", "is_new", "title", "file_path", "line",
              "check", "scanners", "rule_id", "cwe", "owasp", "description", "exploitation",
              "recommendation", "status_note", "fingerprint"]
SARIF_LEVEL = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note"}


def _cell(value) -> str:
    if isinstance(value, list):
        value = ", ".join(map(str, value))
    text = "" if value is None else str(value)
    # Spreadsheet formula injection: neutralise cells that a spreadsheet would evaluate.
    if text[:1] in ("=", "+", "-", "@", "\t", "\r"):
        text = "'" + text
    return text


def to_csv(findings: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_FIELDS)
    for f in findings:
        row = dict(f, status=STATUSES.get(f.get("status"), f.get("status")))
        w.writerow([_cell(row.get(k)) for k in CSV_FIELDS])
    return buf.getvalue()


def to_sarif(scan: dict, findings: list[dict]) -> dict:
    rules: dict[str, dict] = {}
    results = []
    is_url = scan["project"]["source_type"] == "url"
    for f in findings:
        rid = f.get("rule_id") or f["title"]
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": f["title"][:200],
                "shortDescription": {"text": f["title"][:500]},
                "fullDescription": {"text": (f.get("description") or f["title"])[:4000]},
                "help": {"text": (f.get("recommendation") or "")[:4000]},
                "properties": {
                    "tags": [t for t in (f.get("cwe"), f.get("owasp"), f.get("check")) if t],
                    "security-severity": str(f.get("cvss_score") or ""),
                },
            }
        if is_url:
            location = {"physicalLocation": {"artifactLocation": {"uri": f["file_path"]}}}
        else:
            region = {"startLine": f["line"]} if f.get("line") else {}
            location = {"physicalLocation": {"artifactLocation": {"uri": f["file_path"],
                                                                   "uriBaseId": "SRCROOT"}, **({"region": region} if region else {})}}
        result = {
            "ruleId": rid,
            "level": SARIF_LEVEL.get(f["severity"], "note"),
            "message": {"text": f"{f['title']}\n\n{f.get('description') or ''}"[:4000]},
            "locations": [location],
            "partialFingerprints": {"vaptFingerprint/v1": f.get("fingerprint") or ""},
            "properties": {"severity": f["severity"], "status": f.get("status"), "scanners": f.get("scanners")},
        }
        if f.get("status") in ("false_positive", "accepted_risk"):
            result["suppressions"] = [{"kind": "external", "status": "accepted",
                                       "justification": f.get("status_note") or STATUSES[f["status"]]}]
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "VAPT Scanner", "informationUri": "https://github.com/drohit065/VAPT",
                                "rules": list(rules.values())}},
            "results": results,
        }],
    }
