"""Smoke tests for the PDF report."""
from datetime import datetime, timezone

from app.pdf_report import build_pdf, severity_bar


def _scan(counts):
    return {
        "id": 7, "project": {"name": "demo <app>", "source": "https://example.com/org/demo"},
        "branch": "main", "commit_sha": "0123456789abcdef", "started_at": datetime.now(timezone.utc),
        "finished_at": datetime.now(timezone.utc), "languages": [{"name": "Python", "files": 3}],
        "frameworks": ["Flask"], "counts": counts, "checks": {"code": True, "secrets": True},
        "notes": ["Semgrep finished with warnings"], "ai_summary": None,
    }


def _finding(sev, title):
    return {
        "severity": sev, "title": title, "file_path": "app.py", "line": 12,
        "snippet": "12 | cur.execute(\"SELECT * FROM users WHERE id=\" + uid)  # " + "x" * 250,
        "description": "SQL built from user input & <tags>", "exploitation": "' OR 1=1 --",
        "recommendation": "Use parameterised queries.", "cwe": "CWE-89", "owasp": "A03:2021 - Injection",
        "scanners": ["semgrep"], "rule_id": "python.sqli", "check": "code",
        "ai_verdict": None, "ai_notes": None,
    }


def test_pdf_with_findings_is_a_pdf():
    findings = [_finding("Critical", "SQL injection"), _finding("Low", "Debug enabled")]
    pdf = build_pdf(_scan({"Critical": 1, "High": 0, "Medium": 0, "Low": 1}), findings)
    assert pdf.startswith(b"%PDF")
    assert len(pdf) > 2000


def test_pdf_without_findings():
    pdf = build_pdf(_scan({}), [])
    assert pdf.startswith(b"%PDF")


def test_severity_bar_skips_empty_counts():
    assert severity_bar({}, 100) is None
    bar = severity_bar({"Critical": 2, "Low": 8}, 100)
    assert len(bar._colWidths) == 2
    assert abs(sum(bar._colWidths) - 100) < 0.01
