"""Tests for ticket text and ticketing configuration validation."""
import pytest

from app.normalize import make_finding
from app.security import ValidationError
from app.ticketing import DEFAULTS, ticket_text, validate_config


def test_ticket_text():
    f = make_finding(severity="High", title="SQL injection", file_path="api/users.py", line=42,
                     snippet="42 | cur.execute(q + uid)", description="Query built from input.",
                     check="code", scanner="semgrep", rule_id="python.sqli", cwe="CWE-89")
    f["fingerprint"] = "abc123"
    title, body = ticket_text(f, "shop-api", 9, "https://vapt.example.com")
    assert title == "[VAPT][High] SQL injection (api/users.py:42)"
    assert "CVSS 7.5" in body and "https://vapt.example.com/scans/9/report" in body
    assert "cur.execute(q + uid)" in body and "abc123" in body and "Recommended fix" in body
    long = dict(f, title="x" * 400)
    assert len(ticket_text(long, "p", 1, "")[0]) <= 250


@pytest.mark.parametrize("cfg", [
    {"provider": "jira", "jira_url": "http://jira.example.com", "jira_email": "a@b.c", "jira_project": "SEC"},
    {"provider": "jira", "jira_url": "https://x.atlassian.net", "jira_email": "a@b.c", "jira_project": "sec lower"},
    {"provider": "jira", "jira_url": "https://x.atlassian.net", "jira_email": "", "jira_project": "SEC"},
    {"provider": "github", "github_repo": "not a repo"},
    {"provider": "gitlab"},
])
def test_invalid_configs(cfg):
    with pytest.raises(ValidationError):
        validate_config({**DEFAULTS, **cfg})


def test_valid_configs():
    validate_config({**DEFAULTS, "provider": "jira", "jira_url": "https://acme.atlassian.net",
                     "jira_email": "sec@acme.com", "jira_project": "SEC"})
    validate_config({**DEFAULTS, "provider": "github", "github_repo": "drohit065/VAPT"})
    validate_config({**DEFAULTS})
