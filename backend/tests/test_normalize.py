"""Tests for the finding normaliser (scanner output -> one format, de-duplicated)."""
import os

import pytest

from app.normalize import (
    count_by_severity,
    dedupe,
    mask_assignments,
    parse_gitleaks,
    parse_semgrep,
    parse_trivy_config,
    parse_trivy_vulns,
    read_snippet,
    redact_findings,
    rel_path,
    secret_values,
)

REQUIRED = {"severity", "title", "file_path", "line", "snippet", "description", "exploitation",
            "recommendation", "cwe", "owasp", "scanners", "rule_id", "check"}


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "app.py").write_text(
        "import os\n"
        "def run(cmd):\n"
        "    os.system('ping ' + cmd)\n"
        "    return True\n"
    )
    (tmp_path / ".env").write_text("X=1\n")
    return tmp_path


def semgrep_result(root, line=3, severity="ERROR", cwe="CWE-78: OS Command Injection", **meta):
    return {
        "check_id": "python.lang.security.dangerous-system-call",
        "path": os.path.join(str(root), "app.py"),
        "start": {"line": line}, "end": {"line": line},
        "extra": {
            "message": "User data reaches os.system",
            "severity": severity,
            "metadata": {"cwe": [cwe], "owasp": ["A01:2017 - Injection", "A03:2021 - Injection"], **meta},
        },
    }


# ---------------------------------------------------------------- Semgrep

def test_semgrep_maps_all_fields(repo):
    [f] = parse_semgrep({"results": [semgrep_result(repo)]}, str(repo))
    assert REQUIRED <= f.keys()
    assert f["severity"] == "High"
    assert f["file_path"] == "app.py"
    assert f["line"] == 3
    assert "os.system('ping ' + cmd)" in f["snippet"]
    assert f["cwe"].startswith("CWE-78")
    assert f["owasp"] == "A03:2021 - Injection"
    assert f["scanners"] == ["semgrep"]
    assert f["check"] == "code"
    assert "shell" in f["exploitation"].lower()
    assert f["recommendation"]


@pytest.mark.parametrize("sev,meta,expected", [
    ("ERROR", {"impact": "HIGH", "likelihood": "HIGH"}, "Critical"),
    ("ERROR", {}, "High"),
    ("WARNING", {}, "Medium"),
    ("INFO", {}, "Low"),
    ("CRITICAL", {}, "Critical"),
])
def test_semgrep_severity(repo, sev, meta, expected):
    [f] = parse_semgrep({"results": [semgrep_result(repo, severity=sev, **meta)]}, str(repo))
    assert f["severity"] == expected


def test_semgrep_fix_is_text_only(repo):
    r = semgrep_result(repo)
    r["extra"]["fix"] = "subprocess.run(['ping', cmd])"
    [f] = parse_semgrep({"results": [r]}, str(repo))
    assert "not applied automatically" in f["recommendation"]
    # the source file is untouched
    assert "os.system('ping ' + cmd)" in (repo / "app.py").read_text()


def test_empty_inputs():
    assert parse_semgrep({}) == []
    assert parse_semgrep(None) == []
    assert parse_trivy_vulns({"Results": None}) == []
    assert parse_trivy_config({}) == []
    assert parse_gitleaks([]) == []


# ---------------------------------------------------------------- Trivy

def test_trivy_vuln():
    data = {"Results": [{"Target": "package-lock.json", "Vulnerabilities": [{
        "VulnerabilityID": "CVE-2019-10744", "PkgName": "lodash", "InstalledVersion": "4.17.4",
        "FixedVersion": "4.17.12", "Severity": "CRITICAL", "Title": "prototype pollution",
        "Description": "desc", "CweIDs": ["CWE-1321"], "PrimaryURL": "https://example.test/cve",
    }]}]}
    [f] = parse_trivy_vulns(data)
    assert f["severity"] == "Critical"
    assert f["check"] == "deps"
    assert f["file_path"] == "package-lock.json"
    assert "4.17.12" in f["recommendation"]
    assert f["owasp"].startswith("A06:2021")
    assert f["rule_id"] == "CVE-2019-10744"
    assert f["cwe"] == "CWE-1321"


def test_trivy_unknown_severity_and_no_fix():
    data = {"Results": [{"Target": "requirements.txt", "Vulnerabilities": [{
        "VulnerabilityID": "GHSA-x", "PkgName": "foo", "InstalledVersion": "1.0", "Severity": "UNKNOWN"}]}]}
    [f] = parse_trivy_vulns(data)
    assert f["severity"] == "Low"
    assert "No fixed version" in f["recommendation"]


def test_trivy_config_only_failures(repo):
    data = {"Results": [{"Target": "Dockerfile", "Misconfigurations": [
        {"ID": "DS002", "AVDID": "AVD-DS-0002", "Title": "Image user should not be root",
         "Severity": "HIGH", "Status": "FAIL", "Resolution": "Add USER",
         "CauseMetadata": {"StartLine": 1, "EndLine": 1, "Code": {"Lines": [{"Number": 1, "Content": "FROM x"}]}}},
        {"ID": "DS001", "Title": "ok", "Severity": "LOW", "Status": "PASS"},
    ]}]}
    [f] = parse_trivy_config(data, str(repo))
    assert f["severity"] == "High"
    assert f["check"] == "iac"
    assert f["recommendation"] == "Add USER"
    assert f["snippet"] == "1 | FROM x"
    assert f["owasp"].startswith("A05:2021")


# ---------------------------------------------------------------- Gitleaks & redaction

GITLEAKS = [{
    "RuleID": "aws-access-token", "Description": "AWS key", "File": "config.py", "StartLine": 4,
    "Match": "KEY = 'AKIAZZZZZZZZZZZZZZZZ'", "Secret": "AKIAZZZZZZZZZZZZZZZZ",
    "Commit": "abcdef1234567890", "Date": "2024-01-02T00:00:00Z",
}]


def test_gitleaks_never_contains_secret():
    [f] = parse_gitleaks(GITLEAKS)
    blob = repr(f)
    assert "AKIAZZZZZZZZZZZZZZZZ" not in blob
    assert "REDACTED" in f["snippet"]
    assert f["severity"] == "Critical"  # cloud key
    assert f["cwe"].startswith("CWE-798")
    assert "abcdef123456" in f["description"]


def test_generic_secret_is_high():
    [f] = parse_gitleaks([{**GITLEAKS[0], "RuleID": "generic-api-key"}])
    assert f["severity"] == "High"


def test_secret_redacted_from_other_scanners():
    secrets = secret_values(GITLEAKS)
    other = {"snippet": "4 | KEY = 'AKIAZZZZZZZZZZZZZZZZ'", "description": "x AKIAZZZZZZZZZZZZZZZZ",
             "title": "t", "recommendation": "r"}
    redact_findings([other], secrets)
    assert "AKIAZZZZZZZZZZZZZZZZ" not in repr(other)


@pytest.mark.parametrize("text,leaked", [
    ('ENV DB_PASSWORD=Sup3rS3cret!', "Sup3rS3cret!"),
    ('API_KEY = "abcd1234efgh"', "abcd1234efgh"),
    ('"client_secret": "xyz98765"', "xyz98765"),
    ("postgresql://app:hunter22@db:5432/x", "hunter22"),
])
def test_mask_assignments(text, leaked):
    assert leaked not in mask_assignments(text)
    assert "REDACTED" in mask_assignments(text)


def test_mask_keeps_code_readable():
    code = 'password = request.form["password"]'
    assert mask_assignments(code) == code


# ---------------------------------------------------------------- de-duplication

def test_dedupe_merges_same_location_and_cwe(repo):
    a = parse_semgrep({"results": [semgrep_result(repo, severity="WARNING")]}, str(repo))[0]
    b = parse_semgrep({"results": [semgrep_result(repo, severity="ERROR")]}, str(repo))[0]
    b["scanners"] = ["other"]
    [m] = dedupe([a, b])
    assert m["severity"] == "High"  # keeps the most severe
    assert set(m["scanners"]) == {"semgrep", "other"}


def test_dedupe_keeps_different_lines(repo):
    a = parse_semgrep({"results": [semgrep_result(repo, line=3)]}, str(repo))[0]
    b = parse_semgrep({"results": [semgrep_result(repo, line=4)]}, str(repo))[0]
    assert len(dedupe([a, b])) == 2


def test_dedupe_secret_across_commits():
    leaks = [dict(GITLEAKS[0], Commit=c) for c in ("1111111111111", "2222222222222", "3333333333333")]
    [m] = dedupe(parse_gitleaks(leaks))
    assert "3 commits" in m["description"]


def test_dedupe_sorted_by_severity(repo):
    low = parse_semgrep({"results": [semgrep_result(repo, line=1, severity="INFO")]}, str(repo))[0]
    crit = parse_gitleaks(GITLEAKS)[0]
    out = dedupe([low, crit])
    assert [f["severity"] for f in out] == ["Critical", "Low"]
    assert count_by_severity(out) == {"Critical": 1, "High": 0, "Medium": 0, "Low": 1}


# ---------------------------------------------------------------- path safety

def test_read_snippet_refuses_escape(repo, tmp_path_factory):
    outside = tmp_path_factory.mktemp("outside") / "secret.txt"
    outside.write_text("TOP SECRET\n")
    (repo / "link.txt").symlink_to(outside)
    assert read_snippet(str(repo), "../" + outside.name, 1) == ""
    assert read_snippet(str(repo), "link.txt", 1) == ""
    assert "os.system" in read_snippet(str(repo), "app.py", 3)


def test_rel_path_keeps_dotfiles():
    assert rel_path("/tmp/x/.env", "/tmp/x") == ".env"
    assert rel_path("./.github/workflows/ci.yml", None) == ".github/workflows/ci.yml"
