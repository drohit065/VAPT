"""Phase 5: report presentation and hygiene."""
import hashlib
import hmac
from datetime import datetime, timezone

from app import secret_display
from app.findings_mgmt import apply_history, vuln_ids
from app.grouping import group_findings, secret_features
from app.normalize import (_gitleaks_snippet, clean_vuln_title, mask_secret_snippet, parse_trivy_vulns,
                           redact_findings)
from app.pdf_report import _changes_section, _count_text, build_pdf
from app.top_actions import build_top_actions, current_actions


# ---------------------------------------------------------------- fingerprints

def test_fingerprint_is_keyed_hmac_truncated_to_8_hex(monkeypatch):
    value = "super-secret-value-123"
    fp = secret_display.fingerprint(value)
    assert fp.startswith("fp:") and len(fp) == 11 and int(fp[3:], 16) >= 0
    assert fp[3:] != hashlib.sha256(value.encode()).hexdigest()[:8]  # never an unsalted hash
    key = secret_display._fp_key()
    assert fp[3:] == hmac.new(key, value.encode(), hashlib.sha256).hexdigest()[:8]


def test_fingerprint_differs_per_installation_key(monkeypatch):
    class S:
        token_encryption_key = "install-A-key"
    monkeypatch.setattr(secret_display, "get_settings", lambda: S)
    a = secret_display.fingerprint("same-value-for-both")
    S.token_encryption_key = "install-B-key"
    b = secret_display.fingerprint("same-value-for-both")
    assert a != b
    S.token_encryption_key = ""  # unconfigured: random per-process key, still keyed
    c = secret_display.fingerprint("same-value-for-both")
    assert c not in (a, b) and c == secret_display.fingerprint("same-value-for-both")


# ---------------------------------------------------------------- masking: keys kept, values hidden

def test_yaml_keys_never_masked():
    text = ("6 | SECURITY_ADMIN_PASSWORD: '************ fp:c9fcc6dc'\n"
            "7 | AWS_S3_SECRET_ACCESS_KEY_FOR_REPORTS: 'q9Wz3Xv7Bn2Mk5Lp8Rt4Yu6Io1Pa0Sd3Fg5Hj7Kl'\n"
            "8 |   spring.datasource.hikari.connection-password: Zx9Qw8Er7Ty6Ui5Op4As3Df")
    out = mask_secret_snippet(text, "generic-api-key")
    assert "SECURITY_ADMIN_PASSWORD:" in out
    assert "AWS_S3_SECRET_ACCESS_KEY_FOR_REPORTS:" in out and "q9Wz3Xv7Bn2Mk5Lp8Rt4" not in out
    assert "spring.datasource.hikari.connection-password:" in out and "Zx9Qw8Er7Ty6" not in out


def test_long_identifiers_in_code_are_not_masked():
    out = mask_secret_snippet('12 | String v = props.getAwsSecretAccessKeyValue(AWS_SECRET_ACCESS_KEY_NAME);',
                              "detected-aws-secret")
    assert "getAwsSecretAccessKeyValue" in out and "AWS_SECRET_ACCESS_KEY_NAME" in out


def test_gitleaks_snippet_is_the_real_line(tmp_path):
    secret = "3f2b9c1d-7e4a-4b8f-9c2d-1a6e5f7b8c9d"
    (tmp_path / "application-secrets.yml").write_text(f"# x\nVIRUS_SCAN_API_KEY: '{secret}'\n")
    g = {"StartLine": 2, "EndLine": 2, "Secret": secret, "Match": f"IRUS_SCAN_API_KEY: '{secret}'"}
    snip = _gitleaks_snippet(g, "application-secrets.yml", str(tmp_path), {secret: "3f2b****8c9d fp:x"})
    assert snip == "2 | VIRUS_SCAN_API_KEY: '3f2b****8c9d fp:x'"
    # history finding whose value is no longer in the current file: the match is used
    g2 = {"StartLine": 2, "Secret": "gone-value-xyz", "Match": "KEY: 'gone-value-xyz'", "Commit": "abc"}
    assert _gitleaks_snippet(g2, "application-secrets.yml", str(tmp_path), {"gone-value-xyz": "****"}) == \
        "2 | KEY: '****'"


def test_password_length_not_printed_anywhere():
    f = {"check": "secrets", "rule_id": "vapt-config-password", "severity": "High", "title": "t",
         "snippet": "3 | password: Adminpw1@123", "description": "", "recommendation": "", "file_path": "a.yml",
         "line": 3, "scanners": ["vapt"]}
    redact_findings([f], {"Adminpw1@123": secret_display.display("Adminpw1@123", rule_id="password")})
    assert "Adminpw1" not in f["snippet"] and "chars" not in f["snippet"] and "password:" in f["snippet"]


# ---------------------------------------------------------------- titles

def test_repeated_prefixes_stripped_from_vulnerability_titles():
    assert clean_vuln_title("jettison: jettison: memory exhaustion") == "jettison: memory exhaustion"
    assert clean_vuln_title("pkg: pkg: pkg: x") == "pkg: x"
    assert clean_vuln_title("jackson-databind: deep nesting") == "jackson-databind: deep nesting"
    raw = parse_trivy_vulns({"Results": [{"Target": "pom.xml", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-1", "PkgName": "a:jettison", "InstalledVersion": "1.4", "FixedVersion": "1.5",
         "Severity": "HIGH", "Title": "jettison: jettison: memory exhaustion"}]}]})
    assert raw[0]["title"] == "CVE-1 in a:jettison 1.4: jettison: memory exhaustion"


# ---------------------------------------------------------------- top actions

def _dep(pkg, sev, n, fix, fp, **kw):
    return {"check": "deps", "severity": sev, "rule_id": f"pkg:{pkg}", "title": f"{pkg} 1.0: {n} vulns",
            "file_path": "pom.xml", "_cve_count": n, "_fix_version": fix, "_fixes_all": bool(fix),
            "fingerprint": fp, "status": "open", **kw}


def test_top_actions_are_concrete_and_ordered():
    fs = [
        {"check": "secrets", "severity": "Critical", "title": "Hardcoded AWS access key pair (key ID fp:1, secret fp:2)",
         "_secret_kind": "aws_secret", "fingerprint": "s1", "status": "open", "file_path": "a.yml"},
        {"check": "secrets", "severity": "Critical", "title": "Hardcoded OpenAI API key (fp:3)",
         "_secret_kind": "openai", "fingerprint": "s2", "status": "open", "file_path": "a.yml"},
        {"check": "secrets", "severity": "High", "title": "Hardcoded password (fp:4)", "_secret_kind": "password",
         "fingerprint": "s3", "status": "open", "file_path": "a.yml"},
        {"check": "secrets", "severity": "Low", "title": "Hardcoded password (fp:5)", "_secret_kind": "password",
         "fingerprint": "s4", "status": "open", "file_path": "src/test/resources/application-test.yml"},
        _dep("com.fasterxml.jackson.core:jackson-databind", "High", 11, "2.18.11", "d1"),
        _dep("mysql:mysql-connector-java", "High", 1, None, "d2",
             _moved_to=("com.mysql:mysql-connector-j", "8.2.0")),
        {"check": "code", "severity": "High", "title": "Spel injection", "fingerprint": "c1", "status": "open",
         "rule_id": "java.spring.security.audit.spel-injection.spel-injection", "file_path": "src/A.java"},
        {"check": "code", "severity": "High", "title": "Spel injection", "fingerprint": "c2", "status": "open",
         "rule_id": "java.spring.security.audit.spel-injection.spel-injection", "file_path": "src/B.java"},
        {"check": "iac", "severity": "Info", "title": "Deprecated MAINTAINER", "fingerprint": "i1", "status": "open",
         "rule_id": "AVD-DS-0022", "file_path": "Dockerfile"},
        {"check": "code", "severity": "Medium", "title": "x", "fingerprint": "fpx", "status": "false_positive",
         "rule_id": "r", "file_path": "x"},
    ]
    actions = build_top_actions(fs)
    texts = [a["text"] for a in actions]
    assert texts[0] == ("Rotate 2 exposed credentials (1 AWS access key pair, 1 OpenAI API key) "
                        "and load them from a secrets manager or environment variables")
    assert texts[1] == ("Rotate 1 exposed credential (1 password) and load it from a secrets manager or "
                        "environment variables")
    assert "Upgrade jackson-databind to 2.18.11 (fixes 11 CVEs)" in texts
    assert "Replace mysql:mysql-connector-java with com.mysql:mysql-connector-j 8.2.0 or later (fixes 1 CVE)" in texts
    assert any(t.startswith("Stop evaluating SpEL") and "(2 places in A.java, B.java)" in t for t in texts)
    assert texts[-1].startswith("Change 1 credential in test configuration")
    assert not any("MAINTAINER" in t or t.endswith(": x") for t in texts)  # Info and triaged left out
    assert len(build_top_actions(fs * 5)) <= 10


def test_triaged_actions_dropped_at_render():
    actions = [{"severity": "High", "text": "a", "fingerprints": ["f1", "f2"]},
               {"severity": "High", "text": "b", "fingerprints": ["f3"]}]
    keep = current_actions(actions, {"f1": "false_positive", "f2": "open", "f3": "accepted_risk"})
    assert [a["text"] for a in keep] == ["a"]


# ---------------------------------------------------------------- changes since the previous scan

def test_changes_lists_new_fixed_still_open_and_cve_level():
    prev = [{"fingerprint": None, "severity": "High", "title": "old", "file_path": "x", "line": 1,
             "status": "open", "snippet": ""}]
    cur = [{"check": "deps", "severity": "High", "title": "pkg 1.0", "rule_id": "pkg:g:a", "file_path": "pom.xml",
            "_fp_key": "deps|pom.xml|g:a", "line": None, "snippet": "CVE-2024-1  High ...\nCVE-2024-3  Medium ..."},
           {"check": "code", "severity": "Low", "title": "new one", "rule_id": "r", "file_path": "b.py",
            "_fp_key": "concept|b.py|z", "line": 3, "snippet": ""}]
    from app.findings_mgmt import fingerprint
    prev = [{**prev[0], "fingerprint": "gone"},
            {"fingerprint": fingerprint(cur[0]), "severity": "High", "title": "pkg 1.0", "file_path": "pom.xml",
             "line": None, "status": "open", "snippet": "CVE-2024-1  High ...\nCVE-2024-2  High ..."}]
    diff = apply_history(cur, prev)
    assert diff["new"] == 1 and diff["fixed"] == 1 and diff["recurring"] == 1
    assert [i["title"] for i in diff["new_items"]] == ["new one"]
    assert diff["cve_changes"] == [{"package": "g:a", "new": ["CVE-2024-3"], "fixed": ["CVE-2024-2"]}]
    texts = [getattr(x, "text", "") for x in _changes_section({**diff, "previous_scan_id": 5}, cur)]
    assert texts[0] == "Changes since scan #5"
    assert any(t.startswith("New (1)") for t in texts) and any(t.startswith("Fixed (1)") for t in texts)
    assert any(t.startswith("Still open (1)") for t in texts)
    assert any("g:a: new CVE-2024-3; fixed CVE-2024-2" in t for t in texts)


def test_vuln_ids():
    assert vuln_ids("CVE-2022-1  High\nGHSA-abcd-1234-efgh  Low\nnot an id") == {"CVE-2022-1", "GHSA-ABCD-1234-EFGH"}


# ---------------------------------------------------------------- summary counts and metadata

def test_count_text_shows_raw_and_unique():
    fs = [{"severity": "High"}, {"severity": "Info"}]
    text = _count_text({"raw_count": 246, "unique_count": 55}, 53, fs)
    assert text.startswith("Raw scanner findings: 246. Unique issues: 55")
    assert "1 informational" in text and "1 triaged" in text


def test_pdf_with_metadata_actions_and_zip_header():
    scan = {"id": 9, "project": {"name": "p", "source": "p.zip", "source_type": "zip"}, "branch": None,
            "commit_sha": None, "started_at": datetime.now(timezone.utc), "finished_at": datetime.now(timezone.utc),
            "languages": [], "frameworks": [], "counts": {"High": 1}, "checks": {"secrets": True, "code": True},
            "notes": [], "ai_summary": None,
            "diff": {"previous_scan_id": 8, "new": 0, "fixed": 0, "recurring": 1, "fixed_items": []},
            "meta": {"raw_count": 3, "unique_count": 1, "archive_sha256": "ab" * 32, "archive_bytes": 1234,
                     "tools": {"semgrep": "1.181.1", "trivy": "0.58.1", "gitleaks": "v8.21.2",
                               "trivy_db_updated": "2026-11-17T01:05:25.260481643Z"},
                     "rulesets": ["Gitleaks built-in rules"], "files": {"extracted": 931, "code_scanned": 900},
                     "warnings": ["Semgrep reported 1 error(s)"],
                     "top_actions": [{"severity": "High", "text": "Upgrade x to 2", "fingerprints": ["f"]}]}}
    f = {"severity": "High", "title": "t", "file_path": "a", "line": 1, "snippet": "", "description": "d",
         "exploitation": "", "recommendation": "", "scanners": ["x"], "rule_id": "r", "check": "code",
         "is_new": False}
    assert build_pdf(scan, [f]).startswith(b"%PDF")


def test_aws_pair_is_one_credential_with_all_locations():
    akia, sec = "AKIAZ7QW3RT5YU8IOP2L", "q9Wz3Xv7Bn2Mk5Lp8Rt4Yu6Io1Pa0Sd3Fg5Hj7Kl"

    def leak(rule, v, path, line):
        name = "secret_access_key" if v == sec else "access_key_id"
        return {"check": "secrets", "severity": "High", "title": "x", "file_path": path, "line": line,
                "snippet": f"{line} | {name}: {v}", "description": "", "rule_id": rule, "scanners": ["gitleaks"],
                **secret_features(v, name)}
    out = group_findings([leak("aws-access-token", akia, "a.yml", 4), leak("generic-api-key", sec, "a.yml", 5),
                          leak("aws-access-token", akia, "b.yml", 10), leak("generic-api-key", sec, "b.yml", 11)])
    assert len(out) == 1 and len(out[0]["locations"]) == 4 and out[0]["severity"] == "Critical"


def test_aws_pairing_uses_key_names_in_sorted_env_files():
    # alphabetical env file: the nearest secret to AWS_S3_ACCESS_KEY is the EH one, but the names say S3
    s3_id, eh_id = "AKIAZ7QW3RT5YU8IOP2L", "AKIAQ1WE2RT3YU4IO5PA"
    s3_sec, eh_sec = "q9Wz3Xv7Bn2Mk5Lp8Rt4Yu6Io1Pa0Sd3Fg5Hj7Kl", "Zx9Cv8Bn7Mq6Wv5Er4Ty3Ui2Op1As0Df9Gh8Jk7L"
    rows = [("aws-access-token", s3_id, "AWS_S3_ACCESS_KEY", 4), ("aws-access-token", eh_id, "AWS_S3_EH_ACCESS_KEY", 5),
            ("generic-api-key", eh_sec, "AWS_S3_EH_SECRET_KEY", 6), ("generic-api-key", s3_sec, "AWS_S3_SECRET_KEY", 7),
            # elsewhere the S3 key ID once appears without its secret nearby: still one key pair
            ("aws-access-token", s3_id, "AWS_S3_ACCESS_KEY", 40), ("aws-access-token", s3_id, "AWS_S3_ACCESS_KEY", 80),
            ("generic-api-key", s3_sec, "AWS_S3_SECRET_KEY", 81)]
    fs = [{"check": "secrets", "severity": "High", "title": "x", "file_path": "application-secrets.yml",
           "line": line, "snippet": f"{line} | {name}: v", "description": "", "rule_id": rule,
           "scanners": ["gitleaks"], **secret_features(v, name)} for rule, v, name, line in rows]
    out = group_findings(fs)
    assert len(out) == 2 and all("access key pair" in f["title"] for f in out)
    s3 = next(f for f in out if secret_features(s3_sec)["_secret_fp"] in f["title"])
    assert secret_features(s3_id)["_secret_fp"] in s3["title"]
    assert sorted(l["line"] for l in s3["locations"]) == [4, 7, 40, 80, 81]


def test_advisory_lower_bound_marks_older_version_for_verification():
    from app.grouping import advisory_check, lower_bounds
    desc = ("From 2.18.0 until 2.18.9, 2.21.5, 2.22.1, 3.1.5, and 3.2.1, UnwrappedPropertyHandler replays buffered "
            "JSON. This issue is fixed in versions 2.18.9, 2.21.5, 2.22.1, 3.1.5, and 3.2.1.")
    note = advisory_check("2.16.2", ["2.21.5", "2.18.9", "2.22.1"], desc)
    assert note and "start at 2.18.0" in note and "2.16.2 is older" in note
    assert advisory_check("2.18.3", ["2.21.5", "2.18.9", "2.22.1"], desc) is None  # inside the range
    assert lower_bounds("Versions 1.2.0 and later fix this; fixed since nothing") == []  # fix wording ignored
    assert lower_bounds("introduced in 4.1.0") == ["4.1.0"] and lower_bounds(">= 5.0.0, < 5.3.2") == ["5.0.0"]
