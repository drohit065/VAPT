"""Tests for how discovered credentials are displayed."""
from app.normalize import mask_assignments, parse_gitleaks, redact_findings, make_finding
from app.secret_display import display, fingerprint


def test_long_key_first_and_last_four():
    out = display("AKIAIOSFODNN7EXAMPLE")
    assert out.startswith("AKIA") and "MPLE fp:" in out and "IOSFODNN7EXA" not in out


def test_medium_key_last_four_only():
    out = display("abcdEFGHijklMN")          # 14 chars
    assert out.startswith("********klMN") and "abcd" not in out


def test_short_value_nothing_visible():
    out = display("abc123")
    assert "abc" not in out and "123" not in out and "fp:" in out


def test_password_never_shows_characters():
    out = display("Bank@1234###", name="DB_PASSWORD")
    assert "Bank" not in out and "###" not in out and "(12 chars)" in out
    out = display("a-very-long-password-value-123", rule_id="generic-password")
    assert "a-ve" not in out and "-123" not in out


def test_fingerprint_stable_and_distinct():
    assert fingerprint("same-secret") == fingerprint("same-secret")
    assert fingerprint("same-secret") != fingerprint("other-secret")
    assert display("AKIAIOSFODNN7EXAMPLE").split()[-1] == display("AKIAIOSFODNN7EXAMPLE").split()[-1]


def test_connection_string_keeps_user_and_host():
    out = mask_assignments("DATABASE_URL=postgres://admin:S3cretPw@db.prod:5432/app")
    assert "postgres://admin:****(fp:" in out and "@db.prod:5432/app" in out and "S3cretPw" not in out


def test_private_key_type_only():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAxyz\n-----END RSA PRIVATE KEY-----"
    out = display(pem)
    assert out.startswith("[RSA private key") and "MIIE" not in out and "fp:" in out


def test_gitleaks_password_rule_and_assignment_names():
    data = [{"RuleID": "generic-api-key", "File": "app.yml", "StartLine": 3, "Match": "secretKey: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
             "Secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}]
    [f] = parse_gitleaks(data)
    assert "wJal" in f["snippet"] and "MPLEKEY" not in f["snippet"] and "fp:" in f["snippet"]
    out = mask_assignments('db_password = "Sup3rS3cret!x"')
    assert "Sup3" not in out and "(13 chars)" in out


def test_already_masked_values_are_not_masked_twice():
    once = mask_assignments('API_KEY = "abcd1234efgh5678ijkl"')
    assert mask_assignments(once) == once


def test_operator_credentials_fully_hidden():
    f = make_finding(severity="Low", title="t", file_path="https://a.example.com", line=None,
                     snippet="Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc.def", description="", check="web",
                     scanner="vapt-web")
    redact_findings([f], {"Bearer eyJhbGciOiJIUzI1NiJ9.abc.def": "REDACTED"})
    assert "eyJh" not in f["snippet"] and "REDACTED" in f["snippet"]


def test_rules_about_passwords_do_not_mask_ordinary_code():
    for rule, snippet in (("python.lang.security.audit.md5-used-as-password", '24 |     username = request.form["password"]'),
                          ("terraform.lang.security.rds-insecure-password-storage", '32 |   instance_class = "db.t2.micro"')):
        f = make_finding(severity="Medium", title="t", file_path="x", line=1, snippet=snippet, description="",
                         check="code", scanner="semgrep", rule_id=rule)
        redact_findings([f], {})
        assert f["snippet"] == snippet


def test_secret_detection_rules_still_mask():
    for rule in ("generic.secrets.security.detected-generic-api-key.detected-generic-api-key",
                 "python.lang.security.audit.hardcoded-password-default-argument", "aws-access-token"):
        f = make_finding(severity="High", title="t", file_path="x", line=1,
                         snippet='3 | value = "q8Zr2LmN0pXw4VbT7yKc"', description="", check="code",
                         scanner="semgrep", rule_id=rule)
        redact_findings([f], {})
        assert "q8Zr2LmN0pXw4" not in f["snippet"], rule
