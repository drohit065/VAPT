"""Fixes from reviewing a real report: leaks and over-masking (all values here are fake)."""
from app.config_checks import config_secret_value, scan_config_secrets
from app.grouping import group_findings, secret_features
from app.normalize import mask_list_rest, mask_pem, mask_secret_snippet, redact_findings


def _write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


# ---------------------------------------------------------------- leaks

def test_plural_password_keys_are_checked():
    assert config_secret_value("SECURITY_QUESS_PASSWORDS", "Alpha123x,Fake@9876") == ("Alpha123x,Fake@9876", False)
    assert config_secret_value("app.api-keys", "k1k1k1k1,k2k2k2k2")
    assert config_secret_value("openai.max-tokens", "4000") is None  # numbers are not secrets


def test_list_of_passwords_fully_masked(tmp_path):
    _write(tmp_path, "application-secrets.yml",
           "SECURITY_ADMIN_PASSWORD: 'Alpha123x'\nSECURITY_QUESS_PASSWORDS: 'Alpha123x,Fake@9876'\n")
    findings, secrets = scan_config_secrets(str(tmp_path))
    assert "Fake@9876" in secrets  # each list item is masked on its own too
    redact_findings(findings, secrets)
    for f in findings:
        assert "Fake@9876" not in f["snippet"] and "Alpha123x" not in f["snippet"]
        assert "SECURITY_QUESS_PASSWORDS:" in f["snippet"]


def test_rest_of_a_partly_masked_list_is_masked():
    assert mask_list_rest("KEYS: '******** fp:0ea8f5ec,Fake@9876'") == "KEYS: '******** fp:0ea8f5ec,********'"
    assert mask_list_rest("k: Fake@9876;******** fp:0ea8f5ec") == "k: ********;******** fp:0ea8f5ec"
    assert mask_list_rest("note: a, b and c") == "note: a, b and c"  # no masked value: unchanged


def test_inline_private_key_never_shows_characters():
    line = ('5 |   "private_key": "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC'
            'BKcwggSjAgEAAoIBAQC7\\ncfUxyzABCDEFGHIJKLMNOPQRSTUV0123456789abcdefgdtO\\n-----END PRIVATE KEY-----\\n",')
    out = mask_secret_snippet(line, "private-key")
    assert "MIIE" not in out and "cfUx" not in out and "gdtO" not in out
    assert '"private_key": "[private key, hidden] fp:' in out
    # a key cut off at the end of a long snippet line (no END marker) is hidden too
    assert "MIIE" not in mask_pem('"k": "-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA')


def test_pem_body_lines_fully_masked_for_private_key_rules():
    out = mask_secret_snippet("2 | MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSj\n3 | AoIBAQC7xyzABCDEFGHIJKLMNOPQRSTUVWX",
                              "private-key")
    assert "MIIE" not in out and "AoIB" not in out and "SCBK" not in out


# ---------------------------------------------------------------- over-masking

def test_hostnames_and_url_paths_not_masked():
    snip = ("66 |     url: jdbc:mysql://rcadev.abcdefghijkl.ap-south-1.rds.amazonaws.com:3306/caprod?useSSL=false\n"
            "26 |   api-url: ${CONV_URL:https://conv-agent-api.example.com:8000/conversationalagentservice}")
    out = mask_secret_snippet(snip, "vapt-config-password")
    assert "rcadev.abcdefghijkl.ap-south-1.rds.amazonaws.com" in out
    assert "conv-agent-api.example.com:8000/conversationalagentservice" in out


def test_lowercase_uuid_keys_still_masked():
    out = mask_secret_snippet("22 | VIRUS_SCAN_API_KEY: 3f2b9c1d-7e4a-4b8f-9c2d-1a6e5f7b8c9d", "generic-api-key")
    assert "7e4a-4b8f" not in out and "VIRUS_SCAN_API_KEY:" in out


# ---------------------------------------------------------------- AWS SES SMTP

def test_ses_smtp_user_and_password_rated_high():
    key_id, pw = "AKIAQ1WE2RT3YU4IO5PA", "BFakeSmtpPassword0123456789abcdefghijKLMN"

    def leak(rule, v, name, line):
        return {"check": "secrets", "severity": "Medium", "title": "x", "file_path": "a.yml", "line": line,
                "snippet": f"{line} | {name}: v", "description": "", "rule_id": rule, "scanners": ["gitleaks"],
                **secret_features(v, name), "_secret_config_key": name if "PASSWORD" in name else None}
    out = group_findings([leak("vapt-config-password", pw, "SPRING_MAIL_PASSWORD", 20),
                          leak("aws-access-token", key_id, "SPRING_MAIL_USERNAME", 21)])
    smtp = next(f for f in out if "SES SMTP" in f["title"])
    assert smtp["severity"] == "High" and "send email" in smtp["description"]
    assert secret_features(pw)["_secret_fp"] in smtp["description"]


def test_key_id_alone_stays_medium():
    out = group_findings([{"check": "secrets", "severity": "Medium", "title": "x", "file_path": "a.yml", "line": 4,
                           "snippet": "4 | username: v", "description": "", "rule_id": "aws-access-token",
                           "scanners": ["gitleaks"], **secret_features("AKIAQ1WE2RT3YU4IO5PA", "username")}])
    assert out[0]["severity"] == "Medium" and "SES" not in out[0]["title"]


def test_gcp_service_account_file_wording(tmp_path):
    import json
    (tmp_path / "google-key.json").write_text(json.dumps({
        "type": "service_account", "project_id": "p", "private_key": "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n",
        "client_email": "svc@p.iam.gserviceaccount.com"}))
    fs = [{"check": "secrets", "severity": "High", "title": "x", "file_path": "google-key.json", "line": line,
           "snippet": "", "description": "", "rule_id": rule, "scanners": ["gitleaks"], **secret_features(v)}
          for rule, v, line in (("private-key", "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----", 5),
                                ("generic-api-key", "0123456789abcdef0123456789", 4))]
    [g] = group_findings(fs, str(tmp_path))
    assert g["locations"] is None and "The whole file is the credential" in g["description"]
    assert "Remove the file from the code (google-key.json) and add it to .gitignore." in g["recommendation"]
