"""Fixes found on a multi-module Spring project (scan of a second real codebase). Fake values only."""
from app.config_checks import static_iv_lines
from app.grouping import annotate_line_secret, config_kind, group_findings, secret_features
from app.normalize import mask_secret_snippet
from app.top_actions import build_top_actions

KEY_ID = "AKIAQ1WE2RT3YU4IO5PA"
AWS_SECRET = "Fake0Secret1Key2For3Tests4Only5abcdefGHI"  # 40 chars, AWS secret shape


def _secret(rule, value, name, line, path="app/application-dev.yml", cfg=None, scanner="gitleaks"):
    return {"check": "secrets", "severity": "High", "title": "x", "file_path": path, "line": line,
            "snippet": f"{line} | {name}: v", "description": "", "rule_id": rule, "scanners": [scanner],
            **secret_features(value, name), "_secret_config_key": cfg}


def _dep(path, pkg, cve, sev="High", rel="indirect", via=None):
    return {"check": "deps", "severity": sev, "title": "t", "file_path": path, "line": None, "rule_id": cve,
            "_pkg": pkg, "_installed": "1.0.0", "_fixed": "1.0.5", "cvss_score": 7.5, "scanners": ["trivy"],
            "_rel": rel, "_via": via or ["org.springframework.boot:spring-boot-starter-web"], "_vtitle": "v"}


def test_same_package_in_several_poms_is_one_issue():
    fs = []
    for path in ("pom.xml", "module-a/pom.xml", "module-b/pom.xml"):
        fs += [_dep(path, "org.example:lib", "CVE-2026-1"), _dep(path, "org.example:lib", "CVE-2026-2")]
    out = [f for f in group_findings(fs) if f["check"] == "deps"]
    assert len(out) == 1
    d = out[0]
    assert d["file_path"] == "pom.xml" and d["_cve_count"] == 2 and "2 known vulnerabilities" in d["title"]
    assert [l["file"] for l in d["locations"]] == ["pom.xml", "module-a/pom.xml", "module-b/pom.xml"]
    assert "2 other manifest(s)" in d["description"]


def test_aws_secret_found_only_by_config_rule_is_paired():
    fs = [_secret("aws-access-token", KEY_ID, "access-key-id", 116),
          _secret("vapt-config-password", AWS_SECRET, "secret-access-key", 117,
                  cfg="spring.mail.aws-ses-config.secret-access-key", scanner="vapt")]
    out = [f for f in group_findings(fs) if f["check"] == "secrets"]
    assert len(out) == 1
    assert out[0]["title"].startswith("Hardcoded AWS access key pair") and out[0]["severity"] == "Critical"


def test_ses_login_paired_by_config_section(tmp_path):
    yml = ["spring:", "  mail:", "    host: smtp.example.com", "    password: FakeMailPassw0rd", "    port: 587",
           *[f"    p{i}: x" for i in range(10)], "    username: " + KEY_ID]
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "application-dev.yml").write_text("\n".join(yml) + "\n")
    fs = [_secret("vapt-config-password", "FakeMailPassw0rd", "password", 4, cfg="spring.mail.password", scanner="vapt"),
          _secret("aws-access-token", KEY_ID, "username", len(yml))]
    out = [f for f in group_findings(fs, str(tmp_path)) if f["check"] == "secrets"]
    smtp = [f for f in out if "SES SMTP" in f["title"]]
    assert smtp and smtp[0]["severity"] == "High"


def test_config_secret_labels():
    assert config_kind("app.security.jwtSecret") == "signing_key"
    assert config_kind("twilio.authToken") == "token"
    assert config_kind("tenovi.api-key") == "api_key"
    assert config_kind("pdf.owner-password") == "password"
    out = group_findings([_secret("vapt-config-password", "FakeJwtSigningValue123", "jwtSecret", 22,
                                  cfg="app.security.jwtSecret", scanner="vapt")])
    assert out[0]["title"].startswith("Hardcoded JWT signing secret")
    assert "forge a valid token" in out[0]["recommendation"]


def test_same_bcrypt_hash_on_sql_lines_is_one_finding_with_plaintext_note():
    h = "$2a$10$" + "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0"
    fs = []
    for line in (301, 323):
        f = {"check": "code", "cwe": "CWE-798", "severity": "High", "title": "Detected bcrypt hash",
             "file_path": "db/changelog.xml", "line": line, "description": "bcrypt hash detected",
             "rule_id": "generic.secrets.security.detected-bcrypt-hash.detected-bcrypt-hash", "scanners": ["semgrep"],
             "snippet": f"{line} | '{h}', -- bcrypt of 'FakePlain1'"}
        annotate_line_secret(f, [])
        f["snippet"] = mask_secret_snippet(f["snippet"], f["rule_id"])
        fs.append(f)
    out = group_findings(fs)
    assert len(out) == 1 and len(out[0]["locations"]) == 2
    assert "plaintext password" in out[0]["description"]


def test_emails_not_masked_in_secret_snippets():
    out = mask_secret_snippet("300 | 'admin.user@example.com', 'Abc123XyzLongTokenValue9'", "generic-api-key")
    assert "admin.user@example.com" in out and "Abc123XyzLongTokenValue9" not in out


def test_static_iv_detected_only_for_encryption_without_securerandom():
    bad = ("void enc(){\n Derived d = derive(p);\n Cipher c = Cipher.getInstance(CBC);\n"
           " c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(d.iv));\n}\n")
    good = ("void enc(){\n byte[] iv = new byte[16];\n new SecureRandom().nextBytes(iv);\n"
            " c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));\n}\n")
    dec = "void dec(byte[] iv){\n c.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));\n}\n"
    assert static_iv_lines(bad) == [4]
    assert static_iv_lines(good) == [] and static_iv_lines(dec) == []


def test_boot_action_lists_each_library_once():
    boot = "org.springframework.boot:spring-boot-starter-web"
    fs = [{"check": "deps", "severity": "Critical", "rule_id": "pkg:org.apache.tomcat.embed:tomcat-embed-core",
           "_cve_count": 3, "_via": [boot], "fingerprint": str(i)} for i in range(3)]
    fs.append({"check": "deps", "severity": "High", "rule_id": "pkg:org.springframework:spring-web",
               "_cve_count": 1, "_via": [boot], "fingerprint": "x"})
    text = build_top_actions(fs)[0]["text"]
    assert text.count("tomcat-embed-core") == 1
