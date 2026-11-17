"""Phase 4: concrete remediation text."""
from app.grouping import group_deps, group_findings
from app.normalize import parse_trivy_vulns, redact, redact_findings
from app.remediation import (apply_remediation, base_family, dockerfile_final_stage, ecosystem, secret_fix,
                             split_blocks)
from app.config_checks import scan_config_secrets


def _write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def _f(**kw):
    base = {"check": "code", "severity": "Medium", "file_path": "x", "line": 1, "scanners": ["semgrep"],
            "exploitation": "generic", "recommendation": "generic"}
    return base | kw


# ---------------------------------------------------------------- fences

def test_split_blocks():
    text = "Do this:\n\n```dockerfile\nRUN a\n  USER app\n```\n\nThen that."
    assert split_blocks(text) == [("text", "Do this:"), ("code", "RUN a\n  USER app"), ("text", "Then that.")]
    assert split_blocks("no fences") == [("text", "no fences")]
    assert split_blocks("open ``` only") == [("text", "open ``` only")]


# ---------------------------------------------------------------- Dockerfile

def test_base_family():
    assert base_family("eclipse-temurin:17-jre-alpine") == "alpine"
    assert base_family("eclipse-temurin:17-jre") == "debian"
    assert base_family("openjdk:17-jdk-slim") == "debian"
    assert base_family("registry.access.redhat.com/ubi9/ubi-minimal") == "rhel"
    assert base_family("amazoncorretto:17") == "rhel"
    assert base_family("amazoncorretto:17-alpine") == "alpine"
    assert base_family("gcr.io/distroless/java17-debian12") == "distroless"
    assert base_family("scratch") == "scratch"
    assert base_family("${BASE_IMAGE}") == "unknown"
    assert base_family("mycorp/base:1") == "unknown"
    assert base_family("node:20") == "debian"  # official image, Debian by default
    assert base_family("openjdk:17") == "unknown"  # official openjdk 17+ defaults to Oracle Linux
    assert base_family("registry.example.com/team/openjdk-17:v1") == "unknown"  # custom: name proves nothing
    assert base_family("registry.example.com/team/node:20") == "unknown"


def test_unknown_base_shows_all_variants(tmp_path):
    _write(tmp_path, "Dockerfile", "FROM registry.example.com/team/openjdk-17:v1\nENTRYPOINT [\"java\"]\n")
    f = _f(check="iac", rule_id="AVD-DS-0002", file_path="Dockerfile")
    apply_remediation([f], str(tmp_path))
    rec = f["recommendation"]
    assert "does not say which Linux distribution" in rec
    assert rec.count("```dockerfile") == 3 and "useradd --system" in rec and "/etc/os-release" in rec


def test_final_stage_follows_aliases():
    df = ("FROM maven:3.9-eclipse-temurin-17 AS build\nRUN mvn package\n"
          "FROM eclipse-temurin:17-jre-alpine AS runtime\n"
          "FROM runtime\nCOPY --from=build /app.jar /app.jar\nEXPOSE 80 8080\nENTRYPOINT [\"java\",\"-jar\",\"/app.jar\"]\n")
    st = dockerfile_final_stage(df)
    assert st == {"image": "eclipse-temurin:17-jre-alpine", "runtime_line": 7, "low_ports": [80]}


def test_docker_root_fix_alpine(tmp_path):
    _write(tmp_path, "Dockerfile", "FROM eclipse-temurin:17-jre-alpine\nCOPY a.jar /a.jar\nENTRYPOINT [\"java\"]\n")
    f = _f(check="iac", rule_id="AVD-DS-0002", file_path="Dockerfile")
    assert apply_remediation([f], str(tmp_path)) == 1
    rec = f["recommendation"]
    assert "```dockerfile\nRUN addgroup -S app && adduser -S -G app app\nUSER app\n```" in rec
    assert "line 3" in rec and "eclipse-temurin:17-jre-alpine (Alpine)" in rec
    assert "root in the container" in f["exploitation"]
    assert not f["exploitation"].startswith("Generic risk")


def test_docker_root_fix_debian_and_unknown(tmp_path):
    _write(tmp_path, "Dockerfile", "FROM openjdk:17-jdk-slim\nCMD [\"java\"]\n")
    f = _f(rule_id="dockerfile.security.missing-user-entrypoint.missing-user-entrypoint", file_path="Dockerfile")
    apply_remediation([f], str(tmp_path))
    assert "RUN addgroup --system app && adduser --system --ingroup app app\nUSER app" in f["recommendation"]
    g = _f(check="iac", rule_id="AVD-DS-0002", file_path="Dockerfile")
    apply_remediation([g], None)  # image or unreadable file: both variants
    assert "adduser --system --ingroup app app" in g["recommendation"]
    assert "adduser -S -G app app" in g["recommendation"]


def test_docker_root_fix_on_merged_finding(tmp_path):
    _write(tmp_path, "Dockerfile", "FROM node:20-alpine\nCMD [\"node\"]\n")
    items = [_f(check="iac", rule_id="AVD-DS-0002", file_path="Dockerfile", scanners=["trivy"]),
             _f(rule_id="dockerfile.security.missing-user.missing-user", file_path="Dockerfile", line=2)]
    out = group_findings(items, str(tmp_path))
    assert len(out) == 1
    apply_remediation(out, str(tmp_path))
    assert "adduser -S -G app app" in out[0]["recommendation"]


# ---------------------------------------------------------------- CBC

def test_cbc_fix_java_with_decrypt(tmp_path):
    _write(tmp_path, "src/Enc.java", "class E {\n Cipher c = Cipher.getInstance(\"AES/CBC/PKCS5Padding\");\n"
           " void d(){ c.init(Cipher.DECRYPT_MODE, k, iv); }\n}\n")
    f = _f(rule_id="java.lang.security.audit.cbc-padding-oracle.cbc-padding-oracle", file_path="src/Enc.java")
    apply_remediation([f], str(tmp_path))
    rec, ex = f["recommendation"], f["exploitation"]
    assert "GCMParameterSpec(TAG_BITS, iv)" in rec and "new byte[IV_BYTES]" in rec and "IV_BYTES = 12" in rec
    assert "```java" in rec and "Migrate" in rec
    assert "only on the decrypt side" in ex and "also decrypts (line 3)" in ex


def test_code_example_shown_once_per_kind(tmp_path):
    _write(tmp_path, "A.java", "import x.StandardEvaluationContext;\nclass A { Object o = new StandardEvaluationContext(); }\n")
    rid = "java.spring.security.audit.spel-injection.spel-injection"
    a, b = _f(rule_id=rid, file_path="A.java", line=2), _f(rule_id=rid, file_path="A.java", line=9)
    apply_remediation([a, b], str(tmp_path))
    assert "```java" in a["recommendation"]
    assert "```" not in b["recommendation"] and "under the same finding at A.java:2" in b["recommendation"]
    assert "(line 2)" in a["exploitation"]  # the import line is not counted as a use


def test_cbc_fix_encrypt_only_and_other_language(tmp_path):
    _write(tmp_path, "Enc.java", "class E { Cipher c = Cipher.getInstance(\"AES/CBC/PKCS5Padding\"); }\n")
    f = _f(rule_id="x.cbc-padding-oracle", file_path="Enc.java")
    apply_remediation([f], str(tmp_path))
    assert "No decryption call was found in Enc.java" in f["exploitation"]
    g = _f(rule_id="go.lang.security.audit.crypto.use-of-cbc", file_path="a.go")
    apply_remediation([g], str(tmp_path))
    assert "```" not in g["recommendation"] and "AES-GCM" in g["recommendation"]


# ---------------------------------------------------------------- SpEL

def test_spel_fix(tmp_path):
    _write(tmp_path, "S.java", "class S { Object v(String e){ return new SpelExpressionParser().parseExpression(e)"
           ".getValue(new StandardEvaluationContext()); } }\n")
    f = _f(rule_id="java.spring.security.audit.spel-injection.spel-injection", file_path="S.java", severity="High")
    apply_remediation([f], str(tmp_path))
    assert "SimpleEvaluationContext.forReadOnlyDataBinding().build()" in f["recommendation"]
    assert "enum Operator" in f["recommendation"]
    assert "uses StandardEvaluationContext (line 1)" in f["exploitation"]


# ---------------------------------------------------------------- secrets

def test_secret_fix_lists_every_location_and_no_purge_without_history():
    locs = [("a.yml", 3), ("b.yml", None)]
    rec = secret_fix("openai", locs, in_history=False)
    assert rec.startswith("Rotate immediately: revoke the key in the OpenAI dashboard")
    assert "- a.yml:3\n- b.yml" in rec and "all 2 locations" in rec
    assert "filter-repo" not in rec and "BFG" not in rec
    assert "git filter-repo" in secret_fix("generic", locs, in_history=True)


def test_config_password_fix_gives_placeholder(tmp_path):
    _write(tmp_path, "application.yml", "spring:\n  datasource:\n    password: S3cr3t-Db\n")
    _write(tmp_path, "application-prod.yml", "spring:\n  mail:\n    password: ${MAIL_PW:S3cr3t-Db}\n")
    findings, secrets = scan_config_secrets(str(tmp_path))
    redact_findings(findings, secrets)
    out = group_findings(findings, str(tmp_path))
    rec = out[0]["recommendation"]
    assert rec.startswith("Rotate immediately: change this password")
    assert "password: ${SPRING_DATASOURCE_PASSWORD}" in rec and "password: ${SPRING_MAIL_PASSWORD}" in rec
    assert "delete the default after the colon" in rec
    assert "- application-prod.yml:3\n- application.yml:3" in rec
    assert "S3cr3t-Db" not in rec


def test_config_key_survives_merge_with_gitleaks(tmp_path):
    from app.normalize import dedupe
    key = "sk-proj-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4"
    _write(tmp_path, "application.yml", f"openai:\n  api-key: {key}\n")
    mine, _ = scan_config_secrets(str(tmp_path))
    gl = dict(mine[0], rule_id="openai-api-key-v2", scanners=["gitleaks"], severity="Critical",
              _secret_name="api-key", _secret_config_key=None)
    out = group_findings(dedupe([gl, mine[0]]), str(tmp_path))
    assert len(out) == 1 and out[0]["title"].startswith("Hardcoded OpenAI API key")
    assert "api-key: ${OPENAI_API_KEY}" in out[0]["recommendation"]
    assert "OpenAI dashboard" in out[0]["recommendation"]


# ---------------------------------------------------------------- masking short values

def test_redact_short_value_whole_token_only():
    secrets = {"root": "****", "Xy7#pass": "********"}
    assert redact("USER non-root", secrets) == "USER non-root"
    assert redact("password: root", secrets) == "password: ****"
    assert redact("user=root;pw=Xy7#pass", secrets) == "user=****;pw=********"
    assert redact("Container runs as root", secrets, prose=True) == "Container runs as root"
    long_secret = "sk-proj-abcdefghijklmnop"
    assert redact("key" + long_secret, {long_secret: "sk-p****"}) == "keysk-p****"


# ---------------------------------------------------------------- ecosystem wording

def test_ecosystem_wording():
    assert ecosystem("pom.xml") == "maven"
    assert ecosystem("usr/lib/x", "os-pkgs", "alpine") == "os"
    assert ecosystem("app/app.jar", "lang-pkgs", "jar") == "maven"
    raw = parse_trivy_vulns({"Results": [
        {"Target": "pom.xml", "Class": "lang-pkgs", "Type": "pom", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-1", "PkgName": "a:b", "InstalledVersion": "1.0", "FixedVersion": "1.1",
             "Severity": "HIGH"}]},
        {"Target": "img (alpine 3.18)", "Class": "os-pkgs", "Type": "alpine", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2", "PkgName": "openssl", "InstalledVersion": "3.1.0", "FixedVersion": "3.1.4",
             "Severity": "HIGH"}]}]})
    assert "Maven has no lockfile" in raw[0]["recommendation"] and "mvn -U verify" in raw[0]["recommendation"]
    assert "lockfile" not in raw[1]["recommendation"] and "apk upgrade" in raw[1]["recommendation"]
    g = {x["rule_id"]: x for x in group_deps(raw)}
    assert "mvn -U verify" in g["pkg:a:b"]["recommendation"]
    assert "regenerate the lockfile" not in g["pkg:a:b"]["recommendation"]
