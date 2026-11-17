"""Phase 3: config passwords, Spring settings, Spring Security code, dependency relationships."""
import re

from app.config_checks import config_secret_value, scan_config_secrets, scan_spring, yaml_entries
from app.grouping import group_deps, group_findings
from app.normalize import parse_trivy_vulns
from app.worker.pipeline import GITLEAKS_CONFIG


def _write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


YML = """\
server:
  port: 8443
  ssl:
    key-store-password: Kst0re!Pass
spring:
  datasource:
    url: jdbc:mysql://db:3306/app?useSSL=false
    username: app
    password: S3cr3t-Db
  mail:
    password: ${MAIL_PASSWORD}
    backup-password: ${MAIL_X:fallbackPw9}
jwt:
  secret-name: not-a-secret-name
  token-validity: 3600
  secret: ${JWT_SECRET:}
management:
  endpoints:
    web:
      exposure:
        include: "*"
  endpoint:
    health:
      show-details: always
"""


def test_yaml_entries_track_nesting():
    keys = {k: v for _, k, v in yaml_entries(YML)}
    assert keys["server.ssl.key-store-password"] == "Kst0re!Pass"
    assert keys["management.endpoints.web.exposure.include"] == "*"
    assert keys["spring.datasource.url"].startswith("jdbc:mysql")


def test_secret_value_rules():
    assert config_secret_value("spring.datasource.password", "S3cr3t-Db") == ("S3cr3t-Db", False)
    assert config_secret_value("x.client-secret", "abcd1234") == ("abcd1234", False)
    assert config_secret_value("aws.secret_access_key", "abcd1234efgh") == ("abcd1234efgh", False)
    assert config_secret_value("mail.password", "${MAIL_PASSWORD}") is None
    assert config_secret_value("mail.password", "${MAIL_PASSWORD:fallbackPw9}") == ("fallbackPw9", True)
    assert config_secret_value("jwt.secret-name", "whatever") is None
    assert config_secret_value("jwt.token-validity", "3600") is None
    assert config_secret_value("app.password", "ENC(abcdef)") is None
    assert config_secret_value("app.password", "<your-password>") is None
    assert config_secret_value("app.encoded-password", "$2a$10$abcdefghijklmnopqrstuv") is None
    assert config_secret_value("app.password-encoder", "bcrypt") is None


def test_config_passwords_found_and_masked(tmp_path):
    _write(tmp_path, "src/main/resources/application.yml", YML)
    _write(tmp_path, "src/test/resources/application-test.yml", "spring:\n  datasource:\n    password: testpw12\n")
    _write(tmp_path, "application-secrets.yml.example", "password: realLooking1\n")
    findings, secrets = scan_config_secrets(str(tmp_path))
    by_key = {f["title"].split(": ", 1)[1]: f for f in findings}
    assert len(findings) == 4  # 3 in main config (empty ${JWT_SECRET:} default is fine) + 1 in test config
    assert set(by_key) == {"server.ssl.key-store-password", "spring.datasource.password", "spring.mail.backup-password"}
    assert by_key["spring.datasource.password"]["_secret_fp"].startswith("fp:")
    sev = {(f["file_path"], f["severity"]) for f in findings}
    assert ("src/test/resources/application-test.yml", "Low") in sev
    assert ("src/main/resources/application.yml", "High") in sev
    assert "S3cr3t-Db" in secrets and "S3cr3t-Db" not in secrets["S3cr3t-Db"]
    assert "fallback" in by_key["spring.mail.backup-password"]["description"]


def test_config_password_groups_with_gitleaks_value(tmp_path):
    _write(tmp_path, "a/application.yml", "spring:\n  datasource:\n    password: S3cr3t-Db\n")
    _write(tmp_path, "b/application-prod.yml", "spring:\n  datasource:\n    password: S3cr3t-Db\n")
    findings, _ = scan_config_secrets(str(tmp_path))
    out = group_findings(findings, str(tmp_path))
    assert len(out) == 1
    assert out[0]["title"].startswith("Hardcoded password (fp:")
    assert len(out[0]["locations"]) == 2


def test_spring_settings(tmp_path):
    _write(tmp_path, "src/main/resources/application.yml", YML)
    _write(tmp_path, "src/main/resources/application.properties",
           "management.endpoints.web.exposure.include=health,env\nspring.h2.console.enabled=true\n"
           "server.error.include-stacktrace=always\n")
    findings, cov = scan_spring(str(tmp_path))
    rules = {f["rule_id"]: f for f in findings}
    assert set(rules) == {"vapt.spring.actuator-exposed", "vapt.spring.health-details", "vapt.spring.db-no-tls",
                          "vapt.spring.h2-console", "vapt.spring.error-stacktrace"}
    assert rules["vapt.spring.actuator-exposed"]["severity"] == "High"
    assert len(rules["vapt.spring.actuator-exposed"]["locations"]) == 2
    assert "heapdump" in rules["vapt.spring.actuator-exposed"]["exploitation"]
    assert not rules["vapt.spring.h2-console"]["exploitation"].startswith("Generic risk")
    assert cov == {"config_files": 2, "java_files": 0}


JAVA = """\
class SecurityConfig {
  SecurityFilterChain chain(HttpSecurity http) {
    // http.csrf().disable();   commented out: not reported
    http.csrf(httpSecurityCsrfConfigurer -> httpSecurityCsrfConfigurer.disable());
    http.authorizeHttpRequests(a -> a.requestMatchers("/login").permitAll()
        .anyRequest()
        .permitAll());
    config.setAllowedOriginPatterns(List.of("*"));
    config.setAllowCredentials(true);
  }
}
"""


def test_spring_security_code(tmp_path):
    _write(tmp_path, "src/main/java/x/SecurityConfig.java", JAVA)
    _write(tmp_path, "src/test/java/x/TestConfig.java", "class T { void c(H h){ h.csrf().disable(); } }")
    findings, cov = scan_spring(str(tmp_path))
    rules = {f["rule_id"]: f for f in findings}
    assert set(rules) == {"vapt.spring.csrf-disabled", "vapt.spring.permit-all-everything", "vapt.spring.cors-wildcard"}
    assert rules["vapt.spring.csrf-disabled"]["line"] == 4
    assert rules["vapt.spring.permit-all-everything"]["severity"] == "High"
    assert rules["vapt.spring.cors-wildcard"]["severity"] == "Medium"  # credentials allowed too
    assert "Authorization header" in rules["vapt.spring.csrf-disabled"]["exploitation"]
    assert cov["java_files"] == 2


def test_csrf_merges_with_semgrep(tmp_path):
    _write(tmp_path, "S.java", "class S { void c(H http){ http.csrf().disable(); } }")
    mine, _ = scan_spring(str(tmp_path))
    semgrep = dict(mine[0], rule_id="java.spring.security.audit.spring-csrf-disabled.spring-csrf-disabled",
                   scanners=["semgrep"])
    out = group_findings(mine + [semgrep], str(tmp_path))
    assert len(out) == 1 and out[0]["scanners"] == ["semgrep", "vapt"]


def test_gitleaks_config_extends_defaults_with_ai_keys():
    assert GITLEAKS_CONFIG.startswith("[extend]\nuseDefault = true")
    rx = re.findall(r"regex = '([^']+)'", GITLEAKS_CONFIG)
    key = "sk-proj-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4"
    assert re.search(rx[0], f'OPENAI_API_KEY="{key}"').group(1) == key
    assert re.search(rx[1], "sk-ant-api03-" + "x" * 90 + "\n")


def _trivy_with_pkgs():
    return {"Results": [{"Target": "pom.xml",
                         "Packages": [
                             {"ID": "me:app:1", "Name": "me:app", "Relationship": "root",
                              "DependsOn": ["a:direct:1.0", "b:lib:2.0"]},
                             {"ID": "a:direct:1.0", "Name": "a:direct", "Relationship": "direct"},
                             {"ID": "b:lib:2.0", "Name": "b:lib", "Relationship": "direct", "DependsOn": ["c:mid:1.0"]},
                             {"ID": "c:mid:1.0", "Name": "c:mid", "Relationship": "indirect", "DependsOn": ["d:deep:3.1"]},
                             {"ID": "d:deep:3.1", "Name": "d:deep", "Relationship": "indirect"}],
                         "Vulnerabilities": [
                             {"VulnerabilityID": "CVE-1", "PkgID": "a:direct:1.0", "PkgName": "a:direct",
                              "InstalledVersion": "1.0", "FixedVersion": "1.1", "Severity": "HIGH"},
                             {"VulnerabilityID": "CVE-2", "PkgID": "d:deep:3.1", "PkgName": "d:deep",
                              "InstalledVersion": "3.1", "FixedVersion": "3.2", "Severity": "HIGH"}]}]}


def test_direct_and_transitive_dependencies():
    raw = parse_trivy_vulns(_trivy_with_pkgs())
    assert [(f["_rel"], f["_via"]) for f in raw] == [("direct", []), ("indirect", ["b:lib"])]
    out = {g["rule_id"]: g for g in group_deps(raw)}
    assert "declared directly in pom.xml" in out["pkg:a:direct"]["description"]
    deep = out["pkg:d:deep"]
    assert "transitive dependency" in deep["description"] and "pulled in by b:lib" in deep["description"]
    assert "pin d:deep 3.2 in <dependencyManagement>" in deep["recommendation"]


def test_no_relationship_data_is_silent():
    raw = parse_trivy_vulns({"Results": [{"Target": "pom.xml", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-1", "PkgName": "a:b", "InstalledVersion": "1.0", "FixedVersion": "1.1",
         "Severity": "HIGH"}]}]})
    g = group_deps(raw)[0]
    assert raw[0]["_rel"] is None
    assert "transitive" not in g["description"] and "declared directly" not in g["description"]


TRIVY_LOG = """\
2026-11-17T09:07:56Z	DEBUG	[pom] Failed to fetch	url="https://repo.maven.apache.org/maven2/org/springframework/boot/spring-boot-starter-parent/3.2.2/spring-boot-starter-parent-3.2.2.pom" statusCode=429
2026-11-17T09:07:56Z	WARN	[pom] Dependency version cannot be determined. Child dependencies will not be found.	details="https://aquasecurity.github.io/trivy/v0.58/docs/coverage/language/java#empty-dependency-version"
2026-11-17T09:07:56Z	DEBUG	[pom] Dependency version cannot be determined.	GroupID="org.springframework.boot" ArtifactID="spring-boot-starter-actuator"
2026-11-17T09:07:56Z	DEBUG	[pom] Dependency version cannot be determined.	GroupID="org.apache.commons" ArtifactID="commons-lang3"
2026-11-17T09:07:57Z	DEBUG	[pom] Failed to fetch	url="https://repo.maven.apache.org/maven2/io/jsonwebtoken/jjwt-api/0.11.3/jjwt-api-0.11.3.pom" statusCode=429
2026-11-17T09:07:57Z	DEBUG	[pom] Repository error	err="io.jsonwebtoken:jjwt-api:0.11.3 was not found in local/remote repositories"
"""


def test_pom_resolution_problems_detects_rate_limit():
    from app.worker.pipeline import pom_resolution_problems
    p = pom_resolution_problems(TRIVY_LOG)
    assert p["throttled"] == 2 and p["failed_fetches"] == 2
    assert p["unresolved"] == ["org.apache.commons:commons-lang3", "org.springframework.boot:spring-boot-starter-actuator"]
    assert p["missing_poms"] == ["io.jsonwebtoken:jjwt-api:0.11.3"]
    assert pom_resolution_problems("") == {"failed_fetches": 0, "throttled": 0, "unresolved": [], "missing_poms": []}
