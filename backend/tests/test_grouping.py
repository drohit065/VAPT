"""Tests for grouping raw findings into one finding per real issue (grouping.py)."""
import json

from app.findings_mgmt import fingerprint
from app.grouping import (
    annotate_line_secret,
    group_deps,
    group_findings,
    group_secrets,
    merge_concepts,
    minimum_fix,
    secret_features,
)
from app.normalize import dedupe, make_finding, parse_gitleaks, parse_trivy_vulns

AKIA = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"   # 40 chars
GCP_KEY = "AIzaSyA1234567890abcdefghijklmnopqrstu"


def leak(rule, value, path, line, match=None):
    return {"RuleID": rule, "Secret": value, "Match": match or f"KEY: '{value}'", "File": path,
            "StartLine": line, "Description": f"{rule} found"}


def run(gitleaks, root=None):
    return group_findings(dedupe(parse_gitleaks(gitleaks)), root)


# ---------------------------------------------------------------- secrets


def test_same_credential_in_many_files_is_one_finding_with_all_locations():
    out = run([leak("gcp-api-key", GCP_KEY, f"conf/app-{env}.yml", 10 + i)
               for i, env in enumerate(["dev", "qa", "uat", "prod"])])
    assert len(out) == 1
    f = out[0]
    assert f["title"].startswith("Hardcoded Google API key (fp:")
    assert len(f["locations"]) == 4
    assert {l["file"] for l in f["locations"]} == {"conf/app-dev.yml", "conf/app-qa.yml",
                                                   "conf/app-uat.yml", "conf/app-prod.yml"}
    assert "Found in 4 locations" in f["description"]
    assert "all 4 locations" in f["recommendation"]
    assert GCP_KEY not in json.dumps(f)


def test_different_credentials_stay_separate():
    out = run([leak("gcp-api-key", GCP_KEY, "a.yml", 1), leak("gcp-api-key", GCP_KEY[:-1] + "X", "a.yml", 2)])
    assert len(out) == 2


def test_several_rules_on_same_value_keep_most_specific_title():
    out = run([leak("generic-api-key", AWS_SECRET, "a.yml", 3, f"aws_secret_access_key: {AWS_SECRET}"),
               leak("aws-secret-access-key", AWS_SECRET, "b.yml", 9)])
    assert len(out) == 1
    assert "AWS secret access key" in out[0]["title"]
    assert "generic-api-key" in out[0]["description"] and "aws-secret-access-key" in out[0]["description"]


def test_generic_rule_on_aws_shaped_secret_is_classified_as_aws_secret():
    out = run([leak("generic-api-key", AWS_SECRET, "a.yml", 3, f"secret_access_key: {AWS_SECRET}")])
    assert "AWS secret access key" in out[0]["title"] and out[0]["severity"] == "Critical"


def test_aws_key_id_with_secret_next_to_it_is_critical():
    out = run([leak("aws-access-token", AKIA, "a.yml", 4, f"access_key_id: {AKIA}"),
               leak("generic-api-key", AWS_SECRET, "a.yml", 5, f"secret_access_key: {AWS_SECRET}")])
    key_id = next(f for f in out if "access key ID" in f["title"])
    assert key_id["severity"] == "Critical"
    assert "secret access key" in key_id["description"]


def test_aws_key_id_paired_only_with_nearest_secret():
    other = "zZalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    out = run([leak("generic-api-key", other, "a.yml", 3, f"S3_SECRET_KEY: {other}"),
               leak("aws-access-token", AKIA, "a.yml", 4, f"SES_ACCESS_KEY: {AKIA}"),
               leak("generic-api-key", AWS_SECRET, "a.yml", 5, f"SES_SECRET_KEY: {AWS_SECRET}")])
    key_id = next(f for f in out if "access key ID" in f["title"])
    assert secret_features(AWS_SECRET)["_secret_fp"] in key_id["description"]
    assert secret_features(other)["_secret_fp"] not in key_id["description"]


def test_aws_key_id_alone_is_medium():
    out = run([leak("aws-access-token", AKIA, "a.yml", 4, f"username: {AKIA}")])
    assert out[0]["severity"] == "Medium"
    assert "does not grant access" in out[0]["description"]


def test_gcp_service_account_file_is_one_finding(tmp_path):
    (tmp_path / "keys").mkdir()
    (tmp_path / "keys" / "google-key.json").write_text(json.dumps({
        "type": "service_account", "project_id": "demo-proj", "private_key_id": "0123456789abcdef0123456789",
        "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----\n",
        "client_email": "svc@demo-proj.iam.gserviceaccount.com"}))
    out = run([leak("private-key", "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----",
                    "keys/google-key.json", 5),
               leak("generic-api-key", "0123456789abcdef0123456789", "keys/google-key.json", 4)], str(tmp_path))
    assert len(out) == 1
    f = out[0]
    assert f["title"] == "GCP service account key file committed: keys/google-key.json"
    assert f["severity"] == "Critical"
    assert "svc@demo-proj.iam.gserviceaccount.com" in f["description"]


def test_json_that_is_not_a_service_account_is_not_merged(tmp_path):
    (tmp_path / "x.json").write_text(json.dumps({"apiKey": GCP_KEY, "other": AWS_SECRET}))
    out = run([leak("gcp-api-key", GCP_KEY, "x.json", 1), leak("generic-api-key", AWS_SECRET, "x.json", 2)],
              str(tmp_path))
    assert len(out) == 2


def test_history_purge_only_mentioned_when_found_in_history():
    current = run([leak("gcp-api-key", GCP_KEY, "a.yml", 1)])[0]
    assert "filter-repo" not in current["recommendation"]
    hist = dict(leak("gcp-api-key", GCP_KEY, "a.yml", 1), Commit="abcdef1234567890")
    assert "filter-repo" in run([hist])[0]["recommendation"]


def test_grouped_secret_fingerprint_is_stable_across_locations():
    a = run([leak("gcp-api-key", GCP_KEY, "a.yml", 1)])[0]
    b = run([leak("gcp-api-key", GCP_KEY, "moved/elsewhere.yml", 99)])[0]
    assert fingerprint(a) == fingerprint(b)


def test_semgrep_secret_line_is_fingerprinted_and_grouped_with_gitleaks():
    sem = make_finding(severity="High", title="Detected aws secret access key", file_path="b.yml", line=7,
                       snippet=f"6 | other: 1\n7 | AWS_S3_SECRET_KEY: '{AWS_SECRET}'\n8 | x: 2",
                       description="AWS Secret Access Key detected", check="code", scanner="semgrep",
                       rule_id="generic.secrets.security.detected-aws-secret-access-key.detected-aws-secret-access-key",
                       cwe="CWE-798: Use of Hard-coded Credentials")
    annotate_line_secret(sem, [AWS_SECRET])
    assert sem["_secret_fp"] == secret_features(AWS_SECRET)["_secret_fp"]
    out = group_findings(dedupe(parse_gitleaks([leak("generic-api-key", AWS_SECRET, "a.yml", 3)]) + [sem]))
    assert len(out) == 1 and len(out[0]["locations"]) == 2
    assert set(out[0]["scanners"]) == {"gitleaks", "semgrep"}


def test_placeholder_values_are_not_fingerprinted():
    f = make_finding(severity="High", title="x", file_path="a.yml", line=1, snippet="1 | password: ${DB_PASSWORD}",
                     description="", check="code", scanner="semgrep", cwe="CWE-798")
    annotate_line_secret(f, [])
    assert "_secret_fp" not in f


def test_dedupe_keeps_secret_fingerprint_when_merging():
    fs = parse_gitleaks([leak("gcp-api-key", GCP_KEY, "a.yml", 1), leak("generic-api-key", GCP_KEY, "a.yml", 1)])
    merged = dedupe(fs)
    assert len(merged) == 1 and merged[0]["_secret_fp"]


def test_non_secret_findings_untouched():
    code = make_finding(severity="Medium", title="Weak random", file_path="A.java", line=3, snippet="",
                        description="", check="code", scanner="semgrep", rule_id="weak-random")
    assert group_secrets([code], None) == [code]


# ---------------------------------------------------------------- dependencies


def test_minimum_fix_single_version_for_all_cves_on_same_major():
    cves = [["2.18.8", "3.1.4", "2.21.4"], ["2.18.10", "2.21.6", "2.22.2"], ["2.18.11", "2.21.7", "2.22.3"],
            ["2.21.5", "2.18.9", "2.22.1"], ["3.1.4", "2.18.9", "2.21.5", "2.22.1"]]
    assert minimum_fix("2.16.2", cves) == ("2.18.11", True)


def test_minimum_fix_never_jumps_major_when_same_major_works():
    assert minimum_fix("2.16.2", [["3.1.4", "2.18.8"]]) == ("2.18.8", True)


def test_minimum_fix_major_upgrade_when_needed():
    assert minimum_fix("3.2.2", [["4.0.4", "3.5.12"], ["4.0.1"]]) == ("4.0.4", False)


def test_minimum_fix_date_versions():
    assert minimum_fix("20210307", [["20230227"], ["20231013"], ["20260719"]]) == ("20260719", True)


def test_minimum_fix_no_fix():
    assert minimum_fix("8.0.29", [[]]) == (None, True)


def vuln(vid, sev, fixed, score=7.5, title="t"):
    return {"VulnerabilityID": vid, "PkgName": "com.fasterxml.jackson.core:jackson-databind",
            "InstalledVersion": "2.16.2", "FixedVersion": fixed, "Severity": sev, "Title": title,
            "CVSS": {"nvd": {"V3Score": score, "V3Vector": "CVSS:3.1/AV:N"}}}


def test_cves_grouped_per_package_with_one_fix_version():
    data = {"Results": [{"Target": "pom.xml", "Vulnerabilities": [
        vuln("CVE-1", "HIGH", "2.18.8, 3.1.4, 2.21.4", 8.1, "RCE"),
        vuln("CVE-2", "MEDIUM", "2.18.10, 2.21.6", 5.3),
        vuln("CVE-3", "HIGH", "2.21.7, 2.18.11, 2.22.3"),
    ]}, {"Target": "pom.xml", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-9", "PkgName": "org.json:json", "InstalledVersion": "20210307",
         "FixedVersion": "20231013", "Severity": "HIGH"}]}]}
    out = group_deps(parse_trivy_vulns(data))
    assert len(out) == 2
    j = next(f for f in out if "jackson" in f["title"])
    assert j["title"] == "com.fasterxml.jackson.core:jackson-databind 2.16.2: 3 known vulnerabilities"
    assert j["severity"] == "High" and j["cvss_score"] == 8.1
    assert "to 2.18.11 or later" in j["recommendation"] and "all 3" in j["recommendation"]
    assert "3.1.4" not in j["recommendation"]
    assert "mvn -U verify" in j["recommendation"] and "lockfile" not in j["recommendation"]
    assert j["snippet"].count("CVE-") == 3
    assert j["rule_id"] == "pkg:com.fasterxml.jackson.core:jackson-databind"


def test_unfixed_cves_are_named():
    data = {"Results": [{"Target": "pom.xml", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2099-1", "PkgName": "org.example:lib", "InstalledVersion": "8.0.29",
         "FixedVersion": "", "Severity": "HIGH"}]}]}
    out = group_deps(parse_trivy_vulns(data))
    assert "No fix is published for CVE-2099-1" in out[0]["recommendation"]


def test_deps_fingerprint_stable_when_cves_change():
    one = group_deps(parse_trivy_vulns({"Results": [{"Target": "pom.xml", "Vulnerabilities": [vuln("CVE-1", "HIGH", "2.18.8")]}]}))
    two = group_deps(parse_trivy_vulns({"Results": [{"Target": "pom.xml", "Vulnerabilities": [
        vuln("CVE-1", "HIGH", "2.18.8"), vuln("CVE-2", "LOW", "2.18.9")]}]}))
    assert fingerprint(one[0]) == fingerprint(two[0])


# ---------------------------------------------------------------- Dockerfile concepts


def test_root_user_reported_by_two_tools_is_one_finding():
    trivy = make_finding(severity="High", title="Image user should not be 'root'", file_path="Dockerfile", line=None,
                         snippet="", description="d1", check="iac", scanner="trivy", rule_id="AVD-DS-0002")
    sem = make_finding(severity="High", title="Missing user entrypoint", file_path="Dockerfile", line=11,
                       snippet="11 | ENTRYPOINT [\"java\"]", description="d2", check="code", scanner="semgrep",
                       rule_id="dockerfile.security.missing-user-entrypoint.missing-user-entrypoint")
    other = make_finding(severity="Low", title="No HEALTHCHECK", file_path="Dockerfile", line=None, snippet="",
                         description="", check="iac", scanner="trivy", rule_id="AVD-DS-0026")
    out = merge_concepts([trivy, sem, other])
    assert len(out) == 2
    root = next(f for f in out if "root" in f["title"])
    assert root["line"] == 11 and set(root["scanners"]) == {"trivy", "semgrep"}
