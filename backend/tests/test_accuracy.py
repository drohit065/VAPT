"""Phase 2: severity follows CVSS, rule overrides, advisory verification, relocated artifacts, Info."""
from app.grouping import advisory_check, group_deps
from app.normalize import GENERIC_RISK, make_finding, parse_trivy_vulns, severity_from_cvss
from app.severity_policy import apply_policy
from app.summary import scan_brief


def _vuln(vid, sev, score, fixed="", desc="", title="t", pkg="g:a", installed="1.4.0"):
    return {"VulnerabilityID": vid, "PkgName": pkg, "InstalledVersion": installed, "FixedVersion": fixed,
            "Severity": sev, "Title": title, "Description": desc,
            "CVSS": {"nvd": {"V3Score": score, "V3Vector": "CVSS:3.1/AV:N"}} if score is not None else {}}


def _trivy(*vulns, target="pom.xml"):
    return {"Results": [{"Target": target, "Vulnerabilities": list(vulns)}]}


def test_cvss_bands():
    assert [severity_from_cvss(x) for x in (9.8, 9.0, 7.5, 7.0, 6.9, 4.0, 3.9, 0.1, 0.0, None)] == \
        ["Critical", "Critical", "High", "High", "Medium", "Medium", "Low", "Low", "Info", None]


def test_severity_follows_cvss_and_keeps_vendor_rating():
    f = parse_trivy_vulns(_trivy(_vuln("CVE-2022-40149", "MEDIUM", 7.5, fixed="1.5.1")))[0]
    assert f["severity"] == "High"
    assert f["_vendor_sev"] == "Medium"
    assert f["_cvss_src"] == "NVD"


def test_no_vendor_note_when_consistent():
    f = parse_trivy_vulns(_trivy(_vuln("CVE-1", "HIGH", 7.5)))[0]
    assert f["severity"] == "High" and "_vendor_sev" not in f


def test_no_score_keeps_scanner_severity():
    f = parse_trivy_vulns(_trivy(_vuln("CVE-1", "MEDIUM", None)))[0]
    assert f["severity"] == "Medium" and f["cvss_source"] == "estimated"


def test_grouped_description_notes_vendor_rating():
    g = group_deps(parse_trivy_vulns(_trivy(_vuln("CVE-2022-40149", "MEDIUM", 7.5, fixed="1.5.1"),
                                            _vuln("CVE-2022-40150", "HIGH", 7.5, fixed="1.5.2"))))[0]
    assert g["severity"] == "High"
    assert "CVE-2022-40149 (High, CVSS 7.5 NVD; vendor rated Medium)" in g["description"]
    assert "Severity follows the CVSS score" in g["description"]


def _f(rule, sev, check="iac", path="Dockerfile"):
    return make_finding(severity=sev, title="x", file_path=path, line=1, snippet="", description="d",
                        check=check, scanner="trivy", rule_id=rule)


def test_policy_overrides():
    fs = [_f("AVD-DS-0022", "High"), _f("AVD-DS-0002", "High"),
          _f("dockerfile.security.missing-user-entrypoint.missing-user-entrypoint", "High", check="code"),
          _f("java.spring.security.audit.spel-injection.spel-injection", "Medium", check="code"),
          _f("java.lang.security.audit.crypto.weak-random.weak-random", "Medium", check="code"),
          _f("AVD-DS-0026", "Low")]
    log = apply_policy(fs)
    assert [f["severity"] for f in fs] == ["Info", "Medium", "Medium", "High", "Low", "Low"]
    assert len(log) == 5
    assert "Severity set to Info (scanner default: High)" in fs[0]["description"]
    assert fs[0]["cvss_score"] == 0.0 and fs[3]["cvss_score"] == 7.5
    assert "Critical if the expression can contain request data" in fs[3]["description"]


def test_policy_is_idempotent():
    fs = [_f("AVD-DS-0022", "High")]
    apply_policy(fs)
    assert apply_policy(fs) == [] and fs[0]["description"].count("Severity set to") == 1


def test_info_not_counted_in_totals():
    class S:
        id, status, branch, commit_sha, created_at, started_at, finished_at = 1, "completed", None, None, None, None, None
        counts = {"High": 2, "Low": 1, "Info": 3}
    b = scan_brief(S())
    assert b["total"] == 3 and b["risk"] == "High"


def test_kb_exploit_text_is_labelled_generic():
    f = _f("x", "Medium", check="code")
    assert f["exploitation"].startswith(GENERIC_RISK)
    own = make_finding(severity="Low", title="x", file_path="a", line=1, snippet="", description="d",
                       check="code", scanner="s", exploitation="Specific scenario.")
    assert own["exploitation"] == "Specific scenario."


def test_verify_when_installed_beyond_stated_range():
    note = advisory_check("2.16.2", [],
                          "FasterXML jackson-databind 2.x before 2.12.7.1 and 2.13.x before 2.13.4.2 allows DoS.")
    assert note and "before 2.12.7.1, before 2.13.4.2" in note


def test_no_verify_when_inside_range():
    assert advisory_check("2.13.0", [], "jackson-databind before 2.12.7.1 and 2.13.x before 2.13.4.2") is None
    assert advisory_check("1.4.0", [], "Jettison 1.5.0 and earlier is vulnerable") is None
    assert advisory_check("1.4.0", [], "No version information here") is None


def test_verify_ignores_other_products_versions():
    # "Spring Framework before 5.3.18" is about another product line (major 5) than jackson 2.x
    assert advisory_check("2.16.2", [], "Used by Spring Framework before 5.3.18") is None


def test_verify_inclusive_and_date_versions():
    assert advisory_check("1.5.1", [], "affects versions through 1.5.0") is not None
    assert advisory_check("1.5.0", [], "affects versions through 1.5.0") is None
    assert advisory_check("20231013", [], "JSON-java before 20230227 is vulnerable") is not None
    assert advisory_check("20210307", [], "JSON-java before 20230227 is vulnerable") is None


def test_inconsistent_advisory_flagged():
    note = advisory_check("2.13.5", ["2.12.7.1", "2.13.4.2"], "")
    assert note and "inconsistent" in note


def test_verify_kept_in_report_and_titled_when_all_flagged():
    g = group_deps(parse_trivy_vulns(_trivy(_vuln("CVE-1", "HIGH", 7.5, desc="Foo 1.x before 1.2.0 is bad",
                                                  installed="1.4.0"))))[0]
    assert g["severity"] == "High"
    assert g["title"].endswith("(verify: may not be affected)")
    assert "Verify: the advisory text describes" in g["description"]
    assert "[verify]" in g["snippet"]


def test_relocated_mysql_connector():
    g = group_deps(parse_trivy_vulns(_trivy(_vuln("CVE-2023-22102", "HIGH", 8.3, pkg="mysql:mysql-connector-java",
                                                  installed="8.0.29"))))[0]
    assert "com.mysql:mysql-connector-j 8.2.0 or later" in g["recommendation"]
    assert "No fixed version" not in g["recommendation"]
    assert "groupId and artifactId" in g["recommendation"]
