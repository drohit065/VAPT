"""Tests for fingerprints, status carry-over, scan diff, CVSS and exports."""
import json

from app.exports import to_csv, to_sarif
from app.findings_mgmt import apply_history, fingerprint, open_counts
from app.normalize import make_finding, parse_trivy_vulns


def code_finding(line=10, snippet=None, rule="python.sqli", path="app.py", sev="High"):
    return make_finding(severity=sev, title="SQL injection", file_path=path, line=line,
                        snippet=snippet or f"{line} | cur.execute(q + uid)", description="d",
                        check="code", scanner="semgrep", rule_id=rule)


def test_fingerprint_ignores_line_moves_for_code():
    a = code_finding(line=10, snippet="10 | cur.execute(q + uid)")
    b = code_finding(line=42, snippet="42 |    cur.execute(q  + uid)")
    assert fingerprint(a) == fingerprint(b)
    assert fingerprint(a) != fingerprint(code_finding(snippet="10 | other()"))
    assert fingerprint(a) != fingerprint(code_finding(path="other.py"))


def test_fingerprint_deps_survives_version_bump():
    def dep(ver):
        return make_finding(severity="High", title=f"CVE-2023-1 in lodash {ver}: proto", file_path="package-lock.json",
                            line=None, snippet="", description="", check="deps", scanner="trivy", rule_id="CVE-2023-1")
    assert fingerprint(dep("4.17.10")) == fingerprint(dep("4.17.11"))


def test_apply_history_new_recurring_fixed_and_sticky_status():
    old_same = code_finding()
    old_fp = code_finding(rule="python.eval", snippet="10 | eval(x)")
    old_gone = code_finding(rule="python.pickle", snippet="10 | pickle.loads(x)", sev="Critical")
    previous = []
    for f, status in ((old_same, "open"), (old_fp, "false_positive"), (old_gone, "open")):
        f = dict(f)
        f["fingerprint"] = fingerprint(f)
        f["status"], f["status_note"] = status, "not reachable" if status == "false_positive" else None
        previous.append(f)

    current = [code_finding(), code_finding(rule="python.eval", snippet="10 | eval(x)"),
               code_finding(rule="python.xss", snippet="10 | render(x)")]
    diff = apply_history(current, previous)
    by_rule = {f["rule_id"]: f for f in current}
    assert by_rule["python.sqli"]["is_new"] is False
    assert by_rule["python.xss"]["is_new"] is True
    assert by_rule["python.eval"]["status"] == "false_positive"
    assert by_rule["python.eval"]["status_note"] == "not reachable"
    assert diff["new"] == 1 and diff["recurring"] == 2 and diff["fixed"] == 1
    assert diff["fixed_items"][0]["severity"] == "Critical"
    assert open_counts(current)["High"] == 2  # the false positive is not counted


def test_apply_history_reopens_fixed():
    prev = dict(code_finding())
    prev.update(fingerprint=fingerprint(prev), status="fixed", status_note=None)
    current = [code_finding()]
    apply_history(current, [prev])
    assert current[0]["status"] == "open" and "found again" in current[0]["status_note"]


def test_cvss_from_trivy_and_estimated_fallback():
    data = {"Results": [{"Target": "requirements.txt", "Vulnerabilities": [{
        "VulnerabilityID": "CVE-2023-30861", "PkgName": "flask", "InstalledVersion": "2.0.1",
        "Severity": "HIGH", "CVSS": {"nvd": {"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                             "V3Score": 7.5}}}]}]}
    f = parse_trivy_vulns(data)[0]
    assert f["cvss_score"] == 7.5 and f["cvss_source"] == "scanner" and f["cvss_vector"].startswith("CVSS:3.1")
    est = code_finding(sev="Medium")
    assert est["cvss_score"] == 5.3 and est["cvss_source"] == "estimated"


def test_csv_neutralises_formulas():
    f = code_finding()
    f.update(fingerprint="x", status="open", is_new=True, title="=HYPERLINK(\"http://evil\")")
    out = to_csv([f])
    assert "'=HYPERLINK" in out
    assert out.splitlines()[0].startswith("severity,cvss_score")


def test_sarif_structure_and_suppression():
    f = code_finding()
    f.update(fingerprint="abc", status="false_positive", status_note="test code", is_new=False)
    sarif = to_sarif({"project": {"source_type": "git"}}, [f])
    json.dumps(sarif)
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    assert run["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 10
    assert run["results"][0]["suppressions"][0]["justification"] == "test code"
    assert run["tool"]["driver"]["rules"][0]["id"] == "python.sqli"
