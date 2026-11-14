"""Tests for the hardening fixes: scanner suppression files, secret snippet masking, sign-out."""
import os

from app.normalize import make_finding, mask_secret_snippet, redact_findings
from app.worker.pipeline import neutralize_suppressions


def test_suppression_files_are_moved_aside(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / ".gitleaks.toml").write_text("[allowlist]\npaths=['.*']\n")
    (tmp_path / ".semgrepignore").write_text("*\n")
    (tmp_path / "sub" / ".gitleaksignore").write_text("abc:file:1\n")
    (tmp_path / "app.py").write_text("x = 1\n")
    found = neutralize_suppressions(str(tmp_path))
    assert found == [".gitleaks.toml", ".semgrepignore", os.path.join("sub", ".gitleaksignore")]
    assert not (tmp_path / ".gitleaks.toml").exists()
    assert (tmp_path / ".vapt-ignored.gitleaks.toml").exists()
    assert (tmp_path / "app.py").exists()


def test_mask_secret_snippet_hides_literals_and_tokens():
    snippet = '12 | const k = "ghp_abcdefghijklmnopqrstuvwxyz123456";\n13 | client(KEY=AKIAABCDEFGHIJKLMNOPQRST)'
    out = mask_secret_snippet(snippet)
    assert "ghp_abc" not in out and "AKIAABCDEFGH" not in out
    assert out.startswith("12 | const k = ") and "13 | client(KEY=REDACTED)" in out


def test_semgrep_secret_rule_masked_without_gitleaks():
    f = make_finding(severity="High", title="Detected github token", file_path="a.js", line=1,
                     snippet='1 | const k = "ghp_abcdefghijklmnopqrstuvwxyz123456"', description="",
                     check="code", scanner="semgrep", rule_id="generic.secrets.security.detected-github-token")
    other = make_finding(severity="High", title="SQLi", file_path="a.py", line=1,
                         snippet='1 | q = "SELECT * FROM users WHERE id=" + uid', description="",
                         check="code", scanner="semgrep", rule_id="python.lang.security.sqli")
    redact_findings([f, other], secrets=[])
    assert "ghp_" not in f["snippet"]
    assert "SELECT * FROM users" in other["snippet"]  # ordinary code stays readable
