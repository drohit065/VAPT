"""Tests for live URL scanning: target validation, web check analysis and the Nuclei parser."""
import pytest

from app.normalize import parse_nuclei
from app.security import ValidationError, validate_target_url, validate_targets
from app.worker.dast import (
    CORS_PROBE_ORIGIN,
    Resp,
    api_docs_finding,
    cookie_findings,
    cors_findings,
    detect_tech,
    directory_listing_finding,
    header_findings,
    path_finding,
    tls_findings,
    trace_findings,
    transport_findings,
)

REQUIRED = {"severity", "title", "file_path", "line", "snippet", "description", "exploitation",
            "recommendation", "cwe", "owasp", "scanners", "rule_id", "check"}


def html(headers=(), body=b"<html></html>", status=200, url="https://app.example.com/"):
    return Resp(url, status, [("content-type", "text/html; charset=utf-8"), *headers], body)


# ---------------------------------------------------------------- target validation


@pytest.mark.parametrize("url,expected", [
    ("https://app.example.com", "https://app.example.com/"),
    ("HTTPS://App.Example.com:443/login?x=1#frag", "https://app.example.com/login?x=1"),
    ("http://api.example.com:8080/health", "http://api.example.com:8080/health"),
    ("https://8.8.8.8/", "https://8.8.8.8/"),
])
def test_valid_targets(url, expected):
    assert validate_target_url(url) == expected


@pytest.mark.parametrize("url", [
    "ftp://example.com/", "file:///etc/passwd", "https://user:pw@example.com/",
    "http://127.0.0.1/", "http://10.0.0.5/", "http://169.254.169.254/latest/meta-data/",
    "http://[::1]/", "https://localhost/", "https://exa mple.com/", "javascript:alert(1)", "",
])
def test_invalid_targets(url):
    with pytest.raises(ValidationError):
        validate_target_url(url)


def test_validate_targets_list():
    assert validate_targets("https://a.example.com\nhttps://a.example.com/, https://b.example.com") == [
        "https://a.example.com/", "https://b.example.com/"]
    with pytest.raises(ValidationError):
        validate_targets("\n".join(f"https://h{i}.example.com" for i in range(6)))
    with pytest.raises(ValidationError):
        validate_targets("  ")


# ---------------------------------------------------------------- header / cookie analysis


def _rules(findings):
    return {f["rule_id"] for f in findings}


def test_missing_headers_on_html_page():
    found = header_findings("https://app.example.com/", html())
    assert {"web.hsts-missing", "web.csp-missing", "web.clickjacking", "web.nosniff-missing",
            "web.referrer-policy-missing"} <= _rules(found)
    for f in found:
        assert REQUIRED <= f.keys()
        assert f["check"] == "web" and f["scanners"] == ["vapt-web"] and f["line"] is None


def test_well_configured_page_has_no_header_findings():
    resp = html([
        ("strict-transport-security", "max-age=31536000"),
        ("content-security-policy", "default-src 'self'; frame-ancestors 'none'"),
        ("x-content-type-options", "nosniff"), ("referrer-policy", "no-referrer"), ("server", "nginx"),
    ])
    assert header_findings("https://app.example.com/", resp) == []


def test_api_json_response_skips_html_only_checks():
    resp = Resp("https://api.example.com/", 200, [("content-type", "application/json")], b"{}")
    rules = _rules(header_findings("https://api.example.com/", resp))
    assert "web.csp-missing" not in rules and "web.clickjacking" not in rules
    assert "web.hsts-missing" in rules


def test_version_disclosure():
    resp = html([("server", "Apache/2.4.49 (Unix)"), ("x-powered-by", "PHP/7.4.3")])
    f = [x for x in header_findings("https://app.example.com/", resp) if x["rule_id"] == "web.version-disclosure"]
    assert f and "Apache/2.4.49" in f[0]["snippet"] and "PHP/7.4.3" in f[0]["snippet"]


def test_cookie_flags_and_value_never_stored():
    resp = html([("set-cookie", "sessionid=SUPERSECRETVALUE123; Path=/"),
                 ("set-cookie", "theme=dark; Path=/; Secure; HttpOnly; SameSite=Lax")])
    found = cookie_findings("https://app.example.com/", resp)
    assert len(found) == 1
    assert found[0]["severity"] == "Medium"
    assert "SUPERSECRETVALUE123" not in found[0]["snippet"]
    assert "Secure" in found[0]["title"] and "HttpOnly" in found[0]["title"]


# ---------------------------------------------------------------- CORS, TRACE, transport, TLS


def test_cors_reflection_with_credentials_is_high():
    resp = Resp("https://api.example.com/", 200, [("access-control-allow-origin", CORS_PROBE_ORIGIN),
                                                  ("access-control-allow-credentials", "true")])
    found = cors_findings("https://api.example.com/", resp)
    assert found[0]["severity"] == "High" and found[0]["cwe"] == "CWE-942"


def test_cors_wildcard_is_not_reported():
    resp = Resp("https://api.example.com/", 200, [("access-control-allow-origin", "*")])
    assert cors_findings("https://api.example.com/", resp) == []


def test_trace():
    assert trace_findings("https://a.example.com/", Resp("u", 200, [], b"TRACE / HTTP/1.1\r\nHost: a")) != []
    assert trace_findings("https://a.example.com/", Resp("u", 405, [], b"")) == []


def test_transport():
    plain = Resp("http://a.example.com/", 200, [])
    redirect = Resp("http://a.example.com/", 301, [("location", "https://a.example.com/")])
    assert transport_findings("http://a.example.com/", plain, https_ok=False)[0]["severity"] == "High"
    assert transport_findings("http://a.example.com/", plain, https_ok=True)[0]["rule_id"] == "web.no-https-redirect"
    assert transport_findings("http://a.example.com/", redirect, https_ok=True) == []


def test_tls():
    assert tls_findings("https://a.example.com/", {"valid": False, "error": "certificate has expired"})[0]["severity"] == "High"
    assert tls_findings("https://a.example.com/", {"valid": True, "days_left": 90, "version": "TLSv1.3"}) == []
    rules = _rules(tls_findings("https://a.example.com/", {"valid": True, "days_left": 3, "version": "TLSv1.1",
                                                          "not_after": "x"}))
    assert rules == {"web.tls-expiring", "web.tls-old-protocol"}


# ---------------------------------------------------------------- exposed paths


def test_git_config_exposed():
    r = Resp("https://a.example.com/.git/config", 200, [("content-type", "text/plain")],
             b"[core]\n\trepositoryformatversion = 0\n")
    f = path_finding("https://a.example.com", "/.git/config", r)
    assert f and f["severity"] == "High" and f["file_path"] == "https://a.example.com/.git/config"


def test_spa_catch_all_is_not_a_false_positive():
    spa = html(body=b"<html><div id=root></div></html>", url="https://a.example.com/.git/config")
    assert path_finding("https://a.example.com", "/.git/config", spa) is None
    assert path_finding("https://a.example.com", "/.env", spa) is None


def test_env_file_values_are_not_stored():
    r = Resp("https://a.example.com/.env", 200, [("content-type", "text/plain")],
             b"DB_PASSWORD=hunter2hunter2\nAWS_SECRET_ACCESS_KEY=abcdEFGHijklMNOP\n")
    f = path_finding("https://a.example.com", "/.env", r)
    assert f and "DB_PASSWORD" in f["snippet"]
    assert "hunter2" not in f["snippet"] and "abcdEFGH" not in f["snippet"]


def test_directory_listing_and_api_docs():
    assert directory_listing_finding("https://a.example.com/", html(body=b"<title>Index of /</title>")) != []
    assert directory_listing_finding("https://a.example.com/", html()) == []
    f = api_docs_finding("https://a.example.com", ["/v3/api-docs", "/swagger-ui.html"])
    assert len(f) == 1 and "/v3/api-docs" in f[0]["snippet"]
    assert api_docs_finding("https://a.example.com", []) == []


def test_detect_tech():
    r = html([("server", "nginx/1.25.3"), ("x-powered-by", "Next.js")], body=b'<script id="__NEXT_DATA__">')
    tech = detect_tech(r)
    assert "nginx/1.25.3" in tech and "Next.js" in tech


# ---------------------------------------------------------------- Nuclei parser


def test_parse_nuclei():
    records = [
        {"template-id": "CVE-2021-41773", "matched-at": "https://a.example.com/cgi-bin/.%2e/etc/passwd",
         "matcher-name": "passwd", "extracted-results": ["root:x:0:0:root:/root:/bin/bash"],
         "info": {"name": "Apache 2.4.49 - Path Traversal", "severity": "critical",
                  "description": "Path traversal in Apache 2.4.49.", "reference": ["https://nvd.nist.gov/x"],
                  "remediation": "Upgrade Apache.",
                  "classification": {"cve-id": ["cve-2021-41773"], "cwe-id": ["cwe-22"]}}},
        {"template-id": "tech-detect", "matched-at": "https://a.example.com/", "info": {"severity": "info"}},
    ]
    found = parse_nuclei(records)
    assert len(found) == 1
    f = found[0]
    assert REQUIRED <= f.keys()
    assert f["severity"] == "Critical" and f["cwe"] == "CWE-22" and f["check"] == "nuclei"
    assert "CVE-2021-41773" in f["title"] and f["recommendation"] == "Upgrade Apache."
    assert f["owasp"].startswith("A01")
    assert "root:x:0:0:root:/root:/bin/bash" not in f["snippet"]  # long extracted values are truncated
    assert f["file_path"].startswith("https://a.example.com/")


# ---------------------------------------------------------------- authenticated scanning / access control

from app.security import parse_auth_headers, validate_endpoints  # noqa: E402
from app.worker.dast import authz_findings, similar  # noqa: E402


def test_parse_auth_headers():
    h = parse_auth_headers("Authorization: Bearer abc.def\n\nCookie: s=1; t=2\n")
    assert h == {"Authorization": "Bearer abc.def", "Cookie": "s=1; t=2"}
    for bad in ("NoColonHere", "Host: evil.example", "Bad Name: x", "X-A: line\rinjection",
                "\n".join(f"X-H{i}: v" for i in range(6))):
        with pytest.raises(ValidationError):
            parse_auth_headers(bad)
    assert parse_auth_headers("") == {}


def test_validate_endpoints_same_host_only():
    targets = ["https://api.example.com/", "https://app.example.com/"]
    eps = validate_endpoints("/api/me\nhttps://app.example.com/orders/1\n/api/me", targets)
    assert eps == ["https://api.example.com/api/me", "https://app.example.com/orders/1"]
    with pytest.raises(ValidationError):
        validate_endpoints("https://other.example.org/x", targets)


def _json(body, status=200):
    return Resp("https://api.example.com/api/orders/1", status, [("content-type", "application/json")], body)


ORDER = b'{"id": 1, "owner": "alice", "items": [{"sku": "A1", "qty": 2}], "address": "1 Main St"}'


def test_authz_no_auth_access_is_high():
    f = authz_findings("https://api.example.com/api/orders/1", _json(ORDER), _json(ORDER), None)
    assert len(f) == 1 and f[0]["severity"] == "High" and f[0]["cwe"] == "CWE-306"


def test_authz_cross_user_idor():
    f = authz_findings("https://api.example.com/api/orders/1", _json(ORDER), _json(b'{"error":"unauthorized"}', 401),
                       _json(ORDER))
    assert len(f) == 1 and f[0]["rule_id"] == "web.authz-cross-user" and f[0]["cwe"] == "CWE-639"


def test_authz_properly_protected():
    assert authz_findings("https://api.example.com/api/orders/1", _json(ORDER), _json(b"{}", 401),
                          _json(b'{"error":"forbidden"}', 403)) == []
    # user B gets their own, different data: fine
    other = b'{"id": 2, "owner": "bob", "items": [{"sku": "Z9", "qty": 7}], "address": "9 Elm Rd"}'
    assert authz_findings("https://api.example.com/api/orders/1", _json(ORDER), _json(b"{}", 401), _json(other)) == []


def test_authz_public_paths_are_downgraded():
    url = "https://api.example.com/health"
    r = Resp(url, 200, [], b'{"status": "UP", "components": {"db": "UP", "disk": "UP"}}')
    assert authz_findings(url, r, r, None)[0]["severity"] == "Low"


def test_similar():
    assert similar(ORDER, ORDER)
    assert similar(ORDER, ORDER.replace(b"1 Main St", b"1 Main Sx"))
    assert not similar(ORDER, b'{"error": "forbidden"}')
