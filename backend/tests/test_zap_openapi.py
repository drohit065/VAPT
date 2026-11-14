"""Tests for ZAP alert normalisation and OpenAPI discovery helpers."""
import json

from app.worker.dast import parse_spec, spec_candidates, spec_get_endpoints
from app.worker.zap import alerts_to_findings

REQUIRED = {"severity", "title", "file_path", "line", "snippet", "description", "exploitation",
            "recommendation", "cwe", "owasp", "scanners", "rule_id", "check"}


def alert(**kw):
    base = {"pluginId": "40018", "alert": "SQL Injection", "risk": "High", "confidence": "Medium",
            "url": "https://api.example.com/items?id=1", "param": "id", "attack": "1' OR '1'='1",
            "evidence": "SQL syntax error", "cweid": "89", "description": "SQL injection may be possible.",
            "solution": "Use prepared statements.", "reference": "https://owasp.org/sqli\n", "method": "GET"}
    base.update(kw)
    return base


def test_alerts_grouped_per_rule_and_site():
    alerts = [alert(), alert(url="https://api.example.com/orders?id=2"),
              alert(pluginId="10202", alert="Absence of Anti-CSRF Tokens", risk="Medium", cweid="352",
                    url="https://api.example.com/form")]
    found = alerts_to_findings(alerts, skip_covered=False)
    assert len(found) == 2
    sqli = next(f for f in found if f["rule_id"] == "zap.40018")
    assert REQUIRED <= sqli.keys()
    assert sqli["severity"] == "High" and sqli["cwe"] == "CWE-89" and sqli["check"] == "zap"
    assert sqli["file_path"] == "https://api.example.com"
    assert "/items?id=1" in sqli["snippet"] and "/orders?id=2" in sqli["snippet"]
    assert "2 location(s)" in sqli["description"]
    assert sqli["owasp"].startswith("A03")


def test_confirmed_injection_is_critical():
    f = alerts_to_findings([alert(confidence="High")], skip_covered=False)[0]
    assert f["severity"] == "Critical"


def test_informational_false_positive_and_covered_rules_skipped():
    alerts = [alert(risk="Informational"), alert(confidence="False Positive"),
              alert(pluginId="10038", alert="CSP Header Not Set", risk="Medium", cweid="693")]
    assert alerts_to_findings(alerts, skip_covered=True) == []
    assert len(alerts_to_findings(alerts, skip_covered=False)) == 1


def test_spec_candidates_from_swagger_ui_path():
    c = spec_candidates("https://api.example.com/app-server/swagger-ui/index.html")
    assert c[0] == "https://api.example.com/app-server/v3/api-docs"
    assert "https://api.example.com/v3/api-docs" in c


def test_parse_spec_and_get_endpoints():
    doc = {"openapi": "3.0.1", "servers": [{"url": "https://api.example.com/app-server"}],
           "paths": {"/api/me": {"get": {}}, "/api/orders/{id}": {"get": {}}, "/api/login": {"post": {}},
                     "/api/products": {"get": {}, "post": {}}}}
    assert parse_spec(json.dumps(doc).encode()) == doc
    assert parse_spec(b"<html>") is None and parse_spec(b'{"foo": 1}') is None
    eps = spec_get_endpoints(doc, "https://api.example.com/app-server/v3/api-docs", {"api.example.com"})
    assert eps == ["https://api.example.com/app-server/api/me", "https://api.example.com/app-server/api/products"]


def test_spec_servers_on_other_hosts_are_ignored():
    doc = {"openapi": "3.0.1", "servers": [{"url": "http://10.0.0.5:8080/internal"}], "paths": {"/a": {"get": {}}}}
    eps = spec_get_endpoints(doc, "https://api.example.com/v3/api-docs", {"api.example.com"})
    assert eps == ["https://api.example.com/a"]
