"""Tests for nmap XML parsing and infrastructure findings."""
from app.worker.infra import (
    behind_cdn,
    parse_ports_xml,
    parse_tls_xml,
    port_findings,
    tls_enum_findings,
)

PORTS_XML = """<?xml version="1.0"?>
<nmaprun><host><address addr="203.0.113.10" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9p1"/></port>
<port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx"/></port>
<port protocol="tcp" portid="6379"><state state="open"/><service name="redis" product="Redis key-value store" version="6.0.16"/></port>
<port protocol="tcp" portid="8081"><state state="open"/><service name="http-proxy"/></port>
<port protocol="tcp" portid="3306"><state state="filtered"/><service name="mysql"/></port>
</ports></host></nmaprun>"""

TLS_XML = """<?xml version="1.0"?>
<nmaprun><host><ports><port protocol="tcp" portid="443"><state state="open"/>
<script id="ssl-enum-ciphers" output="...">
  <table key="TLSv1.0">
    <table key="ciphers">
      <table><elem key="name">TLS_RSA_WITH_3DES_EDE_CBC_SHA</elem><elem key="strength">C</elem></table>
      <table><elem key="name">TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA</elem><elem key="strength">A</elem></table>
    </table>
    <table key="warnings"><elem>64-bit block cipher 3DES vulnerable to SWEET32 attack</elem></table>
  </table>
  <table key="TLSv1.2">
    <table key="ciphers">
      <table><elem key="name">TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384</elem><elem key="strength">A</elem></table>
    </table>
  </table>
  <elem key="least strength">C</elem>
</script></port></ports></host></nmaprun>"""

GOOD_TLS_XML = """<?xml version="1.0"?><nmaprun><host><ports><port protocol="tcp" portid="443">
<script id="ssl-enum-ciphers"><table key="TLSv1.2"><table key="ciphers">
<table><elem key="name">TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384</elem><elem key="strength">A</elem></table>
</table></table><table key="TLSv1.3"><table key="ciphers">
<table><elem key="name">TLS_AKE_WITH_AES_256_GCM_SHA384</elem><elem key="strength">A</elem></table>
</table></table><elem key="least strength">A</elem></script></port></ports></host></nmaprun>"""


def test_parse_ports_only_open_tcp():
    ports = parse_ports_xml(PORTS_XML)
    assert [p["port"] for p in ports] == [22, 443, 6379, 8081]
    assert ports[2]["product"] == "Redis key-value store" and ports[2]["version"] == "6.0.16"


def test_port_findings():
    found = port_findings("api.example.com", "203.0.113.10", parse_ports_xml(PORTS_XML), expected={443})
    by_port = {f["rule_id"]: f for f in found}
    assert set(by_port) == {"ports.22", "ports.6379", "ports.8081"}
    assert by_port["ports.6379"]["severity"] == "High" and "Redis" in by_port["ports.6379"]["title"]
    assert by_port["ports.22"]["severity"] == "Low"
    assert by_port["ports.8081"]["severity"] == "Low" and "Unexpected" in by_port["ports.8081"]["title"]
    assert by_port["ports.6379"]["file_path"] == "api.example.com (203.0.113.10):6379/tcp"
    assert all(f["check"] == "ports" and f["scanners"] == ["nmap"] for f in found)


def test_parse_tls_and_findings():
    info = parse_tls_xml(TLS_XML)
    assert set(info["protocols"]) == {"TLSv1.0", "TLSv1.2"} and info["least"] == "C"
    assert info["weak"] == [("TLSv1.0", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "C")]
    found = tls_enum_findings("https://api.example.com/", info)
    rules = {f["rule_id"]: f for f in found}
    assert rules["tls.old-protocols"]["severity"] == "Medium" and "TLSv1.0" in rules["tls.old-protocols"]["title"]
    assert "SWEET32" in rules["tls.weak-ciphers"]["snippet"]


def test_good_tls_has_no_findings():
    assert tls_enum_findings("https://api.example.com/", parse_tls_xml(GOOD_TLS_XML)) == []


def test_cdn_detection():
    assert behind_cdn([("server", "cloudflare"), ("cf-ray", "abc")])
    assert behind_cdn([("x-amz-cf-id", "xyz")])
    assert behind_cdn([("server", "nginx/1.25")]) is None


def test_port_spec_covers_all_risky_ports():
    from app.worker.infra import PORT_SPEC, RISKY_PORTS
    ports = set()
    for part in PORT_SPEC.split(","):
        a, _, b = part.partition("-")
        ports.update(range(int(a), int(b or a) + 1))
    assert set(RISKY_PORTS) <= ports and 6379 in ports and 27017 in ports
