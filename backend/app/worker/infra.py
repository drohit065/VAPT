"""Infrastructure checks with nmap: TLS protocols/ciphers and open ports / exposed services.

nmap always targets the IP address that was validated as public for the target host (never a name
it would resolve again), runs as an unprivileged TCP connect scan (-sT) and writes XML that is
parsed here. Parsing functions are pure and unit tested.
"""
from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit

from ..knowledge import A02, A05
from ..normalize import make_finding

# port -> (service, severity, why it matters)
RISKY_PORTS = {
    21: ("FTP", "High", "FTP sends credentials and data unencrypted and is a frequent brute-force target."),
    23: ("Telnet", "High", "Telnet sends credentials in clear text and should never face the internet."),
    135: ("MS RPC", "High", "Windows RPC exposed to the internet is a common entry point for worms."),
    139: ("NetBIOS/SMB", "High", "SMB exposed to the internet enables ransomware-style exploits (e.g. EternalBlue)."),
    445: ("SMB", "High", "SMB exposed to the internet enables ransomware-style exploits (e.g. EternalBlue)."),
    1433: ("Microsoft SQL Server", "High", "A database port open to the internet invites brute force and exploits."),
    1521: ("Oracle DB", "High", "A database port open to the internet invites brute force and exploits."),
    2375: ("Docker API (no TLS)", "Critical", "An unauthenticated Docker API gives full control of the host."),
    2376: ("Docker API (TLS)", "Medium", "The Docker API should only be reachable from management networks."),
    2379: ("etcd", "Critical", "etcd often holds cluster secrets and may allow unauthenticated reads/writes."),
    3306: ("MySQL", "High", "A database port open to the internet invites brute force and exploits."),
    3389: ("RDP", "High", "RDP exposed to the internet is a top ransomware entry point (brute force, BlueKeep)."),
    5432: ("PostgreSQL", "High", "A database port open to the internet invites brute force and exploits."),
    5601: ("Kibana", "Medium", "Kibana can expose log data and has had remote code execution flaws."),
    5672: ("RabbitMQ", "Medium", "Message brokers should not be reachable from the internet."),
    5900: ("VNC", "High", "VNC often has weak or no authentication and gives full desktop control."),
    5984: ("CouchDB", "High", "CouchDB has had unauthenticated admin and RCE flaws."),
    6379: ("Redis", "High", "Redis frequently runs without authentication; exposed instances are hijacked within hours."),
    6443: ("Kubernetes API", "High", "The Kubernetes API server should only be reachable from trusted networks."),
    8500: ("Consul", "High", "Consul's HTTP API can allow remote command execution when exposed."),
    9090: ("Prometheus", "Medium", "Prometheus exposes internal metrics, hostnames and sometimes secrets."),
    9200: ("Elasticsearch", "High", "Elasticsearch without authentication leaks all indexed data."),
    9300: ("Elasticsearch transport", "High", "The Elasticsearch transport port should never face the internet."),
    10250: ("Kubelet", "High", "An exposed kubelet can allow command execution in pods."),
    11211: ("Memcached", "High", "Exposed memcached leaks cached data and is abused for DDoS amplification."),
    15672: ("RabbitMQ management", "Medium", "Admin consoles should not be reachable from the internet."),
    27017: ("MongoDB", "High", "MongoDB without authentication has caused many mass data leaks."),
    22: ("SSH", "Low", "SSH is exposed to the internet; make sure only key-based login is allowed and limit source IPs."),
}
WEB_PORTS = {80, 443}
# Well-known ports 1-1024, every port in RISKY_PORTS (several, e.g. Redis 6379 or MongoDB 27017, are not in
# nmap's "top 1000") and common alternative web / admin ports.
PORT_SPEC = ",".join(["1-1024", "3000", "5000", "7001", "8000-8100", "8443", "8888", "9000-9100"]
                     + [str(p) for p in sorted(RISKY_PORTS) if p > 1024])
CDN_MARKERS = (("server", "cloudflare"), ("server", "akamaighost"), ("server", "cloudfront"), ("via", "cloudfront"),
               ("x-amz-cf-id", ""), ("cf-ray", ""), ("x-akamai-transformed", ""), ("x-served-by", "cache-"),
               ("server", "sucuri"), ("x-sucuri-id", ""), ("server", "imperva"), ("x-cdn", ""))


def behind_cdn(headers: list[tuple[str, str]]) -> str | None:
    for name, needle in CDN_MARKERS:
        for k, v in headers:
            if k == name and needle in v.lower():
                return f"{k}: {v[:60]}"
    return None


# ---------------------------------------------------------------- parsing (pure)


def parse_ports_xml(xml_text: str) -> list[dict]:
    """Open TCP ports from nmap -oX output: [{port, service, product, version, extrainfo}]."""
    out = []
    root = ET.fromstring(xml_text)
    for port in root.iter("port"):
        state = port.find("state")
        if port.get("protocol") != "tcp" or state is None or state.get("state") != "open":
            continue
        svc = port.find("service")
        out.append({
            "port": int(port.get("portid")),
            "service": (svc.get("name") if svc is not None else "") or "",
            "product": (svc.get("product") if svc is not None else "") or "",
            "version": (svc.get("version") if svc is not None else "") or "",
            "extrainfo": (svc.get("extrainfo") if svc is not None else "") or "",
        })
    return out


def port_findings(host: str, ip: str, ports: list[dict], expected: set[int]) -> list[dict]:
    out = []
    for p in ports:
        n = p["port"]
        if n in expected or n in WEB_PORTS and n not in RISKY_PORTS:
            continue
        banner = " ".join(x for x in (p["product"], p["version"], p["extrainfo"]) if x).strip()
        evidence = f"{ip}:{n}/tcp open  {p['service'] or '?'}" + (f"  ({banner})" if banner else "")
        where = f"{host} ({ip}):{n}/tcp"
        if n in RISKY_PORTS:
            name, sev, why = RISKY_PORTS[n]
            title = f"{name} port {n} is open to the internet"
        else:
            name, sev = (p["service"] or "unknown service"), "Low"
            why = "A port that is not part of the website is reachable from the internet."
            title = f"Unexpected open port {n} ({name})"
        out.append(make_finding(
            severity=sev, title=title, file_path=where, line=None, snippet=evidence,
            description=f"{why} Detected service: {banner or p['service'] or 'unknown'}.",
            check="ports", scanner="nmap", rule_id=f"ports.{n}", cwe="CWE-668", owasp=A05,
            exploitation="Attackers scan the whole internet continuously; exposed management, database and "
                         "file-sharing ports are found within hours and attacked with brute force or known exploits.",
            recommendation="Close the port in the firewall / security group, or allow it only from specific "
                           "trusted IP ranges or a VPN. Bind internal services to private interfaces.",
        ))
    return out


WEAK_GRADES = {"C": "Medium", "D": "Medium", "E": "High", "F": "High"}


def parse_tls_xml(xml_text: str) -> dict:
    """ssl-enum-ciphers output -> {"protocols": {name: [ciphers]}, "least": grade, "warnings": [...],
    "weak": [(protocol, cipher, grade)]}."""
    root = ET.fromstring(xml_text)
    res = {"protocols": {}, "least": None, "warnings": [], "weak": []}
    script = next((s for s in root.iter("script") if s.get("id") == "ssl-enum-ciphers"), None)
    if script is None:
        return res
    for elem in script.findall("elem"):
        if elem.get("key") == "least strength":
            res["least"] = (elem.text or "").strip()
    for proto in script.findall("table"):
        pname = proto.get("key")
        ciphers = []
        for t in proto.findall("table"):
            if t.get("key") == "ciphers":
                for c in t.findall("table"):
                    name = next((e.text for e in c.findall("elem") if e.get("key") == "name"), "")
                    grade = next((e.text for e in c.findall("elem") if e.get("key") == "strength"), "")
                    ciphers.append(name)
                    if grade in WEAK_GRADES:
                        res["weak"].append((pname, name, grade))
            if t.get("key") == "warnings":
                res["warnings"] += [(e.text or "").strip() for e in t.findall("elem") if e.text]
        res["protocols"][pname] = ciphers
    res["warnings"] = sorted(set(res["warnings"]))
    return res


def tls_enum_findings(url: str, info: dict) -> list[dict]:
    out = []
    protos = set(info.get("protocols") or {})
    where = urlsplit(url).netloc
    listing = "\n".join(f"{p}: {len(c)} cipher(s)" for p, c in sorted((info.get("protocols") or {}).items()))
    old = sorted(p for p in protos if p in ("SSLv3", "TLSv1.0", "TLSv1.1"))
    if old:
        sev = "High" if "SSLv3" in old else "Medium"
        out.append(make_finding(
            severity=sev, title=f"Deprecated protocol(s) enabled: {', '.join(old)}", file_path=f"https://{where}",
            line=None, snippet=listing, check="tls", scanner="nmap", rule_id="tls.old-protocols", cwe="CWE-327",
            owasp=A02, description="The server still accepts deprecated SSL/TLS versions.",
            exploitation="Downgrade and protocol attacks (POODLE, BEAST) can let a network attacker decrypt traffic; "
                         "PCI DSS and most compliance standards forbid these versions.",
            recommendation="Allow only TLS 1.2 and TLS 1.3 on the server or load balancer "
                           "(e.g. AWS ELB policy ELBSecurityPolicy-TLS13-1-2-2021-06).",
        ))
    weak = info.get("weak") or []
    if weak or info.get("warnings"):
        worst = max((g for _, _, g in weak), default=info.get("least") or "C")
        sev = WEAK_GRADES.get(worst, "Medium")
        lines = [f"{p}  {c}  (grade {g})" for p, c, g in weak[:15]] + [f"warning: {w}" for w in info["warnings"][:10]]
        out.append(make_finding(
            severity=sev, title=f"Weak TLS ciphers accepted (least strength: {info.get('least') or worst})",
            file_path=f"https://{where}", line=None, snippet="\n".join(lines), check="tls", scanner="nmap",
            rule_id="tls.weak-ciphers", cwe="CWE-326", owasp=A02,
            description="The server accepts cipher suites that are weak or have known problems "
                        "(e.g. 3DES/SWEET32, RC4, CBC with SHA1, no forward secrecy).",
            exploitation="A network attacker may be able to recover parts of encrypted traffic or force a weak cipher.",
            recommendation="Disable weak cipher suites; prefer ECDHE with AES-GCM or ChaCha20-Poly1305.",
        ))
    return out


# ---------------------------------------------------------------- orchestration


def run_tls(targets, out_dir, home, budget, run_tool) -> tuple[list[dict], str]:
    findings, scanned = [], 0
    seen = set()
    for t in targets:
        p = urlsplit(t.url)
        if p.scheme != "https" or (p.netloc in seen):
            continue
        seen.add(p.netloc)
        port = p.port or 443
        out = os.path.join(out_dir, f"tls-{scanned}.xml")
        cmd = ["nmap", "-sT", "-Pn", "-n", "-p", str(port), "--script", "ssl-enum-ciphers",
               "--script-args", f"tls.servername={p.hostname}", "-oX", out, t.ip]
        run_tool(cmd, out_dir, home, min(budget(), 300))
        scanned += 1
        if os.path.exists(out):
            with open(out, encoding="utf-8", errors="replace") as fh:
                findings += tls_enum_findings(t.url, parse_tls_xml(fh.read()))
    if not scanned:
        return [], "No https:// targets"
    return findings, f"{len(findings)} issue(s) on {scanned} TLS endpoint(s)"


def run_ports(targets, out_dir, home, budget, run_tool) -> tuple[list[dict], str, list[str]]:
    findings, notes, scanned = [], [], 0
    by_ip: dict[str, tuple] = {}
    for t in targets:
        cdn = behind_cdn(t.resp.headers)
        host = urlsplit(t.url).hostname
        if cdn:
            notes.append(f"Port scan skipped for {host}: it is behind a CDN/WAF ({cdn}), so the scan would only "
                         "reach the CDN. Scan the origin server's address directly if you are allowed to.")
            continue
        p = urlsplit(t.url)
        by_ip.setdefault(t.ip, (host, set()))[1].add(p.port or (443 if p.scheme == "https" else 80))
    for ip, (host, expected) in by_ip.items():
        if budget() < 120:
            notes.append(f"Port scan of {host} skipped: time limit.")
            continue
        out = os.path.join(out_dir, f"ports-{scanned}.xml")
        cmd = ["nmap", "-sT", "-Pn", "-n", "-p", PORT_SPEC, "-sV", "--version-light", "-T3",
               "--max-retries", "1", "--host-timeout", f"{int(min(budget() - 60, 900))}s", "-oX", out, ip]
        run_tool(cmd, out_dir, home, min(budget(), 960))
        scanned += 1
        if os.path.exists(out):
            with open(out, encoding="utf-8", errors="replace") as fh:
                ports = parse_ports_xml(fh.read())
            findings += port_findings(host, ip, ports, expected)
            notes.append(f"Open TCP ports on {host} ({ip}): " + (", ".join(str(p["port"]) for p in ports) or "none"))
    detail = f"{len(findings)} issue(s) on {scanned} host(s)" if scanned else "No hosts scanned"
    return findings, detail, notes
