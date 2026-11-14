"""Live URL checks (DAST) for targets the operator is authorised to test.

Sends ordinary HTTP requests only (GET, HEAD-like GETs of well-known paths, one OPTIONS-style
CORS probe and one TRACE). Never follows redirects, never submits forms, never brute-forces.
Every connection is pinned to an address that was validated as public, so DNS changes
between the check and the request cannot redirect the scanner to internal networks.

The analysis functions (`*_findings`) are pure and unit tested; `fetch` does the network I/O.
"""
from __future__ import annotations

import difflib
import http.client
import json
import re
import socket
import ssl
import time
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from ..knowledge import A02, A05, A07
from ..normalize import make_finding, mask_assignments
from ..security import assert_public_target

USER_AGENT = "VAPT-Scanner/1.0 (authorised security test)"
MAX_BODY = 256 * 1024
TIMEOUT = 10
CORS_PROBE_ORIGIN = "https://cors-probe.vapt-scanner.invalid"
SESSION_COOKIE_RE = re.compile(r"sess|sid|token|auth|jwt|login|remember", re.I)


class TargetError(Exception):
    pass


@dataclass
class Resp:
    url: str
    status: int
    headers: list[tuple[str, str]]  # lower-cased names, in order received
    body: bytes = b""
    method: str = "GET"

    def header(self, name: str) -> str | None:
        name = name.lower()
        return next((v for k, v in self.headers if k == name), None)

    def header_all(self, name: str) -> list[str]:
        name = name.lower()
        return [v for k, v in self.headers if k == name]

    @property
    def is_html(self) -> bool:
        return "text/html" in (self.header("content-type") or "").lower()

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def status_line(self) -> str:
        return f"{self.method} {self.url} -> HTTP {self.status}"


# ---------------------------------------------------------------- network


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, ip, port, timeout):
        super().__init__(host, port, timeout=timeout)
        self._ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, ip, port, timeout, context):
        super().__init__(host, port, timeout=timeout, context=context)
        self._ip = ip

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _context(verify: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def fetch(url: str, ip: str, method: str = "GET", headers: dict | None = None,
          verify: bool = True, timeout: float = TIMEOUT) -> Resp:
    """One request to `url`, connecting to the pre-validated `ip`. Redirects are not followed."""
    p = urlsplit(url)
    host = p.hostname or ""
    https = p.scheme == "https"
    port = p.port or (443 if https else 80)
    path = (p.path or "/") + (f"?{p.query}" if p.query else "")
    conn = (_PinnedHTTPS(host, ip, port, timeout, _context(verify)) if https
            else _PinnedHTTP(host, ip, port, timeout))
    try:
        conn.request(method, path, headers={"User-Agent": USER_AGENT, "Accept": "*/*", **(headers or {})})
        r = conn.getresponse()
        body = r.read(MAX_BODY)
        return Resp(url, r.status, [(k.lower(), v) for k, v in r.getheaders()], body, method)
    finally:
        conn.close()


def tls_info(url: str, ip: str, timeout: float = TIMEOUT) -> dict:
    """Certificate validity, days to expiry and negotiated protocol."""
    p = urlsplit(url)
    host, port = p.hostname or "", p.port or 443
    try:
        with socket.create_connection((ip, port), timeout) as sock:
            with _context(True).wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                days = (ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) / 86400
                return {"valid": True, "days_left": days, "version": tls.version(),
                        "not_after": cert["notAfter"], "error": None}
    except ssl.SSLCertVerificationError as e:
        return {"valid": False, "error": e.verify_message or str(e)}


def _origin(url: str) -> str:
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, "", "", ""))


# ---------------------------------------------------------------- helpers


def _finding(sev, slug, title, url, evidence, desc, exploit, fix, cwe, owasp=None) -> dict:
    return make_finding(severity=sev, title=title, file_path=url, line=None,
                        snippet=mask_assignments(evidence), description=desc, check="web",
                        scanner="vapt-web", rule_id=f"web.{slug}", cwe=cwe, owasp=owasp,
                        exploitation=exploit, recommendation=fix)


def _headers_evidence(resp: Resp, names: list[str]) -> str:
    lines = [resp.status_line()]
    for n in names:
        vals = resp.header_all(n)
        lines += [f"{n}: {v[:300]}" for v in vals] or [f"{n}: (not set)"]
    return "\n".join(lines)


# ---------------------------------------------------------------- analysis (pure)


def header_findings(url: str, resp: Resp) -> list[dict]:
    out = []
    https = url.startswith("https://")
    csp = resp.header("content-security-policy") or ""
    if https and not resp.header("strict-transport-security"):
        out.append(_finding(
            "Medium", "hsts-missing", "Strict-Transport-Security (HSTS) header missing", url,
            _headers_evidence(resp, ["strict-transport-security"]),
            "The site does not send an HSTS header, so browsers will still try plain HTTP first.",
            "An attacker on the same network (public Wi-Fi) can intercept the first HTTP request and "
            "downgrade the user to an unencrypted connection (SSL stripping) to read or alter traffic.",
            "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains' on all HTTPS responses.",
            "CWE-319", A02))
    if resp.is_html and not csp:
        out.append(_finding(
            "Medium", "csp-missing", "Content-Security-Policy header missing", url,
            _headers_evidence(resp, ["content-security-policy"]),
            "HTML pages are served without a Content Security Policy.",
            "If any cross-site scripting flaw exists, nothing stops injected scripts from running, "
            "loading code from attacker servers or sending session data out.",
            "Define a Content-Security-Policy that allows only your own script sources "
            "(e.g. default-src 'self'; object-src 'none'; frame-ancestors 'none').",
            "CWE-693", A05))
    if resp.is_html and not resp.header("x-frame-options") and "frame-ancestors" not in csp.lower():
        out.append(_finding(
            "Medium", "clickjacking", "Page can be framed by other sites (clickjacking)", url,
            _headers_evidence(resp, ["x-frame-options", "content-security-policy"]),
            "Neither X-Frame-Options nor a CSP frame-ancestors directive is set.",
            "An attacker embeds the page in an invisible frame on their own site and tricks a logged-in "
            "user into clicking buttons (e.g. change settings, confirm payments).",
            "Send 'X-Frame-Options: DENY' or a CSP with 'frame-ancestors 'none''.",
            "CWE-1021", A05))
    if (resp.header("x-content-type-options") or "").lower() != "nosniff":
        out.append(_finding(
            "Low", "nosniff-missing", "X-Content-Type-Options: nosniff missing", url,
            _headers_evidence(resp, ["x-content-type-options"]),
            "Browsers may guess (sniff) the content type of responses.",
            "Uploaded or reflected content can be interpreted as script or HTML, enabling XSS.",
            "Send 'X-Content-Type-Options: nosniff' on all responses.",
            "CWE-693", A05))
    if resp.is_html and not resp.header("referrer-policy"):
        out.append(_finding(
            "Low", "referrer-policy-missing", "Referrer-Policy header missing", url,
            _headers_evidence(resp, ["referrer-policy"]),
            "No Referrer-Policy is set, so full URLs may be sent to third-party sites.",
            "Tokens or identifiers in URLs leak to external sites through the Referer header.",
            "Send 'Referrer-Policy: strict-origin-when-cross-origin' (or stricter).",
            "CWE-200", A05))
    disclosed = [(n, v) for n in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")
                 for v in resp.header_all(n) if n != "server" or re.search(r"\d", v)]
    if disclosed:
        out.append(_finding(
            "Low", "version-disclosure", "Server software version disclosed in headers", url,
            resp.status_line() + "\n" + "\n".join(f"{n}: {v[:200]}" for n, v in disclosed),
            "Response headers reveal the server or framework and its version.",
            "Attackers use exact versions to look up known exploits for that software.",
            "Remove or genericise Server / X-Powered-By headers (e.g. nginx 'server_tokens off', "
            "Express 'app.disable(\"x-powered-by\")').",
            "CWE-200", A05))
    return out


def cookie_findings(url: str, resp: Resp) -> list[dict]:
    out = []
    https = url.startswith("https://")
    for raw in resp.header_all("set-cookie"):
        name = raw.split("=", 1)[0].strip()[:100]
        attrs = {a.strip().split("=", 1)[0].lower() for a in raw.split(";")[1:]}
        missing = []
        if https and "secure" not in attrs:
            missing.append("Secure")
        if "httponly" not in attrs:
            missing.append("HttpOnly")
        if "samesite" not in attrs:
            missing.append("SameSite")
        if not missing:
            continue
        session_like = bool(SESSION_COOKIE_RE.search(name))
        sev = "Medium" if session_like and ("Secure" in missing or "HttpOnly" in missing) else "Low"
        out.append(_finding(
            sev, f"cookie-flags-{name.lower()}", f"Cookie '{name}' missing {', '.join(missing)}", url,
            f"{resp.status_line()}\nset-cookie: {name}=REDACTED; "
            + "; ".join(a.strip() for a in raw.split(";")[1:])[:300],
            f"The cookie '{name}' is set without the {', '.join(missing)} attribute(s).",
            "Without HttpOnly, injected scripts can steal the cookie; without Secure it can be sent "
            "over plain HTTP; without SameSite it is sent on cross-site requests (CSRF).",
            "Set cookies with 'Secure; HttpOnly; SameSite=Lax' (or Strict) unless a script truly needs to read them.",
            "CWE-614" if "Secure" in missing else "CWE-1004", A05))
    return out


def cors_findings(url: str, resp: Resp, probe_origin: str = CORS_PROBE_ORIGIN) -> list[dict]:
    acao = (resp.header("access-control-allow-origin") or "").strip()
    creds = (resp.header("access-control-allow-credentials") or "").strip().lower() == "true"
    evidence = (f"{resp.status_line()} (request sent with Origin: {probe_origin})\n"
                f"access-control-allow-origin: {acao or '(not set)'}\n"
                f"access-control-allow-credentials: {resp.header('access-control-allow-credentials') or '(not set)'}")
    if acao == probe_origin and creds:
        return [_finding(
            "High", "cors-reflect-credentials", "CORS reflects any origin and allows credentials", url, evidence,
            "The server echoes back an arbitrary Origin in Access-Control-Allow-Origin together with "
            "Access-Control-Allow-Credentials: true.",
            "Any website a logged-in user visits can call this API with the user's cookies and read the "
            "responses, stealing personal data or tokens.",
            "Allow only an explicit list of trusted origins; never reflect the request Origin when credentials are allowed.",
            "CWE-942", A05)]
    if acao == probe_origin or acao == "null":
        return [_finding(
            "Low", "cors-reflect", "CORS reflects arbitrary origins", url, evidence,
            "The server accepts any Origin in Access-Control-Allow-Origin (without credentials).",
            "Other websites can read responses from this endpoint; harmful if it returns non-public "
            "data based on network position or other implicit trust.",
            "Restrict Access-Control-Allow-Origin to the origins that need access.",
            "CWE-942", A05)]
    return []


def trace_findings(url: str, resp: Resp) -> list[dict]:
    if resp.status == 200 and b"TRACE /" in resp.body[:2000]:
        return [_finding(
            "Low", "trace-enabled", "HTTP TRACE method enabled", url, resp.status_line(),
            "The server answers TRACE requests by echoing the request back.",
            "Combined with other flaws, TRACE can expose headers such as cookies or authorization "
            "values (cross-site tracing).",
            "Disable the TRACE method on the web server or load balancer.",
            "CWE-693", A05)]
    return []


def transport_findings(url: str, http_resp: Resp, https_ok: bool) -> list[dict]:
    """For http:// targets: is HTTPS available, and does HTTP redirect to it?"""
    if not url.startswith("http://"):
        return []
    location = http_resp.header("location") or ""
    redirects = http_resp.status in (301, 302, 307, 308) and location.lower().startswith("https://")
    if not https_ok:
        return [_finding(
            "High", "no-https", "Site is only available over unencrypted HTTP", url, http_resp.status_line(),
            "The target does not accept HTTPS connections on port 443.",
            "Anyone on the network path can read and modify all traffic, including passwords and session cookies.",
            "Serve the site over HTTPS with a valid certificate and redirect all HTTP requests to HTTPS.",
            "CWE-319", A02)]
    if not redirects:
        return [_finding(
            "Medium", "no-https-redirect", "HTTP does not redirect to HTTPS", url,
            _headers_evidence(http_resp, ["location"]),
            "HTTPS is available, but plain HTTP requests are served instead of being redirected.",
            "Users who type the address or follow old links stay on unencrypted HTTP, exposing their traffic.",
            "Redirect every HTTP request to the HTTPS URL with a 301 and enable HSTS.",
            "CWE-319", A02)]
    return []


def tls_findings(url: str, info: dict) -> list[dict]:
    if not info:
        return []
    if not info.get("valid"):
        return [_finding(
            "High", "tls-invalid", f"Invalid TLS certificate: {info.get('error')}", url,
            f"TLS handshake with {urlsplit(url).netloc}: {info.get('error')}",
            "The certificate is not trusted (expired, self-signed, wrong host name or incomplete chain).",
            "Users learn to click through certificate warnings, which lets an attacker impersonate the "
            "site with their own certificate; API clients may disable verification altogether.",
            "Install a valid certificate for this host name (e.g. Let's Encrypt) including the full chain.",
            "CWE-295", A07)]
    out = []
    if info.get("days_left", 999) < 14:
        out.append(_finding(
            "Medium", "tls-expiring", f"TLS certificate expires in {max(0, int(info['days_left']))} day(s)", url,
            f"notAfter: {info.get('not_after')}",
            "The certificate is about to expire.",
            "Once it expires, browsers block the site and clients may be pushed to insecure workarounds.",
            "Renew the certificate and automate renewal.",
            "CWE-298", A02))
    if info.get("version") in ("TLSv1", "TLSv1.1", "SSLv3"):
        out.append(_finding(
            "Medium", "tls-old-protocol", f"Outdated TLS protocol negotiated ({info['version']})", url,
            f"Negotiated protocol: {info['version']}",
            "The server negotiated a deprecated TLS version.",
            "Old protocol versions have known weaknesses that allow traffic decryption in some conditions.",
            "Allow only TLS 1.2 and TLS 1.3.",
            "CWE-327", A02))
    return out


# (path, validator, severity, slug, title, description, exploitation, fix, cwe)
_ENV_LINE = re.compile(rb"^\s*[A-Z][A-Z0-9_]{2,}\s*=", re.M)
SENSITIVE_PATHS = [
    ("/.git/config", lambda r: b"[core]" in r.body and not r.is_html, "High", "git-exposed",
     "Git repository exposed (/.git/)",
     "The site's .git folder is downloadable.",
     "An attacker downloads the whole repository, including source code, history and any secrets ever committed.",
     "Block access to /.git (and other dot-folders) on the web server and remove it from the web root.",
     "CWE-538"),
    ("/.env", lambda r: len(_ENV_LINE.findall(r.body)) >= 2 and not r.is_html, "High", "env-exposed",
     "Environment file exposed (/.env)",
     "A .env configuration file is publicly downloadable.",
     ".env files usually contain database passwords, API keys and signing secrets, giving direct access to backend systems.",
     "Remove the file from the web root, block dot-files on the web server, and rotate every secret it contained.",
     "CWE-538"),
    ("/actuator/env", lambda r: b"propertySources" in r.body or b"activeProfiles" in r.body, "High",
     "actuator-env", "Spring Boot Actuator /env endpoint exposed",
     "The Actuator environment endpoint is reachable without authentication.",
     "It reveals configuration and sometimes credentials; some Actuator endpoints allow changing settings or dumping memory.",
     "Expose only health/info publicly (management.endpoints.web.exposure.include=health,info) and protect the rest.",
     "CWE-215"),
    ("/server-status", lambda r: b"Apache Server Status" in r.body, "Medium", "apache-status",
     "Apache server-status page exposed",
     "mod_status is publicly reachable.",
     "It lists live requests, client IPs and internal URLs, helping attackers map the application.",
     "Restrict /server-status to localhost or an admin network.",
     "CWE-200"),
    ("/phpinfo.php", lambda r: b"phpinfo()" in r.body or b"PHP Version" in r.body and b"<title>PHP" in r.body,
     "Medium", "phpinfo", "phpinfo() page exposed",
     "A phpinfo page is publicly reachable.",
     "It reveals PHP version, modules, paths and environment variables that help an attacker plan exploits.",
     "Delete the phpinfo file from the server.",
     "CWE-200"),
    ("/.DS_Store", lambda r: r.body[:8] == b"\x00\x00\x00\x01Bud1", "Low", "ds-store",
     "macOS .DS_Store file exposed",
     "A .DS_Store file is downloadable.",
     "It lists file and folder names in the directory, revealing hidden files to attackers.",
     "Delete .DS_Store files from the web root and block dot-files.",
     "CWE-538"),
]
API_DOC_PATHS = ["/swagger-ui.html", "/swagger-ui/index.html", "/v3/api-docs", "/v2/api-docs",
                 "/openapi.json", "/swagger.json", "/api-docs"]


def _is_api_doc(r: Resp) -> bool:
    head = r.body[:4000]
    return r.status == 200 and (b'"openapi"' in head or b'"swagger"' in head or b"swagger-ui" in head)


def path_finding(origin: str, path: str, resp: Resp) -> dict | None:
    for p, ok, sev, slug, title, desc, exploit, fix, cwe in SENSITIVE_PATHS:
        if p == path and resp.status == 200 and ok(resp):
            evidence = resp.status_line()
            if slug == "env-exposed":
                names = [m.decode(errors="replace").strip(" =") for m in _ENV_LINE.findall(resp.body)[:10]]
                evidence += "\nVariables (values not stored): " + ", ".join(names)
            return _finding(sev, slug, title, origin + path, evidence, desc, exploit, fix, cwe, A05)
    return None


def directory_listing_finding(url: str, resp: Resp) -> list[dict]:
    if resp.status == 200 and resp.is_html and re.search(rb"<title>\s*Index of /", resp.body[:3000], re.I):
        return [_finding(
            "Medium", "dir-listing", "Directory listing enabled", url, resp.status_line(),
            "The server lists the files in a directory instead of serving a page.",
            "Attackers browse and download files that were never meant to be linked, such as backups or configs.",
            "Disable directory listing (nginx 'autoindex off', Apache 'Options -Indexes').",
            "CWE-548", A05)]
    return []


def api_docs_finding(origin: str, found: list[str]) -> list[dict]:
    if not found:
        return []
    return [_finding(
        "Low", "api-docs", "API documentation publicly exposed", origin + found[0],
        "Reachable without authentication:\n" + "\n".join(origin + p for p in found),
        "Swagger / OpenAPI documentation is reachable without authentication.",
        "Attackers get a full map of every endpoint and parameter, which makes finding broken access "
        "control and injection points much faster.",
        "Disable API docs in production or put them behind authentication.",
        "CWE-200", A05)]


TECH_MARKERS = [(rb"__NEXT_DATA__", "Next.js"), (rb"__NUXT__", "Nuxt"), (rb"ng-version=", "Angular"),
                (rb"/wp-content/", "WordPress"), (rb"data-reactroot|react-dom", "React"),
                (rb"csrfmiddlewaretoken", "Django"), (rb"laravel_session", "Laravel")]


def detect_tech(resp: Resp) -> list[str]:
    found = []
    for n in ("server", "x-powered-by"):
        v = resp.header(n)
        if v:
            found.append(re.sub(r"[^\w./ ()-]", "", v)[:60])
    cookies = " ".join(resp.header_all("set-cookie")).encode()
    for pattern, name in TECH_MARKERS:
        if re.search(pattern, resp.body[:200000]) or re.search(pattern, cookies):
            found.append(name)
    return found


# ---------------------------------------------------------------- orchestration


@dataclass
class Target:
    url: str
    ip: str
    verify: bool
    resp: Resp
    tls: dict | None


def probe(url: str, auth: dict | None = None) -> Target:
    """Validate, resolve (public only) and fetch the target once. Raises TargetError."""
    try:
        ip = assert_public_target(url)[0]
    except Exception as e:  # ValidationError
        raise TargetError(str(e))
    try:
        tls = tls_info(url, ip) if url.startswith("https://") else None
        verify = not (tls and not tls.get("valid"))
        resp = fetch(url, ip, headers=auth, verify=verify)
    except (OSError, http.client.HTTPException, ssl.SSLError) as e:
        raise TargetError(f"{url} is not reachable: {e.__class__.__name__}: {str(e)[:200]}")
    return Target(url, ip, verify, resp, tls)


def run_web_checks(targets: list[Target], time_left, auth: dict | None = None) -> list[dict]:
    findings: list[dict] = []
    auth = auth or {}

    def safe(fn, *a, **kw):
        if time_left() < 15:
            raise TimeoutError("Web checks exceeded the time limit")
        try:
            return fn(*a, **kw)
        except (OSError, http.client.HTTPException, ssl.SSLError):
            return None

    seen_origins: set[str] = set()
    for t in targets:
        findings += header_findings(t.url, t.resp)
        findings += cookie_findings(t.url, t.resp)
        findings += directory_listing_finding(t.url, t.resp)
        if t.url.startswith("https://"):
            findings += tls_findings(t.url, t.tls)
        else:
            host = urlsplit(t.url).hostname or ""
            https_url = urlunsplit(("https", f"[{host}]" if ":" in host else host, "/", "", ""))
            https_ok = safe(fetch, https_url, t.ip, verify=False) is not None
            findings += transport_findings(t.url, t.resp, https_ok)
        r = safe(fetch, t.url, t.ip, headers={**auth, "Origin": CORS_PROBE_ORIGIN}, verify=t.verify)
        if r:
            findings += cors_findings(t.url, r)
        r = safe(fetch, t.url, t.ip, method="TRACE", verify=t.verify)  # never sends credentials
        if r:
            findings += trace_findings(t.url, r)

        origin = _origin(t.url)
        if origin in seen_origins:
            continue
        seen_origins.add(origin)
        for path, *_ in SENSITIVE_PATHS:
            r = safe(fetch, origin + path, t.ip, verify=t.verify)
            if r:
                f = path_finding(origin, path, r)
                if f:
                    findings.append(f)
        docs = []
        for path in API_DOC_PATHS:
            r = safe(fetch, origin + path, t.ip, verify=t.verify)
            if r and _is_api_doc(r):
                docs.append(path)
        findings += api_docs_finding(origin, docs)
    return findings


# ---------------------------------------------------------------- access control (authz)

PUBLIC_HINT = re.compile(r"/(swagger|openapi|api-docs|health|status|ping|version|favicon|robots\.txt|static|assets|public)\b",
                         re.I)


def similar(a: bytes, b: bytes) -> bool:
    """True when two response bodies are (nearly) the same content."""
    if a == b:
        return True
    if not a or not b:
        return False
    la, lb = len(a), len(b)
    if min(la, lb) / max(la, lb) < 0.9:
        return False
    sa, sb = a[:20000].decode("utf-8", "replace"), b[:20000].decode("utf-8", "replace")
    sm = difflib.SequenceMatcher(None, sa, sb, autojunk=False)
    return sm.quick_ratio() >= 0.95 and sm.ratio() >= 0.95


def _ok(r: Resp | None) -> bool:
    return r is not None and 200 <= r.status < 300


def _meaningful(r: Resp) -> bool:
    """A body worth protecting: not empty and not an obvious login / error page."""
    body = r.body.strip()
    if len(body) < 20:
        return False
    low = body[:3000].lower()
    return not (b'type="password"' in low or b"sign in" in low or b"log in" in low and b"<form" in low)


def authz_findings(url: str, ra: Resp | None, rn: Resp | None, rb: Resp | None) -> list[dict]:
    """ra: as user A, rn: without credentials, rb: as user B (or None)."""
    if not _ok(ra) or not _meaningful(ra):
        return []
    out = []
    public_hint = bool(PUBLIC_HINT.search(urlsplit(url).path))
    if _ok(rn) and similar(ra.body, rn.body):
        out.append(_finding(
            "Low" if public_hint else "High", "authz-no-auth",
            "Endpoint returns the same data without authentication", url,
            f"GET {url}\n  as user A       -> HTTP {ra.status}, {len(ra.body)} bytes\n"
            f"  no credentials  -> HTTP {rn.status}, {len(rn.body)} bytes (same content)",
            "The endpoint answered an unauthenticated request with the same content it returns to an "
            "authenticated user. Verify whether it is meant to be public.",
            "Anyone on the internet can read this data without logging in.",
            "Require authentication on this route (deny by default) and add an automated test that "
            "calls it without credentials and expects 401/403.",
            "CWE-306", "A01:2021 - Broken Access Control"))
    elif rb is not None and _ok(rb) and similar(ra.body, rb.body):
        out.append(_finding(
            "Medium" if public_hint else "High", "authz-cross-user",
            "Possible broken access control: user B receives user A's data", url,
            f"GET {url}\n  as user A -> HTTP {ra.status}, {len(ra.body)} bytes\n"
            f"  as user B -> HTTP {rb.status}, {len(rb.body)} bytes (same content)\n"
            f"  no credentials -> HTTP {rn.status if rn else 'error'}",
            "User B received the same response as user A for this endpoint. If the endpoint returns data "
            "that belongs to user A (an IDOR / horizontal privilege escalation), user B should have been "
            "refused. Shared data (e.g. a product catalogue) is expected to match: verify before fixing.",
            "An attacker with any account changes an ID in the URL to read (and possibly modify) other "
            "users' records.",
            "Check on the server that the logged-in user owns or may access the requested object on every "
            "request; never rely on IDs being hard to guess.",
            "CWE-639", "A01:2021 - Broken Access Control"))
    return out


def run_authz(endpoints: list[str], ips: dict[str, str], verify: dict[str, bool], time_left,
              auth_a: dict, auth_b: dict | None) -> tuple[list[dict], str]:
    findings, tested, skipped = [], 0, 0
    for url in endpoints:
        if time_left() < 15:
            raise TimeoutError("Access control checks exceeded the time limit")
        host = urlsplit(url).netloc
        ip, ver = ips.get(host), verify.get(host, True)
        if not ip:
            skipped += 1
            continue

        def get(headers):
            try:
                return fetch(url, ip, headers=headers, verify=ver)
            except (OSError, http.client.HTTPException, ssl.SSLError):
                return None
        ra = get(auth_a)
        if not _ok(ra):
            skipped += 1
            continue
        tested += 1
        findings += authz_findings(url, ra, get(None), get(auth_b) if auth_b else None)
    detail = f"{len(findings)} issue(s); {tested} endpoint(s) compared"
    if skipped:
        detail += f", {skipped} skipped (not 2xx as user A or unreachable)"
    return findings, detail


# ---------------------------------------------------------------- OpenAPI / Swagger discovery

SPEC_SUFFIXES = ["/v3/api-docs", "/v2/api-docs", "/openapi.json", "/swagger.json", "/api-docs",
                 "/swagger/v1/swagger.json", "/openapi.yaml"]


def spec_candidates(url: str) -> list[str]:
    """Where an OpenAPI document is likely to live, given a target (e.g. a swagger-ui page)."""
    p = urlsplit(url)
    origin = f"{p.scheme}://{p.netloc}"
    prefixes = [""]
    m = re.search(r"^(.*?)/swagger-ui(?:/|\.html|$)", p.path)
    if m and m.group(1):
        prefixes.insert(0, m.group(1).rstrip("/"))
    out = []
    for pre in prefixes:
        for suf in SPEC_SUFFIXES:
            u = origin + pre + suf
            if u not in out:
                out.append(u)
    return out


def parse_spec(body: bytes) -> dict | None:
    try:
        doc = json.loads(body.decode("utf-8", "replace"))
    except ValueError:
        return None
    if isinstance(doc, dict) and ("openapi" in doc or "swagger" in doc) and isinstance(doc.get("paths"), dict):
        return doc
    return None


def spec_get_endpoints(doc: dict, spec_url: str, allowed_netlocs: set[str], limit: int = 30) -> list[str]:
    """GET operations without path parameters, as absolute URLs on the allowed hosts."""
    p = urlsplit(spec_url)
    base = f"{p.scheme}://{p.netloc}"
    servers = doc.get("servers") or []
    if servers and isinstance(servers[0], dict):
        s = str(servers[0].get("url") or "")
        sp = urlsplit(s)
        if sp.netloc in allowed_netlocs:
            base = s.rstrip("/")
        elif s.startswith("/"):
            base += s.rstrip("/")
    elif doc.get("basePath"):
        base += str(doc["basePath"]).rstrip("/")
    out = []
    for path, ops in doc.get("paths", {}).items():
        if not isinstance(ops, dict) or "get" not in ops or "{" in path:
            continue
        url = base + (path if path.startswith("/") else "/" + path)
        if urlsplit(url).netloc in allowed_netlocs and url not in out:
            out.append(url)
        if len(out) >= limit:
            break
    return out


def discover_specs(targets: list[Target], auth: dict | None, explicit: list[str]) -> list[tuple[str, dict]]:
    """Return [(spec_url, doc)] found at explicit URLs or common locations on the targets."""
    found: list[tuple[str, dict]] = []
    seen: set[str] = set()
    by_host = {urlsplit(t.url).netloc: t for t in targets}
    candidates = list(explicit)
    for t in targets:
        candidates += spec_candidates(t.url)
    for c in candidates:
        if c in seen or len(found) >= 3:
            continue
        seen.add(c)
        t = by_host.get(urlsplit(c).netloc)
        if not t:
            continue
        try:
            r = fetch(c, t.ip, headers=auth, verify=t.verify)
        except (OSError, http.client.HTTPException, ssl.SSLError):
            continue
        doc = parse_spec(r.body) if r.status == 200 else None
        if doc:
            found.append((c, doc))
    return found
