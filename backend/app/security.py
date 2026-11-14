"""Input validation and secret handling shared by the API and the worker."""
import ipaddress
import re
import socket
from urllib.parse import urlsplit, urlunsplit

from cryptography.fernet import Fernet, InvalidToken

from .config import get_settings

# ---------------------------------------------------------------- Git URLs

_HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
_PATH_RE = re.compile(r"^/[A-Za-z0-9._~/%+-]{1,500}$")
_BRANCH_RE = re.compile(r"^[A-Za-z0-9._/+-]{1,200}$")


class ValidationError(ValueError):
    pass


def validate_git_url(url: str) -> str:
    """Return a normalised https Git URL or raise ValidationError.

    Rules: https only, host name (no IP literals), no embedded credentials, no query or
    fragment, conservative character set. Never passed to a shell.
    """
    url = (url or "").strip()
    if not url or len(url) > 1000 or any(c.isspace() for c in url):
        raise ValidationError("Enter a Git repository URL.")
    parts = urlsplit(url)
    if parts.scheme.lower() != "https":
        raise ValidationError("Only https:// Git URLs are allowed.")
    if parts.username or parts.password or "@" in parts.netloc:
        raise ValidationError("Do not put credentials in the URL. Use the access token field.")
    if parts.query or parts.fragment:
        raise ValidationError("The URL must not contain a query string or fragment.")
    host = (parts.hostname or "").lower()
    if not host or not _HOST_RE.match(host) or host.startswith("-") or "." not in host:
        raise ValidationError("The URL must contain a valid host name.")
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    if is_ip:
        raise ValidationError("Use a host name, not an IP address.")
    port = parts.port  # raises ValueError on garbage
    if not _PATH_RE.match(parts.path or "") or ".." in parts.path:
        raise ValidationError("The URL path is not a valid repository path.")
    netloc = host if port in (None, 443) else f"{host}:{port}"
    path = parts.path.rstrip("/")
    return urlunsplit(("https", netloc, path, "", ""))


def assert_public_host(url: str) -> None:
    """Block clones from private, loopback, link-local (cloud metadata) and reserved ranges."""
    host = urlsplit(url).hostname or ""
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise ValidationError(f"Could not resolve host {host}.")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            raise ValidationError("The repository host resolves to a private or internal address.")


# ---------------------------------------------------------------- Live URL targets (DAST)

MAX_TARGETS = 5


def validate_target_url(url: str) -> str:
    """Return a normalised http(s) URL for a live scan target or raise ValidationError.

    Host names and public IP literals are allowed; credentials, fragments, whitespace and
    control characters are not. Never passed to a shell.
    """
    url = (url or "").strip()
    if not url or len(url) > 2000:
        raise ValidationError("Enter a target URL.")
    if any(not (0x21 <= ord(c) <= 0x7E) for c in url):
        raise ValidationError(f"The URL contains spaces or characters that are not allowed: {url[:100]}")
    parts = urlsplit(url)
    if parts.scheme.lower() not in ("http", "https"):
        raise ValidationError(f"Only http:// and https:// URLs can be scanned: {url[:100]}")
    if parts.username or parts.password or "@" in parts.netloc:
        raise ValidationError("Do not put credentials in the URL.")
    host = (parts.hostname or "").lower()
    if not host:
        raise ValidationError(f"The URL must contain a host name: {url[:100]}")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        if not ip.is_global:
            raise ValidationError("Private, loopback and link-local addresses cannot be scanned.")
    elif not _HOST_RE.match(host) or host.startswith("-") or "." not in host:
        raise ValidationError(f"The URL must contain a valid host name: {url[:100]}")
    port = parts.port  # raises ValueError on garbage
    scheme = parts.scheme.lower()
    default = 443 if scheme == "https" else 80
    hostpart = f"[{host}]" if ip is not None and ip.version == 6 else host
    netloc = hostpart if port in (None, default) else f"{hostpart}:{port}"
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))


def validate_targets(raw: str | None) -> list[str]:
    """One URL per line (or comma separated), de-duplicated, at most MAX_TARGETS."""
    items = [x.strip() for x in re.split(r"[\n,]", raw or "") if x.strip()]
    if not items:
        raise ValidationError("Enter at least one URL to scan.")
    urls: list[str] = []
    for item in items:
        u = validate_target_url(item)
        if u not in urls:
            urls.append(u)
    if len(urls) > MAX_TARGETS:
        raise ValidationError(f"Scan at most {MAX_TARGETS} URLs at a time.")
    return urls


def assert_public_target(url: str) -> list[str]:
    """Resolve the target and return its addresses; refuse anything non-public (SSRF guard)."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise ValidationError(f"Could not resolve host {host}.")
    ips: list[str] = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            raise ValidationError(f"{host} resolves to a private or internal address; it cannot be scanned.")
        if str(ip) not in ips:
            ips.append(str(ip))
    return ips


_HEADER_NAME = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_FORBIDDEN_HEADERS = {"host", "content-length", "transfer-encoding", "connection", "upgrade", "te",
                      "proxy-authorization", "expect"}
MAX_ENDPOINTS = 50


def parse_auth_headers(raw: str | None) -> dict[str, str]:
    """'Name: value' per line -> dict. Used for authenticated scanning (e.g. Authorization, Cookie)."""
    headers: dict[str, str] = {}
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line:
            continue
        if ":" not in line:
            raise ValidationError("Each authentication line must look like 'Header-Name: value'.")
        name, value = (x.strip() for x in line.split(":", 1))
        if not _HEADER_NAME.match(name) or name.lower() in _FORBIDDEN_HEADERS:
            raise ValidationError(f"Header name not allowed: {name[:64]}")
        if not value or len(value) > 8000 or any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
            raise ValidationError(f"Invalid value for header {name}.")
        headers[name] = value
    if len(headers) > 5:
        raise ValidationError("Use at most 5 authentication headers per user.")
    return headers


def validate_endpoints(raw: str | None, targets: list[str]) -> list[str]:
    """Endpoints for the access-control check: full URLs or paths relative to the first target.
    Every endpoint must be on one of the target hosts (the operator confirmed authorisation for those)."""
    hosts = {urlsplit(t).netloc for t in targets}
    base = urlsplit(targets[0])
    out: list[str] = []
    for item in re.split(r"[\n,]", raw or ""):
        item = item.strip()
        if not item:
            continue
        if item.startswith("/"):
            item = urlunsplit((base.scheme, base.netloc, "", "", "")) + item
        url = validate_target_url(item)
        if urlsplit(url).netloc not in hosts:
            raise ValidationError(f"Endpoint is not on one of the target hosts: {item[:100]}")
        if url not in out:
            out.append(url)
    if len(out) > MAX_ENDPOINTS:
        raise ValidationError(f"Use at most {MAX_ENDPOINTS} endpoints.")
    return out


def target_project_name(urls: list[str]) -> str:
    first = urlsplit(urls[0]).hostname or "website"
    return first if len(urls) == 1 else f"{first} (+{len(urls) - 1})"


def validate_branch(branch: str | None) -> str | None:
    branch = (branch or "").strip()
    if not branch:
        return None
    if (
        not _BRANCH_RE.match(branch)
        or branch.startswith(("-", "/", "."))
        or branch.endswith(("/", ".", ".lock"))
        or ".." in branch
        or "//" in branch
    ):
        raise ValidationError("Branch name contains characters that are not allowed.")
    return branch


def project_name_from_url(url: str) -> str:
    name = urlsplit(url).path.rstrip("/").rsplit("/", 1)[-1]
    if name.endswith(".git"):
        name = name[:-4]
    return name or urlsplit(url).hostname or "repository"


def canonical_repo_source(url: str) -> str:
    """Key used to group scans of the same repository into one project."""
    return url[:-4] if url.endswith(".git") else url


# ---------------------------------------------------------------- Tokens


def _fernet() -> Fernet:
    key = get_settings().token_encryption_key.strip()
    if not key or key.startswith("replace-with"):
        raise RuntimeError("TOKEN_ENCRYPTION_KEY is not configured")
    return Fernet(key.encode())


def encrypt_token(token: str) -> bytes:
    return _fernet().encrypt(token.encode())


def decrypt_token(blob: bytes) -> str:
    try:
        return _fernet().decrypt(blob).decode()
    except InvalidToken:
        raise RuntimeError("Stored Git token could not be decrypted (TOKEN_ENCRYPTION_KEY changed?)")


def scrub(text: str, *secrets: str | None) -> str:
    """Remove secrets from text that may be logged or stored (e.g. git stderr)."""
    text = text or ""
    for s in secrets:
        if s:
            text = text.replace(s, "***")
    # Also mask any credentials that slipped into a URL.
    return re.sub(r"(https?://)[^/@\s]+@", r"\1***@", text)
