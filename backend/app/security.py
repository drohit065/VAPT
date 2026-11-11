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
