"""How a discovered credential is shown in reports: enough to identify it, never enough to use it.

  cloud / API keys, tokens   >= 20 chars: first 4 + last 4      AKIA************MPLE fp:1a2b3c4d
                             12-19 chars: last 4 only           ********MPLE fp:1a2b3c4d
                             < 12 chars:  nothing               ****** fp:1a2b3c4d
  passwords (by rule/name)   never any characters, only length  ************ (12 chars) fp:1a2b3c4d
  connection strings         user and host kept                 postgres://admin:****(fp:1a2b3c4d)@db.prod:5432/app
  private keys               type and size only                 [RSA private key, 2048-bit] fp:1a2b3c4d

The fingerprint is an HMAC of the value keyed with a secret derived from TOKEN_ENCRYPTION_KEY: the same
credential gets the same fingerprint in every file, repository and scan, but it cannot be reversed or
brute-forced offline by someone who only has a report.
"""
from __future__ import annotations

import hashlib
import hmac
import re

from .config import get_settings

_PASSWORD_HINT = re.compile(r"pass(word|wd|phrase)?\b|pwd|passw|pass_|_pass|db_?pass|smtp_?pass", re.I)
_PEM = re.compile(r"-----BEGIN ([A-Z ]*)PRIVATE KEY-----")
_ALREADY_MASKED = re.compile(r"\*{4,}|fp:[0-9a-f]{8}|REDACTED|\[[A-Za-z ]*private key")


def _fp_key() -> bytes:
    base = (get_settings().token_encryption_key or "vapt-fingerprint-fallback").encode()
    return hashlib.sha256(b"vapt-secret-fingerprint:" + base).digest()


def fingerprint(value: str) -> str:
    return "fp:" + hmac.new(_fp_key(), value.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:8]


def is_masked(value: str) -> bool:
    return bool(_ALREADY_MASKED.search(value or ""))


def is_password(rule_id: str = "", name: str = "") -> bool:
    return bool(_PASSWORD_HINT.search(f"{rule_id} {name}"))


def _private_key(value: str) -> str:
    m = _PEM.search(value)
    kind = (m.group(1).strip() if m else "") or "private"
    label = f"{kind} private key" if kind != "private" else "private key"
    bits = ""
    try:  # key size helps identify it; never fatal
        from cryptography.hazmat.primitives import serialization
        loader = serialization.load_ssh_private_key if "OPENSSH" in kind else serialization.load_pem_private_key
        key = loader(value.encode(), password=None)
        size = getattr(key, "key_size", None) or getattr(getattr(key, "curve", None), "key_size", None)
        if size:
            bits = f", {size}-bit"
    except Exception:  # noqa: BLE001 - encrypted, truncated or unusual keys: type only
        pass
    return f"[{label}{bits}] {fingerprint(value)}"


def display(value: str, rule_id: str = "", name: str = "") -> str:
    """Safe, recognisable rendering of a secret value."""
    value = value or ""
    if not value:
        return value
    if _PEM.search(value):
        return _private_key(value)
    n = len(value)
    fp = fingerprint(value)
    if is_password(rule_id, name):
        return f"{'*' * min(n, 12)} ({n} chars) {fp}"
    if n >= 20:
        return f"{value[:4]}{'*' * min(n - 8, 12)}{value[-4:]} {fp}"
    if n >= 12:
        return f"{'*' * 8}{value[-4:]} {fp}"
    return f"{'*' * min(max(n, 4), 8)} {fp}"


def display_url_password(password: str) -> str:
    """Password inside a URL (user:password@host): keep the URL readable."""
    return f"****({fingerprint(password)})"
