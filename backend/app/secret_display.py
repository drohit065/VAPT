"""How a discovered credential is shown in reports: enough to identify it, never enough to use it.

  cloud / API keys, tokens   >= 20 chars: first 4 + last 4      AKIA************MPLE fp:1a2b3c4d
                             < 20 chars:  nothing               ******** fp:1a2b3c4d
  passwords (by rule/name)   never any characters               ******** fp:1a2b3c4d
  connection strings         user and host kept                 postgres://admin:****(fp:1a2b3c4d)@db.prod:5432/app
  private keys               type and size only                 [RSA private key, 2048-bit] fp:1a2b3c4d

The number of stars is fixed, so the length of a value is never revealed.

The fingerprint is HMAC-SHA256 of the value, truncated to 8 hex characters, keyed with a secret derived
from this installation's TOKEN_ENCRYPTION_KEY (never an unsalted hash): the same credential gets the
same fingerprint in every file, repository and scan of this installation, but it cannot be reversed or
brute-forced offline by someone who only has a report, and another installation's fingerprints differ.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re

from .config import get_settings

# Used only when no TOKEN_ENCRYPTION_KEY is configured (tests, a misconfigured dev setup): a random
# key per process, so fingerprints are still keyed, just not stable across restarts.
_PROCESS_KEY = os.urandom(32)

_PASSWORD_HINT = re.compile(r"pass(word|wd|phrase)?\b|pwd|passw|pass_|_pass|db_?pass|smtp_?pass", re.I)
_PEM = re.compile(r"-----BEGIN ([A-Z ]*)PRIVATE KEY-----")
_ALREADY_MASKED = re.compile(r"\*{4,}|fp:[0-9a-f]{8}|REDACTED|\[[A-Za-z ]*private key")


def _fp_key() -> bytes:
    base = (get_settings().token_encryption_key or "").strip()
    secret = base.encode() if base and not base.startswith("replace-with") else _PROCESS_KEY
    return hashlib.sha256(b"vapt-secret-fingerprint:" + secret).digest()


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
    fp = fingerprint(value)
    if len(value) >= 20 and not is_password(rule_id, name):
        return f"{value[:4]}{'*' * 12}{value[-4:]} {fp}"
    return f"{'*' * 8} {fp}"


def display_url_password(password: str) -> str:
    """Password inside a URL (user:password@host): keep the URL readable."""
    return f"****({fingerprint(password)})"
