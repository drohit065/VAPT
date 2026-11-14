"""Read / write admin settings with encrypted secrets."""
from __future__ import annotations

import json

from .models import AppSetting
from .security import decrypt_token, encrypt_token


def load(db, key: str) -> tuple[dict, dict]:
    """(public values, decrypted secrets)."""
    row = db.get(AppSetting, key)
    if not row:
        return {}, {}
    secrets = json.loads(decrypt_token(row.secret_enc)) if row.secret_enc else {}
    return dict(row.value or {}), secrets


def save(db, key: str, value: dict, secrets: dict) -> None:
    row = db.get(AppSetting, key) or AppSetting(key=key)
    row.value = value
    clean = {k: v for k, v in secrets.items() if v}
    row.secret_enc = encrypt_token(json.dumps(clean)) if clean else None
    db.add(row)
    db.commit()


def merge_secrets(current: dict, incoming: dict, clear: list[str]) -> dict:
    """Secrets are write-only: an empty field keeps the stored value, `clear` removes it."""
    out = dict(current)
    for k, v in incoming.items():
        if v:
            out[k] = v
    for k in clear:
        out.pop(k, None)
    return out
