"""Authentication and roles.

* The admin from .env (ADMIN_USERNAME / ADMIN_PASSWORD) is a built-in admin that always exists.
* Further users live in the database with a role: admin > analyst > viewer.
    viewer  - read projects, reports and exports
    analyst - viewer + start scans, triage findings, manage schedules
    admin   - analyst + manage users and read the audit log
* Sessions are HS256 JWTs. Database users carry a token version, so changing a password,
  role or deactivating a user ends their existing sessions immediately.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select

from .config import get_settings
from .db import SessionLocal

ALGORITHM = "HS256"
ROLES = ("viewer", "analyst", "admin")
_RANK = {r: i for i, r in enumerate(ROLES)}
_bearer = HTTPBearer(auto_error=False)

# Simple in-memory brute-force guard: max failures per client IP per window.
_FAIL_LIMIT = 5
_FAIL_WINDOW = 300
_failures: dict[str, list[float]] = {}
_lock = threading.Lock()


@dataclass
class CurrentUser:
    username: str
    role: str
    builtin: bool = False

    def can(self, role: str) -> bool:
        return _RANK[self.role] >= _RANK[role]


# ---------------------------------------------------------------- passwords (scrypt, stdlib)

_SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1}


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, dklen=32, **_SCRYPT)
    return "scrypt${}${}${}${}${}".format(_SCRYPT["n"], _SCRYPT["r"], _SCRYPT["p"],
                                          base64.b64encode(salt).decode(), base64.b64encode(dk).decode())


def check_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, dk = stored.split("$")
        if algo != "scrypt":
            return False
        calc = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), dklen=32, n=int(n), r=int(r), p=int(p))
        return hmac.compare_digest(calc, base64.b64decode(dk))
    except (ValueError, TypeError):
        return False


_DUMMY_HASH = hash_password(os.urandom(8).hex())


def validate_password(password: str) -> None:
    if len(password or "") < 12:
        raise HTTPException(400, "Passwords must be at least 12 characters.")
    if len(password) > 500:
        raise HTTPException(400, "Password is too long.")


# ---------------------------------------------------------------- rate limiting


def check_rate_limit(client_ip: str) -> None:
    now = time.monotonic()
    with _lock:
        recent = [t for t in _failures.get(client_ip, []) if now - t < _FAIL_WINDOW]
        if recent:
            _failures[client_ip] = recent
        else:
            _failures.pop(client_ip, None)
        if len(recent) >= _FAIL_LIMIT:
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many failed logins. Try again later.")


def record_failure(client_ip: str) -> None:
    with _lock:
        _failures.setdefault(client_ip, []).append(time.monotonic())


# ---------------------------------------------------------------- login / tokens


def authenticate(username: str, password: str) -> CurrentUser | None:
    s = get_settings()
    builtin_user = hmac.compare_digest(username.encode(), s.admin_username.encode())
    builtin_pass = hmac.compare_digest(password.encode(), s.admin_password.encode())
    if builtin_user:
        return CurrentUser(s.admin_username, "admin", builtin=True) if builtin_pass else None
    from .models import User

    db = SessionLocal()
    try:
        u = db.scalar(select(User).where(User.username == username))
        if u is None:
            check_password(password, _DUMMY_HASH)  # same timing as a real check
            return None
        if not u.active or not check_password(password, u.password_hash):
            return None
        u.last_login_at = datetime.now(timezone.utc)
        db.commit()
        return CurrentUser(u.username, u.role)
    finally:
        db.close()


def create_token(user: CurrentUser) -> tuple[str, int]:
    s = get_settings()
    expires = s.jwt_expire_minutes * 60
    now = datetime.now(timezone.utc)
    payload = {"sub": user.username, "role": user.role, "iat": now, "exp": now + timedelta(seconds=expires)}
    if user.builtin:
        payload["bi"] = True
    else:
        from .models import User

        db = SessionLocal()
        try:
            u = db.scalar(select(User).where(User.username == user.username))
            payload["tv"] = u.token_version if u else 0
        finally:
            db.close()
    return jwt.encode(payload, s.jwt_secret, algorithm=ALGORITHM), expires


def _unauthorized():
    return HTTPException(status.HTTP_401_UNAUTHORIZED, "Session expired or invalid")


def require_user(creds: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> CurrentUser:
    if creds is None or creds.scheme.lower() != "bearer":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    s = get_settings()
    try:
        payload = jwt.decode(creds.credentials, s.jwt_secret, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        raise _unauthorized()
    sub = payload.get("sub")
    if payload.get("bi"):
        if sub != s.admin_username:
            raise _unauthorized()
        return CurrentUser(sub, "admin", builtin=True)
    from .models import User

    db = SessionLocal()
    try:
        u = db.scalar(select(User).where(User.username == sub))
        if u is None or not u.active or u.token_version != payload.get("tv"):
            raise _unauthorized()
        return CurrentUser(u.username, u.role)
    finally:
        db.close()


def require_role(role: str):
    def dep(user: CurrentUser = Depends(require_user)) -> CurrentUser:
        if not user.can(role):
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"This action needs the {role} role.")
        return user
    return dep


# ---------------------------------------------------------------- audit log


def client_ip(request: Request | None) -> str | None:
    return request.client.host if request is not None and request.client else None


def audit(username: str, action: str, target: str | None = None, detail: dict | None = None,
          ip: str | None = None, db=None) -> None:
    """Append to the audit log. Never pass secrets in `detail`."""
    from .models import AuditLog

    own = db is None
    db = db or SessionLocal()
    try:
        db.add(AuditLog(username=username[:100], action=action[:60], target=(target or "")[:300] or None,
                        detail=detail or {}, ip=ip))
        db.commit()
    finally:
        if own:
            db.close()
