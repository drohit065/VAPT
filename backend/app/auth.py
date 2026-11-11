"""Single admin user, credentials from .env, JWT bearer session."""
import hmac
import threading
import time
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import get_settings

ALGORITHM = "HS256"
_bearer = HTTPBearer(auto_error=False)

# Simple in-memory brute-force guard: max failures per client IP per window.
_FAIL_LIMIT = 5
_FAIL_WINDOW = 300
_failures: dict[str, list[float]] = {}
_lock = threading.Lock()


def check_rate_limit(client_ip: str) -> None:
    now = time.monotonic()
    with _lock:
        recent = [t for t in _failures.get(client_ip, []) if now - t < _FAIL_WINDOW]
        _failures[client_ip] = recent
        if len(recent) >= _FAIL_LIMIT:
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS, "Too many failed logins. Try again later."
            )


def record_failure(client_ip: str) -> None:
    with _lock:
        _failures.setdefault(client_ip, []).append(time.monotonic())


def verify_credentials(username: str, password: str) -> bool:
    s = get_settings()
    user_ok = hmac.compare_digest(username.encode(), s.admin_username.encode())
    pass_ok = hmac.compare_digest(password.encode(), s.admin_password.encode())
    return user_ok and pass_ok


def create_token(username: str) -> tuple[str, int]:
    s = get_settings()
    expires = s.jwt_expire_minutes * 60
    now = datetime.now(timezone.utc)
    payload = {"sub": username, "iat": now, "exp": now + timedelta(seconds=expires)}
    return jwt.encode(payload, s.jwt_secret, algorithm=ALGORITHM), expires


def require_user(creds: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> str:
    if creds is None or creds.scheme.lower() != "bearer":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    s = get_settings()
    try:
        payload = jwt.decode(creds.credentials, s.jwt_secret, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session expired or invalid")
    if payload.get("sub") != s.admin_username:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session expired or invalid")
    return payload["sub"]
