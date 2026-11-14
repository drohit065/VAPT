from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from ..auth import (
    CurrentUser,
    audit,
    authenticate,
    check_rate_limit,
    client_ip,
    create_token,
    record_failure,
    require_user,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginIn(BaseModel):
    username: str = Field(max_length=200)
    password: str = Field(max_length=500)


@router.post("/login")
def login(body: LoginIn, request: Request):
    ip = client_ip(request) or "unknown"
    check_rate_limit(ip)
    user = authenticate(body.username, body.password)
    if user is None:
        record_failure(ip)
        audit(body.username[:100] or "?", "login_failed", ip=ip)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")
    token, expires_in = create_token(user)
    audit(user.username, "login", ip=ip)
    return {"access_token": token, "token_type": "bearer", "expires_in": expires_in,
            "username": user.username, "role": user.role}


@router.get("/me")
def me(user: CurrentUser = Depends(require_user)):
    return {"username": user.username, "role": user.role, "builtin": user.builtin}
