from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from ..auth import check_rate_limit, create_token, record_failure, require_user, verify_credentials

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginIn(BaseModel):
    username: str = Field(max_length=200)
    password: str = Field(max_length=500)


@router.post("/login")
def login(body: LoginIn, request: Request):
    ip = request.client.host if request.client else "unknown"
    check_rate_limit(ip)
    if not verify_credentials(body.username, body.password):
        record_failure(ip)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")
    token, expires_in = create_token(body.username)
    return {"access_token": token, "token_type": "bearer", "expires_in": expires_in}


@router.get("/me")
def me(user: str = Depends(require_user)):
    return {"username": user}
