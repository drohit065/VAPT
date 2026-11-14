"""API keys for CI/CD (admin managed)."""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import CurrentUser, audit, client_ip, new_api_key, require_role
from ..db import get_db
from ..models import ApiKey

router = APIRouter(prefix="/api/api-keys", tags=["api-keys"])
admin_only = require_role("admin")


def key_dict(k: ApiKey) -> dict:
    return {"id": k.id, "name": k.name, "prefix": k.prefix, "role": k.role, "created_by": k.created_by,
            "created_at": k.created_at, "expires_at": k.expires_at, "last_used_at": k.last_used_at,
            "revoked": k.revoked}


class ApiKeyIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    role: str = "analyst"
    expires_days: int | None = Field(default=365, ge=1, le=3650)


@router.get("")
def list_keys(db: Session = Depends(get_db), _: CurrentUser = Depends(admin_only)):
    return [key_dict(k) for k in db.scalars(select(ApiKey).order_by(ApiKey.id.desc()))]


@router.post("")
def create_key(body: ApiKeyIn, request: Request, db: Session = Depends(get_db),
               me: CurrentUser = Depends(admin_only)):
    if body.role not in ("viewer", "analyst"):
        raise HTTPException(400, "API keys can have the viewer or analyst role.")
    key, prefix, digest = new_api_key()
    k = ApiKey(name=body.name.strip(), prefix=prefix, key_hash=digest, role=body.role, created_by=me.username,
               expires_at=(datetime.now(timezone.utc) + timedelta(days=body.expires_days)) if body.expires_days else None)
    db.add(k)
    db.commit()
    audit(me.username, "api_key_created", k.name, {"role": k.role, "prefix": prefix}, client_ip(request))
    return key_dict(k) | {"key": key}  # the only time the full key is returned


@router.delete("/{key_id}")
def revoke_key(key_id: int, request: Request, db: Session = Depends(get_db), me: CurrentUser = Depends(admin_only)):
    k = db.get(ApiKey, key_id)
    if not k:
        raise HTTPException(404, "API key not found")
    k.revoked = True
    db.commit()
    audit(me.username, "api_key_revoked", k.name, {"prefix": k.prefix}, client_ip(request))
    return key_dict(k)
