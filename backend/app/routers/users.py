"""User management and audit log (admin only)."""
import re

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import ROLES, CurrentUser, audit, client_ip, hash_password, require_role, validate_password
from ..config import get_settings
from ..db import get_db
from ..models import AuditLog, User

router = APIRouter(prefix="/api", tags=["users"])
admin_only = require_role("admin")
_USERNAME = re.compile(r"^[A-Za-z0-9._@-]{3,100}$")


def user_dict(u: User) -> dict:
    return {"id": u.id, "username": u.username, "role": u.role, "active": u.active,
            "created_at": u.created_at, "last_login_at": u.last_login_at}


class UserIn(BaseModel):
    username: str = Field(max_length=100)
    password: str = Field(max_length=500)
    role: str = "viewer"


class UserPatch(BaseModel):
    role: str | None = None
    active: bool | None = None
    password: str | None = Field(default=None, max_length=500)


@router.get("/users")
def list_users(db: Session = Depends(get_db), _: CurrentUser = Depends(admin_only)):
    s = get_settings()
    users = [user_dict(u) for u in db.scalars(select(User).order_by(User.username))]
    return {"builtin_admin": s.admin_username, "users": users, "roles": list(ROLES)}


@router.post("/users")
def create_user(body: UserIn, request: Request, db: Session = Depends(get_db),
                me: CurrentUser = Depends(admin_only)):
    if not _USERNAME.match(body.username):
        raise HTTPException(400, "Usernames are 3-100 characters: letters, digits, . _ @ -")
    if body.username.lower() == get_settings().admin_username.lower():
        raise HTTPException(400, "That name is reserved for the built-in admin.")
    if body.role not in ROLES:
        raise HTTPException(400, f"role must be one of: {', '.join(ROLES)}")
    validate_password(body.password)
    if db.scalar(select(User).where(User.username == body.username)):
        raise HTTPException(409, "A user with that name already exists.")
    u = User(username=body.username, password_hash=hash_password(body.password), role=body.role)
    db.add(u)
    db.commit()
    audit(me.username, "user_created", body.username, {"role": body.role}, client_ip(request))
    return user_dict(u)


@router.patch("/users/{user_id}")
def update_user(user_id: int, body: UserPatch, request: Request, db: Session = Depends(get_db),
                me: CurrentUser = Depends(admin_only)):
    u = db.get(User, user_id)
    if not u:
        raise HTTPException(404, "User not found")
    changes = {}
    if body.role is not None:
        if body.role not in ROLES:
            raise HTTPException(400, f"role must be one of: {', '.join(ROLES)}")
        changes["role"] = [u.role, body.role]
        u.role = body.role
    if body.active is not None:
        changes["active"] = [u.active, body.active]
        u.active = body.active
    if body.password:
        validate_password(body.password)
        u.password_hash = hash_password(body.password)
        changes["password"] = "reset"
    if changes:
        u.token_version = (u.token_version or 0) + 1  # end existing sessions
        db.commit()
        audit(me.username, "user_updated", u.username, changes, client_ip(request))
    return user_dict(u)


@router.delete("/users/{user_id}")
def delete_user(user_id: int, request: Request, db: Session = Depends(get_db),
                me: CurrentUser = Depends(admin_only)):
    u = db.get(User, user_id)
    if not u:
        raise HTTPException(404, "User not found")
    name = u.username
    db.delete(u)
    db.commit()
    audit(me.username, "user_deleted", name, ip=client_ip(request))
    return {"deleted": user_id}


@router.get("/audit")
def audit_log(limit: int = 200, offset: int = 0, username: str | None = None, action: str | None = None,
              db: Session = Depends(get_db), _: CurrentUser = Depends(admin_only)):
    q = select(AuditLog).order_by(AuditLog.id.desc())
    if username:
        q = q.where(AuditLog.username == username)
    if action:
        q = q.where(AuditLog.action == action)
    rows = db.scalars(q.offset(max(0, offset)).limit(max(1, min(limit, 1000)))).all()
    return [{"id": r.id, "at": r.at, "username": r.username, "action": r.action, "target": r.target,
             "detail": r.detail, "ip": r.ip} for r in rows]
