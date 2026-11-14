from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    source_type: Mapped[str] = mapped_column(String(10))  # "git" | "zip" | "url" | "image"
    # Git URL without credentials, the zip file name, target URLs (one per line) or an image reference.
    source: Mapped[str] = mapped_column(String(1000), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    # Scheduled re-scans: none | daily | weekly, at schedule_hour (UTC).
    schedule: Mapped[str] = mapped_column(String(10), default="none")
    schedule_hour: Mapped[int] = mapped_column(Integer, default=2)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Non-secret copy of the scan settings to repeat: {"checks", "branch", "options"}.
    schedule_config: Mapped[dict] = mapped_column(JSON, default=dict)

    scans: Mapped[list["Scan"]] = relationship(
        back_populates="project", cascade="all, delete-orphan", order_by="Scan.id.desc()"
    )


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    # queued | running | completed | failed
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)
    branch: Mapped[str | None] = mapped_column(String(255), nullable=True)
    commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    checks: Mapped[dict] = mapped_column(JSON, default=dict)
    steps: Mapped[list] = mapped_column(JSON, default=list)
    languages: Mapped[list] = mapped_column(JSON, default=list)
    frameworks: Mapped[list] = mapped_column(JSON, default=list)
    counts: Mapped[dict] = mapped_column(JSON, default=dict)
    notes: Mapped[list] = mapped_column(JSON, default=list)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Comparison with the previous completed scan of the same project:
    # {"previous_scan_id", "new", "recurring", "fixed", "fixed_items": [...]}
    diff: Mapped[dict] = mapped_column(JSON, default=dict)
    # Non-secret scan options, e.g. {"endpoints": [...], "auth_a": true, "auth_b": false}.
    options: Mapped[dict] = mapped_column(JSON, default=dict)

    # Fernet-encrypted secret: the Git token (git scans) or the JSON auth headers (URL scans).
    # Wiped as soon as the scan finishes. Never returned by the API.
    git_token_enc: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    # Path of the uploaded zip on the shared volume. Deleted when the scan finishes.
    upload_path: Mapped[str | None] = mapped_column(String(1000), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    project: Mapped[Project] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    severity: Mapped[str] = mapped_column(String(10), index=True)  # Critical | High | Medium | Low
    title: Mapped[str] = mapped_column(String(500))
    file_path: Mapped[str] = mapped_column(String(1000))
    line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    snippet: Mapped[str] = mapped_column(Text, default="")
    description: Mapped[str] = mapped_column(Text, default="")
    exploitation: Mapped[str] = mapped_column(Text, default="")
    recommendation: Mapped[str] = mapped_column(Text, default="")
    cwe: Mapped[str | None] = mapped_column(String(100), nullable=True)
    owasp: Mapped[str | None] = mapped_column(String(200), nullable=True)
    scanners: Mapped[list] = mapped_column(JSON, default=list)
    rule_id: Mapped[str | None] = mapped_column(String(500), nullable=True)
    check: Mapped[str] = mapped_column(String(30))
    ai_verdict: Mapped[str | None] = mapped_column(String(30), nullable=True)
    ai_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Finding management. The fingerprint identifies the same issue across scans of a project.
    fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    # open | false_positive | accepted_risk | fixed
    status: Mapped[str] = mapped_column(String(20), default="open")
    status_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    status_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_new: Mapped[bool] = mapped_column(Boolean, default=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(200), nullable=True)
    cvss_source: Mapped[str | None] = mapped_column(String(20), nullable=True)  # scanner | estimated

    scan: Mapped[Scan] = relationship(back_populates="findings")


class User(Base):
    """Dashboard users. The admin from .env always exists in addition to these (built-in admin)."""
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(300))
    role: Mapped[str] = mapped_column(String(20), default="viewer")  # admin | analyst | viewer
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Bumped on password change / deactivation: older sessions stop working immediately.
    token_version: Mapped[int] = mapped_column(Integer, default=0)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    username: Mapped[str] = mapped_column(String(100), index=True)
    action: Mapped[str] = mapped_column(String(60), index=True)
    target: Mapped[str | None] = mapped_column(String(300), nullable=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
