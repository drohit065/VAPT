from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import get_settings


class Base(DeclarativeBase):
    pass


_engine = None
_SessionLocal = None


def get_engine():
    global _engine, _SessionLocal
    if _engine is None:
        url = get_settings().sqlalchemy_url
        # A connect timeout turns a hanging connection into a logged, retried error.
        connect_args = {"connect_timeout": 10} if url.startswith("postgresql") else {}
        _engine = create_engine(url, pool_pre_ping=True, connect_args=connect_args)
        _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False)
    return _engine


def SessionLocal():
    get_engine()
    return _SessionLocal()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    from . import models  # noqa: F401  (register tables)

    engine = get_engine()
    with engine.begin() as conn:
        if engine.dialect.name == "postgresql":
            # Backend and worker start together: let only one create the tables at a time.
            conn.execute(text("SELECT pg_advisory_xact_lock(7316001)"))
        Base.metadata.create_all(conn)
        if engine.dialect.name == "postgresql":
            for stmt in MIGRATIONS:
                conn.execute(text(stmt))


# Columns added after the first release. create_all() only creates missing tables, so existing
# databases get new columns here (idempotent).
MIGRATIONS = [
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS diff JSON",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS options JSON",
    "ALTER TABLE findings ADD COLUMN IF NOT EXISTS fingerprint VARCHAR(64)",
    "CREATE INDEX IF NOT EXISTS ix_findings_fingerprint ON findings (fingerprint)",
    "ALTER TABLE findings ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'open'",
    "ALTER TABLE findings ADD COLUMN IF NOT EXISTS status_note TEXT",
    "ALTER TABLE findings ADD COLUMN IF NOT EXISTS status_updated_at TIMESTAMPTZ",
    "ALTER TABLE findings ADD COLUMN IF NOT EXISTS is_new BOOLEAN NOT NULL DEFAULT TRUE",
    "ALTER TABLE findings ADD COLUMN IF NOT EXISTS cvss_score DOUBLE PRECISION",
    "ALTER TABLE findings ADD COLUMN IF NOT EXISTS cvss_vector VARCHAR(200)",
    "ALTER TABLE findings ADD COLUMN IF NOT EXISTS cvss_source VARCHAR(20)",
]
