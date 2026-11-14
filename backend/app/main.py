import logging
import time

from fastapi import FastAPI
from sqlalchemy.exc import OperationalError

from .config import get_settings
from .db import init_db
from .routers import auth, projects, scans, users

# No public docs/openapi routes: every route except login requires authentication.
app = FastAPI(title="VAPT Scanner", docs_url=None, redoc_url=None, openapi_url=None)

app.include_router(auth.router)
app.include_router(projects.router)
app.include_router(scans.router)
app.include_router(users.router)


@app.on_event("startup")
def startup():
    get_settings().validate_api_settings()  # fail fast on missing / placeholder secrets
    log = logging.getLogger("uvicorn.error")
    for attempt in range(30):
        try:
            init_db()
            return
        except OperationalError as e:
            reason = str(e.orig).strip().splitlines()[0] if e.orig else str(e)
            log.warning("Database not ready (attempt %s/30): %s", attempt + 1, reason)
            if "password authentication failed" in reason:
                log.error("POSTGRES_PASSWORD in .env does not match the existing database volume. "
                          "If you have no data to keep, run: docker compose down -v && docker compose up -d")
            time.sleep(2)
    init_db()
