import time

from fastapi import FastAPI
from sqlalchemy.exc import OperationalError

from .config import get_settings
from .db import init_db
from .routers import auth, projects, scans

# No public docs/openapi routes: every route except login requires authentication.
app = FastAPI(title="VAPT Scanner", docs_url=None, redoc_url=None, openapi_url=None)

app.include_router(auth.router)
app.include_router(projects.router)
app.include_router(scans.router)


@app.on_event("startup")
def startup():
    get_settings().validate_api_settings()  # fail fast on missing / placeholder secrets
    for attempt in range(30):
        try:
            init_db()
            return
        except OperationalError:
            time.sleep(2)
    init_db()
