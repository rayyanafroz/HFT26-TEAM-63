"""The FastAPI application (SOT 5.1, 6.1, 6.7).

``create_app`` builds the app: the JSON API under ``/api`` and, if the ``ui/``
folder has an ``index.html``, the dashboard files at ``/``. Errors are always
JSON of the form ``{"error": "message"}`` (SOT 6.1); internal details are never
sent to the client.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from ..config import Config
from ..core.ctx import AgentContexts
from ..core.pipeline import AnalyzeFn, Pipeline
from ..db import Database, open_database
from ..models import ErrorResponse
from ..providers.catalog import Catalog
from ..providers.resolver import Resolver
from . import routes_ingest, routes_stream, routes_system
from .sse import EventBus

log = logging.getLogger("shadowlens.api")

# <repo>/ui, found relative to this file (src/shadowlens/api/app.py -> repo root).
DEFAULT_UI_DIR = Path(__file__).resolve().parents[3] / "ui"

# Shown at "/" until the real dashboard (ui/index.html) exists. No external requests.
PLACEHOLDER_HTML = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>ShadowLens</title>
<meta name="viewport" content="width=device-width, initial-scale=1"></head>
<body>
<h1>ShadowLens</h1>
<p>The server is running. The dashboard (<code>ui/index.html</code>) has not been added yet.</p>
<p>API health: <a href="/api/health">/api/health</a></p>
</body>
</html>
"""


def _error(status: int, message: str) -> JSONResponse:
    return JSONResponse(ErrorResponse(error=message).model_dump(), status_code=status)


def _default_analyzer() -> AnalyzeFn | None:
    """The real analyzer once ``shadowlens.analysis.analyze`` exists; until then the pipeline uses a stub."""
    from .. import analysis
    return getattr(analysis, "analyze", None)


def create_app(
    config: Config | None = None,
    db: Database | None = None,
    ui_dir: Path | None = None,
    *,
    bus: EventBus | None = None,
    catalog: Catalog | None = None,
    resolver: Resolver | None = None,
    pipeline: Pipeline | None = None,
    analyze: AnalyzeFn | None = None,
) -> FastAPI:
    """Build the application.

    Everything can be passed in (tests do). Otherwise the app builds what it needs when it
    starts: it opens the database at ``config.db_path``, starts the host-name resolver
    (unless ``SHADOWLENS_RESOLVE=false``) and creates the ingest pipeline; when it stops it
    closes them in the reverse order.
    """
    config = config or Config.load()
    ui_path = Path(ui_dir) if ui_dir is not None else DEFAULT_UI_DIR
    bus = bus or EventBus()
    catalog = catalog or Catalog.load()
    resolver = resolver if resolver is not None else Resolver(catalog, enabled=config.resolve)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        owns_db = app.state.db is None
        if owns_db:
            config.ensure_dirs()
            app.state.db = open_database(config)
        owns_pipeline = pipeline is None
        app.state.pipeline = pipeline or Pipeline(
            config, app.state.db, catalog, resolver=resolver, contexts=AgentContexts(),
            analyze=analyze or _default_analyzer(), publish=bus.publish)
        resolver.start()
        try:
            yield
        finally:
            resolver.stop()
            bus.close()
            if owns_pipeline:
                app.state.pipeline = None
            if owns_db:
                app.state.db.close()
                app.state.db = None

    app = FastAPI(title="ShadowLens", version="0.1.0", lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.state.config = config
    app.state.db = db
    app.state.bus = bus
    app.state.catalog = catalog
    app.state.resolver = resolver
    app.state.pipeline = pipeline

    # ---- errors: always {"error": "..."} ---------------------------------
    @app.exception_handler(StarletteHTTPException)
    async def http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        return _error(exc.status_code, str(exc.detail))

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        first = exc.errors()[0] if exc.errors() else {}
        where = ".".join(str(p) for p in first.get("loc", ()) if p != "body")
        message = f"invalid request: {where + ': ' if where else ''}{first.get('msg', 'bad input')}"
        return _error(422, message)

    @app.exception_handler(Exception)
    async def unexpected_error(_: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error", exc_info=exc)
        return _error(500, "internal error")

    # ---- API routes ------------------------------------------------------
    app.include_router(routes_system.router)
    app.include_router(routes_ingest.router)
    app.include_router(routes_stream.router)

    # ---- dashboard files (must be added last: "/" would swallow routes) ---
    if (ui_path / "index.html").is_file():
        app.mount("/", StaticFiles(directory=ui_path, html=True), name="ui")
    else:
        @app.get("/", include_in_schema=False)
        def placeholder() -> HTMLResponse:
            return HTMLResponse(PLACEHOLDER_HTML)

    return app
