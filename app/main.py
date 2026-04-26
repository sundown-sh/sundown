"""Sundown FastAPI application factory.

Wires together:

  * REST API under ``/api/v1``
  * Server-rendered HTMX UI at ``/``
  * Prometheus ``/metrics``
  * Liveness ``/healthz`` / readiness ``/readyz``
  * APScheduler periodic jobs (scan + daily digest)
  * Bootstrap admin user on first run
"""
from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Histogram,
    generate_latest,
    multiprocess,
)
from sqlalchemy import select
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app import __version__
from app.api import audit as audit_api
from app.api import auth as auth_api
from app.api import ghosts as ghosts_api
from app.api import integrations as integrations_api
from app.api import reports as reports_api
from app.config import get_settings
from app.db import get_session_factory
from app.integrations import load_builtin_connectors
from app.logging_config import configure_logging, get_logger
from app.models.user import User
from app.scheduler import build_scheduler
from app.security import hash_password
from app.ui import router as ui_router

log = get_logger(__name__)

# --- Prometheus instruments ----------------------------------------------

REQUESTS = Counter(
    "sundown_http_requests_total",
    "HTTP requests handled.",
    ("method", "path", "status"),
)
LATENCY = Histogram(
    "sundown_http_request_duration_seconds",
    "HTTP request duration.",
    ("method", "path"),
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
)


class MetricsMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        import time

        start = time.perf_counter()
        response = await call_next(request)
        elapsed = time.perf_counter() - start
        # Use the matched route template if present so we don't blow out cardinality.
        route = request.scope.get("route")
        path = getattr(route, "path", request.url.path)
        REQUESTS.labels(request.method, path, str(response.status_code)).inc()
        LATENCY.labels(request.method, path).observe(elapsed)
        return response


# --- Bootstrap ------------------------------------------------------------


def _ensure_bootstrap_admin() -> None:
    """Create the initial admin user if none exists.

    Reads ``SUNDOWN_BOOTSTRAP_ADMIN_EMAIL`` and ``..._PASSWORD``. If
    password is empty, we skip — operators will create users via API.
    """
    settings = get_settings()
    if not settings.bootstrap_admin_password:
        return
    factory = get_session_factory()
    db = factory()
    try:
        existing = db.scalar(
            select(User).where(
                User.email == settings.bootstrap_admin_email,
                User.workspace_id == settings.default_workspace,
            )
        )
        if existing is not None:
            return
        user = User(
            workspace_id=settings.default_workspace,
            email=settings.bootstrap_admin_email,
            password_hash=hash_password(settings.bootstrap_admin_password),
            role="admin",
            is_active=True,
        )
        db.add(user)
        db.commit()
        log.info("bootstrap.admin.created", email=settings.bootstrap_admin_email)
    finally:
        db.close()


# --- Lifespan -------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    configure_logging()
    settings.ensure_dirs()

    load_builtin_connectors()
    _ensure_bootstrap_admin()

    # Scheduler in-process. Disabled in tests via SUNDOWN_DISABLE_SCHEDULER.
    scheduler = None
    if not os.environ.get("SUNDOWN_DISABLE_SCHEDULER"):
        scheduler = build_scheduler()
        scheduler.start()
        log.info("scheduler.started")

    try:
        yield
    finally:
        if scheduler is not None:
            scheduler.shutdown(wait=False)
            log.info("scheduler.stopped")


# --- App factory ----------------------------------------------------------


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="Sundown",
        description="Open-source ghost-account auditor.",
        version=__version__,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )

    app.add_middleware(MetricsMiddleware)

    # API
    app.include_router(auth_api.router, prefix="/api/v1")
    app.include_router(integrations_api.router, prefix="/api/v1")
    app.include_router(ghosts_api.router, prefix="/api/v1")
    app.include_router(reports_api.router, prefix="/api/v1")
    app.include_router(audit_api.router, prefix="/api/v1")

    # UI (cookie-authed, server-rendered)
    app.include_router(ui_router)

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> JSONResponse:
        return JSONResponse({"status": "ok", "version": __version__})

    @app.get("/readyz", include_in_schema=False)
    def readyz() -> JSONResponse:
        from sqlalchemy import text

        try:
            factory = get_session_factory()
            db = factory()
            try:
                db.execute(text("SELECT 1"))
            finally:
                db.close()
        except Exception as e:
            return JSONResponse({"status": "error", "error": str(e)}, status_code=503)
        return JSONResponse({"status": "ready", "workspace": settings.default_workspace})

    @app.get("/metrics", include_in_schema=False)
    def metrics() -> Response:
        # Multiprocess support if running under gunicorn workers; otherwise use
        # the default (process-local) registry.
        if "PROMETHEUS_MULTIPROC_DIR" in os.environ:
            registry = CollectorRegistry()
            multiprocess.MultiProcessCollector(registry)
            data = generate_latest(registry)
        else:
            data = generate_latest()
        return PlainTextResponse(data.decode("utf-8"), media_type=CONTENT_TYPE_LATEST)

    @app.get("/robots.txt", include_in_schema=False, response_class=PlainTextResponse)
    def robots() -> str:
        return "User-agent: *\nDisallow: /\n"

    return app


app = create_app()
