"""Smoke tests covering main, scheduler wiring, UI, notifications, seed.

Goal: prove the app boots, the UI renders, the scheduler can be built,
the seed produces ghosts, and the notification dispatchers don't blow up
when no sinks are configured.
"""
from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("SUNDOWN_DISABLE_SCHEDULER", "1")
    from app.main import create_app

    app = create_app()
    return TestClient(app)


# --- public surface -------------------------------------------------------


def test_healthz(client: TestClient) -> None:
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_readyz(client: TestClient) -> None:
    r = client.get("/readyz")
    assert r.status_code == 200
    assert r.json()["status"] == "ready"


def test_metrics_exposes_prometheus_format(client: TestClient) -> None:
    client.get("/healthz")  # ensure at least one labelled request
    r = client.get("/metrics")
    assert r.status_code == 200
    body = r.text
    assert "sundown_http_requests_total" in body


def test_openapi(client: TestClient) -> None:
    r = client.get("/api/openapi.json")
    assert r.status_code == 200
    schema = r.json()
    paths = schema["paths"]
    assert "/api/v1/auth/login" in paths
    assert "/api/v1/ghosts" in paths
    assert "/api/v1/integrations" in paths
    assert "/api/v1/reports" in paths
    assert "/api/v1/audit" in paths


def test_robots(client: TestClient) -> None:
    r = client.get("/robots.txt")
    assert r.status_code == 200
    assert "Disallow" in r.text


# --- UI redirects when unauthed -------------------------------------------


def test_dashboard_unauthed_redirects_to_login(client: TestClient) -> None:
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"] == "/login"


def test_login_page_renders(client: TestClient) -> None:
    r = client.get("/login")
    assert r.status_code == 200
    assert "Sign in to Sundown" in r.text


# --- UI authed via cookie -------------------------------------------------


def _login(client: TestClient, db_session) -> str:
    """Create an admin user, log in via API, return access token."""
    from app.config import get_settings
    from app.models.user import User
    from app.security import hash_password

    s = get_settings()
    db_session.add(
        User(
            workspace_id=s.default_workspace,
            email="ada@acme.com",
            password_hash=hash_password("hunter2-hunter2"),
            role="admin",
            is_active=True,
        )
    )
    db_session.commit()

    r = client.post(
        "/api/v1/auth/login",
        json={"email": "ada@acme.com", "password": "hunter2-hunter2"},
    )
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def test_authed_dashboard_renders_setup_wizard_when_empty(client: TestClient, session) -> None:
    token = _login(client, session)
    client.cookies.set("sundown_token", token)
    r = client.get("/")
    assert r.status_code == 200
    assert "Welcome to Sundown" in r.text


def test_authed_ui_routes(client: TestClient, session) -> None:
    token = _login(client, session)
    client.cookies.set("sundown_token", token)

    for path in ("/ghosts", "/integrations", "/reports", "/settings", "/audit"):
        r = client.get(path)
        assert r.status_code == 200, f"{path} -> {r.status_code}"

    # api docs
    r = client.get("/api/docs")
    assert r.status_code == 200


# --- scheduler wiring -----------------------------------------------------


def test_build_scheduler_has_both_jobs() -> None:
    from app.scheduler import build_scheduler

    sched = build_scheduler()
    ids = {j.id for j in sched.get_jobs()}
    assert {"scan", "digest"}.issubset(ids)
    # Don't call shutdown() — it raises if the scheduler hasn't been started.


# --- notifications no-op when unconfigured --------------------------------


@pytest.mark.asyncio
async def test_notify_daily_digest_noop_when_unconfigured() -> None:
    from app.notifications import notify_daily_digest

    # No webhooks configured → must not raise.
    await notify_daily_digest(0, 0, 0, 0)


@pytest.mark.asyncio
async def test_notify_new_critical_ghost_noop_when_unconfigured() -> None:
    from app.notifications import notify_new_critical_ghost
    from app.notifications.dispatch import GhostSummary

    await notify_new_critical_ghost(
        GhostSummary(
            id="g1",
            person_email="ed@acme.com",
            connector="okta",
            severity="critical",
            days_since_termination=14,
        )
    )


# --- seed -----------------------------------------------------------------


def test_seed_produces_one_ghost_per_severity_tier(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.config import get_settings
    from app.db import session_scope
    from app.models.ghost import Ghost
    from scripts.seed import main as seed_main

    seed_main(reset=True)

    with session_scope() as db:
        ws = get_settings().default_workspace
        ghosts = db.query(Ghost).filter_by(workspace_id=ws).all()
        sev = {g.severity for g in ghosts}
    # We seed at least one ghost for every severity tier.
    assert {"critical", "high", "medium"}.issubset(sev)
    assert len(ghosts) >= 5  # 3 terminated × {okta, github} minus those without a github account


# --- CLI parser smoke -----------------------------------------------------


def test_cli_help_exits_zero() -> None:
    import subprocess
    import sys

    r = subprocess.run(
        [sys.executable, "-m", "app.cli", "--help"],
        capture_output=True,
        text=True,
        env={**os.environ, "SUNDOWN_DISABLE_SCHEDULER": "1"},
    )
    assert r.returncode == 0
    assert "serve" in r.stdout
    assert "migrate" in r.stdout
    assert "seed" in r.stdout
