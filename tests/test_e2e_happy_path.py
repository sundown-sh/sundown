"""End-to-end happy path: seed → log in → see ghosts → generate report.

This is the demo flow on the README and on the marketing landing page.
If this test ever breaks the README is wrong.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def app_and_token(monkeypatch: pytest.MonkeyPatch) -> tuple[TestClient, str]:
    monkeypatch.setenv("SUNDOWN_DISABLE_SCHEDULER", "1")

    from app.main import create_app
    from scripts.seed import DEMO_ADMIN_EMAIL, DEMO_ADMIN_PASSWORD
    from scripts.seed import main as seed_main

    seed_main(reset=True)
    app = create_app()
    client = TestClient(app)
    r = client.post(
        "/api/v1/auth/login",
        json={"email": DEMO_ADMIN_EMAIL, "password": DEMO_ADMIN_PASSWORD},
    )
    assert r.status_code == 200, r.text
    return client, r.json()["access_token"]


def test_dashboard_lists_seeded_ghosts(app_and_token: tuple[TestClient, str]) -> None:
    client, token = app_and_token
    client.cookies.set("sundown_token", token)

    r = client.get("/")
    assert r.status_code == 200
    body = r.text
    # Dashboard, not setup wizard.
    assert "Open ghosts" in body
    assert "Welcome to Sundown" not in body
    # We should see at least one of our seeded terminated employees.
    assert "edsger@acme.com" in body or "ken@acme.com" in body


def test_ghosts_list_renders_and_filters(app_and_token: tuple[TestClient, str]) -> None:
    client, token = app_and_token
    client.cookies.set("sundown_token", token)

    r = client.get("/ghosts")
    assert r.status_code == 200
    assert "Ghost accounts" in r.text

    # Filter to critical only
    r = client.get("/ghosts?severity=critical")
    assert r.status_code == 200
    assert "critical" in r.text


def test_api_ghost_listing_authenticated(app_and_token: tuple[TestClient, str]) -> None:
    client, token = app_and_token
    headers = {"Authorization": f"Bearer {token}"}
    r = client.get("/api/v1/ghosts?limit=200", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["total"] >= 5
    severities = {item["severity"] for item in body["items"]}
    assert {"critical", "high", "medium"}.issubset(severities)


def test_generate_csv_report_end_to_end(app_and_token: tuple[TestClient, str]) -> None:
    client, token = app_and_token
    headers = {"Authorization": f"Bearer {token}"}

    r = client.post("/api/v1/reports", headers=headers, json={"kind": "csv"})
    assert r.status_code in (200, 201)
    rep = r.json()
    assert rep["kind"] == "csv"
    assert rep["ghost_count"] >= 5

    r2 = client.get(f"/api/v1/reports/{rep['id']}/download", headers=headers)
    assert r2.status_code == 200
    assert "person_email" in r2.text or "work_email" in r2.text


def test_report_download_works_with_session_cookie_only(
    app_and_token: tuple[TestClient, str],
) -> None:
    """Clicking "download" is a plain GET — the browser sends the HttpOnly
    cookie but not ``Authorization``. ``get_principal`` must accept the cookie."""
    client, token = app_and_token
    client.cookies.set("sundown_token", token)

    r = client.post(
        "/api/v1/reports",
        headers={"Authorization": f"Bearer {token}"},
        json={"kind": "csv"},
    )
    assert r.status_code in (200, 201)
    rep_id = r.json()["id"]

    r2 = client.get(f"/api/v1/reports/{rep_id}/download")
    assert r2.status_code == 200
    assert "person_email" in r2.text or "work_email" in r2.text


@pytest.mark.parametrize("kind", ["json", "csv", "html", "pdf"])
def test_every_report_kind_renders(
    app_and_token: tuple[TestClient, str], kind: str
) -> None:
    """Regression: HTML/PDF rendering once silently failed because the
    embedded CSS contained literal ``{`` ``}`` and the template was
    formatted with ``str.format``. We now exercise every format.
    """
    client, token = app_and_token
    headers = {"Authorization": f"Bearer {token}"}

    r = client.post(
        "/api/v1/reports",
        headers=headers,
        json={"kind": kind, "scope": {"severity": "critical"}},
    )
    assert r.status_code in (200, 201), f"{kind}: {r.status_code} {r.text}"
    rep = r.json()
    if kind == "pdf":
        # Linux/macOS CI often has WeasyPrint → real PDF. Windows (and
        # bare images without Cairo) fall back to printable HTML.
        assert rep["kind"] in ("pdf", "html"), rep
    else:
        assert rep["kind"] == kind
    assert rep["sha256"], f"{kind} report has no sha256"

    r2 = client.get(f"/api/v1/reports/{rep['id']}/download", headers=headers)
    assert r2.status_code == 200
    assert len(r2.content) > 64, f"{kind} download empty"
    if rep["kind"] == "pdf":
        assert r2.content.startswith(b"%PDF"), "expected PDF magic bytes"
    elif rep["kind"] == "html":
        head = r2.content[:200].lower()
        assert b"<!doctype html" in head or b"<html" in head


def test_audit_log_chain_is_intact(app_and_token: tuple[TestClient, str]) -> None:
    client, token = app_and_token
    headers = {"Authorization": f"Bearer {token}"}
    # Trigger at least one audit-worthy action.
    r = client.post("/api/v1/ghosts/rescan", headers=headers)
    assert r.status_code in (200, 202)

    v = client.get("/api/v1/audit/verify", headers=headers)
    assert v.status_code == 200
    body = v.json()
    assert body["ok"] is True
    assert body["checked"] >= 1
