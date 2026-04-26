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
