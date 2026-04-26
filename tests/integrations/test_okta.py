"""Okta connector — replays recorded fixtures."""
from __future__ import annotations

import pytest

from app.integrations.idp.okta import OktaConnector


def _cfg() -> dict[str, str]:
    return {"domain": "acme.okta.com", "api_token": "00xTEST"}


@pytest.mark.asyncio
async def test_healthcheck(use_replay_fixtures: None) -> None:
    async with OktaConnector(_cfg()) as c:
        assert await c.healthcheck() is True


@pytest.mark.asyncio
async def test_fetch_active_principals(use_replay_fixtures: None) -> None:
    async with OktaConnector(_cfg()) as c:
        out = [p async for p in c.fetch_active_principals()]

    ext_ids = sorted(p.external_id for p in out)
    assert ext_ids == ["00uALICE", "00uBOB", "00uCAROL"]

    bob = next(p for p in out if p.external_id == "00uBOB")
    assert bob.email == "bob@acme.com"
    assert "bob.personal@gmail.com" in bob.aliases
    assert bob.status == "suspended"  # important: suspended != deactivated
    assert bob.sso_subject == "00uBOB"
    assert bob.last_login_at is not None
    assert bob.display_name == "Bob Boomerang"
