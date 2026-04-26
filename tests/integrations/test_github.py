"""GitHub Organizations connector — replays recorded fixtures."""
from __future__ import annotations

import pytest

from app.integrations.saas.github import GitHubConnector


def _cfg() -> dict[str, str]:
    return {"org": "acme", "pat": "ghp_TEST"}


@pytest.mark.asyncio
async def test_healthcheck(use_replay_fixtures: None) -> None:
    async with GitHubConnector(_cfg()) as c:
        assert await c.healthcheck() is True


@pytest.mark.asyncio
async def test_fetch_active_principals(use_replay_fixtures: None) -> None:
    async with GitHubConnector(_cfg()) as c:
        out = [p async for p in c.fetch_active_principals()]

    assert sorted(p.username or "" for p in out) == ["alice", "bob"]

    bob = next(p for p in out if p.username == "bob")
    assert bob.email == "bob@acme.com"
    assert bob.display_name == "Bob Boomerang"
    assert bob.sso_subject == "bob@acme.com"  # from external-identities
    assert bob.external_id == "MDQ6VXNlcjIwMDE="  # node_id, the stable one


def test_connector_refuses_without_auth() -> None:
    from app.integrations.base import ConfigError

    c = GitHubConnector({"org": "acme"})
    with pytest.raises(ConfigError):
        c.auth()
