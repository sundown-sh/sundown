"""BambooHR connector — replays recorded fixtures, no network."""
from __future__ import annotations

from datetime import date

import pytest

from app.integrations.hris.bamboohr import BambooHRConnector


@pytest.mark.asyncio
async def test_healthcheck_replays_fixture(use_replay_fixtures: None) -> None:
    async with BambooHRConnector({"subdomain": "acme", "api_key": "k"}) as c:
        assert await c.healthcheck() is True


@pytest.mark.asyncio
async def test_fetch_terminated_only_terminations(use_replay_fixtures: None) -> None:
    async with BambooHRConnector({"subdomain": "acme", "api_key": "k"}) as c:
        out = [e async for e in c.fetch_terminated_employees()]

    # Active "Alice" must be filtered out; only Bob + Carol returned.
    ext_ids = sorted(e.external_id for e in out)
    assert ext_ids == ["201", "202"]

    bob = next(e for e in out if e.external_id == "201")
    assert bob.work_email == "bob@acme.com"
    assert "bob.personal@gmail.com" in bob.secondary_emails
    assert bob.termination_date == date(2026, 4, 10)
    assert bob.status == "terminated"
    assert bob.employee_number == "E-201"

    carol = next(e for e in out if e.external_id == "202")
    # When bestEmail == workEmail, no duplicate in secondary_emails.
    assert carol.secondary_emails == []
    assert carol.termination_date == date(2026, 1, 1)
