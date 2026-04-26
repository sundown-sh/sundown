"""Rippling HRIS connector.

Auth: OAuth (we accept a pre-issued bearer token in v1 to avoid
shipping a redirect-handler in the OSS install. The hosted version
ships the OAuth dance.)

Docs: https://developer.rippling.com/
"""
from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import date, datetime
from typing import Any

from app.integrations.base import (
    AuthStrategy,
    BaseConnector,
    ConfigError,
    ConnectorKind,
    ConnectorTier,
    Employee,
    StaticBearerAuth,
)
from app.integrations.registry import register


@register
class RipplingConnector(BaseConnector):
    name = "rippling"
    kind = ConnectorKind.HRIS
    tier = ConnectorTier.CORE
    rate_limit_per_minute = 84  # 70% of 120/min

    config_schema = [
        {"key": "access_token", "label": "Rippling OAuth access token", "secret": True, "optional": False},
        {"key": "base_url", "label": "API base URL", "secret": False, "optional": True},
    ]

    def _base(self) -> str:
        return str(self.config.get("base_url") or "https://api.rippling.com/platform/api")

    def auth(self) -> AuthStrategy:
        tok = self.config.get("access_token")
        if not tok:
            raise ConfigError("Rippling config missing `access_token`")
        return StaticBearerAuth(str(tok))

    async def healthcheck(self) -> bool:
        resp = await self.request("GET", f"{self._base()}/me")
        return resp.status_code == 200

    async def fetch_terminated_employees(
        self, since: datetime | None = None
    ) -> AsyncIterator[Employee]:
        async for row in self.paginate(
            f"{self._base()}/employees",
            params={"limit": 100, "status": "TERMINATED"},
            items_key="results",
            next_url_fn=lambda d: d.get("next"),
        ):
            term_date = _parse_date(row.get("endDate") or row.get("terminationDate"))
            email = (row.get("workEmail") or "").lower() or None
            personal = (row.get("personalEmail") or "").lower() or None
            yield Employee(
                external_id=str(row.get("id") or row.get("employeeNumber") or ""),
                display_name=row.get("name")
                or " ".join(filter(None, (row.get("firstName"), row.get("lastName"))))
                or "(unknown)",
                work_email=email,
                secondary_emails=[e for e in [personal] if e and e != email],
                sso_subject=row.get("ssoSubject") or None,
                employee_number=row.get("employeeNumber") or None,
                status="terminated",
                start_date=_parse_date(row.get("startDate")),
                termination_date=term_date,
                raw=row,
            )


def _parse_date(value: Any) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(str(value)[:10])
    except ValueError:
        return None
