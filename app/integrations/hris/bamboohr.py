"""BambooHR HRIS connector.

Auth: API key (basic auth, password literal "x").
Docs:  https://documentation.bamboohr.com/reference/

We use two endpoints:
  * GET /api/gateway.php/{subdomain}/v1/employees/directory
        — fast directory listing, no termination_date
  * GET /api/gateway.php/{subdomain}/v1/reports/custom
        — custom report with the fields we actually need

For simplicity (and zero-config setup) v1 reads only the directory and
the per-employee detail endpoint for terminated status. BambooHR
returns ``status`` of ``"Inactive"`` for terminated employees plus a
``terminationDate`` field on the detail record.

Documented rate limit: ~50 req/sec across all endpoints. We run at 70%
of that — 35/sec = 2100/min — well below.
"""
from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import date, datetime
from typing import Any

from app.integrations.base import (
    AuthStrategy,
    BaseConnector,
    BasicAuth,
    ConfigError,
    ConnectorKind,
    ConnectorTier,
    Employee,
)
from app.integrations.registry import register


@register
class BambooHRConnector(BaseConnector):
    name = "bamboohr"
    kind = ConnectorKind.HRIS
    tier = ConnectorTier.CORE
    rate_limit_per_minute = 2100  # 70% of 3000/min

    config_schema = [
        {"key": "subdomain", "label": "BambooHR subdomain", "secret": False, "optional": False},
        {"key": "api_key", "label": "API key", "secret": True, "optional": False},
    ]

    # --- helpers --------------------------------------------------------

    def _require(self, key: str) -> str:
        v = self.config.get(key)
        if not v:
            raise ConfigError(f"BambooHR config missing `{key}`")
        return str(v)

    def auth(self) -> AuthStrategy:
        return BasicAuth(self._require("api_key"), "x")

    def _base(self) -> str:
        sub = self._require("subdomain")
        return f"https://api.bamboohr.com/api/gateway.php/{sub}/v1"

    # --- contract -------------------------------------------------------

    async def healthcheck(self) -> bool:
        # The "meta/users" endpoint is cheap and confirms key + subdomain.
        resp = await self.request(
            "GET",
            f"{self._base()}/meta/users",
            headers={"Accept": "application/json"},
        )
        return resp.status_code == 200

    async def fetch_terminated_employees(
        self, since: datetime | None = None
    ) -> AsyncIterator[Employee]:
        directory = await self.request(
            "GET",
            f"{self._base()}/employees/directory",
            headers={"Accept": "application/json"},
        )
        body: Any = directory.json()
        employees = body.get("employees", []) if isinstance(body, dict) else []

        # Directory only lists active employees. To find terminations we
        # request a custom report.
        report = await self.request(
            "POST",
            f"{self._base()}/reports/custom?format=JSON",
            json_body={
                "title": "Sundown — terminations",
                "fields": [
                    "employeeNumber",
                    "displayName",
                    "workEmail",
                    "status",
                    "hireDate",
                    "terminationDate",
                    "bestEmail",
                ],
            },
            headers={"Accept": "application/json"},
        )
        report_body: Any = report.json()
        rows = report_body.get("employees", []) if isinstance(report_body, dict) else []

        directory_by_id = {str(e.get("id")): e for e in employees}

        for row in rows:
            status = (row.get("status") or "").lower()
            term = row.get("terminationDate")
            if status != "inactive" and not term:
                continue

            ext_id = str(row.get("id") or row.get("employeeNumber") or "")
            if not ext_id:
                continue

            term_date = _parse_date(term)
            start_date = _parse_date(row.get("hireDate"))
            email = (row.get("workEmail") or "").lower() or None
            best_email = (row.get("bestEmail") or "").lower() or None
            secondaries = [e for e in {best_email} - {email} if e]

            dir_entry = directory_by_id.get(ext_id, {})

            yield Employee(
                external_id=ext_id,
                display_name=row.get("displayName") or dir_entry.get("displayName") or "",
                work_email=email,
                secondary_emails=secondaries,
                employee_number=row.get("employeeNumber") or None,
                status="terminated",
                start_date=start_date,
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
