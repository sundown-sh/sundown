"""Google Workspace destination connector.

Auth: Service account with **domain-wide delegation** of the
``https://www.googleapis.com/auth/admin.directory.user.readonly`` scope,
impersonating a super-admin on the customer's domain.

We mint a signed JWT, exchange it for an OAuth bearer at
``oauth2.googleapis.com/token``, and call the Admin SDK Directory API
with that token. Tokens are cached for ~50 minutes.

Docs: https://developers.google.com/admin-sdk/directory/reference/rest/v1/users/list
Rate limit: 2400/min default; we run at 70% = 1680/min.
"""
from __future__ import annotations

import time
from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any

import httpx
import jwt

from app.integrations.base import (
    AuthStrategy,
    BaseConnector,
    ConfigError,
    ConnectorKind,
    ConnectorTier,
    Principal,
)
from app.integrations.registry import register

_SCOPE = "https://www.googleapis.com/auth/admin.directory.user.readonly"
_TOKEN_URL = "https://oauth2.googleapis.com/token"


class _ServiceAccountAuth(AuthStrategy):
    def __init__(self, client_email: str, private_key_pem: str, subject: str) -> None:
        self._email = client_email
        self._key = private_key_pem
        self._subject = subject
        self._token: str | None = None
        self._expires_at: float = 0.0

    async def apply(self, request: httpx.Request) -> None:
        if not self._token or time.time() > self._expires_at - 60:
            await self._refresh()
        request.headers["Authorization"] = f"Bearer {self._token}"

    async def _refresh(self) -> None:
        now = int(time.time())
        assertion = jwt.encode(
            {
                "iss": self._email,
                "scope": _SCOPE,
                "aud": _TOKEN_URL,
                "iat": now,
                "exp": now + 3600,
                "sub": self._subject,
            },
            self._key,
            algorithm="RS256",
        )
        async with httpx.AsyncClient(timeout=30.0) as cli:
            resp = await cli.post(
                _TOKEN_URL,
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "assertion": assertion,
                },
            )
            resp.raise_for_status()
            body = resp.json()
        self._token = body["access_token"]
        self._expires_at = time.time() + int(body.get("expires_in", 3600))


@register
class GoogleWorkspaceConnector(BaseConnector):
    name = "google_workspace"
    kind = ConnectorKind.DESTINATION
    tier = ConnectorTier.CORE
    rate_limit_per_minute = 1680

    config_schema = [
        {"key": "customer_id", "label": "Customer ID (or 'my_customer')", "secret": False, "optional": False},
        {"key": "service_account_email", "label": "Service-account client email", "secret": False, "optional": False},
        {"key": "private_key_pem", "label": "Service-account private key (PEM)", "secret": True, "optional": False},
        {"key": "impersonate", "label": "Super-admin to impersonate (email)", "secret": False, "optional": False},
    ]

    def auth(self) -> AuthStrategy:
        for k in ("service_account_email", "private_key_pem", "impersonate"):
            if not self.config.get(k):
                raise ConfigError(f"Google Workspace config missing `{k}`")
        return _ServiceAccountAuth(
            str(self.config["service_account_email"]),
            str(self.config["private_key_pem"]),
            str(self.config["impersonate"]),
        )

    async def healthcheck(self) -> bool:
        resp = await self.request(
            "GET",
            "https://admin.googleapis.com/admin/directory/v1/users",
            params={"customer": self._customer(), "maxResults": 1},
        )
        return resp.status_code == 200

    def _customer(self) -> str:
        return str(self.config.get("customer_id") or "my_customer")

    async def fetch_active_principals(
        self, since: datetime | None = None
    ) -> AsyncIterator[Principal]:
        async for u in self.paginate(
            "https://admin.googleapis.com/admin/directory/v1/users",
            params={"customer": self._customer(), "maxResults": 500},
            items_key="users",
            next_url_fn=lambda d: (
                "https://admin.googleapis.com/admin/directory/v1/users"
                if d.get("nextPageToken")
                else None
            ),
        ):
            yield _user_to_principal(u)


def _user_to_principal(u: dict[str, Any]) -> Principal:
    primary = (u.get("primaryEmail") or "").lower() or None
    aliases = [a.lower() for a in (u.get("aliases") or []) if a]
    name = (u.get("name") or {}).get("fullName")
    return Principal(
        external_id=str(u.get("id")),
        username=primary,
        display_name=name,
        email=primary,
        aliases=aliases,
        sso_subject=str(u.get("id")),
        status="suspended" if u.get("suspended") else "active",
        last_login_at=_parse_iso(u.get("lastLoginTime")),
        created_at_remote=_parse_iso(u.get("creationTime")),
        raw=u,
    )


def _parse_iso(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
