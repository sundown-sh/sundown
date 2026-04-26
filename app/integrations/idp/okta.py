"""Okta destination connector.

Auth: OAuth client-credentials with a JWT-signed assertion is the
"correct" production path, but Okta also supports an SSWS API token
("API Token" in the admin UI). For zero-config self-hosting we accept
either; OAuth client-credentials is preferred.

We list all users (any status) so the matching engine can detect
ghosts whose Okta account is suspended-but-not-deactivated.

Docs: https://developer.okta.com/docs/reference/api/users/
Rate limit: org-dependent; ``GET /users`` is typically 600/min for
trial orgs and ~1200/min for paid. We default to 70% of 600.
"""
from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any

import httpx

from app.integrations.base import (
    AuthStrategy,
    BaseConnector,
    ConfigError,
    ConnectorKind,
    ConnectorTier,
    Principal,
    StaticBearerAuth,
    _parse_next_link,
)
from app.integrations.registry import register


class _SswsAuth(AuthStrategy):
    """Okta API Token auth: ``Authorization: SSWS <token>``."""

    def __init__(self, token: str) -> None:
        self._token = token

    async def apply(self, request: httpx.Request) -> None:
        request.headers["Authorization"] = f"SSWS {self._token}"


@register
class OktaConnector(BaseConnector):
    name = "okta"
    kind = ConnectorKind.DESTINATION
    tier = ConnectorTier.CORE
    rate_limit_per_minute = 420  # 70% of 600

    config_schema = [
        {"key": "domain", "label": "Okta domain (e.g. acme.okta.com)", "secret": False},
        {"key": "api_token", "label": "API token (SSWS) — preferred for self-host", "secret": True, "optional": True},
        {"key": "oauth_token", "label": "OAuth bearer token", "secret": True, "optional": True},
    ]

    # --- helpers -------------------------------------------------------

    def _domain(self) -> str:
        d = self.config.get("domain")
        if not d:
            raise ConfigError("Okta config missing `domain`")
        d = str(d).strip().rstrip("/")
        if not d.startswith("http"):
            d = f"https://{d}"
        return d

    def auth(self) -> AuthStrategy:
        if self.config.get("api_token"):
            return _SswsAuth(str(self.config["api_token"]))
        if self.config.get("oauth_token"):
            return StaticBearerAuth(str(self.config["oauth_token"]))
        raise ConfigError("Okta config requires `api_token` or `oauth_token`")

    # --- contract ------------------------------------------------------

    async def healthcheck(self) -> bool:
        # /api/v1/users/me returns 200 for any valid auth principal.
        resp = await self.request("GET", f"{self._domain()}/api/v1/users/me")
        # API tokens may map to no user; org settings as fallback.
        if resp.status_code == 200:
            return True
        resp = await self.request("GET", f"{self._domain()}/api/v1/org")
        return resp.status_code == 200

    async def fetch_active_principals(
        self, since: datetime | None = None
    ) -> AsyncIterator[Principal]:
        url = f"{self._domain()}/api/v1/users"
        params: dict[str, Any] = {"limit": 200}

        # Okta exposes RFC-5988 Link headers for pagination.
        next_url: str | None = url
        first = True
        while next_url:
            resp = await self.request(
                "GET",
                next_url,
                params=params if first else None,
                headers={"Accept": "application/json"},
            )
            first = False
            users = resp.json()
            if not isinstance(users, list):
                break
            for u in users:
                yield _user_to_principal(u)

            link = resp.headers.get("link") or resp.headers.get("Link")
            next_url = _parse_next_link(link) if link else None


def _user_to_principal(u: dict[str, Any]) -> Principal:
    profile = u.get("profile") or {}
    email = (profile.get("email") or "").lower() or None
    second = (profile.get("secondEmail") or "").lower() or None
    aliases = [e for e in [second] if e and e != email]
    last_login = _parse_iso(u.get("lastLogin"))
    created = _parse_iso(u.get("created"))
    return Principal(
        external_id=str(u.get("id")),
        username=profile.get("login") or email,
        display_name=" ".join(
            x for x in (profile.get("firstName"), profile.get("lastName")) if x
        )
        or profile.get("displayName")
        or None,
        email=email,
        aliases=aliases,
        sso_subject=str(u.get("id")),  # Okta sub == user id
        status=(u.get("status") or "ACTIVE").lower(),
        last_login_at=last_login,
        created_at_remote=created,
        raw=u,
    )


def _parse_iso(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
