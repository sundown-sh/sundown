"""GitHub Organizations destination connector.

Auth: GitHub App installation token. The hosted/operator path:

  1. Operator creates a GitHub App with read-only ``Members`` and
     ``Organization administration`` permissions.
  2. They install it on their org and provide the installation_id +
     app_id + the App's PEM private key.
  3. We mint a JWT (RS256) signed by the private key, exchange it for
     an installation access token, and call the REST API with that
     token. Tokens auto-rotate every hour.

For the simplest possible self-host bring-up we ALSO accept a personal
access token (``pat``); this is documented as not-recommended-for-prod
in the UI.

Docs: https://docs.github.com/en/rest/orgs/members
Rate limit: GitHub Apps get 5000 req/hour per installation = ~83/min;
we run at 70% = 58/min.
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
    StaticBearerAuth,
)
from app.integrations.registry import register


class _GithubAppAuth(AuthStrategy):
    """Mints an installation token on demand and caches it."""

    def __init__(self, app_id: str, installation_id: str, private_key_pem: str) -> None:
        self._app_id = app_id
        self._installation_id = installation_id
        self._key = private_key_pem
        self._token: str | None = None
        self._expires_at: float = 0.0

    async def apply(self, request: httpx.Request) -> None:
        if not self._token or time.time() > self._expires_at - 60:
            await self._refresh()
        request.headers["Authorization"] = f"Bearer {self._token}"
        request.headers["Accept"] = "application/vnd.github+json"
        request.headers["X-GitHub-Api-Version"] = "2022-11-28"

    async def _refresh(self) -> None:
        now = int(time.time())
        app_jwt = jwt.encode(
            {"iat": now - 30, "exp": now + 540, "iss": self._app_id},
            self._key,
            algorithm="RS256",
        )
        async with httpx.AsyncClient(timeout=30.0) as cli:
            resp = await cli.post(
                f"https://api.github.com/app/installations/{self._installation_id}/access_tokens",
                headers={
                    "Authorization": f"Bearer {app_jwt}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            resp.raise_for_status()
            body = resp.json()
        self._token = body["token"]
        # GitHub returns ISO-8601 expires_at; keep it simple, cache 50min.
        self._expires_at = time.time() + 3000


@register
class GitHubConnector(BaseConnector):
    name = "github"
    kind = ConnectorKind.DESTINATION
    tier = ConnectorTier.CORE
    rate_limit_per_minute = 58  # 70% of 83/min (5000/hr)

    config_schema = [
        {"key": "org", "label": "GitHub organization (login)", "secret": False, "optional": False},
        {"key": "pat", "label": "Personal access token (read-only) — quickest to set up", "secret": True, "optional": True},
        {"key": "app_id", "label": "GitHub App ID", "secret": False, "optional": True},
        {"key": "installation_id", "label": "Installation ID", "secret": False, "optional": True},
        {"key": "private_key_pem", "label": "App private key (PEM)", "secret": True, "optional": True},
    ]

    # --- helpers --------------------------------------------------------

    def _org(self) -> str:
        org = self.config.get("org")
        if not org:
            raise ConfigError("GitHub config missing `org`")
        return str(org)

    def auth(self) -> AuthStrategy:
        if self.config.get("pat"):
            return StaticBearerAuth(str(self.config["pat"]))
        if self.config.get("app_id") and self.config.get("installation_id") and self.config.get("private_key_pem"):
            return _GithubAppAuth(
                str(self.config["app_id"]),
                str(self.config["installation_id"]),
                str(self.config["private_key_pem"]),
            )
        raise ConfigError("GitHub config requires `pat` OR (`app_id` + `installation_id` + `private_key_pem`)")

    # --- contract -------------------------------------------------------

    async def healthcheck(self) -> bool:
        resp = await self.request("GET", f"https://api.github.com/orgs/{self._org()}")
        return resp.status_code == 200

    async def fetch_active_principals(
        self, since: datetime | None = None
    ) -> AsyncIterator[Principal]:
        org = self._org()

        # 1) members of the org
        async for member in self.paginate(
            f"https://api.github.com/orgs/{org}/members",
            params={"per_page": 100, "filter": "all"},
        ):
            login = member.get("login")
            if not login:
                continue

            # 2) hydrate with email if the org allows it (admins see it)
            user_resp = await self.request(
                "GET", f"https://api.github.com/users/{login}"
            )
            user_body: Any = user_resp.json() if user_resp.status_code == 200 else {}

            # 3) for SAML-enabled orgs, fetch SCIM external_id
            sso_subject = await self._sso_subject(org, login)

            yield Principal(
                external_id=str(member.get("node_id") or member.get("id") or login),
                username=login,
                display_name=user_body.get("name") or login,
                email=(user_body.get("email") or "").lower() or None,
                aliases=[],
                sso_subject=sso_subject,
                status="active",
                last_login_at=None,  # not exposed on GitHub
                created_at_remote=_parse_iso(user_body.get("created_at")),
                raw={"member": member, "user": user_body},
            )

    async def _sso_subject(self, org: str, login: str) -> str | None:
        """For SAML-enabled orgs, the user's NameID via the SCIM API.

        Returns ``None`` quietly if the API isn't available (most common
        case is a non-Enterprise org).
        """
        try:
            resp = await self.request(
                "GET",
                f"https://api.github.com/orgs/{org}/external-identities",
                params={"per_page": 100},
            )
        except Exception:
            return None
        if resp.status_code != 200:
            return None
        body: Any = resp.json()
        nodes = body.get("nodes") if isinstance(body, dict) else None
        if not isinstance(nodes, list):
            return None
        for n in nodes:
            user = n.get("user") or {}
            if user.get("login") == login:
                return n.get("samlIdentity", {}).get("nameId") or None
        return None


def _parse_iso(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
