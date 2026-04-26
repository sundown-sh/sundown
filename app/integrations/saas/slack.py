"""Slack destination connector.

Auth: bot token (``xoxb-...``) with ``users:read`` and
``users:read.email`` scopes. Optional ``team:read``.

Docs: https://api.slack.com/methods/users.list
Rate limit: Tier 2 = ~20 req/min; we run at 70% = 14/min.
"""
from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any

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


@register
class SlackConnector(BaseConnector):
    name = "slack"
    kind = ConnectorKind.DESTINATION
    tier = ConnectorTier.CORE
    rate_limit_per_minute = 14

    config_schema = [
        {"key": "bot_token", "label": "Bot token (xoxb-...)", "secret": True, "optional": False},
    ]

    def auth(self) -> AuthStrategy:
        tok = self.config.get("bot_token")
        if not tok:
            raise ConfigError("Slack config missing `bot_token`")
        return StaticBearerAuth(str(tok))

    async def healthcheck(self) -> bool:
        resp = await self.request("POST", "https://slack.com/api/auth.test")
        body: Any = resp.json()
        return bool(body.get("ok"))

    async def fetch_active_principals(
        self, since: datetime | None = None
    ) -> AsyncIterator[Principal]:
        cursor: str | None = None
        while True:
            params: dict[str, Any] = {"limit": 200}
            if cursor:
                params["cursor"] = cursor
            resp = await self.request(
                "GET", "https://slack.com/api/users.list", params=params
            )
            body: Any = resp.json()
            if not body.get("ok"):
                raise RuntimeError(f"slack: {body.get('error')}")
            for u in body.get("members", []):
                if u.get("deleted") or u.get("is_bot") or u.get("id") == "USLACKBOT":
                    continue
                yield _user_to_principal(u)
            cursor = (body.get("response_metadata") or {}).get("next_cursor")
            if not cursor:
                return


def _user_to_principal(u: dict[str, Any]) -> Principal:
    profile = u.get("profile") or {}
    email = (profile.get("email") or "").lower() or None
    return Principal(
        external_id=str(u.get("id")),
        username=u.get("name") or email,
        display_name=profile.get("real_name") or profile.get("display_name") or u.get("name"),
        email=email,
        aliases=[],
        sso_subject=u.get("enterprise_user", {}).get("id") if u.get("enterprise_user") else None,
        status="active",
        last_login_at=None,  # not exposed without admin.users.session
        created_at_remote=_ts(u.get("updated")),
        raw=u,
    )


def _ts(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromtimestamp(int(value))
    except (TypeError, ValueError):
        return None
