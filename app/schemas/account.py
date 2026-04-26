"""Account DTOs."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from app.schemas.common import ORMModel


class AccountBase(ORMModel):
    external_id: str
    username: str | None = None
    display_name: str | None = None
    email: str | None = None
    aliases: list[str] = Field(default_factory=list)
    sso_subject: str | None = None
    status: Literal["active", "suspended", "deprovisioned"] = "active"
    last_login_at: datetime | None = None
    created_at_remote: datetime | None = None


class AccountOut(AccountBase):
    id: str
    workspace_id: str
    integration_id: str
    raw: dict[str, Any] = Field(default_factory=dict)
    first_seen_at: datetime
    last_seen_at: datetime
