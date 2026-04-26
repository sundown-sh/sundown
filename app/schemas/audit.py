"""Audit event DTO."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from app.schemas.common import ORMModel


class AuditEventOut(ORMModel):
    id: str
    workspace_id: str
    actor_type: Literal["user", "api_key", "system"]
    actor_id: str
    action: str
    target_type: str | None = None
    target_id: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    ip: str | None = None
    user_agent: str | None = None
    prev_hash: str
    hash: str
    at: datetime
