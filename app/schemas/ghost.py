"""Ghost DTOs."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.schemas.common import ORMModel

Severity = Literal["critical", "high", "medium"]
GhostState = Literal["open", "acknowledged", "false_positive", "suppressed", "resolved"]
MatchRule = Literal["email", "alias", "sso_subject", "fuzzy"]


class GhostPersonRef(ORMModel):
    id: str
    display_name: str
    work_email: str
    employee_number: str | None = None
    termination_date: datetime | None = None


class GhostAccountRef(ORMModel):
    id: str
    integration_id: str
    connector: str
    external_id: str
    username: str | None = None
    email: str | None = None
    last_login_at: datetime | None = None


class GhostMatchRef(BaseModel):
    rule: MatchRule
    confidence: Literal["high", "medium"]
    evidence: dict[str, str | list[str] | int | float] = Field(default_factory=dict)


class GhostOut(ORMModel):
    id: str
    workspace_id: str
    severity: Severity
    state: GhostState
    days_since_termination: int
    notes: str | None = None
    suppressed_until: datetime | None = None
    first_seen_at: datetime
    last_seen_at: datetime

    person: GhostPersonRef
    account: GhostAccountRef
    match: GhostMatchRef


class GhostUpdate(BaseModel):
    state: GhostState | None = None
    notes: str | None = None
    suppressed_until: datetime | None = None
