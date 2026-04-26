"""Person DTOs."""
from __future__ import annotations

from datetime import date, datetime
from typing import Any, Literal

from pydantic import EmailStr, Field

from app.schemas.common import ORMModel


class PersonBase(ORMModel):
    external_id: str
    employee_number: str | None = None
    display_name: str
    work_email: EmailStr
    secondary_emails: list[EmailStr] = Field(default_factory=list)
    sso_subject: str | None = None
    status: Literal["active", "terminated"]
    start_date: date | None = None
    termination_date: date | None = None


class PersonOut(PersonBase):
    id: str
    workspace_id: str
    integration_id: str
    raw: dict[str, Any] = Field(default_factory=dict)
    first_seen_at: datetime
    last_seen_at: datetime
