"""Report DTOs."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.schemas.common import ORMModel

ReportKind = Literal["json", "csv", "html", "pdf"]


class ReportCreate(BaseModel):
    kind: ReportKind = "pdf"
    scope: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Optional filters: severity, integration_id, state, "
            "include_suppressed (bool)"
        ),
    )


class ReportOut(ORMModel):
    id: str
    workspace_id: str
    kind: ReportKind
    scope: dict[str, Any] = Field(default_factory=dict)
    ghost_count: int
    path: str
    sha256: str
    generated_by_user_id: str | None = None
    generated_at: datetime
