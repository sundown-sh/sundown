"""Integration DTOs.

Note: ``config`` (the secret blob) is **write-only**. We never return it.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.schemas.common import ORMModel


class IntegrationCreate(BaseModel):
    connector: str
    display_name: str
    config: dict[str, Any] = Field(
        ..., description="Provider-specific. e.g. {api_key: '...', subdomain: '...'}"
    )
    enabled: bool = True
    feature_flags: list[str] = Field(default_factory=list)


class IntegrationUpdate(BaseModel):
    display_name: str | None = None
    enabled: bool | None = None
    config: dict[str, Any] | None = None
    feature_flags: list[str] | None = None


class IntegrationOut(ORMModel):
    id: str
    workspace_id: str
    connector: str
    kind: Literal["hris", "destination"]
    tier: Literal["core", "premium"]
    display_name: str
    enabled: bool
    last_sync_at: datetime | None = None
    last_sync_status: str | None = None
    last_sync_error: str | None = None
    last_sync_count: int | None = None
    feature_flags: list[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class HealthcheckResult(BaseModel):
    ok: bool
    detail: str | None = None
    latency_ms: int | None = None


class SyncResult(BaseModel):
    ok: bool
    fetched: int
    duration_ms: int
    error: str | None = None
