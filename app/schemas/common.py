"""Shared schema primitives."""
from __future__ import annotations

from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    limit: int
    offset: int


class Problem(BaseModel):
    """RFC-7807-ish error envelope."""

    type: str = "about:blank"
    title: str
    detail: str | None = None
    status: int = 400
    instance: str | None = None
    extra: dict[str, str] | None = Field(default=None)
