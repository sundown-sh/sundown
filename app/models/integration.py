"""Integration — a configured connector instance."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, LargeBinary, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models._mixins import IdMixin, JSONType, TimestampMixin, WorkspaceMixin


class Integration(WorkspaceMixin, IdMixin, TimestampMixin, Base):
    __tablename__ = "integration"

    connector: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(16), nullable=False, index=True)  # hris|destination
    tier: Mapped[str] = mapped_column(String(16), nullable=False, default="core")  # core|premium
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    config_encrypted: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_sync_status: Mapped[str | None] = mapped_column(String(16))  # success|error|running
    last_sync_error: Mapped[str | None] = mapped_column(Text)
    last_sync_count: Mapped[int | None] = mapped_column()
    feature_flags: Mapped[list[str]] = mapped_column(JSONType, default=list)
