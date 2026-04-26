"""Report — a generated evidence pack."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models._mixins import IdMixin, JSONType, TimestampMixin, WorkspaceMixin


class Report(WorkspaceMixin, IdMixin, TimestampMixin, Base):
    __tablename__ = "report"

    kind: Mapped[str] = mapped_column(String(16), nullable=False, index=True)  # json|csv|html|pdf
    scope: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    ghost_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    path: Mapped[str] = mapped_column(String(512), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    generated_by_user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("user.id", ondelete="SET NULL")
    )
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
