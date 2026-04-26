"""Account — a principal on a destination system."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models._mixins import IdMixin, JSONType, TimestampMixin, WorkspaceMixin


class Account(WorkspaceMixin, IdMixin, TimestampMixin, Base):
    __tablename__ = "account"
    __table_args__ = (
        UniqueConstraint(
            "workspace_id", "integration_id", "external_id", name="uq_account_external"
        ),
    )

    integration_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("integration.id", ondelete="CASCADE"), nullable=False, index=True
    )
    external_id: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    username: Mapped[str | None] = mapped_column(String(256))
    display_name: Mapped[str | None] = mapped_column(String(256))
    email: Mapped[str | None] = mapped_column(String(256), index=True)
    aliases: Mapped[list[str]] = mapped_column(JSONType, default=list)
    sso_subject: Mapped[str | None] = mapped_column(String(256), index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active", index=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at_remote: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    raw: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    def all_emails(self) -> list[str]:
        out: list[str] = []
        if self.email:
            out.append(self.email.lower())
        for e in self.aliases or []:
            if e:
                out.append(e.lower())
        return out
