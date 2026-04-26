"""Person — an employee record from the HRIS source-of-truth."""
from __future__ import annotations

from datetime import date, datetime
from typing import Any

from sqlalchemy import Date, DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models._mixins import IdMixin, JSONType, TimestampMixin, WorkspaceMixin


class Person(WorkspaceMixin, IdMixin, TimestampMixin, Base):
    __tablename__ = "person"
    __table_args__ = (
        UniqueConstraint("workspace_id", "integration_id", "external_id", name="uq_person_external"),
    )

    integration_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("integration.id", ondelete="CASCADE"), nullable=False, index=True
    )
    external_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    employee_number: Mapped[str | None] = mapped_column(String(64))
    display_name: Mapped[str] = mapped_column(String(256), nullable=False)
    work_email: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    secondary_emails: Mapped[list[str]] = mapped_column(JSONType, default=list)
    sso_subject: Mapped[str | None] = mapped_column(String(256), index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, index=True)  # active|terminated
    start_date: Mapped[date | None] = mapped_column(Date)
    termination_date: Mapped[date | None] = mapped_column(Date, index=True)
    raw: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    def is_terminated(self) -> bool:
        return self.status == "terminated" and self.termination_date is not None

    def all_emails(self) -> list[str]:
        out: list[str] = []
        if self.work_email:
            out.append(self.work_email.lower())
        for e in self.secondary_emails or []:
            if e:
                out.append(e.lower())
        return out
