"""Ghost — a Person×Account match where the Person is terminated."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models._mixins import IdMixin, TimestampMixin, WorkspaceMixin


class Ghost(WorkspaceMixin, IdMixin, TimestampMixin, Base):
    __tablename__ = "ghost"
    __table_args__ = (
        UniqueConstraint("workspace_id", "person_id", "account_id", name="uq_ghost_pair"),
    )

    person_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("person.id", ondelete="CASCADE"), nullable=False, index=True
    )
    account_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("account.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # match_id can become NULL if the match is purged but the ghost
    # is preserved for audit history (e.g. operator marked it resolved).
    match_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("match.id", ondelete="SET NULL"), nullable=True
    )
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    # critical | high | medium
    days_since_termination: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="open", index=True)
    # open | acknowledged | false_positive | suppressed | resolved
    acknowledged_by_user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("user.id", ondelete="SET NULL")
    )
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    notes: Mapped[str | None] = mapped_column(Text)
    suppressed_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


def severity_for(days: int) -> str:
    """Severity rule lifted directly from the spec."""
    if days > 7:
        return "critical"
    if days >= 1:  # 24h .. 7d
        return "high"
    return "medium"
