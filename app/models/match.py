"""Match — an explainable join between a Person and an Account."""
from __future__ import annotations

from typing import Any

from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models._mixins import IdMixin, JSONType, TimestampMixin, WorkspaceMixin


class Match(WorkspaceMixin, IdMixin, TimestampMixin, Base):
    __tablename__ = "match"
    __table_args__ = (
        UniqueConstraint("workspace_id", "person_id", "account_id", name="uq_match_pair"),
    )

    person_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("person.id", ondelete="CASCADE"), nullable=False, index=True
    )
    account_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("account.id", ondelete="CASCADE"), nullable=False, index=True
    )
    rule: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    # email | alias | sso_subject | fuzzy
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)  # high|medium
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
