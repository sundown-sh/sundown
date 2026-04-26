"""Revoked refresh-token registry.

We don't track access tokens here — they're short-lived (8h default) and
checked by signature + ``exp`` claim alone. Refresh tokens live for 14
days, so a user logging out (or a server-side "log everywhere out"
later) needs a way to invalidate a specific ``jti``.

Rows older than their ``expires_at`` are safe to purge; the token is
already invalid by ``exp`` claim. A simple periodic cleanup job can do
this — for v1 the table is small enough to ignore.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models._mixins import IdMixin, TimestampMixin


class RevokedToken(IdMixin, TimestampMixin, Base):
    __tablename__ = "revoked_token"

    jti: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("user.id", ondelete="CASCADE")
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
