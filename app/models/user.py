"""User and ApiKey — local authentication principals."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models._mixins import IdMixin, TimestampMixin, WorkspaceMixin

ROLES = ("viewer", "analyst", "admin")
ROLE_ORDER = {r: i for i, r in enumerate(ROLES)}

# After this many consecutive failed logins, the account is locked for
# ``LOCKOUT_DURATION_SECONDS``. Both are constants rather than env vars
# because they're security-sensitive defaults; if an operator wants to
# tune them, they own the consequences and can edit the code.
LOCKOUT_THRESHOLD = 5
LOCKOUT_DURATION_SECONDS = 15 * 60


def role_at_least(actual: str, minimum: str) -> bool:
    return ROLE_ORDER.get(actual, -1) >= ROLE_ORDER.get(minimum, 99)


class User(WorkspaceMixin, IdMixin, TimestampMixin, Base):
    __tablename__ = "user"
    __table_args__ = (UniqueConstraint("workspace_id", "email", name="uq_user_email"),)

    email: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False, default="analyst")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # --- Account lockout (auth hardening) ---
    # Reset on successful login. When ``failed_login_count`` reaches
    # ``LOCKOUT_THRESHOLD`` we set ``locked_until = now + 15min``. The
    # login endpoint refuses requests while ``locked_until`` is in the
    # future and emits a ``user.lockout.triggered`` audit event when it
    # transitions.
    failed_login_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ApiKey(WorkspaceMixin, IdMixin, TimestampMixin, Base):
    __tablename__ = "api_key"

    name: Mapped[str] = mapped_column(String(128), nullable=False)
    prefix: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    hash: Mapped[str] = mapped_column(String(256), nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False, default="analyst")
    created_by_user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("user.id", ondelete="SET NULL")
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
