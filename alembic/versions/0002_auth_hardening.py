"""auth hardening: lockout columns + revoked-token table

Adds:
  * ``user.failed_login_count`` (NOT NULL, default 0)
  * ``user.locked_until`` (nullable timestamp)
  * ``revoked_token`` table for refresh-token jti revocation

The 0001 migration creates the schema dynamically from
``Base.metadata.create_all``, so on a *fresh* install the new columns
and table are already in place before this migration runs. We therefore
make every step idempotent — it's also nicer for operators retrying a
migration that crashed mid-flight.

Revision ID: 0002_auth_hardening
Revises: 0001_initial
Create Date: 2026-04-26
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0002_auth_hardening"
down_revision: str | None = "0001_initial"
branch_labels = None
depends_on = None


def _existing_columns(table: str) -> set[str]:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    return {c["name"] for c in insp.get_columns(table)}


def _has_table(name: str) -> bool:
    bind = op.get_bind()
    return sa.inspect(bind).has_table(name)


def upgrade() -> None:
    cols = _existing_columns("user")
    if "failed_login_count" not in cols:
        op.add_column(
            "user",
            sa.Column(
                "failed_login_count",
                sa.Integer(),
                nullable=False,
                server_default="0",
            ),
        )
    if "locked_until" not in cols:
        op.add_column(
            "user",
            sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        )

    if not _has_table("revoked_token"):
        op.create_table(
            "revoked_token",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("jti", sa.String(length=64), nullable=False),
            sa.Column(
                "user_id",
                sa.String(length=36),
                sa.ForeignKey("user.id", ondelete="CASCADE"),
                nullable=True,
            ),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("jti", name="uq_revoked_token_jti"),
        )
        op.create_index("ix_revoked_token_jti", "revoked_token", ["jti"])


def downgrade() -> None:
    if _has_table("revoked_token"):
        op.drop_index("ix_revoked_token_jti", table_name="revoked_token")
        op.drop_table("revoked_token")
    cols = _existing_columns("user")
    if "locked_until" in cols:
        op.drop_column("user", "locked_until")
    if "failed_login_count" in cols:
        op.drop_column("user", "failed_login_count")
