"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-04-25
"""
from __future__ import annotations

from alembic import op
from app.db import Base
from app.models import (  # noqa: F401  (force-register all tables)
    account,
    audit,
    ghost,
    identity,
    integration,
    match,
    report,
    user,
)

# revision identifiers, used by Alembic.
revision = "0001_initial"
down_revision: str | None = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create the entire baseline schema from the SQLAlchemy models.

    Subsequent revisions should use explicit ``op.add_column`` /
    ``op.create_table`` calls. Building the baseline from
    ``Base.metadata`` keeps this v1 migration short, and exactly matches
    the ORM (which is the source of truth for v1).
    """
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)


def downgrade() -> None:
    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind)
