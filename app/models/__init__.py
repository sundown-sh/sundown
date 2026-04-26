"""ORM models. Importing this module registers every table on `Base.metadata`."""
from __future__ import annotations


def register_all_models() -> None:
    """Import side-effect: ensure every model is bound to Base.metadata."""
    from app.models import (  # noqa: F401
        account,
        audit,
        ghost,
        identity,
        integration,
        match,
        report,
        user,
    )


register_all_models()
