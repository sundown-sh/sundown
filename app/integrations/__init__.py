"""Connector framework + bundled connectors.

Importing this package triggers registration of every bundled
connector via the side-effect imports below.
"""
from __future__ import annotations


def load_builtin_connectors() -> None:
    """Force-import every bundled connector so the registry sees them."""
    from app.integrations.hris import bamboohr, rippling  # noqa: F401
    from app.integrations.idp import google_workspace, okta  # noqa: F401
    from app.integrations.saas import github, slack  # noqa: F401
