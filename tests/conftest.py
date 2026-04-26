"""Shared test fixtures.

Sets up an isolated SQLite DB per test, loads the schema, and bootstraps
the connector registry. CI runs against this fixture set — no live HTTP
calls are ever made.
"""
from __future__ import annotations

import os
from collections.abc import Generator
from pathlib import Path

os.environ.setdefault("SUNDOWN_SECRET_KEY", "ci-test-secret-please-be-32-bytes-long")
os.environ.setdefault("SUNDOWN_ENV", "test")

import pytest
from sqlalchemy.orm import Session

from app import config
from app import db as db_mod
from app.integrations import load_builtin_connectors
from app.models import register_all_models


@pytest.fixture(autouse=True)
def _isolate_db(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Generator[None, None, None]:
    """Fresh SQLite per test."""
    db_file = tmp_path / "test.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file}")
    config.reset_settings_cache()
    db_mod.reset_engine_cache()

    register_all_models()
    db_mod.Base.metadata.create_all(db_mod.get_engine())
    load_builtin_connectors()

    yield

    db_mod.reset_engine_cache()
    config.reset_settings_cache()


@pytest.fixture
def session() -> Generator[Session, None, None]:
    factory = db_mod.get_session_factory()
    s = factory()
    try:
        yield s
        s.commit()
    finally:
        s.close()


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).resolve().parent / "fixtures"


@pytest.fixture
def use_replay_fixtures(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SUNDOWN_FIXTURES", "replay")
