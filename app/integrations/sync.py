"""Connector → DB sync service.

Wraps a connector instance, drains it, and UPSERTs into Person /
Account. Idempotent. Records sync status onto the Integration row and
emits an audit event.
"""
from __future__ import annotations

import time
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit import SYSTEM_ACTOR, record
from app.integrations import registry
from app.integrations.base import (
    AuthError,
    BaseConnector,
    ConfigError,
    ConnectorKind,
    Employee,
    Principal,
)
from app.logging_config import get_logger
from app.models.account import Account
from app.models.identity import Person
from app.models.integration import Integration
from app.security import decrypt_blob

log = get_logger(__name__)


class SyncResult:
    def __init__(self, fetched: int, ms: int, error: str | None = None) -> None:
        self.fetched = fetched
        self.ms = ms
        self.error = error
        self.ok = error is None


def make_connector(integration: Integration) -> BaseConnector:
    """Decrypt config and instantiate the connector."""
    import json

    try:
        raw = decrypt_blob(integration.config_encrypted)
        cfg = json.loads(raw.decode("utf-8"))
    except Exception as e:
        raise ConfigError(f"unable to decrypt config: {e}") from e
    return registry.make(integration.connector, cfg)


async def healthcheck(integration: Integration) -> tuple[bool, str | None, int]:
    """Return (ok, error, latency_ms)."""
    started = time.perf_counter()
    try:
        async with make_connector(integration) as c:
            ok = await c.healthcheck()
        return ok, None, int((time.perf_counter() - started) * 1000)
    except (AuthError, ConfigError) as e:
        return False, str(e), int((time.perf_counter() - started) * 1000)
    except Exception as e:
        return False, f"{type(e).__name__}: {e}", int((time.perf_counter() - started) * 1000)


async def sync_one(db: Session, integration: Integration) -> SyncResult:
    """Run one full sync of an integration. Updates DB and the
    Integration's last_sync fields."""
    integration.last_sync_status = "running"
    db.flush()

    started = time.perf_counter()
    fetched = 0
    err: str | None = None
    try:
        async with make_connector(integration) as c:
            spec = registry.get(integration.connector)
            if spec.kind is ConnectorKind.HRIS:
                fetched = await _drain_hris(db, integration, c)
            else:
                fetched = await _drain_destination(db, integration, c)
    except Exception as e:
        err = f"{type(e).__name__}: {e}"
        log.exception("sync.failed", connector=integration.connector, error=err)

    ms = int((time.perf_counter() - started) * 1000)
    integration.last_sync_at = datetime.now(UTC)
    integration.last_sync_status = "error" if err else "success"
    integration.last_sync_error = err
    integration.last_sync_count = fetched

    record(
        db,
        actor=SYSTEM_ACTOR,
        action="integration.sync",
        target_type="integration",
        target_id=integration.id,
        payload={
            "connector": integration.connector,
            "fetched": fetched,
            "ms": ms,
            "error": err,
        },
    )

    return SyncResult(fetched=fetched, ms=ms, error=err)


# --- drain helpers --------------------------------------------------------


async def _drain_hris(db: Session, integration: Integration, c: BaseConnector) -> int:
    n = 0
    async for emp in c.fetch_terminated_employees():
        _upsert_person(db, integration, emp)
        n += 1
    db.flush()
    return n


async def _drain_destination(
    db: Session, integration: Integration, c: BaseConnector
) -> int:
    n = 0
    async for p in c.fetch_active_principals():
        _upsert_account(db, integration, p)
        n += 1
    db.flush()
    return n


# --- UPSERTs --------------------------------------------------------------


def _upsert_person(db: Session, integration: Integration, emp: Employee) -> Person:
    now = datetime.now(UTC)
    existing = db.scalar(
        select(Person).where(
            Person.workspace_id == integration.workspace_id,
            Person.integration_id == integration.id,
            Person.external_id == emp.external_id,
        )
    )
    if existing is None:
        row = Person(
            workspace_id=integration.workspace_id,
            integration_id=integration.id,
            external_id=emp.external_id,
            employee_number=emp.employee_number,
            display_name=emp.display_name,
            work_email=(emp.work_email or "").lower(),
            secondary_emails=[e.lower() for e in emp.secondary_emails or []],
            sso_subject=emp.sso_subject,
            status=emp.status,
            start_date=emp.start_date,
            termination_date=emp.termination_date,
            raw=emp.raw,
            first_seen_at=now,
            last_seen_at=now,
        )
        db.add(row)
        return row

    existing.employee_number = emp.employee_number or existing.employee_number
    existing.display_name = emp.display_name or existing.display_name
    if emp.work_email:
        existing.work_email = emp.work_email.lower()
    existing.secondary_emails = [e.lower() for e in emp.secondary_emails or []]
    existing.sso_subject = emp.sso_subject or existing.sso_subject
    existing.status = emp.status
    existing.start_date = emp.start_date or existing.start_date
    existing.termination_date = emp.termination_date or existing.termination_date
    existing.raw = emp.raw
    existing.last_seen_at = now
    return existing


def _upsert_account(
    db: Session, integration: Integration, p: Principal
) -> Account:
    now = datetime.now(UTC)
    existing = db.scalar(
        select(Account).where(
            Account.workspace_id == integration.workspace_id,
            Account.integration_id == integration.id,
            Account.external_id == p.external_id,
        )
    )
    if existing is None:
        row = Account(
            workspace_id=integration.workspace_id,
            integration_id=integration.id,
            external_id=p.external_id,
            username=p.username,
            display_name=p.display_name,
            email=(p.email or "").lower() or None,
            aliases=[a.lower() for a in p.aliases or []],
            sso_subject=p.sso_subject,
            status=p.status,
            last_login_at=p.last_login_at,
            created_at_remote=p.created_at_remote,
            raw=p.raw,
            first_seen_at=now,
            last_seen_at=now,
        )
        db.add(row)
        return row

    existing.username = p.username or existing.username
    existing.display_name = p.display_name or existing.display_name
    existing.email = (p.email or "").lower() or existing.email
    existing.aliases = [a.lower() for a in p.aliases or []]
    existing.sso_subject = p.sso_subject or existing.sso_subject
    existing.status = p.status
    if p.last_login_at:
        existing.last_login_at = p.last_login_at
    existing.created_at_remote = p.created_at_remote or existing.created_at_remote
    existing.raw = p.raw
    existing.last_seen_at = now
    return existing
