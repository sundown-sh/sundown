"""Seed Sundown with believable demo data so the dashboard isn't empty.

Creates:
  * one HRIS integration (BambooHR-shaped) with 8 employees, 3 of them
    terminated at varying days-in-the-past so we hit every severity tier
  * two destination integrations (Okta + GitHub) with corresponding
    accounts that are still active for terminated folks (the ghosts)
  * a bootstrap admin user (admin@example.com / changeme)
  * runs the matching engine so ghosts appear immediately

Run with:

    python -m scripts.seed --reset
"""
from __future__ import annotations

import argparse
import json
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import delete

from app.config import get_settings
from app.db import Base, get_engine, session_scope
from app.integrations import load_builtin_connectors
from app.matching.engine import run_match
from app.models.account import Account
from app.models.audit import AuditEvent
from app.models.ghost import Ghost
from app.models.identity import Person
from app.models.integration import Integration
from app.models.match import Match
from app.models.report import Report
from app.models.user import ApiKey, User
from app.security import encrypt_blob, hash_password


def _enc(config: dict) -> bytes:
    return encrypt_blob(json.dumps(config).encode("utf-8"))


DEMO_ADMIN_EMAIL = "admin@example.com"
DEMO_ADMIN_PASSWORD = "changeme"


def _ensure_admin(db, workspace: str) -> None:
    if db.query(User).filter_by(email=DEMO_ADMIN_EMAIL, workspace_id=workspace).first():
        return
    db.add(
        User(
            workspace_id=workspace,
            email=DEMO_ADMIN_EMAIL,
            password_hash=hash_password(DEMO_ADMIN_PASSWORD),
            role="admin",
            is_active=True,
        )
    )


def _wipe(db, workspace: str) -> None:
    """Delete prior demo state — but never touch other workspaces."""
    for model in (Ghost, Match, Account, Person, Integration, Report, AuditEvent, ApiKey):
        db.execute(delete(model).where(model.workspace_id == workspace))


def main(reset: bool = False) -> None:
    load_builtin_connectors()
    settings = get_settings()
    workspace = settings.default_workspace
    now = datetime.now(UTC)
    today = now.date()

    # Ensure schema exists so `seed` is a one-shot demo command. We import
    # the model modules first so every table is registered on Base.metadata.
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
    Base.metadata.create_all(bind=get_engine())

    with session_scope() as db:
        if reset:
            _wipe(db, workspace)
        _ensure_admin(db, workspace)

        # --- integrations ---------------------------------------------------
        hris = Integration(
            workspace_id=workspace,
            connector="bamboohr",
            kind="hris",
            tier="core",
            display_name="BambooHR (demo)",
            enabled=True,
            config_encrypted=_enc({"api_key": "demo", "subdomain": "acme"}),
            last_sync_status="success",
            last_sync_at=now,
            last_sync_count=8,
        )
        okta = Integration(
            workspace_id=workspace,
            connector="okta",
            kind="destination",
            tier="core",
            display_name="Okta (demo)",
            enabled=True,
            config_encrypted=_enc({"domain": "acme.okta.com", "api_token": "demo"}),
            last_sync_status="success",
            last_sync_at=now,
            last_sync_count=8,
        )
        github = Integration(
            workspace_id=workspace,
            connector="github",
            kind="destination",
            tier="core",
            display_name="acme on GitHub (demo)",
            enabled=True,
            config_encrypted=_enc({"org": "acme", "token": "demo"}),
            last_sync_status="success",
            last_sync_at=now,
            last_sync_count=6,
        )
        for i in (hris, okta, github):
            db.add(i)
        db.flush()

        # --- people --------------------------------------------------------
        people_spec = [
            # (external_id, name, email, status, term_days_ago)
            ("E1001", "Ada Lovelace",   "ada@acme.com",       "active",     None),
            ("E1002", "Alan Turing",    "alan@acme.com",      "active",     None),
            ("E1003", "Grace Hopper",   "grace@acme.com",     "active",     None),
            ("E1004", "Linus Torvalds", "linus@acme.com",     "active",     None),
            ("E1005", "Edsger Dijkstra","edsger@acme.com",    "terminated", 14),  # critical
            ("E1006", "Margaret Hamilton","margaret@acme.com","terminated", 3),   # high
            ("E1007", "Donald Knuth",   "don@acme.com",       "terminated", 0),   # medium
            ("E1008", "Ken Thompson",   "ken@acme.com",       "terminated", 35),  # critical, multiple
        ]
        people: dict[str, Person] = {}
        for ext, name, email, status, days in people_spec:
            term = (today - timedelta(days=days)) if days is not None else None
            p = Person(
                workspace_id=workspace,
                integration_id=hris.id,
                external_id=ext,
                employee_number=ext,
                display_name=name,
                work_email=email,
                secondary_emails=[email.replace("@acme.com", "@acmecorp.io")] if status == "terminated" else [],
                sso_subject=f"acme|{ext}",
                status=status,
                start_date=date(2018, 1, 1),
                termination_date=term,
                raw={"seed": True},
                first_seen_at=now,
                last_seen_at=now,
            )
            db.add(p)
            people[ext] = p
        db.flush()

        # --- accounts ------------------------------------------------------
        # Active employees ALL have accounts (so engine doesn't flag them).
        # Terminated ones have lingering accounts → ghosts.
        accounts: list[Account] = []
        for ext, name, email, status, days in people_spec:
            # Okta account for everyone
            accounts.append(
                Account(
                    workspace_id=workspace,
                    integration_id=okta.id,
                    external_id=f"okta-{ext}",
                    username=email.split("@")[0],
                    display_name=name,
                    email=email,
                    aliases=[],
                    sso_subject=f"acme|{ext}",
                    status="active",
                    last_login_at=now - timedelta(days=2 if status == "active" else (days or 0) + 1),
                    first_seen_at=now,
                    last_seen_at=now,
                    raw={"seed": True},
                )
            )
        # GitHub account only for engineers (most of them) — keep it interesting.
        gh_targets = ["E1002", "E1003", "E1004", "E1005", "E1007", "E1008"]
        for ext in gh_targets:
            name, email = next((n, e) for (x, n, e, _, _) in people_spec if x == ext)
            accounts.append(
                Account(
                    workspace_id=workspace,
                    integration_id=github.id,
                    external_id=f"gh-{ext}",
                    username=email.split("@")[0],
                    display_name=name,
                    email=email,
                    aliases=[],
                    sso_subject=f"acme|{ext}",
                    status="active",
                    last_login_at=now - timedelta(days=5),
                    first_seen_at=now,
                    last_seen_at=now,
                    raw={"seed": True},
                )
            )
        for a in accounts:
            db.add(a)
        db.flush()

        # --- run the matching engine to materialize ghosts -----------------
        stats = run_match(db, workspace_id=workspace)

    print(
        f"seeded: persons={stats.persons} accounts={stats.accounts} "
        f"matches+={stats.matches_upserted} ghosts_opened={stats.ghosts_opened}"
    )
    print(f"login:  {DEMO_ADMIN_EMAIL} / {DEMO_ADMIN_PASSWORD}")


def _cli() -> None:
    parser = argparse.ArgumentParser(description="Seed Sundown with demo data.")
    parser.add_argument("--reset", action="store_true", help="wipe demo workspace first")
    args = parser.parse_args()
    main(reset=args.reset)


if __name__ == "__main__":
    _cli()
