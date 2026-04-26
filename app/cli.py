"""``sundown`` command-line entry point.

Commands:

  * ``serve``       — run the API + UI under uvicorn
  * ``migrate``     — apply Alembic migrations
  * ``scan``        — sync every enabled integration once + run matching
  * ``seed``        — load demo data (calls scripts/seed.py)
  * ``verify-audit``— check the audit chain
  * ``create-user`` — add a local user
  * ``unlock-user`` — clear auth lockout after too many failed logins

Designed so ``docker run sundown serve`` works with no extra args.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
from getpass import getpass

from app import __version__


def _serve(args: argparse.Namespace) -> int:
    import uvicorn

    from app.config import get_settings

    settings = get_settings()
    uvicorn.run(
        "app.main:app",
        host=args.host or settings.host,
        port=args.port or settings.port,
        log_level=settings.log_level.lower(),
        reload=bool(args.reload),
        proxy_headers=True,
        forwarded_allow_ips="*",
    )
    return 0


def _migrate(_: argparse.Namespace) -> int:
    from alembic.config import Config

    from alembic import command
    from app.config import get_settings

    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", get_settings().database_url)
    command.upgrade(cfg, "head")
    print("ok: schema is at head")
    return 0


def _scan(_: argparse.Namespace) -> int:
    from app.integrations import load_builtin_connectors
    from app.scheduler.jobs import scan_job

    load_builtin_connectors()
    asyncio.run(scan_job())
    print("ok: scan complete")
    return 0


def _seed(args: argparse.Namespace) -> int:
    from scripts.seed import main as seed_main

    seed_main(reset=args.reset)
    return 0


def _verify_audit(_: argparse.Namespace) -> int:
    from app.audit import verify_chain
    from app.db import session_scope

    with session_scope() as db:
        ok, n = verify_chain(db)
    if ok:
        print(f"ok: audit chain intact ({n} events)")
        return 0
    print(f"FAIL: audit chain broken at index {n}")
    return 1


def _create_user(args: argparse.Namespace) -> int:
    from app.config import get_settings
    from app.db import session_scope
    from app.models.user import User
    from app.security import (
        PasswordTooWeakError,
        hash_password,
        validate_password_strength,
    )

    pw = args.password or getpass("Password: ")
    try:
        validate_password_strength(pw)
    except PasswordTooWeakError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    settings = get_settings()
    with session_scope() as db:
        u = User(
            workspace_id=settings.default_workspace,
            email=args.email,
            password_hash=hash_password(pw),
            role=args.role,
            is_active=True,
        )
        db.add(u)
    print(f"ok: created {args.role} user {args.email}")
    return 0


def _unlock_user(args: argparse.Namespace) -> int:
    from sqlalchemy import func, select

    from app.config import get_settings
    from app.db import session_scope
    from app.models.user import User

    settings = get_settings()
    email_norm = args.email.strip().lower()
    with session_scope() as db:
        u = db.scalar(
            select(User).where(
                func.lower(User.email) == email_norm,
                User.workspace_id == settings.default_workspace,
            )
        )
        if u is None:
            print(f"error: no user {args.email!r} in workspace", file=sys.stderr)
            return 2
        u.failed_login_count = 0
        u.locked_until = None
    print(f"ok: cleared lockout for {args.email}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sundown", description="Ghost-account auditor.")
    parser.add_argument("--version", action="version", version=f"sundown {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_serve = sub.add_parser("serve", help="run the API and UI")
    p_serve.add_argument("--host", default=None)
    p_serve.add_argument("--port", type=int, default=None)
    p_serve.add_argument("--reload", action="store_true")
    p_serve.set_defaults(fn=_serve)

    p_mig = sub.add_parser("migrate", help="apply database migrations")
    p_mig.set_defaults(fn=_migrate)

    p_scan = sub.add_parser("scan", help="sync enabled integrations + run matching")
    p_scan.set_defaults(fn=_scan)

    p_seed = sub.add_parser("seed", help="load demo data")
    p_seed.add_argument("--reset", action="store_true", help="wipe existing data first")
    p_seed.set_defaults(fn=_seed)

    p_va = sub.add_parser("verify-audit", help="check audit-log integrity")
    p_va.set_defaults(fn=_verify_audit)

    p_user = sub.add_parser("create-user", help="create a local user")
    p_user.add_argument("--email", required=True)
    p_user.add_argument("--role", default="admin", choices=["viewer", "analyst", "admin"])
    p_user.add_argument("--password", default=os.environ.get("SUNDOWN_USER_PASSWORD"))
    p_user.set_defaults(fn=_create_user)

    p_unlock = sub.add_parser(
        "unlock-user",
        help="reset failed-login lockout (after too many bad passwords)",
    )
    p_unlock.add_argument("--email", required=True)
    p_unlock.set_defaults(fn=_unlock_user)

    args = parser.parse_args(argv)
    return int(args.fn(args))


if __name__ == "__main__":
    raise SystemExit(main())
