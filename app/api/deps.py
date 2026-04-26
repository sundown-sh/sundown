"""FastAPI dependencies: DB session, current user/principal, role gating.

Two auth methods are accepted on every protected endpoint:

  * ``Authorization: Bearer <jwt>``      — human users
  * ``Authorization: Bearer sdn_...``    — service callers (API key)
  * ``X-API-Key: sdn_...``               — alternate API-key header

All write endpoints require role >= ``analyst``.
"""
from __future__ import annotations

from collections.abc import Generator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.user import ApiKey, User, role_at_least
from app.security import API_KEY_PREFIX, decode_token, verify_api_key


@dataclass(frozen=True)
class Principal:
    """Resolved auth subject. ``actor_type`` mirrors the audit-log column."""

    actor_type: Literal["user", "api_key"]
    id: str
    email: str | None
    role: Literal["viewer", "analyst", "admin"]
    workspace_id: str


# --- low-level extractors -------------------------------------------------


def _bearer(authorization: str | None) -> str | None:
    if not authorization:
        return None
    parts = authorization.split(" ", 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return None


def _resolve_user(db: Session, sub: str, ws: str) -> User | None:
    return db.scalar(
        select(User).where(User.id == sub, User.workspace_id == ws, User.is_active.is_(True))
    )


def _resolve_api_key(db: Session, full_key: str) -> ApiKey | None:
    prefix = full_key[: len(API_KEY_PREFIX) + 8]
    candidates = list(
        db.execute(select(ApiKey).where(ApiKey.prefix == prefix)).scalars()
    )
    for k in candidates:
        if k.revoked_at is not None:
            continue
        if k.expires_at is not None and k.expires_at <= datetime.now(UTC):
            continue
        if verify_api_key(full_key, k.hash):
            return k
    return None


# --- main dependency -----------------------------------------------------


def get_principal(
    request: Request,
    db: Session = Depends(get_db),
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> Principal:
    """Resolve the caller into a Principal or 401."""

    # Order: explicit X-API-Key, then bearer (could be JWT or API key).
    raw = x_api_key or _bearer(authorization)
    if not raw:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if raw.startswith(API_KEY_PREFIX):
        key = _resolve_api_key(db, raw)
        if key is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid or revoked API key",
            )
        key.last_used_at = datetime.now(UTC)
        db.flush()
        return Principal(
            actor_type="api_key",
            id=key.id,
            email=None,
            role=key.role,  # type: ignore[arg-type]
            workspace_id=key.workspace_id,
        )

    try:
        claims = decode_token(raw)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"invalid token: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e

    if claims.get("typ") != "access":
        raise HTTPException(401, detail="not an access token")

    user = _resolve_user(db, claims["sub"], claims["ws"])
    if user is None:
        raise HTTPException(401, detail="user not found or disabled")

    return Principal(
        actor_type="user",
        id=user.id,
        email=user.email,
        role=user.role,  # type: ignore[arg-type]
        workspace_id=user.workspace_id,
    )


# --- role gates ----------------------------------------------------------


def require_role(minimum: Literal["viewer", "analyst", "admin"]) -> object:
    def _dep(p: Principal = Depends(get_principal)) -> Principal:
        if not role_at_least(p.role, minimum):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"requires role >= {minimum}",
            )
        return p

    return _dep


require_viewer = require_role("viewer")
require_analyst = require_role("analyst")
require_admin = require_role("admin")


# --- request metadata helpers --------------------------------------------


def request_meta(request: Request) -> tuple[str | None, str | None]:
    """Return (ip, user_agent) for audit logging."""
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent")
    return ip, ua


# Re-export for convenience
__all__ = [
    "Principal",
    "get_db",
    "get_principal",
    "request_meta",
    "require_admin",
    "require_analyst",
    "require_viewer",
]


def _get_db_passthrough() -> Generator[Session, None, None]:
    """Re-exported for routers that don't need to import db.py directly."""
    yield from get_db()
