"""Authentication endpoints: login, refresh, logout, API-key CRUD.

Hardening notes (OSS):

* **Per-IP throttle** rejects > 10 attempts / 60s on the login endpoint
  (``app.security_throttle.LOGIN_IP_THROTTLE``). Reset on process restart.
* **Per-account throttle** caps attempts per email (10 / 5min) so an
  attacker can't bypass IP throttling by rotating proxies.
* **Persistent lockout** kicks in after 5 consecutive failed logins for
  a real user — locks for 15 minutes regardless of IP. Audit-logged.
* **Refresh-token revocation**: each refresh JWT carries a random
  ``jti``; logout records the ``jti`` in ``revoked_token`` so a stolen
  refresh token can't outlive the session. ``/auth/refresh`` rejects any
  ``jti`` that is in the revocation table.
* **Cookie hardening**: on successful login we set the ``sundown_token``
  cookie server-side with ``HttpOnly`` (mitigates XSS token theft) and
  ``Secure`` when the request was served over HTTPS (auto-detected via
  proxy headers / ``request.url.scheme``).
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import (
    Principal,
    get_db,
    get_principal,
    request_meta,
    require_admin,
)
from app.audit import ActorRef, record
from app.config import get_settings
from app.models.revoked_token import RevokedToken
from app.models.user import (
    LOCKOUT_DURATION_SECONDS,
    LOCKOUT_THRESHOLD,
    ApiKey,
    User,
)
from app.schemas.auth import (
    ApiKeyCreate,
    ApiKeyCreated,
    ApiKeyOut,
    LoginRequest,
    LogoutRequest,
    RefreshRequest,
    TokenResponse,
    UserOut,
)
from app.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_api_key,
    verify_password,
)
from app.security_throttle import LOGIN_ACCOUNT_THROTTLE, LOGIN_IP_THROTTLE

router = APIRouter(prefix="/auth", tags=["auth"])

COOKIE_NAME = "sundown_token"


def _is_https(request: Request) -> bool:
    """Trust ``X-Forwarded-Proto`` only because uvicorn is started with
    ``proxy_headers=True`` and ``forwarded_allow_ips="*"``. Behind a TLS
    terminator (Caddy/nginx/Cloud Run) ``request.url.scheme`` will be
    ``https`` even though the inner connection is plain HTTP."""
    return request.url.scheme == "https"


def _set_session_cookie(response: Response, request: Request, token: str) -> None:
    settings = get_settings()
    response.set_cookie(
        COOKIE_NAME,
        token,
        max_age=settings.jwt_ttl_minutes * 60,
        httponly=True,
        secure=_is_https(request),
        samesite="lax",
        path="/",
    )


def _clear_session_cookie(response: Response, request: Request) -> None:
    response.delete_cookie(
        COOKIE_NAME,
        path="/",
        secure=_is_https(request),
        samesite="lax",
    )


def _client_ip(request: Request) -> str:
    """Best-effort. Same proxy-header trust as ``_is_https``."""
    return request.client.host if request.client else "unknown"


def _is_locked(user: User, now: datetime) -> bool:
    """SQLite stores datetimes as naive strings; on read we get back a
    naive ``datetime``. We treat any naive timestamp coming from the DB
    as already-UTC (which it always is — we only ever write UTC)."""
    if user.locked_until is None:
        return False
    locked = user.locked_until
    if locked.tzinfo is None:
        locked = locked.replace(tzinfo=UTC)
    return locked > now


def _record_failed_login(
    db: Session, user: User, *, ip: str | None, user_agent: str | None
) -> bool:
    """Returns True if this failure transitioned the account into lockout."""
    user.failed_login_count = (user.failed_login_count or 0) + 1
    transitioned = False
    if user.failed_login_count >= LOCKOUT_THRESHOLD:
        user.locked_until = datetime.now(UTC) + timedelta(seconds=LOCKOUT_DURATION_SECONDS)
        transitioned = True
        record(
            db,
            actor=ActorRef("user", user.id),
            action="user.lockout.triggered",
            target_type="user",
            target_id=user.id,
            payload={
                "failed_count": user.failed_login_count,
                "locked_until": user.locked_until.isoformat(),
            },
            ip=ip,
            user_agent=user_agent,
        )
    return transitioned


@router.post("/login", response_model=TokenResponse)
def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> TokenResponse:
    settings = get_settings()
    ip, ua = request_meta(request)
    ip_key = _client_ip(request)
    # Case-insensitive email match (DB may have been created with any casing).
    email_norm = str(body.email).strip().lower()

    user = db.scalar(
        select(User).where(
            func.lower(User.email) == email_norm,
            User.workspace_id == settings.default_workspace,
            User.is_active.is_(True),
        )
    )
    now = datetime.now(UTC)

    if user is None:
        # Throttle only failed attempts — successful logins must not eat
        # budget slots (otherwise heavy UI retry / demo refreshes → 429).
        if not LOGIN_IP_THROTTLE.allow(ip_key):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="too many login attempts from this IP, try again in a minute",
            )
        if not LOGIN_ACCOUNT_THROTTLE.allow(email_norm):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="too many login attempts for this account, try again later",
            )
        # Constant-ish branch: still hash a dummy password to keep timing
        # roughly comparable, then return the same generic error as a
        # bad-password attempt to avoid user enumeration.
        verify_password(body.password, "$2b$12$" + "x" * 53)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")

    if _is_locked(user, now):
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=(
                "account is temporarily locked after too many failed logins; "
                f"try again at {user.locked_until.isoformat() if user.locked_until else 'later'}"
            ),
        )

    if not verify_password(body.password, user.password_hash):
        if not LOGIN_IP_THROTTLE.allow(ip_key):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="too many login attempts from this IP, try again in a minute",
            )
        if not LOGIN_ACCOUNT_THROTTLE.allow(email_norm):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="too many login attempts for this account, try again later",
            )
        _record_failed_login(db, user, ip=ip, user_agent=ua)
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")

    # Successful login. Reset all counters + in-memory throttle windows.
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = now
    LOGIN_IP_THROTTLE.reset(ip_key)
    LOGIN_ACCOUNT_THROTTLE.reset(email_norm)

    record(
        db,
        actor=ActorRef("user", user.id),
        action="user.login",
        ip=ip,
        user_agent=ua,
    )
    db.commit()

    access = create_access_token(user.id, role=user.role, workspace_id=user.workspace_id)
    refresh = create_refresh_token(user.id, workspace_id=user.workspace_id)

    _set_session_cookie(response, request, access)

    return TokenResponse(
        access_token=access,
        refresh_token=refresh,
        expires_in=settings.jwt_ttl_minutes * 60,
    )


def _is_jti_revoked(db: Session, jti: str | None) -> bool:
    if not jti:
        return False
    return (
        db.scalar(select(RevokedToken.id).where(RevokedToken.jti == jti)) is not None
    )


@router.post("/refresh", response_model=TokenResponse)
def refresh(
    body: RefreshRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> TokenResponse:
    settings = get_settings()
    try:
        claims = decode_token(body.refresh_token)
    except Exception as e:
        raise HTTPException(401, f"invalid refresh token: {e}") from e
    if claims.get("typ") != "refresh":
        raise HTTPException(401, "not a refresh token")
    if _is_jti_revoked(db, claims.get("jti")):
        raise HTTPException(401, "refresh token has been revoked")

    user = db.scalar(
        select(User).where(User.id == claims["sub"], User.is_active.is_(True))
    )
    if user is None:
        raise HTTPException(401, "user not found")
    if _is_locked(user, datetime.now(UTC)):
        raise HTTPException(423, "account is locked")

    access = create_access_token(user.id, role=user.role, workspace_id=user.workspace_id)
    new_refresh = create_refresh_token(user.id, workspace_id=user.workspace_id)
    _set_session_cookie(response, request, access)
    return TokenResponse(
        access_token=access,
        refresh_token=new_refresh,
        expires_in=settings.jwt_ttl_minutes * 60,
    )


@router.post("/logout", status_code=204)
def logout(
    body: LogoutRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> Response:
    """Revoke a refresh token's ``jti`` and clear the session cookie.

    We accept the refresh token in the body rather than reading it from a
    cookie — the access cookie is HttpOnly (so JS can't read it), and the
    refresh token is stored in JS-accessible localStorage. JS sends both
    on logout: ``Authorization: Bearer <access>`` for audit attribution
    and the refresh token in the JSON body so we can record its jti.
    """
    ip, ua = request_meta(request)
    user_id: str | None = None
    try:
        claims = decode_token(body.refresh_token)
    except Exception:
        claims = {}
    jti = claims.get("jti")
    if jti and claims.get("typ") == "refresh":
        exp = claims.get("exp")
        # Default to the configured refresh TTL if the token didn't carry
        # an exp (shouldn't happen but be defensive).
        expires_at = (
            datetime.fromtimestamp(int(exp), tz=UTC)
            if exp is not None
            else datetime.now(UTC) + timedelta(days=14)
        )
        # Only insert if not already revoked — idempotent logout.
        if not _is_jti_revoked(db, jti):
            db.add(
                RevokedToken(
                    jti=jti,
                    user_id=claims.get("sub"),
                    expires_at=expires_at,
                )
            )
        user_id = claims.get("sub")

    if user_id:
        record(
            db,
            actor=ActorRef("user", user_id),
            action="user.logout",
            ip=ip,
            user_agent=ua,
        )
    db.commit()

    _clear_session_cookie(response, request)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.get("/me", response_model=UserOut)
def me(p: Annotated[Principal, Depends(get_principal)], db: Session = Depends(get_db)) -> UserOut:
    if p.actor_type != "user":
        raise HTTPException(400, "API keys do not have a user record")
    user = db.get(User, p.id)
    if user is None:
        raise HTTPException(404, "user not found")
    return UserOut.model_validate(user)


# --- API keys ------------------------------------------------------------


@router.get("/api-keys", response_model=list[ApiKeyOut])
def list_api_keys(
    p: Annotated[Principal, Depends(require_admin)], db: Session = Depends(get_db)
) -> list[ApiKeyOut]:
    rows = list(
        db.execute(
            select(ApiKey).where(ApiKey.workspace_id == p.workspace_id)
        ).scalars()
    )
    return [ApiKeyOut.model_validate(r) for r in rows]


@router.post("/api-keys", response_model=ApiKeyCreated, status_code=201)
def create_api_key(
    body: ApiKeyCreate,
    request: Request,
    p: Annotated[Principal, Depends(require_admin)],
    db: Session = Depends(get_db),
) -> ApiKeyCreated:
    full, prefix, hashed = generate_api_key()
    row = ApiKey(
        workspace_id=p.workspace_id,
        name=body.name,
        prefix=prefix,
        hash=hashed,
        role=body.role,
        created_by_user_id=p.id if p.actor_type == "user" else None,
        expires_at=body.expires_at,
    )
    db.add(row)
    db.flush()

    ip, ua = request_meta(request)
    record(
        db,
        actor=ActorRef(p.actor_type, p.id),
        action="api_key.create",
        target_type="api_key",
        target_id=row.id,
        payload={"name": body.name, "role": body.role, "prefix": prefix},
        ip=ip,
        user_agent=ua,
    )
    db.commit()

    return ApiKeyCreated(
        id=row.id,
        name=row.name,
        prefix=prefix,
        role=row.role,
        key=full,
        expires_at=row.expires_at,
    )


@router.delete("/api-keys/{key_id}", status_code=204)
def revoke_api_key(
    key_id: str,
    request: Request,
    p: Annotated[Principal, Depends(require_admin)],
    db: Session = Depends(get_db),
) -> None:
    row = db.get(ApiKey, key_id)
    if row is None or row.workspace_id != p.workspace_id:
        raise HTTPException(404, "api key not found")
    if row.revoked_at is not None:
        return
    row.revoked_at = datetime.now(UTC)

    ip, ua = request_meta(request)
    record(
        db,
        actor=ActorRef(p.actor_type, p.id),
        action="api_key.revoke",
        target_type="api_key",
        target_id=row.id,
        payload={"name": row.name, "prefix": row.prefix},
        ip=ip,
        user_agent=ua,
    )
    db.commit()

