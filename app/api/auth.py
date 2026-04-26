"""Authentication endpoints: login, refresh, API-key CRUD."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
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
from app.models.user import ApiKey, User
from app.schemas.auth import (
    ApiKeyCreate,
    ApiKeyCreated,
    ApiKeyOut,
    LoginRequest,
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

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
def login(
    body: LoginRequest, request: Request, db: Session = Depends(get_db)
) -> TokenResponse:
    settings = get_settings()
    user = db.scalar(
        select(User).where(
            User.email == body.email,
            User.workspace_id == settings.default_workspace,
            User.is_active.is_(True),
        )
    )
    if user is None or not verify_password(body.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
    user.last_login_at = datetime.now(UTC)

    ip, ua = request_meta(request)
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
    return TokenResponse(
        access_token=access,
        refresh_token=refresh,
        expires_in=settings.jwt_ttl_minutes * 60,
    )


@router.post("/refresh", response_model=TokenResponse)
def refresh(body: RefreshRequest, db: Session = Depends(get_db)) -> TokenResponse:
    settings = get_settings()
    try:
        claims = decode_token(body.refresh_token)
    except Exception as e:
        raise HTTPException(401, f"invalid refresh token: {e}") from e
    if claims.get("typ") != "refresh":
        raise HTTPException(401, "not a refresh token")

    user = db.scalar(
        select(User).where(User.id == claims["sub"], User.is_active.is_(True))
    )
    if user is None:
        raise HTTPException(401, "user not found")

    access = create_access_token(user.id, role=user.role, workspace_id=user.workspace_id)
    new_refresh = create_refresh_token(user.id, workspace_id=user.workspace_id)
    return TokenResponse(
        access_token=access,
        refresh_token=new_refresh,
        expires_in=settings.jwt_ttl_minutes * 60,
    )


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
