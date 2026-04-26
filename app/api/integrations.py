"""Integrations API: CRUD + healthcheck + sync."""
from __future__ import annotations

import json
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import (
    Principal,
    get_db,
    request_meta,
    require_analyst,
    require_viewer,
)
from app.audit import ActorRef, record
from app.integrations import registry
from app.integrations.base import ConnectorTier
from app.integrations.sync import healthcheck as do_healthcheck
from app.integrations.sync import sync_one
from app.matching.engine import run_match
from app.models.integration import Integration
from app.schemas.integration import (
    HealthcheckResult,
    IntegrationCreate,
    IntegrationOut,
    IntegrationUpdate,
    SyncResult,
)
from app.security import encrypt_blob

router = APIRouter(prefix="/integrations", tags=["integrations"])


# --- catalog (no auth — used by setup wizard) ----------------------------


@router.get("/catalog")
def catalog() -> dict[str, list[dict[str, Any]]]:
    """Return the list of installable connectors. Tier == 'core' only in OSS."""
    return {
        "core": [registry.to_dict(s) for s in registry.by_tier(ConnectorTier.CORE)],
        "premium": [registry.to_dict(s) for s in registry.by_tier(ConnectorTier.PREMIUM)],
    }


# --- CRUD ----------------------------------------------------------------


@router.get("", response_model=list[IntegrationOut])
def list_integrations(
    p: Annotated[Principal, Depends(require_viewer)], db: Session = Depends(get_db)
) -> list[IntegrationOut]:
    rows = list(
        db.execute(
            select(Integration).where(Integration.workspace_id == p.workspace_id)
        ).scalars()
    )
    return [IntegrationOut.model_validate(r) for r in rows]


@router.post("", response_model=IntegrationOut, status_code=201)
def create_integration(
    body: IntegrationCreate,
    request: Request,
    p: Annotated[Principal, Depends(require_analyst)],
    db: Session = Depends(get_db),
) -> IntegrationOut:
    try:
        spec = registry.get(body.connector)
    except KeyError as e:
        raise HTTPException(400, f"unknown connector `{body.connector}`") from e

    blob = encrypt_blob(json.dumps(body.config).encode("utf-8"))
    row = Integration(
        workspace_id=p.workspace_id,
        connector=body.connector,
        kind=spec.kind.value,
        tier=spec.tier.value,
        display_name=body.display_name,
        enabled=body.enabled,
        config_encrypted=blob,
        feature_flags=body.feature_flags,
    )
    db.add(row)
    db.flush()

    ip, ua = request_meta(request)
    record(
        db,
        actor=ActorRef(p.actor_type, p.id),
        action="integration.create",
        target_type="integration",
        target_id=row.id,
        payload={"connector": body.connector, "display_name": body.display_name},
        ip=ip,
        user_agent=ua,
    )
    db.commit()
    return IntegrationOut.model_validate(row)


@router.get("/{integration_id}", response_model=IntegrationOut)
def get_integration(
    integration_id: str,
    p: Annotated[Principal, Depends(require_viewer)],
    db: Session = Depends(get_db),
) -> IntegrationOut:
    row = db.get(Integration, integration_id)
    if row is None or row.workspace_id != p.workspace_id:
        raise HTTPException(404, "integration not found")
    return IntegrationOut.model_validate(row)


@router.patch("/{integration_id}", response_model=IntegrationOut)
def update_integration(
    integration_id: str,
    body: IntegrationUpdate,
    request: Request,
    p: Annotated[Principal, Depends(require_analyst)],
    db: Session = Depends(get_db),
) -> IntegrationOut:
    row = db.get(Integration, integration_id)
    if row is None or row.workspace_id != p.workspace_id:
        raise HTTPException(404, "integration not found")
    if body.display_name is not None:
        row.display_name = body.display_name
    if body.enabled is not None:
        row.enabled = body.enabled
    if body.feature_flags is not None:
        row.feature_flags = body.feature_flags
    if body.config is not None:
        row.config_encrypted = encrypt_blob(json.dumps(body.config).encode("utf-8"))

    ip, ua = request_meta(request)
    record(
        db,
        actor=ActorRef(p.actor_type, p.id),
        action="integration.update",
        target_type="integration",
        target_id=row.id,
        payload={"fields": [k for k, v in body.model_dump().items() if v is not None]},
        ip=ip,
        user_agent=ua,
    )
    db.commit()
    return IntegrationOut.model_validate(row)


@router.delete("/{integration_id}", status_code=204)
def delete_integration(
    integration_id: str,
    request: Request,
    p: Annotated[Principal, Depends(require_analyst)],
    db: Session = Depends(get_db),
) -> None:
    row = db.get(Integration, integration_id)
    if row is None or row.workspace_id != p.workspace_id:
        raise HTTPException(404, "integration not found")
    db.delete(row)

    ip, ua = request_meta(request)
    record(
        db,
        actor=ActorRef(p.actor_type, p.id),
        action="integration.delete",
        target_type="integration",
        target_id=integration_id,
        payload={"connector": row.connector, "display_name": row.display_name},
        ip=ip,
        user_agent=ua,
    )
    db.commit()


# --- actions -------------------------------------------------------------


@router.post("/{integration_id}/healthcheck", response_model=HealthcheckResult)
async def integration_healthcheck(
    integration_id: str,
    p: Annotated[Principal, Depends(require_viewer)],
    db: Session = Depends(get_db),
) -> HealthcheckResult:
    row = db.get(Integration, integration_id)
    if row is None or row.workspace_id != p.workspace_id:
        raise HTTPException(404, "integration not found")
    ok, err, ms = await do_healthcheck(row)
    return HealthcheckResult(ok=ok, detail=err, latency_ms=ms)


@router.post("/{integration_id}/sync", response_model=SyncResult)
async def integration_sync(
    integration_id: str,
    request: Request,
    p: Annotated[Principal, Depends(require_analyst)],
    db: Session = Depends(get_db),
) -> SyncResult:
    row = db.get(Integration, integration_id)
    if row is None or row.workspace_id != p.workspace_id:
        raise HTTPException(404, "integration not found")
    result = await sync_one(db, row)
    # Re-run matching after a sync so the UI reflects new ghosts immediately.
    if result.ok:
        run_match(db, workspace_id=p.workspace_id)

    ip, ua = request_meta(request)
    record(
        db,
        actor=ActorRef(p.actor_type, p.id),
        action="integration.sync.requested",
        target_type="integration",
        target_id=row.id,
        payload={"fetched": result.fetched, "ms": result.ms, "error": result.error},
        ip=ip,
        user_agent=ua,
    )
    db.commit()
    return SyncResult(
        ok=result.ok, fetched=result.fetched, duration_ms=result.ms, error=result.error
    )
