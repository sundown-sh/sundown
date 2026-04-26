"""Audit log API: list + verify chain."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import Principal, get_db, require_admin, require_viewer
from app.audit import verify_chain
from app.models.audit import AuditEvent
from app.schemas.audit import AuditEventOut
from app.schemas.common import Page

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=Page[AuditEventOut])
def list_events(
    p: Annotated[Principal, Depends(require_viewer)],
    db: Session = Depends(get_db),
    actor_id: str | None = None,
    action: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    limit: int = Query(50, le=500),
    offset: int = 0,
) -> Page[AuditEventOut]:
    stmt = select(AuditEvent).where(AuditEvent.workspace_id == p.workspace_id)
    if actor_id:
        stmt = stmt.where(AuditEvent.actor_id == actor_id)
    if action:
        stmt = stmt.where(AuditEvent.action == action)
    if target_type:
        stmt = stmt.where(AuditEvent.target_type == target_type)
    if target_id:
        stmt = stmt.where(AuditEvent.target_id == target_id)

    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = list(
        db.execute(
            stmt.order_by(AuditEvent.at.desc()).limit(limit).offset(offset)
        ).scalars()
    )
    return Page(
        items=[AuditEventOut.model_validate(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/verify")
def verify(
    p: Annotated[Principal, Depends(require_admin)],
    db: Session = Depends(get_db),
) -> dict[str, bool | int]:
    """Walk the hash chain and confirm no tampering. Admin only."""
    ok, n = verify_chain(db, workspace_id=p.workspace_id)
    return {"ok": ok, "checked": n, "broken_at": (0 if ok else n)}
