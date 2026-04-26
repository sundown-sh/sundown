"""Reports API: list, generate, download."""
from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
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
from app.models.report import Report
from app.reports.service import generate_report
from app.schemas.report import ReportCreate, ReportOut

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("", response_model=list[ReportOut])
def list_reports(
    p: Annotated[Principal, Depends(require_viewer)], db: Session = Depends(get_db)
) -> list[ReportOut]:
    rows = list(
        db.execute(
            select(Report)
            .where(Report.workspace_id == p.workspace_id)
            .order_by(Report.generated_at.desc())
        ).scalars()
    )
    return [ReportOut.model_validate(r) for r in rows]


@router.post("", response_model=ReportOut, status_code=201)
def create_report(
    body: ReportCreate,
    request: Request,
    p: Annotated[Principal, Depends(require_analyst)],
    db: Session = Depends(get_db),
) -> ReportOut:
    row = generate_report(
        db,
        workspace_id=p.workspace_id,
        kind=body.kind,
        scope=body.scope,
        generated_by_user_id=p.id if p.actor_type == "user" else None,
    )
    ip, ua = request_meta(request)
    payload: dict[str, Any] = {
        "kind": row.kind,
        "ghost_count": row.ghost_count,
        "sha256": row.sha256,
    }
    if body.kind != row.kind:
        payload["requested_kind"] = body.kind
    record(
        db,
        actor=ActorRef(p.actor_type, p.id),
        action="report.generate",
        target_type="report",
        target_id=row.id,
        payload=payload,
        ip=ip,
        user_agent=ua,
    )
    db.commit()
    return ReportOut.model_validate(row)


@router.get("/{report_id}", response_model=ReportOut)
def get_report(
    report_id: str,
    p: Annotated[Principal, Depends(require_viewer)],
    db: Session = Depends(get_db),
) -> ReportOut:
    row = db.get(Report, report_id)
    if row is None or row.workspace_id != p.workspace_id:
        raise HTTPException(404, "report not found")
    return ReportOut.model_validate(row)


@router.get("/{report_id}/download")
def download_report(
    report_id: str,
    p: Annotated[Principal, Depends(require_viewer)],
    db: Session = Depends(get_db),
) -> FileResponse:
    row = db.get(Report, report_id)
    if row is None or row.workspace_id != p.workspace_id:
        raise HTTPException(404, "report not found")
    media_types = {
        "json": "application/json",
        "csv": "text/csv",
        "html": "text/html",
        "pdf": "application/pdf",
    }
    media = media_types.get(row.kind, "application/octet-stream")
    filename = f"sundown-{row.id[:8]}.{row.kind}"
    return FileResponse(row.path, media_type=media, filename=filename)
