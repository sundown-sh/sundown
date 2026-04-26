"""Report generation service.

Persists the rendered file under ``settings.reports_dir`` and writes a
``Report`` row pointing at it (including a sha256 of the content for
evidence integrity).
"""
from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.report import Report
from app.reports.data import collect_report_data
from app.reports.renderers import render_csv, render_html, render_json, render_pdf, write_to_path


def generate_report(
    db: Session,
    *,
    workspace_id: str,
    kind: str,
    scope: dict[str, Any] | None = None,
    generated_by_user_id: str | None = None,
) -> Report:
    if kind not in {"json", "csv", "html", "pdf"}:
        raise ValueError(f"unsupported report kind: {kind}")

    data = collect_report_data(db, workspace_id=workspace_id, scope=scope)

    settings = get_settings()
    settings.ensure_dirs()
    ts = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    out_path = settings.reports_dir / f"sundown-{ts}.{kind}"

    # Render. PDF needs the report id for the footer, so we pre-create
    # the row, then re-render once we know it.
    row = Report(
        workspace_id=workspace_id,
        kind=kind,
        scope=scope or {},
        ghost_count=len(data.rows),
        path="",  # placeholder
        sha256="",
        generated_by_user_id=generated_by_user_id,
        generated_at=data.generated_at,
    )
    db.add(row)
    db.flush()

    if kind == "json":
        content = render_json(data)
    elif kind == "csv":
        content = render_csv(data)
    elif kind == "html":
        content = render_html(data, report_id=row.id)
    else:
        content = render_pdf(data, report_id=row.id)

    write_to_path(content, out_path)
    row.path = str(out_path)
    row.sha256 = hashlib.sha256(content).hexdigest()
    db.flush()
    return row
