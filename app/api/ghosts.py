"""Ghosts API: list, detail, ack, false-positive, suppress."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import (
    Principal,
    get_db,
    request_meta,
    require_analyst,
    require_viewer,
)
from app.audit import ActorRef, record
from app.matching.engine import run_match
from app.models.account import Account
from app.models.ghost import Ghost
from app.models.identity import Person
from app.models.integration import Integration
from app.models.match import Match
from app.schemas.common import Page
from app.schemas.ghost import (
    GhostAccountRef,
    GhostMatchRef,
    GhostOut,
    GhostPersonRef,
    GhostUpdate,
)

router = APIRouter(prefix="/ghosts", tags=["ghosts"])


def _to_out(
    g: Ghost, person: Person, account: Account, integration: Integration, match: Match | None
) -> GhostOut:
    return GhostOut(
        id=g.id,
        workspace_id=g.workspace_id,
        severity=g.severity,
        state=g.state,
        days_since_termination=g.days_since_termination,
        notes=g.notes,
        suppressed_until=g.suppressed_until,
        first_seen_at=g.first_seen_at,
        last_seen_at=g.last_seen_at,
        person=GhostPersonRef(
            id=person.id,
            display_name=person.display_name,
            work_email=person.work_email,
            employee_number=person.employee_number,
            termination_date=(
                datetime.combine(person.termination_date, datetime.min.time())
                if person.termination_date
                else None
            ),
        ),
        account=GhostAccountRef(
            id=account.id,
            integration_id=integration.id,
            connector=integration.connector,
            external_id=account.external_id,
            username=account.username,
            email=account.email,
            last_login_at=account.last_login_at,
        ),
        match=GhostMatchRef(
            rule=(match.rule if match else "email"),
            confidence=(match.confidence if match else "high"),
            evidence=(match.evidence if match else {}),
        ),
    )


def _hydrate(db: Session, ghosts: list[Ghost]) -> list[GhostOut]:
    if not ghosts:
        return []
    person_ids = {g.person_id for g in ghosts}
    account_ids = {g.account_id for g in ghosts}
    match_ids = {g.match_id for g in ghosts if g.match_id}

    persons = {p.id: p for p in db.execute(select(Person).where(Person.id.in_(person_ids))).scalars()}
    accounts = {
        a.id: a
        for a in db.execute(select(Account).where(Account.id.in_(account_ids))).scalars()
    }
    integrations = {
        i.id: i
        for i in db.execute(
            select(Integration).where(
                Integration.id.in_({a.integration_id for a in accounts.values()})
            )
        ).scalars()
    }
    matches = (
        {
            m.id: m
            for m in db.execute(select(Match).where(Match.id.in_(match_ids))).scalars()
        }
        if match_ids
        else {}
    )

    out: list[GhostOut] = []
    for g in ghosts:
        person = persons.get(g.person_id)
        account = accounts.get(g.account_id)
        if person is None or account is None:
            continue
        integration = integrations.get(account.integration_id)
        if integration is None:
            continue
        out.append(_to_out(g, person, account, integration, matches.get(g.match_id) if g.match_id else None))
    return out


@router.get("", response_model=Page[GhostOut])
def list_ghosts(
    p: Annotated[Principal, Depends(require_viewer)],
    db: Session = Depends(get_db),
    severity: list[Literal["critical", "high", "medium"]] | None = Query(default=None),
    state: list[Literal["open", "acknowledged", "false_positive", "suppressed", "resolved"]] | None = Query(default=None),
    integration_id: str | None = None,
    min_days: int | None = None,
    limit: int = Query(50, le=500),
    offset: int = 0,
) -> Page[GhostOut]:
    stmt = select(Ghost).where(Ghost.workspace_id == p.workspace_id)
    if severity:
        stmt = stmt.where(Ghost.severity.in_(severity))
    if state:
        stmt = stmt.where(Ghost.state.in_(state))
    else:
        stmt = stmt.where(Ghost.state.in_(("open", "acknowledged", "suppressed")))
    if min_days is not None:
        stmt = stmt.where(Ghost.days_since_termination >= min_days)
    if integration_id is not None:
        stmt = stmt.join(Account, Account.id == Ghost.account_id).where(
            Account.integration_id == integration_id
        )

    total = db.scalar(
        select(func.count()).select_from(stmt.subquery())
    ) or 0

    rows = list(
        db.execute(
            stmt.order_by(Ghost.severity.desc(), Ghost.last_seen_at.desc())
            .limit(limit)
            .offset(offset)
        ).scalars()
    )
    return Page(items=_hydrate(db, rows), total=total, limit=limit, offset=offset)


@router.get("/{ghost_id}", response_model=GhostOut)
def get_ghost(
    ghost_id: str,
    p: Annotated[Principal, Depends(require_viewer)],
    db: Session = Depends(get_db),
) -> GhostOut:
    g = db.get(Ghost, ghost_id)
    if g is None or g.workspace_id != p.workspace_id:
        raise HTTPException(404, "ghost not found")
    out = _hydrate(db, [g])
    if not out:
        raise HTTPException(404, "ghost not found")
    return out[0]


def _patch(
    db: Session,
    p: Principal,
    ghost: Ghost,
    new_state: str | None,
    notes: str | None,
    suppress_until: datetime | None,
    request: Request,
    action: str,
) -> Ghost:
    if new_state is not None:
        ghost.state = new_state
    if notes is not None:
        ghost.notes = notes
    if suppress_until is not None:
        ghost.suppressed_until = suppress_until
    if new_state == "acknowledged":
        ghost.acknowledged_by_user_id = p.id if p.actor_type == "user" else None
        ghost.acknowledged_at = datetime.now(UTC)

    ip, ua = request_meta(request)
    record(
        db,
        actor=ActorRef(p.actor_type, p.id),
        action=action,
        target_type="ghost",
        target_id=ghost.id,
        payload={"new_state": new_state, "notes": notes, "suppress_until": str(suppress_until or "")},
        ip=ip,
        user_agent=ua,
    )
    db.commit()
    return ghost


@router.patch("/{ghost_id}", response_model=GhostOut)
def update_ghost(
    ghost_id: str,
    body: GhostUpdate,
    request: Request,
    p: Annotated[Principal, Depends(require_analyst)],
    db: Session = Depends(get_db),
) -> GhostOut:
    g = db.get(Ghost, ghost_id)
    if g is None or g.workspace_id != p.workspace_id:
        raise HTTPException(404, "ghost not found")
    _patch(db, p, g, body.state, body.notes, body.suppressed_until, request, "ghost.update")
    out = _hydrate(db, [g])
    return out[0]


@router.post("/{ghost_id}/ack", response_model=GhostOut)
def acknowledge_ghost(
    ghost_id: str,
    request: Request,
    p: Annotated[Principal, Depends(require_analyst)],
    db: Session = Depends(get_db),
) -> GhostOut:
    g = db.get(Ghost, ghost_id)
    if g is None or g.workspace_id != p.workspace_id:
        raise HTTPException(404, "ghost not found")
    _patch(db, p, g, "acknowledged", None, None, request, "ghost.ack")
    return _hydrate(db, [g])[0]


@router.post("/{ghost_id}/false-positive", response_model=GhostOut)
def mark_false_positive(
    ghost_id: str,
    request: Request,
    p: Annotated[Principal, Depends(require_analyst)],
    db: Session = Depends(get_db),
) -> GhostOut:
    g = db.get(Ghost, ghost_id)
    if g is None or g.workspace_id != p.workspace_id:
        raise HTTPException(404, "ghost not found")
    _patch(db, p, g, "false_positive", None, None, request, "ghost.false_positive")
    return _hydrate(db, [g])[0]


@router.post("/{ghost_id}/suppress", response_model=GhostOut)
def suppress_ghost(
    ghost_id: str,
    request: Request,
    p: Annotated[Principal, Depends(require_analyst)],
    db: Session = Depends(get_db),
    days: int = Query(default=30, ge=1, le=365),
) -> GhostOut:
    g = db.get(Ghost, ghost_id)
    if g is None or g.workspace_id != p.workspace_id:
        raise HTTPException(404, "ghost not found")
    until = datetime.now(UTC) + timedelta(days=days)
    _patch(db, p, g, "suppressed", None, until, request, "ghost.suppress")
    return _hydrate(db, [g])[0]


@router.post("/rescan", response_model=dict[str, int])
def rescan(
    request: Request,
    p: Annotated[Principal, Depends(require_analyst)],
    db: Session = Depends(get_db),
) -> dict[str, int]:
    """Re-run the matching engine against current Person/Account data."""
    stats = run_match(db, workspace_id=p.workspace_id)
    ip, ua = request_meta(request)
    record(
        db,
        actor=ActorRef(p.actor_type, p.id),
        action="ghosts.rescan",
        payload=stats.as_dict(),
        ip=ip,
        user_agent=ua,
    )
    db.commit()
    return stats.as_dict()
