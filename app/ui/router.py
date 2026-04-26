"""HTMX + Tailwind UI.

This is a thin presentation layer that *only* reads from the database.
All write operations are POSTed via HTMX to ``/api/v1/...`` and reuse the
JWT/API-key auth machinery, so the UI is just a different client of the
same API.

Auth is cookie-based (``sundown_token``) so server-side templates can be
authenticated without a per-request JS shim. The cookie is set by the
``/login`` flow in ``login.html``.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode

from fastapi import APIRouter, Cookie, Depends, HTTPException, Path, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import __version__ as APP_VERSION
from app.api.deps import Principal
from app.config import get_settings
from app.db import get_db
from app.integrations import registry
from app.models.account import Account
from app.models.audit import AuditEvent
from app.models.ghost import Ghost
from app.models.identity import Person
from app.models.integration import Integration
from app.models.match import Match
from app.models.report import Report
from app.models.user import ApiKey
from app.security import API_KEY_PREFIX, decode_token, verify_api_key

router = APIRouter(tags=["ui"], include_in_schema=False)
templates = Jinja2Templates(directory="app/templates")


# --- helpers --------------------------------------------------------------


def _principal_from_cookie(db: Session, token: str | None) -> Principal | None:
    if not token:
        return None
    try:
        if token.startswith(API_KEY_PREFIX):
            prefix = token[: len(API_KEY_PREFIX) + 8]
            for k in db.execute(select(ApiKey).where(ApiKey.prefix == prefix)).scalars():
                if k.revoked_at is None and verify_api_key(token, k.hash):
                    return Principal(
                        actor_type="api_key",
                        id=k.id,
                        email=None,
                        role=k.role,  # type: ignore[arg-type]
                        workspace_id=k.workspace_id,
                    )
            return None
        claims = decode_token(token)
        if claims.get("typ") != "access":
            return None
        from app.models.user import User

        user = db.scalar(
            select(User).where(User.id == claims["sub"], User.workspace_id == claims["ws"])
        )
        if user is None or not user.is_active:
            return None
        return Principal(
            actor_type="user",
            id=user.id,
            email=user.email,
            role=user.role,  # type: ignore[arg-type]
            workspace_id=user.workspace_id,
        )
    except Exception:
        return None


def _ctx(request: Request, principal: Principal | None, **extra: Any) -> dict[str, Any]:
    qs = dict(request.query_params)

    def querystring(**overrides: Any) -> str:
        merged = {**qs, **{k: v for k, v in overrides.items() if v is not None}}
        return urlencode({k: v for k, v in merged.items() if v != ""}, doseq=True)

    return {
        "request": request,
        "principal": principal,
        "version": APP_VERSION,
        "querystring": querystring,
        **extra,
    }


def _require_login(
    request: Request,
    db: Session,
    sundown_token: str | None,
) -> Principal | RedirectResponse:
    p = _principal_from_cookie(db, sundown_token)
    if p is None:
        # Don't redirect-loop on /login itself.
        if request.url.path == "/login":
            return p  # type: ignore[return-value]
        return RedirectResponse(url="/login", status_code=302)
    return p


# --- routes ---------------------------------------------------------------


@router.get("/login", response_class=HTMLResponse)
def login_page(
    request: Request,
    db: Session = Depends(get_db),
    sundown_token: str | None = Cookie(default=None),
) -> Response:
    p = _principal_from_cookie(db, sundown_token)
    if p is not None:
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse(request, "login.html", _ctx(request, None))


@router.post("/ui/logout")
def ui_logout() -> Response:
    resp = RedirectResponse(url="/login", status_code=302)
    resp.delete_cookie("sundown_token")
    return resp


@router.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    db: Session = Depends(get_db),
    sundown_token: str | None = Cookie(default=None),
) -> Response:
    auth = _require_login(request, db, sundown_token)
    if isinstance(auth, RedirectResponse):
        return auth
    p: Principal = auth

    integrations = list(
        db.execute(
            select(Integration).where(Integration.workspace_id == p.workspace_id)
        ).scalars()
    )

    # If no integrations exist, show the setup wizard instead of an empty dashboard.
    if not integrations:
        return templates.TemplateResponse(request, "setup_wizard.html", _ctx(request, p))

    open_states = ("open", "acknowledged")
    base_q = select(Ghost).where(
        Ghost.workspace_id == p.workspace_id, Ghost.state.in_(open_states)
    )
    ghosts = list(db.execute(base_q).scalars())
    stats = {
        "open": len(ghosts),
        "critical": sum(1 for g in ghosts if g.severity == "critical"),
        "high": sum(1 for g in ghosts if g.severity == "high"),
        "medium": sum(1 for g in ghosts if g.severity == "medium"),
    }
    recent = sorted(ghosts, key=lambda g: g.last_seen_at, reverse=True)[:10]
    rows = _hydrate_ghost_rows(db, recent)
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        _ctx(
            request,
            p,
            stats=stats,
            recent=rows,
            integrations=integrations,
        ),
    )


@router.get("/ghosts", response_class=HTMLResponse)
def ghosts_page(
    request: Request,
    severity: str | None = Query(default=None),
    state: str | None = Query(default="open"),
    integration_id: str | None = Query(default=None),
    min_days: int | None = Query(default=None, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    sundown_token: str | None = Cookie(default=None),
) -> Response:
    auth = _require_login(request, db, sundown_token)
    if isinstance(auth, RedirectResponse):
        return auth
    p: Principal = auth

    q = select(Ghost).where(Ghost.workspace_id == p.workspace_id)
    if severity:
        q = q.where(Ghost.severity == severity)
    if state:
        q = q.where(Ghost.state == state)
    if min_days is not None:
        q = q.where(Ghost.days_since_termination >= min_days)
    if integration_id:
        q = q.join(Account, Ghost.account_id == Account.id).where(
            Account.integration_id == integration_id
        )

    total = db.scalar(select(func.count()).select_from(q.subquery())) or 0
    items = list(
        db.execute(q.order_by(Ghost.days_since_termination.desc()).offset(offset).limit(limit)).scalars()
    )
    rows = _hydrate_ghost_rows(db, items)
    integrations = list(
        db.execute(
            select(Integration).where(Integration.workspace_id == p.workspace_id)
        ).scalars()
    )
    filters = {
        "severity": severity or "",
        "state": state or "",
        "integration_id": integration_id or "",
        "min_days": min_days,
        "limit": limit,
        "offset": offset,
    }
    return templates.TemplateResponse(
        request,
        "ghosts.html",
        _ctx(
            request,
            p,
            items=rows,
            total=total,
            filters=filters,
            integrations=integrations,
        ),
    )


@router.get("/ghosts/{ghost_id}", response_class=HTMLResponse)
def ghost_detail(
    request: Request,
    ghost_id: str = Path(...),
    db: Session = Depends(get_db),
    sundown_token: str | None = Cookie(default=None),
) -> Response:
    auth = _require_login(request, db, sundown_token)
    if isinstance(auth, RedirectResponse):
        return auth
    p: Principal = auth
    g = db.get(Ghost, ghost_id)
    if g is None or g.workspace_id != p.workspace_id:
        raise HTTPException(404, "ghost not found")
    [row] = _hydrate_ghost_rows(db, [g])
    return templates.TemplateResponse(request, "ghost_detail.html", _ctx(request, p, g=row))


@router.get("/integrations", response_class=HTMLResponse)
def integrations_page(
    request: Request,
    db: Session = Depends(get_db),
    sundown_token: str | None = Cookie(default=None),
) -> Response:
    auth = _require_login(request, db, sundown_token)
    if isinstance(auth, RedirectResponse):
        return auth
    p: Principal = auth
    integrations = list(
        db.execute(
            select(Integration).where(Integration.workspace_id == p.workspace_id)
        ).scalars()
    )
    catalog = [
        {
            "connector": s.name,
            "display_name": _humanize(s.name),
            "kind": s.kind.value,
            "tier": s.tier.value,
            "description": _connector_description(s.name),
            "config_schema_url": "",
        }
        for s in registry.all_specs()
    ]
    return templates.TemplateResponse(
        request,
        "integrations.html",
        _ctx(request, p, integrations=integrations, catalog=catalog),
    )


@router.get("/reports", response_class=HTMLResponse)
def reports_page(
    request: Request,
    db: Session = Depends(get_db),
    sundown_token: str | None = Cookie(default=None),
) -> Response:
    auth = _require_login(request, db, sundown_token)
    if isinstance(auth, RedirectResponse):
        return auth
    p: Principal = auth
    reports = list(
        db.execute(
            select(Report)
            .where(Report.workspace_id == p.workspace_id)
            .order_by(Report.created_at.desc())
            .limit(50)
        ).scalars()
    )
    return templates.TemplateResponse(request, "reports.html", _ctx(request, p, reports=reports))


@router.get("/settings", response_class=HTMLResponse)
def settings_page(
    request: Request,
    db: Session = Depends(get_db),
    sundown_token: str | None = Cookie(default=None),
) -> Response:
    auth = _require_login(request, db, sundown_token)
    if isinstance(auth, RedirectResponse):
        return auth
    p: Principal = auth
    api_keys = list(
        db.execute(
            select(ApiKey)
            .where(ApiKey.workspace_id == p.workspace_id, ApiKey.revoked_at.is_(None))
            .order_by(ApiKey.created_at.desc())
        ).scalars()
    )
    return templates.TemplateResponse(
        request,
        "settings.html",
        _ctx(request, p, settings=get_settings(), api_keys=api_keys),
    )


@router.get("/audit", response_class=HTMLResponse)
def audit_page(
    request: Request,
    db: Session = Depends(get_db),
    sundown_token: str | None = Cookie(default=None),
    limit: int = Query(default=200, ge=1, le=1000),
) -> Response:
    auth = _require_login(request, db, sundown_token)
    if isinstance(auth, RedirectResponse):
        return auth
    p: Principal = auth
    events = list(
        db.execute(
            select(AuditEvent)
            .where(AuditEvent.workspace_id == p.workspace_id)
            .order_by(AuditEvent.at.desc())
            .limit(limit)
        ).scalars()
    )
    return templates.TemplateResponse(request, "audit.html", _ctx(request, p, events=events))


# --- hydration ------------------------------------------------------------


def _hydrate_ghost_rows(db: Session, ghosts: list[Ghost]) -> list[Any]:
    """Build template-friendly rows joining person/account/integration/match."""
    if not ghosts:
        return []
    person_ids = list({g.person_id for g in ghosts})
    account_ids = list({g.account_id for g in ghosts})
    match_ids = list({g.match_id for g in ghosts if g.match_id})

    persons = {
        p.id: p for p in db.execute(select(Person).where(Person.id.in_(person_ids))).scalars()
    }
    accounts = {
        a.id: a for a in db.execute(select(Account).where(Account.id.in_(account_ids))).scalars()
    }
    integration_ids = {a.integration_id for a in accounts.values()}
    integrations = {
        i.id: i
        for i in db.execute(
            select(Integration).where(Integration.id.in_(integration_ids))
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

    rows: list[Any] = []
    for g in ghosts:
        a = accounts.get(g.account_id)
        i = integrations.get(a.integration_id) if a else None
        m = matches.get(g.match_id) if g.match_id else None
        rows.append(
            _Row(
                id=g.id,
                severity=g.severity,
                state=g.state,
                days_since_termination=g.days_since_termination,
                first_seen_at=g.first_seen_at,
                last_seen_at=g.last_seen_at,
                person=persons.get(g.person_id),
                account=_AccountView(
                    connector=i.connector if i else "?",
                    external_id=a.external_id if a else "",
                    username=a.username if a else None,
                    email=a.email if a else None,
                    status=a.status if a else "?",
                    last_login_at=a.last_login_at if a else None,
                ),
                match=_MatchView(
                    rule=m.rule if m else "—",
                    confidence=m.confidence if m else "—",
                    evidence=(m.evidence if m else None),
                ),
            )
        )
    return rows


# --- tiny view models -----------------------------------------------------


from dataclasses import dataclass  # noqa: E402


@dataclass
class _AccountView:
    connector: str
    external_id: str
    username: str | None
    email: str | None
    status: str
    last_login_at: datetime | None


@dataclass
class _MatchView:
    rule: str
    confidence: str
    evidence: dict[str, Any] | None


@dataclass
class _Row:
    id: str
    severity: str
    state: str
    days_since_termination: int
    first_seen_at: datetime
    last_seen_at: datetime
    person: Person | None
    account: _AccountView
    match: _MatchView


# --- catalog text ---------------------------------------------------------


_DESCRIPTIONS = {
    "bamboohr": "Pull active and terminated employees from BambooHR via API key.",
    "rippling": "Pull employees from Rippling via OAuth (read scopes only).",
    "okta": "List Okta users to detect any with active status post-termination.",
    "google_workspace": "Domain-wide-delegated read of Google Workspace users.",
    "github": "List GitHub Org members and SAML-linked external identities.",
    "slack": "List Slack workspace members via admin scopes.",
}


def _connector_description(name: str) -> str:
    return _DESCRIPTIONS.get(name, "Read-only connector.")


def _humanize(name: str) -> str:
    return name.replace("_", " ").title().replace("Hris", "HRIS").replace("Github", "GitHub")


# Make sure datetime import isn't dead-pruned if Python 3.10 typing tightens.
_ = datetime.now(UTC)
