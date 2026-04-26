"""Pull the report row-set from the DB.

Centralized so every renderer (json/csv/html/pdf) sees the same data.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.account import Account
from app.models.ghost import Ghost
from app.models.identity import Person
from app.models.integration import Integration
from app.models.match import Match


@dataclass
class GhostRow:
    """Flat denormalized row, the unit of data every renderer consumes."""

    ghost_id: str
    severity: str
    state: str
    days_since_termination: int
    person_name: str
    person_email: str
    employee_number: str | None
    termination_date: str | None
    connector: str
    integration_name: str
    account_external_id: str
    account_username: str | None
    account_email: str | None
    last_login_at: str | None
    match_rule: str
    match_confidence: str
    match_evidence: dict[str, Any]
    first_seen_at: str
    last_seen_at: str
    notes: str | None


@dataclass
class ReportData:
    generated_at: datetime
    workspace_id: str
    scope: dict[str, Any]
    rows: list[GhostRow] = field(default_factory=list)

    @property
    def by_severity(self) -> dict[str, int]:
        out = {"critical": 0, "high": 0, "medium": 0}
        for r in self.rows:
            out[r.severity] = out.get(r.severity, 0) + 1
        return out

    @property
    def by_connector(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for r in self.rows:
            out[r.connector] = out.get(r.connector, 0) + 1
        return out


def collect_report_data(
    db: Session, *, workspace_id: str, scope: dict[str, Any] | None = None
) -> ReportData:
    scope = scope or {}
    stmt = select(Ghost).where(Ghost.workspace_id == workspace_id)

    severity_filter = scope.get("severity")
    if severity_filter:
        stmt = stmt.where(Ghost.severity.in_(severity_filter))

    state_filter = scope.get("state")
    if state_filter:
        stmt = stmt.where(Ghost.state.in_(state_filter))
    elif not scope.get("include_suppressed"):
        # By default exclude resolved + false_positive from reports.
        stmt = stmt.where(Ghost.state.in_(("open", "acknowledged", "suppressed")))

    integration_id = scope.get("integration_id")
    if integration_id:
        stmt = stmt.join(Account, Account.id == Ghost.account_id).where(
            Account.integration_id == integration_id
        )

    ghosts = list(db.execute(stmt.order_by(Ghost.severity.desc())).scalars())

    persons = {
        p.id: p
        for p in db.execute(
            select(Person).where(Person.id.in_({g.person_id for g in ghosts}))
        ).scalars()
    } if ghosts else {}
    accounts = {
        a.id: a
        for a in db.execute(
            select(Account).where(Account.id.in_({g.account_id for g in ghosts}))
        ).scalars()
    } if ghosts else {}
    integrations = {
        i.id: i
        for i in db.execute(
            select(Integration).where(
                Integration.id.in_({a.integration_id for a in accounts.values()})
            )
        ).scalars()
    } if accounts else {}
    matches = {
        m.id: m
        for m in db.execute(
            select(Match).where(Match.id.in_({g.match_id for g in ghosts if g.match_id}))
        ).scalars()
    } if ghosts else {}

    rows: list[GhostRow] = []
    for g in ghosts:
        person = persons.get(g.person_id)
        account = accounts.get(g.account_id)
        if person is None or account is None:
            continue
        integration = integrations.get(account.integration_id)
        if integration is None:
            continue
        match = matches.get(g.match_id) if g.match_id else None
        rows.append(
            GhostRow(
                ghost_id=g.id,
                severity=g.severity,
                state=g.state,
                days_since_termination=g.days_since_termination,
                person_name=person.display_name,
                person_email=person.work_email,
                employee_number=person.employee_number,
                termination_date=str(person.termination_date) if person.termination_date else None,
                connector=integration.connector,
                integration_name=integration.display_name,
                account_external_id=account.external_id,
                account_username=account.username,
                account_email=account.email,
                last_login_at=account.last_login_at.isoformat() if account.last_login_at else None,
                match_rule=match.rule if match else "—",
                match_confidence=match.confidence if match else "—",
                match_evidence=match.evidence if match else {},
                first_seen_at=g.first_seen_at.isoformat(),
                last_seen_at=g.last_seen_at.isoformat(),
                notes=g.notes,
            )
        )

    return ReportData(
        generated_at=datetime.now(UTC),
        workspace_id=workspace_id,
        scope=scope,
        rows=rows,
    )
