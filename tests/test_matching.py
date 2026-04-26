"""Matching engine + rule-chain tests.

Exercises every documented rule (email / alias / sso_subject / fuzzy)
plus the ghost reconciliation pipeline (open/reopen/resolve).
"""
from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

import pytest
from sqlalchemy.orm import Session

from app.matching.engine import run_match
from app.matching.rules import (
    match_alias,
    match_fuzzy,
    match_primary_email,
    match_sso_subject,
)
from app.models.account import Account
from app.models.ghost import Ghost
from app.models.identity import Person
from app.models.integration import Integration
from app.models.match import Match

# --- helpers ---------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(UTC)


def _hris(db: Session) -> Integration:
    i = Integration(
        connector="bamboohr",
        kind="hris",
        display_name="acme bhr",
        config_encrypted=b"",
    )
    db.add(i)
    db.flush()
    return i


def _idp(db: Session, name: str = "okta") -> Integration:
    i = Integration(
        connector=name,
        kind="destination",
        display_name=f"acme {name}",
        config_encrypted=b"",
    )
    db.add(i)
    db.flush()
    return i


def _person(
    db: Session,
    integ: Integration,
    *,
    email: str,
    name: str = "Some Person",
    terminated_days_ago: int | None = None,
    aliases: list[str] | None = None,
    sso: str | None = None,
) -> Person:
    p = Person(
        integration_id=integ.id,
        external_id=f"E-{email}",
        display_name=name,
        work_email=email.lower(),
        secondary_emails=aliases or [],
        sso_subject=sso,
        status="terminated" if terminated_days_ago is not None else "active",
        termination_date=(
            (date.today() - timedelta(days=terminated_days_ago))
            if terminated_days_ago is not None
            else None
        ),
        first_seen_at=_now(),
        last_seen_at=_now(),
    )
    db.add(p)
    db.flush()
    return p


def _account(
    db: Session,
    integ: Integration,
    *,
    email: str | None = None,
    name: str | None = None,
    aliases: list[str] | None = None,
    sso: str | None = None,
    ext_id: str | None = None,
) -> Account:
    a = Account(
        integration_id=integ.id,
        external_id=ext_id or (email or name or "x"),
        username=email,
        display_name=name,
        email=email.lower() if email else None,
        aliases=aliases or [],
        sso_subject=sso,
        status="active",
        first_seen_at=_now(),
        last_seen_at=_now(),
    )
    db.add(a)
    db.flush()
    return a


# --- pure rule tests ------------------------------------------------------


def test_rule_primary_email_exact_case_insensitive(session: Session) -> None:
    h, d = _hris(session), _idp(session)
    p = _person(session, h, email="Alice@Acme.com", name="Alice", terminated_days_ago=10)
    a = _account(session, d, email="alice@acme.com", name="Alice")
    ev = match_primary_email(p, a)
    assert ev is not None
    assert ev.rule == "email"
    assert ev.confidence == "high"


def test_rule_alias_matches_secondary(session: Session) -> None:
    h, d = _hris(session), _idp(session)
    p = _person(
        session, h, email="bob@acme.com", aliases=["bob.personal@gmail.com"],
        terminated_days_ago=30,
    )
    a = _account(session, d, email="bob.personal@gmail.com", name="Bob")
    ev = match_alias(p, a)
    assert ev is not None
    assert ev.rule == "alias"


def test_rule_sso_subject(session: Session) -> None:
    h, d = _hris(session), _idp(session)
    p = _person(
        session, h, email="carol@acme.com", sso="00uCAROL", terminated_days_ago=2
    )
    a = _account(session, d, email="completely.different@acme.com", sso="00uCAROL")
    ev = match_sso_subject(p, a)
    assert ev is not None
    assert ev.rule == "sso_subject"


def test_rule_fuzzy_local_part_close_same_domain(session: Session) -> None:
    h, d = _hris(session), _idp(session)
    # local-part Levenshtein 1: "dave.d" -> "daved"
    p = _person(
        session, h, email="dave.d@acme.com", name="Dave Designer",
        terminated_days_ago=15,
    )
    a = _account(session, d, email="daved@acme.com", name="Dave Designer")
    ev = match_fuzzy(p, a)
    assert ev is not None
    assert ev.rule == "fuzzy"
    assert ev.confidence == "medium"


def test_rule_fuzzy_rejects_cross_domain(session: Session) -> None:
    h, d = _hris(session), _idp(session)
    p = _person(session, h, email="x@acme.com", name="Pat Person", terminated_days_ago=1)
    a = _account(session, d, email="x@evil.com", name="Pat Person")
    assert match_fuzzy(p, a) is None


# --- engine tests ----------------------------------------------------------


def test_engine_opens_ghost_for_terminated_match(session: Session) -> None:
    h, d = _hris(session), _idp(session)
    _person(session, h, email="bob@acme.com", name="Bob", terminated_days_ago=20)
    _account(session, d, email="bob@acme.com", name="Bob")

    stats = run_match(session)
    session.flush()
    assert stats.matches_upserted == 1
    assert stats.ghosts_opened == 1
    g = session.query(Ghost).one()
    assert g.severity == "critical"
    assert g.state == "open"
    assert g.days_since_termination == 20


def test_engine_no_ghost_for_active_employee(session: Session) -> None:
    h, d = _hris(session), _idp(session)
    _person(session, h, email="alice@acme.com", name="Alice")  # not terminated
    _account(session, d, email="alice@acme.com")
    stats = run_match(session)
    assert stats.matches_upserted == 1
    assert stats.ghosts_opened == 0
    assert session.query(Ghost).count() == 0


def test_engine_severity_buckets(session: Session) -> None:
    h, d = _hris(session), _idp(session)
    _person(session, h, email="critical@acme.com", terminated_days_ago=30)
    _account(session, d, email="critical@acme.com")
    _person(session, h, email="high@acme.com", terminated_days_ago=3)
    _account(session, d, email="high@acme.com")
    _person(session, h, email="medium@acme.com", terminated_days_ago=0)
    _account(session, d, email="medium@acme.com")

    run_match(session)

    sev_by_email: dict[str, str] = {}
    for g in session.query(Ghost).all():
        person = session.get(Person, g.person_id)
        assert person is not None
        sev_by_email[person.work_email] = g.severity

    assert sev_by_email["critical@acme.com"] == "critical"
    assert sev_by_email["high@acme.com"] == "high"
    assert sev_by_email["medium@acme.com"] == "medium"


def test_engine_is_idempotent(session: Session) -> None:
    h, d = _hris(session), _idp(session)
    _person(session, h, email="bob@acme.com", terminated_days_ago=10)
    _account(session, d, email="bob@acme.com")

    run_match(session)
    run_match(session)
    run_match(session)
    assert session.query(Ghost).count() == 1
    assert session.query(Match).count() == 1


def test_engine_records_explainable_rule_on_match(session: Session) -> None:
    h, d = _hris(session), _idp(session)
    _person(
        session,
        h,
        email="x@acme.com",
        sso="00uX",
        aliases=["x.personal@gmail.com"],
        terminated_days_ago=5,
    )
    _account(session, d, email="x.personal@gmail.com", sso="00uX")
    run_match(session)
    m = session.query(Match).one()
    # primary email differs → rule must be alias (rule 2 wins over 3)
    assert m.rule == "alias"


def test_engine_resolves_ghost_when_account_disappears(session: Session) -> None:
    """Simulates a destination account being deprovisioned upstream:
    the next sync no longer returns it, so the engine no longer matches
    it, and the ghost should transition to ``resolved``."""
    h, d = _hris(session), _idp(session)
    _person(session, h, email="bob@acme.com", terminated_days_ago=10)
    acct = _account(session, d, email="bob@acme.com")
    run_match(session)
    assert session.query(Ghost).filter_by(state="open").count() == 1

    # Sim: the destination account no longer matches anything (e.g. its
    # email was changed upstream during deprovisioning).
    acct.email = "deprovisioned-old@acme.com"
    session.flush()

    # Need to also delete the now-stale Match row, since matches survive
    # across runs if the same (person, account) tuple is still seen.
    session.query(Match).delete()
    session.flush()

    run_match(session)
    g = session.query(Ghost).one()
    assert g.state == "resolved"


def test_engine_preserves_acknowledged_state(session: Session) -> None:
    h, d = _hris(session), _idp(session)
    _person(session, h, email="bob@acme.com", terminated_days_ago=10)
    _account(session, d, email="bob@acme.com")
    run_match(session)
    g = session.query(Ghost).one()
    g.state = "acknowledged"
    session.flush()

    run_match(session)
    g = session.query(Ghost).one()
    assert g.state == "acknowledged"  # not reopened


def test_fuzzy_does_not_fire_when_two_candidates(session: Session) -> None:
    """Spec: fuzzy only fires when there is exactly one candidate."""
    h, d = _hris(session), _idp(session)
    _person(
        session, h, email="dave.designer@acme.com", name="Dave Designer",
        terminated_days_ago=10,
    )
    _account(session, d, email="ddesigner@acme.com", name="Dave Designer", ext_id="a1")
    _account(session, d, email="dave.d@acme.com",   name="Dave Designer", ext_id="a2")
    run_match(session)
    # No fuzzy match should be created
    assert session.query(Match).count() == 0


@pytest.mark.parametrize(
    "days,severity",
    [(0, "medium"), (1, "high"), (7, "high"), (8, "critical"), (90, "critical")],
)
def test_severity_for_table(days: int, severity: str) -> None:
    from app.models.ghost import severity_for

    assert severity_for(days) == severity
