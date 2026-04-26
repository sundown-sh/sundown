"""Audit-log hash chain."""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.audit import GENESIS_HASH, ActorRef, record, verify_chain
from app.models.audit import AuditEvent


def test_first_event_chains_from_genesis(session: Session) -> None:
    ev = record(
        session,
        actor=ActorRef(type="user", id="u1"),
        action="user.login",
    )
    assert ev.prev_hash == GENESIS_HASH
    assert ev.hash != GENESIS_HASH


def test_chain_is_consecutive(session: Session) -> None:
    ev1 = record(session, actor=ActorRef("user", "u1"), action="ghost.ack", target_id="g-1")
    ev2 = record(session, actor=ActorRef("user", "u1"), action="ghost.ack", target_id="g-2")
    ev3 = record(session, actor=ActorRef("user", "u1"), action="ghost.ack", target_id="g-3")
    session.flush()
    assert ev2.prev_hash == ev1.hash
    assert ev3.prev_hash == ev2.hash


def test_verify_chain_detects_tampering(session: Session) -> None:
    record(session, actor=ActorRef("user", "u"), action="a")
    record(session, actor=ActorRef("user", "u"), action="b")
    session.flush()

    ok, _ = verify_chain(session)
    assert ok

    # Tamper with the action of an earlier event
    row = session.query(AuditEvent).order_by(AuditEvent.at.asc()).first()
    assert row is not None
    row.action = "tampered"
    session.flush()

    ok, _ = verify_chain(session)
    assert not ok
