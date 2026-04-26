"""Append-only audit log with hash-chained tamper detection.

Each row's ``hash`` is sha256(prev_hash || canonical_payload). The very
first row uses a fixed genesis ``prev_hash`` so the chain is verifiable
end-to-end. This shape mirrors what SOC 2 / ISO 27001 evidence
collectors expect.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy.orm import Session

from app.config import get_settings
from app.logging_config import get_logger

if TYPE_CHECKING:
    from app.models.audit import AuditEvent

log = get_logger(__name__)

GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class ActorRef:
    type: str  # "user" | "api_key" | "system"
    id: str


SYSTEM_ACTOR = ActorRef(type="system", id="sundown")


def _canonicalize(d: dict[str, Any]) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _canon_at(at: datetime) -> str:
    """Canonical UTC ISO string. SQLite strips tzinfo on roundtrip, so we
    always force-UTC before formatting to keep the hash stable."""
    if at.tzinfo is None:
        at = at.replace(tzinfo=UTC)
    else:
        at = at.astimezone(UTC)
    return at.isoformat()


def _next_hash(prev_hash: str, row: dict[str, Any]) -> str:
    h = hashlib.sha256()
    h.update(prev_hash.encode("ascii"))
    h.update(_canonicalize(row))
    return h.hexdigest()


def record(
    db: Session,
    *,
    actor: ActorRef,
    action: str,
    target_type: str | None = None,
    target_id: str | None = None,
    payload: dict[str, Any] | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
    workspace_id: str | None = None,
) -> AuditEvent:
    """Append a single audit event, hash-chained to the previous one."""
    from app.models.audit import AuditEvent  # local import to avoid cycle

    settings = get_settings()
    ws = workspace_id or settings.default_workspace

    last = (
        db.query(AuditEvent)
        .filter(AuditEvent.workspace_id == ws)
        .order_by(AuditEvent.at.desc(), AuditEvent.id.desc())
        .first()
    )
    prev = last.hash if last else GENESIS_HASH

    at = datetime.now(UTC)
    body = {
        "workspace_id": ws,
        "actor_type": actor.type,
        "actor_id": actor.id,
        "action": action,
        "target_type": target_type,
        "target_id": target_id,
        "payload": payload or {},
        "ip": ip,
        "user_agent": user_agent,
        "at": _canon_at(at),
    }
    h = _next_hash(prev, body)

    ev = AuditEvent(
        workspace_id=ws,
        actor_type=actor.type,
        actor_id=actor.id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        payload=body["payload"],
        ip=ip,
        user_agent=user_agent,
        prev_hash=prev,
        hash=h,
        at=at,
    )
    db.add(ev)
    db.flush()
    log.info(
        "audit",
        action=action,
        actor=f"{actor.type}:{actor.id}",
        target=f"{target_type}:{target_id}" if target_type else None,
    )
    return ev


def verify_chain(db: Session, *, workspace_id: str | None = None) -> tuple[bool, int]:
    """Walk the chain; return (ok, count_checked)."""
    from app.models.audit import AuditEvent

    settings = get_settings()
    ws = workspace_id or settings.default_workspace
    rows = (
        db.query(AuditEvent)
        .filter(AuditEvent.workspace_id == ws)
        .order_by(AuditEvent.at.asc(), AuditEvent.id.asc())
        .all()
    )
    prev = GENESIS_HASH
    for i, r in enumerate(rows, 1):
        body = {
            "workspace_id": r.workspace_id,
            "actor_type": r.actor_type,
            "actor_id": r.actor_id,
            "action": r.action,
            "target_type": r.target_type,
            "target_id": r.target_id,
            "payload": r.payload or {},
            "ip": r.ip,
            "user_agent": r.user_agent,
            "at": _canon_at(r.at),
        }
        if r.prev_hash != prev or r.hash != _next_hash(prev, body):
            return False, i
        prev = r.hash
    return True, len(rows)
