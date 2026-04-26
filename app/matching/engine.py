"""Matching engine.

Run order per (workspace):

  1. Load all Persons and Accounts in the workspace.
  2. Build indexes on Account: by email, by alias, by sso_subject, by
     (name, domain) — for cheap lookups.
  3. For each Person, walk the rule chain in order. The first rule that
     produces a MatchEvidence wins. Rule 4 (fuzzy) only fires when it
     is the **unique** candidate among single-domain peers.
  4. UPSERT Match rows.
  5. For every Person whose ``status == terminated`` and which has
     matches, ensure a Ghost row exists per (person, account). Compute
     severity from ``days_since_termination``. Carry forward state
     (acknowledged / false_positive / suppressed) across re-scans.

The engine is **idempotent** — running it twice produces the same DB
state.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, date, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.logging_config import get_logger
from app.matching.rules import (
    MatchEvidence,
    fuzzy_score,
    match_alias,
    match_fuzzy,
    match_primary_email,
    match_sso_subject,
)
from app.models.account import Account
from app.models.ghost import Ghost, severity_for
from app.models.identity import Person
from app.models.match import Match

log = get_logger(__name__)


@dataclass
class MatchRunStats:
    persons: int
    accounts: int
    matches_upserted: int
    ghosts_opened: int
    ghosts_reopened: int
    ghosts_resolved: int

    def as_dict(self) -> dict[str, int]:
        return self.__dict__.copy()


def _today() -> date:
    return datetime.now(UTC).date()


def _local_and_domain(email: str | None) -> tuple[str, str] | None:
    if not email or "@" not in email:
        return None
    local, _, domain = email.partition("@")
    return local.lower(), domain.lower()


class MatchingEngine:
    def __init__(self, db: Session, *, workspace_id: str | None = None) -> None:
        self.db = db
        self.workspace_id = workspace_id or get_settings().default_workspace

    # --- public --------------------------------------------------------

    def run(self) -> MatchRunStats:
        persons = self._load_persons()
        accounts = self._load_accounts()

        idx = _AccountIndex(accounts)
        log.info(
            "engine.start",
            workspace=self.workspace_id,
            persons=len(persons),
            accounts=len(accounts),
        )

        upserted = 0
        for person in persons:
            for account, evidence in self._candidates_for(person, idx):
                self._upsert_match(person, account, evidence)
                upserted += 1

        ghosts_opened, ghosts_reopened, ghosts_resolved = self._reconcile_ghosts(persons)
        # Flush so a subsequent engine.run() in the same session sees our writes.
        self.db.flush()

        stats = MatchRunStats(
            persons=len(persons),
            accounts=len(accounts),
            matches_upserted=upserted,
            ghosts_opened=ghosts_opened,
            ghosts_reopened=ghosts_reopened,
            ghosts_resolved=ghosts_resolved,
        )
        log.info("engine.done", **stats.as_dict())
        return stats

    # --- person-level rule chain --------------------------------------

    def _candidates_for(
        self, person: Person, idx: _AccountIndex
    ) -> Iterable[tuple[Account, MatchEvidence]]:
        """Yield (account, evidence) for each account that matches ``person``.

        We walk rules 1..3 across all candidate accounts. Rule 4 only
        fires for the single-candidate case among same-domain peers.
        """
        seen: set[str] = set()

        # Rule 1: primary work email
        if person.work_email:
            for acct in idx.by_email(person.work_email):
                ev = match_primary_email(person, acct)
                if ev and acct.id not in seen:
                    seen.add(acct.id)
                    yield acct, ev

        # Rule 2: any alias
        for email in person.all_emails():
            for acct in idx.by_any_email(email):
                if acct.id in seen:
                    continue
                ev = match_alias(person, acct)
                if ev:
                    seen.add(acct.id)
                    yield acct, ev

        # Rule 3: SSO subject
        if person.sso_subject:
            for acct in idx.by_sso(person.sso_subject):
                if acct.id in seen:
                    continue
                ev = match_sso_subject(person, acct)
                if ev:
                    seen.add(acct.id)
                    yield acct, ev

        # Rule 4: fuzzy — only when there is exactly one candidate
        if person.work_email and person.display_name:
            ld = _local_and_domain(person.work_email)
            if ld is not None:
                _, domain = ld
                domain_candidates = [
                    a for a in idx.by_domain(domain) if a.id not in seen
                ]
                scored = [
                    (a, fuzzy_score(person, a))
                    for a in domain_candidates
                    if a.display_name
                ]
                viable = [
                    (a, s) for (a, s) in scored
                    if s is not None and s[1] <= 2
                ]
                if len(viable) == 1:
                    acct, _ = viable[0]
                    ev = match_fuzzy(person, acct)
                    if ev:
                        yield acct, ev

    # --- ghost reconciliation -----------------------------------------

    def _reconcile_ghosts(
        self, persons: list[Person]
    ) -> tuple[int, int, int]:
        """Open new ghosts, refresh open ones, close ghosts whose
        underlying account/match disappeared."""
        terminated_ids = {p.id for p in persons if p.is_terminated()}
        person_by_id = {p.id: p for p in persons}

        # All current matches involving a terminated person:
        if terminated_ids:
            rows = list(
                self.db.execute(
                    select(Match).where(
                        Match.workspace_id == self.workspace_id,
                        Match.person_id.in_(terminated_ids),
                    )
                )
                .scalars()
                .all()
            )
        else:
            rows = []

        now = datetime.now(UTC)
        today = _today()
        opened = reopened = resolved = 0

        seen_pairs: set[tuple[str, str]] = set()
        for m in rows:
            person = person_by_id[m.person_id]
            assert person.termination_date is not None
            days = max(0, (today - person.termination_date).days)
            sev = severity_for(days)

            existing = self.db.scalar(
                select(Ghost).where(
                    Ghost.workspace_id == self.workspace_id,
                    Ghost.person_id == m.person_id,
                    Ghost.account_id == m.account_id,
                )
            )
            if existing is None:
                ghost = Ghost(
                    workspace_id=self.workspace_id,
                    person_id=m.person_id,
                    account_id=m.account_id,
                    match_id=m.id,
                    severity=sev,
                    days_since_termination=days,
                    state="open",
                    first_seen_at=now,
                    last_seen_at=now,
                )
                self.db.add(ghost)
                opened += 1
            else:
                existing.match_id = m.id
                existing.severity = sev
                existing.days_since_termination = days
                existing.last_seen_at = now
                # If a previously-resolved ghost reappears, reopen it
                # (unless the operator marked it false_positive — that
                # decision sticks across re-scans).
                if existing.state == "resolved":
                    existing.state = "open"
                    reopened += 1
                # Auto-clear an expired suppression
                if (
                    existing.state == "suppressed"
                    and existing.suppressed_until
                    and existing.suppressed_until <= now
                ):
                    existing.state = "open"
                    existing.suppressed_until = None
            seen_pairs.add((m.person_id, m.account_id))

        # Resolve ghosts whose match no longer exists (account was
        # deprovisioned upstream → it stopped showing up in fetches).
        existing_ghosts = (
            self.db.execute(
                select(Ghost).where(
                    Ghost.workspace_id == self.workspace_id,
                    Ghost.state.in_(("open", "acknowledged", "suppressed")),
                )
            )
            .scalars()
            .all()
        )
        for g in existing_ghosts:
            if (g.person_id, g.account_id) not in seen_pairs:
                g.state = "resolved"
                g.last_seen_at = now
                resolved += 1

        return opened, reopened, resolved

    # --- DB I/O --------------------------------------------------------

    def _load_persons(self) -> list[Person]:
        return list(
            self.db.execute(
                select(Person).where(Person.workspace_id == self.workspace_id)
            ).scalars()
        )

    def _load_accounts(self) -> list[Account]:
        return list(
            self.db.execute(
                select(Account).where(Account.workspace_id == self.workspace_id)
            ).scalars()
        )

    def _upsert_match(
        self, person: Person, account: Account, ev: MatchEvidence
    ) -> Match:
        existing = self.db.scalar(
            select(Match).where(
                Match.workspace_id == self.workspace_id,
                Match.person_id == person.id,
                Match.account_id == account.id,
            )
        )
        if existing is None:
            row = Match(
                workspace_id=self.workspace_id,
                person_id=person.id,
                account_id=account.id,
                rule=ev.rule,
                confidence=ev.confidence,
                evidence=ev.evidence,
            )
            self.db.add(row)
            self.db.flush()
            return row
        existing.rule = ev.rule
        existing.confidence = ev.confidence
        existing.evidence = ev.evidence
        return existing


# --- helpers --------------------------------------------------------------


class _AccountIndex:
    """Build cheap O(1)-ish lookups for the rule chain."""

    def __init__(self, accounts: list[Account]) -> None:
        self._by_email: dict[str, list[Account]] = defaultdict(list)
        self._by_any_email: dict[str, list[Account]] = defaultdict(list)
        self._by_sso: dict[str, list[Account]] = defaultdict(list)
        self._by_domain: dict[str, list[Account]] = defaultdict(list)

        for a in accounts:
            if a.email:
                self._by_email[a.email.lower()].append(a)
            for em in a.all_emails():
                self._by_any_email[em].append(a)
                ld = _local_and_domain(em)
                if ld:
                    self._by_domain[ld[1]].append(a)
            if a.sso_subject:
                self._by_sso[a.sso_subject].append(a)

    def by_email(self, email: str) -> list[Account]:
        return self._by_email.get(email.lower(), [])

    def by_any_email(self, email: str) -> list[Account]:
        return self._by_any_email.get(email.lower(), [])

    def by_sso(self, sso: str) -> list[Account]:
        return self._by_sso.get(sso, [])

    def by_domain(self, domain: str) -> list[Account]:
        return self._by_domain.get(domain.lower(), [])


def run_match(db: Session, *, workspace_id: str | None = None) -> MatchRunStats:
    """Convenience wrapper used by the API and the scheduler."""
    return MatchingEngine(db, workspace_id=workspace_id).run()
