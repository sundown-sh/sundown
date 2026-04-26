"""Per-rule modules.

Each rule is a small pure function ``(person, account) -> MatchEvidence | None``.
Rules are stateless so they're trivially composable and testable.

Rules NEVER mutate the inputs.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rapidfuzz.distance import Levenshtein

from app.models.account import Account
from app.models.identity import Person


@dataclass(frozen=True)
class MatchEvidence:
    rule: str           # email | alias | sso_subject | fuzzy
    confidence: str     # high | medium
    evidence: dict[str, Any]


# --- Rule 1: primary work email (exact, case-insensitive) -----------------


def match_primary_email(person: Person, account: Account) -> MatchEvidence | None:
    if not person.work_email or not account.email:
        return None
    if person.work_email.lower() == account.email.lower():
        return MatchEvidence(
            rule="email",
            confidence="high",
            evidence={
                "matched_field": "work_email",
                "value": person.work_email.lower(),
            },
        )
    return None


# --- Rule 2: secondary email / alias --------------------------------------


def match_alias(person: Person, account: Account) -> MatchEvidence | None:
    person_emails = set(person.all_emails())
    account_emails = set(account.all_emails())
    overlap = person_emails & account_emails
    if not overlap:
        return None
    # Skip if the only overlap is the primary email — that's rule 1's job.
    if person.work_email and account.email and person.work_email.lower() == account.email.lower():
        if overlap == {person.work_email.lower()}:
            return None
    matched = next(iter(overlap))
    return MatchEvidence(
        rule="alias",
        confidence="high",
        evidence={
            "matched_field": "alias",
            "value": matched,
            "person_emails": sorted(person_emails),
            "account_emails": sorted(account_emails),
        },
    )


# --- Rule 3: SSO subject / external_id ------------------------------------


def match_sso_subject(person: Person, account: Account) -> MatchEvidence | None:
    if not person.sso_subject or not account.sso_subject:
        return None
    if person.sso_subject == account.sso_subject:
        return MatchEvidence(
            rule="sso_subject",
            confidence="high",
            evidence={"matched_field": "sso_subject", "value": person.sso_subject},
        )
    return None


# --- Rule 4: fuzzy name + domain (only with single candidate) -------------


def _local_and_domain(email: str) -> tuple[str, str] | None:
    if not email or "@" not in email:
        return None
    local, _, domain = email.partition("@")
    return local.lower(), domain.lower()


def fuzzy_score(person: Person, account: Account) -> tuple[int, int] | None:
    """Returns (name_distance, local_distance) if both fields are present.

    Lower is better. Used by the engine to filter candidates BEFORE
    deciding whether to apply the rule (which requires single-candidate).
    """
    if not account.display_name or not person.display_name:
        return None
    name_dist = Levenshtein.distance(
        person.display_name.strip().lower(),
        account.display_name.strip().lower(),
    )
    local_dist = 99
    p = _local_and_domain(person.work_email or "")
    a = _local_and_domain(account.email or "")
    if p and a and p[1] == a[1]:
        local_dist = Levenshtein.distance(p[0], a[0])
    else:
        return None  # different domain → not a fuzzy candidate at all
    return name_dist, local_dist


def match_fuzzy(person: Person, account: Account) -> MatchEvidence | None:
    """Used by the engine ONLY when this is the unique candidate."""
    s = fuzzy_score(person, account)
    if s is None:
        return None
    name_dist, local_dist = s
    if local_dist > 2:
        return None
    if name_dist > 8:  # generous; engine filters single-candidate
        return None
    return MatchEvidence(
        rule="fuzzy",
        confidence="medium",
        evidence={
            "matched_field": "name+domain",
            "name_distance": name_dist,
            "local_distance": local_dist,
            "person_name": person.display_name,
            "account_name": account.display_name,
            "person_email": person.work_email,
            "account_email": account.email,
        },
    )
