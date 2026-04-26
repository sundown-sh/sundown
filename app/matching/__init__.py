"""Matching engine: cross-reference HRIS people against destination accounts.

Rule chain (in order, first match wins):
    1. ``email``       — primary work email (case-insensitive exact)
    2. ``alias``       — any HRIS secondary email / alias matches account email or alias
    3. ``sso_subject`` — HRIS SSO subject equals account.sso_subject
    4. ``fuzzy``       — fuzzy name + email-domain match (Lev <= 2 on local-part);
                          only fires when destination exposes a name and there
                          is exactly one candidate.

Every match records the rule + evidence so the UI can explain *why*.
"""
from app.matching.engine import MatchingEngine, run_match  # noqa: F401
