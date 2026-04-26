"""Background jobs.

Two periodic jobs:

  * **scan**     — every ``SUNDOWN_SCAN_INTERVAL_MINUTES``: sync every
                   enabled integration, then run the matching engine,
                   then fire ``notify_new_critical_ghost`` for any
                   newly-opened critical ghost.
  * **digest**   — every day at ``SUNDOWN_DIGEST_HOUR_UTC``: send the
                   daily Slack/email digest.

We use APScheduler's AsyncIOScheduler so jobs share the FastAPI event
loop. Each job runs inside its own DB session.
"""
from __future__ import annotations

from datetime import UTC, datetime

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import select

from app.audit import SYSTEM_ACTOR, record
from app.config import get_settings
from app.db import session_scope
from app.integrations.sync import sync_one
from app.logging_config import get_logger
from app.matching.engine import run_match
from app.models.ghost import Ghost
from app.models.integration import Integration
from app.notifications import notify_daily_digest, notify_new_critical_ghost
from app.notifications.dispatch import GhostSummary

log = get_logger(__name__)


async def scan_job() -> None:
    """Sync every enabled integration, then re-run matching, then notify."""
    settings = get_settings()
    log.info("job.scan.start")

    new_critical_ids: list[str] = []

    with session_scope() as db:
        integrations = list(
            db.execute(
                select(Integration).where(
                    Integration.workspace_id == settings.default_workspace,
                    Integration.enabled.is_(True),
                )
            ).scalars()
        )
        for integ in integrations:
            try:
                await sync_one(db, integ)
            except Exception as e:
                log.exception("job.scan.integration.failed", connector=integ.connector, error=str(e))

        before_critical = {
            g.id
            for g in db.execute(
                select(Ghost).where(
                    Ghost.workspace_id == settings.default_workspace,
                    Ghost.severity == "critical",
                    Ghost.state == "open",
                )
            ).scalars()
        }

        run_match(db, workspace_id=settings.default_workspace)

        after = list(
            db.execute(
                select(Ghost).where(
                    Ghost.workspace_id == settings.default_workspace,
                    Ghost.severity == "critical",
                    Ghost.state == "open",
                )
            ).scalars()
        )

        # Hydrate the ones that weren't critical+open before (or didn't exist).
        for g in after:
            if g.id in before_critical:
                continue
            from app.models.account import Account
            from app.models.identity import Person

            person = db.get(Person, g.person_id)
            account = db.get(Account, g.account_id)
            if not person or not account:
                continue
            integ_row = db.get(Integration, account.integration_id)
            new_critical_ids.append(g.id)
            await notify_new_critical_ghost(
                GhostSummary(
                    id=g.id,
                    person_email=person.work_email,
                    connector=integ_row.connector if integ_row else "?",
                    severity=g.severity,
                    days_since_termination=g.days_since_termination,
                )
            )

        record(
            db,
            actor=SYSTEM_ACTOR,
            action="scheduler.scan",
            payload={
                "integrations": len(integrations),
                "new_critical": len(new_critical_ids),
            },
        )

    log.info("job.scan.done", new_critical=len(new_critical_ids))


async def digest_job() -> None:
    settings = get_settings()
    log.info("job.digest.start")
    with session_scope() as db:
        ghosts = list(
            db.execute(
                select(Ghost).where(
                    Ghost.workspace_id == settings.default_workspace,
                    Ghost.state.in_(("open", "acknowledged", "suppressed")),
                )
            ).scalars()
        )
        critical = sum(1 for g in ghosts if g.severity == "critical")
        high = sum(1 for g in ghosts if g.severity == "high")
        medium = sum(1 for g in ghosts if g.severity == "medium")

        record(
            db,
            actor=SYSTEM_ACTOR,
            action="scheduler.digest",
            payload={"open_count": len(ghosts), "critical": critical, "high": high, "medium": medium},
        )

    await notify_daily_digest(
        len(ghosts),
        critical,
        high,
        medium,
        base_url="",
    )
    log.info("job.digest.done", open=len(ghosts))


def build_scheduler() -> AsyncIOScheduler:
    settings = get_settings()
    scheduler = AsyncIOScheduler(timezone="UTC")
    scheduler.add_job(
        scan_job,
        IntervalTrigger(minutes=settings.scan_interval_minutes),
        id="scan",
        next_run_time=datetime.now(UTC),
        coalesce=True,
        max_instances=1,
        misfire_grace_time=300,
    )
    scheduler.add_job(
        digest_job,
        CronTrigger(hour=settings.digest_hour_utc, minute=0),
        id="digest",
        coalesce=True,
        max_instances=1,
        misfire_grace_time=600,
    )
    return scheduler
