"""High-level notification dispatchers.

Two events are emitted:

  * ``notify_daily_digest(stats)`` — once a day, summary of open ghosts.
  * ``notify_new_critical_ghost(ghost_summary)`` — realtime alert.

Each event fans out to whichever sinks are configured: Slack incoming
webhook, SMTP email, and a generic outbound webhook (HMAC-signed).
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

import httpx

from app.config import get_settings
from app.logging_config import get_logger
from app.security import sign_webhook_payload

log = get_logger(__name__)


@dataclass
class GhostSummary:
    id: str
    person_email: str
    connector: str
    severity: str
    days_since_termination: int


# --- entry points ---------------------------------------------------------


async def notify_new_critical_ghost(ghost: GhostSummary) -> None:
    settings = get_settings()
    text = (
        f":fire_engine: *New critical ghost*: `{ghost.person_email}` is still active "
        f"in *{ghost.connector}* — {ghost.days_since_termination} days since "
        f"termination."
    )
    payload = {
        "event": "ghost.critical",
        "ghost": {
            "id": ghost.id,
            "person_email": ghost.person_email,
            "connector": ghost.connector,
            "severity": ghost.severity,
            "days_since_termination": ghost.days_since_termination,
        },
    }
    await _post_slack(settings.slack_webhook_url, text)
    await _post_webhook(settings.outbound_webhook_url, settings.outbound_webhook_secret, payload)


async def notify_daily_digest(
    open_count: int,
    critical: int,
    high: int,
    medium: int,
    *,
    base_url: str = "",
) -> None:
    settings = get_settings()
    if open_count == 0:
        text = ":sun_with_face: *Sundown*: no open ghosts. Nice and tidy."
    else:
        text = (
            f":sun_behind_small_cloud: *Sundown daily digest*\n"
            f"• Open ghosts: *{open_count}*\n"
            f"• Critical (>7d): *{critical}*  •  High (24h–7d): *{high}*  •  Medium (<24h): *{medium}*\n"
        )
        if base_url:
            text += f"<{base_url.rstrip('/')}/ghosts|Open in Sundown>"
    payload = {
        "event": "digest.daily",
        "open_count": open_count,
        "by_severity": {"critical": critical, "high": high, "medium": medium},
    }
    await _post_slack(settings.slack_webhook_url, text)
    await _post_webhook(settings.outbound_webhook_url, settings.outbound_webhook_secret, payload)


# --- transports -----------------------------------------------------------


async def _post_slack(webhook_url: str, text: str) -> None:
    if not webhook_url:
        return
    try:
        async with httpx.AsyncClient(timeout=10.0) as cli:
            await cli.post(webhook_url, json={"text": text})
    except Exception as e:
        log.warning("slack.post.failed", error=str(e))


async def _post_webhook(url: str, secret: str, payload: dict[str, Any]) -> None:
    if not url:
        return
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if secret:
        sig = sign_webhook_payload(body, secret=secret, timestamp=int(time.time()))
        headers["X-Sundown-Signature"] = sig
    try:
        async with httpx.AsyncClient(timeout=10.0) as cli:
            await cli.post(url, content=body, headers=headers)
    except Exception as e:
        log.warning("webhook.post.failed", url=url, error=str(e))
