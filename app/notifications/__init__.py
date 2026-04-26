"""Notifications: Slack, email, signed webhooks."""
from app.notifications.dispatch import (  # noqa: F401
    notify_daily_digest,
    notify_new_critical_ghost,
)
