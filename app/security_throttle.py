"""In-memory sliding-window throttle for the login endpoint.

We deliberately keep this in-process rather than backing it with Redis or
a database table:

* The OSS edition is a single-process app that must run from one ``docker
  run``. Adding Redis would violate the 30-second time-to-value promise.
* Login throttling is a defense-in-depth control. The persistent control
  is the per-user lockout in the ``user`` table (5 failures => 15-min
  lock). Even if a process restart wipes this throttle, lockout stops
  the realistic offline-style attack.
* Resetting on restart actually helps legitimate operators — if you
  somehow trip the throttle by typoing your password 10 times, you can
  ``docker restart sundown`` and try again.

If a future deployment runs multiple replicas (commercial tier), it
should swap this module for a Redis-backed implementation behind the
same ``allow()`` / ``reset()`` API.
"""
from __future__ import annotations

from collections import deque
from threading import Lock
from time import monotonic


class InMemoryThrottle:
    """Sliding window. Each ``allow(key)`` call records the attempt."""

    def __init__(self, *, max_attempts: int, window_seconds: int) -> None:
        if max_attempts <= 0 or window_seconds <= 0:
            raise ValueError("max_attempts and window_seconds must be positive")
        self._max = max_attempts
        self._window = window_seconds
        self._buckets: dict[str, deque[float]] = {}
        self._lock = Lock()

    def allow(self, key: str) -> bool:
        """Record an attempt for ``key`` and return whether it is allowed."""
        now = monotonic()
        cutoff = now - self._window
        with self._lock:
            dq = self._buckets.setdefault(key, deque())
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= self._max:
                return False
            dq.append(now)
            return True

    def remaining(self, key: str) -> int:
        """Best-effort: how many attempts are left in the current window."""
        now = monotonic()
        cutoff = now - self._window
        with self._lock:
            dq = self._buckets.get(key)
            if dq is None:
                return self._max
            while dq and dq[0] < cutoff:
                dq.popleft()
            return max(0, self._max - len(dq))

    def reset(self, key: str) -> None:
        with self._lock:
            self._buckets.pop(key, None)


# Module-level singletons. Keep the limits conservative: a real human
# typing their password wrong is not going to hit 10 in 60s. A scripted
# brute-forcer hits this on the first burst.
LOGIN_IP_THROTTLE = InMemoryThrottle(max_attempts=10, window_seconds=60)

# Per-account throttle (in addition to per-IP) catches credential
# stuffing where the attacker rotates IPs but targets one email.
LOGIN_ACCOUNT_THROTTLE = InMemoryThrottle(max_attempts=10, window_seconds=300)


__all__ = [
    "LOGIN_ACCOUNT_THROTTLE",
    "LOGIN_IP_THROTTLE",
    "InMemoryThrottle",
]
