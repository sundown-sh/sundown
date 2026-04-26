"""Connector framework.

Defines the abstract base every connector subclasses, the shared dataclasses
returned to the rest of the app (so the matching engine never sees provider
DTOs), the rate-limiting + retry transport, and a small fixture-recording
hook used in tests.

The contract every connector implements:

  * ``healthcheck() -> bool``                        — auth + connectivity
  * ``fetch_terminated_employees(since) -> AsyncIterator[Employee]``  (HRIS)
  * ``fetch_active_principals(since) -> AsyncIterator[Principal]``    (dest)
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import date, datetime
from enum import Enum
from pathlib import Path
from typing import Any, ClassVar

import httpx
from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential_jitter,
)

from app.logging_config import get_logger

log = get_logger(__name__)


# --- Enums -----------------------------------------------------------------


class ConnectorKind(str, Enum):
    HRIS = "hris"
    DESTINATION = "destination"


class ConnectorTier(str, Enum):
    CORE = "core"        # Apache 2.0 / OSS
    PREMIUM = "premium"  # hosted only — never set in this repo


# --- Domain dataclasses ----------------------------------------------------


@dataclass
class Employee:
    """An HRIS employee record. Connectors return these from
    ``fetch_terminated_employees``.

    All fields except ``external_id`` and ``display_name`` are optional;
    the matching engine will use whatever's present.
    """

    external_id: str
    display_name: str
    work_email: str | None = None
    secondary_emails: list[str] = field(default_factory=list)
    sso_subject: str | None = None
    employee_number: str | None = None
    status: str = "terminated"  # connectors filter; default reflects the call
    start_date: date | None = None
    termination_date: date | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class Principal:
    """An active account on a destination system."""

    external_id: str
    username: str | None = None
    display_name: str | None = None
    email: str | None = None
    aliases: list[str] = field(default_factory=list)
    sso_subject: str | None = None
    status: str = "active"
    last_login_at: datetime | None = None
    created_at_remote: datetime | None = None
    raw: dict[str, Any] = field(default_factory=dict)


# --- Auth strategies -------------------------------------------------------


class AuthStrategy(ABC):
    """Pluggable auth: API key, OAuth client-credentials, GitHub App JWT, ..."""

    @abstractmethod
    async def apply(self, request: httpx.Request) -> None:
        ...


class StaticBearerAuth(AuthStrategy):
    def __init__(self, token: str) -> None:
        self._token = token

    async def apply(self, request: httpx.Request) -> None:
        request.headers["Authorization"] = f"Bearer {self._token}"


class BasicAuth(AuthStrategy):
    def __init__(self, username: str, password: str = "x") -> None:
        import base64
        creds = base64.b64encode(f"{username}:{password}".encode()).decode()
        self._header = f"Basic {creds}"

    async def apply(self, request: httpx.Request) -> None:
        request.headers["Authorization"] = self._header


# --- Token-bucket rate limiter --------------------------------------------


class _TokenBucket:
    """Simple async token bucket. Refills continuously at ``rate``/sec."""

    def __init__(self, rate_per_sec: float, capacity: float | None = None) -> None:
        self._rate = max(rate_per_sec, 0.001)
        self._capacity = capacity if capacity is not None else max(rate_per_sec, 1.0)
        self._tokens = self._capacity
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, n: float = 1.0) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                self._tokens = min(self._capacity, self._tokens + (now - self._last) * self._rate)
                self._last = now
                if self._tokens >= n:
                    self._tokens -= n
                    return
                deficit = n - self._tokens
                await asyncio.sleep(deficit / self._rate)


# --- Fixture recorder/replayer --------------------------------------------


def _fixture_path(connector: str, request: httpx.Request) -> Path:
    """Stable filename for a request → response fixture."""
    method = request.method.lower()
    url = str(request.url)
    safe = (
        url.replace("https://", "")
        .replace("http://", "")
        .replace("/", "_")
        .replace("?", "_q_")
        .replace("&", "_a_")
        .replace("=", "_e_")
        .replace(":", "_c_")
    )[:200]
    base = Path(__file__).resolve().parent.parent.parent / "tests" / "fixtures" / connector
    return base / f"{method}__{safe}.json"


class FixtureMode(str, Enum):
    OFF = "off"
    RECORD = "record"
    REPLAY = "replay"


def fixture_mode_from_env() -> FixtureMode:
    val = os.environ.get("SUNDOWN_FIXTURES", "").lower()
    if val == "record":
        return FixtureMode.RECORD
    if val == "replay":
        return FixtureMode.REPLAY
    return FixtureMode.OFF


# --- BaseConnector --------------------------------------------------------


class ConnectorError(Exception):
    """Base class for connector failures."""


class ConfigError(ConnectorError):
    """The Integration row has invalid/missing config."""


class TransientError(ConnectorError):
    """Retryable: 429, 5xx, network blips."""


class AuthError(ConnectorError):
    """Auth failed and won't be fixed by a retry."""


class BaseConnector(ABC):
    """Subclass and use ``@register`` to plug into Sundown.

    Subclasses MUST set ``name``, ``kind``, and (optionally) ``tier``.
    Subclasses MAY set ``rate_limit_per_minute`` (defaults conservatively).
    """

    name: ClassVar[str]
    kind: ClassVar[ConnectorKind]
    tier: ClassVar[ConnectorTier] = ConnectorTier.CORE
    rate_limit_per_minute: ClassVar[int] = 60  # conservative default
    timeout_s: ClassVar[float] = 30.0

    #: list of {key, label, secret, optional} dicts describing the config
    #: shape this connector needs. Used by the UI to render the form.
    config_schema: ClassVar[list[dict[str, Any]]] = []

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self._http: httpx.AsyncClient | None = None
        self._bucket = _TokenBucket(rate_per_sec=self.rate_limit_per_minute / 60.0)
        self._fixture_mode = fixture_mode_from_env()

    # --- abstract API --------------------------------------------------

    @abstractmethod
    async def healthcheck(self) -> bool:
        ...

    async def fetch_terminated_employees(
        self, since: datetime | None = None
    ) -> AsyncIterator[Employee]:
        if self.kind != ConnectorKind.HRIS:
            raise NotImplementedError(f"{self.name} is not an HRIS connector")
        raise NotImplementedError
        yield  # pragma: no cover  -- make this an async generator

    async def fetch_active_principals(
        self, since: datetime | None = None
    ) -> AsyncIterator[Principal]:
        if self.kind != ConnectorKind.DESTINATION:
            raise NotImplementedError(f"{self.name} is not a destination connector")
        raise NotImplementedError
        yield  # pragma: no cover

    # --- HTTP helpers --------------------------------------------------

    @property
    def http(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=self.timeout_s, follow_redirects=True)
        return self._http

    async def aclose(self) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    async def __aenter__(self) -> BaseConnector:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.aclose()

    def auth(self) -> AuthStrategy | None:
        """Override in subclasses that need auth."""
        return None

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Single rate-limited, retried, optionally-replayed HTTP call."""
        await self._bucket.acquire()

        request = self.http.build_request(
            method, url, params=params, json=json_body, headers=headers
        )
        auth = self.auth()
        if auth is not None:
            await auth.apply(request)

        if self._fixture_mode is FixtureMode.REPLAY:
            return self._replay(request)

        async for attempt in AsyncRetrying(
            stop=stop_after_attempt(5),
            wait=wait_exponential_jitter(initial=0.5, max=15.0),
            retry=retry_if_exception_type((TransientError, httpx.TransportError)),
            reraise=True,
        ):
            with attempt:
                resp = await self.http.send(request)
                if resp.status_code == 429 or resp.status_code >= 500:
                    log.warning(
                        "connector.transient",
                        connector=self.name,
                        status=resp.status_code,
                        url=str(request.url),
                    )
                    raise TransientError(f"{resp.status_code} on {request.url}")
                if resp.status_code in (401, 403):
                    raise AuthError(f"{resp.status_code} on {request.url}")

                if self._fixture_mode is FixtureMode.RECORD:
                    self._record(request, resp)

                return resp

        raise ConnectorError("retries exhausted")  # pragma: no cover  (reraise=True)

    # --- fixtures ------------------------------------------------------

    def _record(self, request: httpx.Request, response: httpx.Response) -> None:
        path = _fixture_path(self.name, request)
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            body: Any = response.json()
        except Exception:
            body = {"_text": response.text}
        path.write_text(
            json.dumps(
                {
                    "request": {
                        "method": request.method,
                        "url": str(request.url),
                    },
                    "response": {
                        "status_code": response.status_code,
                        "headers": dict(response.headers),
                        "json": body,
                    },
                },
                indent=2,
                default=str,
            )
        )
        log.info("fixture.recorded", connector=self.name, path=str(path))

    def _replay(self, request: httpx.Request) -> httpx.Response:
        path = _fixture_path(self.name, request)
        if not path.exists():
            raise ConnectorError(
                f"no fixture for {request.method} {request.url} at {path}"
            )
        data = json.loads(path.read_text())
        return httpx.Response(
            status_code=data["response"]["status_code"],
            headers=data["response"].get("headers", {}),
            content=json.dumps(data["response"]["json"]).encode(),
            request=request,
        )

    # --- pagination helper --------------------------------------------

    async def paginate(
        self,
        first_url: str,
        *,
        params: dict[str, Any] | None = None,
        items_key: str | None = None,
        next_link_header: str = "link",
        next_url_fn: Any = None,
    ) -> AsyncIterator[Any]:
        """Generic paginator.

        Use whichever knobs apply to the provider:

        * ``next_url_fn(resp_json) -> str | None`` for body-link APIs.
        * ``next_link_header`` for RFC-5988 ``Link: <url>; rel="next"`` APIs.
        * ``items_key`` to dig into a nested list (e.g. ``"members"``).
        """
        url: str | None = first_url
        cur_params = params
        while url:
            resp = await self.request("GET", url, params=cur_params)
            data: Any = resp.json()
            items: Any = data
            if items_key is not None and isinstance(data, dict):
                items = data.get(items_key, [])
            if isinstance(items, list):
                for item in items:
                    yield item

            cur_params = None  # only on first page

            next_url: str | None = None
            if next_url_fn is not None:
                next_url = next_url_fn(data)
            else:
                link = resp.headers.get(next_link_header) or resp.headers.get("Link")
                if link:
                    next_url = _parse_next_link(link)
            url = next_url


def _parse_next_link(link_header: str) -> str | None:
    """Parse RFC-5988 ``Link`` header for rel=next."""
    for part in link_header.split(","):
        section = part.split(";")
        if len(section) < 2:
            continue
        url_part = section[0].strip().strip("<>").strip()
        for p in section[1:]:
            if 'rel="next"' in p.replace("'", '"'):
                return url_part
    return None
