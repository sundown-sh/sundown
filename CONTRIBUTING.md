# Contributing to Sundown

Thanks for considering a contribution. Sundown is intentionally small and
focused; the bar for new features is high, but the bar for **new
connectors**, **bug fixes**, and **docs** is low. Open a PR.

---

## Local development

```bash
git clone https://github.com/sundown-sh/sundown.git
cd sundown
python -m venv .venv && source .venv/bin/activate    # or .venv\Scripts\activate
pip install -e '.[dev]'
cp .env.example .env
alembic upgrade head
uvicorn app.main:app --reload
```

Run the checks the same way CI does:

```bash
ruff check app tests
mypy app
pytest
```

## Project layout

```
app/
  main.py            FastAPI application + lifespan
  config.py          pydantic-settings, env-driven
  db.py              SQLAlchemy 2.x engine + session
  security.py        JWT, password hashing, API keys, encryption
  audit.py           append-only audit log writer
  logging_config.py  structlog setup
  models/            ORM models
  schemas/           Pydantic v2 DTOs
  api/               routers (one file per resource)
  integrations/
    base.py          BaseConnector interface
    registry.py      connector discovery + factory
    hris/            BambooHR, Rippling
    idp/             Okta, Google Workspace
    saas/            GitHub, Slack
  matching/          ordered rule chain
  reports/           JSON/CSV/HTML/PDF renderers
  scheduler/         APScheduler jobs
  templates/         Jinja2 + HTMX, Tailwind via CDN
tests/
  fixtures/          recorded provider responses (no live calls in CI)
scripts/seed.py
alembic/
```

## Writing a connector

A connector is one file in `app/integrations/{hris,idp,saas}/<name>.py`.
It subclasses `BaseConnector` and implements three methods:

```python
from app.integrations.base import BaseConnector, ConnectorKind, register

@register
class AcmeConnector(BaseConnector):
    name = "acme"
    kind = ConnectorKind.DESTINATION   # or HRIS
    tier = "core"                      # "core" (OSS) or "premium" (hosted)
    rate_limit_per_minute = 70         # 70% of provider's limit

    async def healthcheck(self) -> bool:
        ...

    async def fetch_active_principals(self, since=None):
        # destinations only
        yield Principal(...)

    async def fetch_terminated_employees(self, since=None):
        # HRIS only
        yield Employee(...)
```

The framework handles:

- **Rate limiting** at 70% of the documented limit (configure via
  `rate_limit_per_minute`).
- **Exponential-backoff retries** on 429/5xx.
- **Pagination** via `httpx_paginated()`.
- **Auth refresh** via the `Auth` strategy on the connector.

### Recorded fixtures

Every connector ships with a fixture set under
`tests/fixtures/<connector>/`. To add one:

1. Run a one-off integration test against the real provider with
   `SUNDOWN_RECORD_FIXTURES=1` set.
2. The HTTP transport will save the responses under
   `tests/fixtures/<connector>/`.
3. Commit them. CI replays them via `respx`; **no live calls** in CI.

### Conventions

- **Read-only scopes only.** PRs that request write scopes will not be
  merged.
- **Pure async.** Use `httpx.AsyncClient` (provided as `self.http`).
- **Stable identifiers.** `external_id` should be the provider's most
  permanent ID (Okta `id`, GitHub `node_id`, Slack `id`), not the email.
- **No PII in logs.** Use `log.bind(account_id=...)`, not the email.

### Tier: core vs premium

All v1 connectors are **core** (Apache 2.0, OSS). The `tier` field on
the registry exists so the hosted commercial version can ship `premium`
connectors without forking. **OSS contributors should always set
`tier = "core"`.**

## Tests

- Unit tests next to the code they test.
- Connector integration tests live in `tests/integrations/<name>/` and
  use `respx` to replay fixtures.
- Run a single test: `pytest tests/integrations/okta -k list_users -x`
- Coverage target: **80%+** for matching engine, connectors, and report
  renderers. The UI layer is covered by smoke tests.

## Commit style

Conventional commits (`feat:`, `fix:`, `docs:`, `chore:`, `refactor:`,
`test:`). Keep commits scoped — one connector per commit, one
matching-rule change per commit.

## Security disclosures

Please do **not** open a public issue. Email **security@sundown.sh**
with details and we'll respond within 72 hours.

## Code of conduct

Be kind. Assume good faith. The full Contributor Covenant applies.
