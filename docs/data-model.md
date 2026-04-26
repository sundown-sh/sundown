# Data model

This document is the source of truth for Sundown's domain model. Every
table carries a `workspace_id` (defaulted to `"default"` in OSS) and
audit columns (`created_at`, `updated_at`) so the same schema can power
the hosted multi-tenant version with no migrations.

## Entity overview

```
              ┌────────────┐                        ┌────────────┐
              │   Person   │                        │  Account   │
              │  (HRIS)    │  ─── Match (1..N) ───► │  (dest.)   │
              └────────────┘                        └────────────┘
                    │                                     │
                    └───── Ghost (1..1 per match) ────────┘
                                     │
                              ┌──────┴──────┐
                              │   Report    │
                              └─────────────┘

   Integration ──► owns ──► Account / Person rows
   AuditEvent  ──► records every read or write Sundown performs
   User / ApiKey ──► access-control principals
```

## Core entities

### `Person`  *(an employee, current or former, from HRIS)*

| Field                | Type      | Notes                                       |
| -------------------- | --------- | ------------------------------------------- |
| `id`                 | UUID      | PK                                          |
| `workspace_id`       | str       | `"default"` in OSS                          |
| `integration_id`     | UUID FK   | The HRIS integration that supplied them     |
| `external_id`        | str       | Provider's stable employee ID               |
| `employee_number`    | str?      | Optional human-readable                     |
| `display_name`       | str       |                                             |
| `work_email`         | str       | Lowercased; **unique within workspace**     |
| `secondary_emails`   | str[]     | Aliases / personal                          |
| `sso_subject`        | str?      | If HRIS surfaces it (e.g. Okta sub)         |
| `status`             | enum      | `active` \| `terminated`                    |
| `start_date`         | date?     |                                             |
| `termination_date`   | date?     | Required if `status == terminated`          |
| `raw`                | JSONB     | Verbatim HRIS payload, redacted             |
| `first_seen_at`      | timestamp |                                             |
| `last_seen_at`       | timestamp | Updated each successful sync                |

```python
# pydantic
class Person(BaseModel):
    id: UUID
    workspace_id: str = "default"
    integration_id: UUID
    external_id: str
    employee_number: str | None
    display_name: str
    work_email: EmailStr
    secondary_emails: list[EmailStr] = []
    sso_subject: str | None = None
    status: Literal["active", "terminated"]
    start_date: date | None = None
    termination_date: date | None = None
    raw: dict[str, Any] = {}
    first_seen_at: datetime
    last_seen_at: datetime
```

### `Account`  *(an account on a destination system)*

| Field                | Type      | Notes                                       |
| -------------------- | --------- | ------------------------------------------- |
| `id`                 | UUID      | PK                                          |
| `workspace_id`       | str       |                                             |
| `integration_id`     | UUID FK   | The destination integration                 |
| `external_id`        | str       | Provider's stable account ID                |
| `username`           | str?      | login / handle                              |
| `display_name`       | str?      |                                             |
| `email`              | str?      | Lowercased                                  |
| `aliases`            | str[]     | Email aliases the destination exposes       |
| `sso_subject`        | str?      |                                             |
| `status`             | enum      | `active` \| `suspended` \| `deprovisioned`  |
| `last_login_at`      | timestamp?| If destination exposes it                   |
| `created_at_remote`  | timestamp?| When the account was created upstream       |
| `raw`                | JSONB     | Verbatim destination payload, redacted      |
| `first_seen_at`      | timestamp |                                             |
| `last_seen_at`       | timestamp |                                             |

### `Match`  *(intermediate join produced by the matching engine)*

Stored so that re-running the engine is idempotent and we can show the
historical reason a ghost was flagged.

| Field             | Type    | Notes                                          |
| ----------------- | ------- | ---------------------------------------------- |
| `id`              | UUID    |                                                |
| `workspace_id`    | str     |                                                |
| `person_id`       | UUID FK |                                                |
| `account_id`      | UUID FK |                                                |
| `rule`            | enum    | `email` \| `alias` \| `sso_subject` \| `fuzzy` |
| `confidence`      | enum    | `high` \| `medium`                             |
| `evidence`        | JSONB   | e.g. `{"matched_field": "work_email", ...}`    |
| `created_at`      | ts      |                                                |

### `Ghost`  *(a person × account match where the person is terminated)*

This is the report row. There is at most one `Ghost` per
`(person_id, account_id)` tuple.

| Field                       | Type      | Notes                                |
| --------------------------- | --------- | ------------------------------------ |
| `id`                        | UUID      |                                      |
| `workspace_id`              | str       |                                      |
| `person_id`                 | UUID FK   |                                      |
| `account_id`                | UUID FK   |                                      |
| `match_id`                  | UUID FK   | The matching evidence                |
| `severity`                  | enum      | `critical` \| `high` \| `medium`     |
| `days_since_termination`    | int       | Snapshotted at scan time             |
| `state`                     | enum      | `open` \| `acknowledged` \| `false_positive` \| `suppressed` \| `resolved` |
| `acknowledged_by_user_id`   | UUID FK?  |                                      |
| `acknowledged_at`           | timestamp?|                                      |
| `notes`                     | text?     |                                      |
| `first_seen_at`             | timestamp |                                      |
| `last_seen_at`              | timestamp |                                      |

**Severity rule**:
```
days_since_termination > 7  → critical
24h <= ... <= 7d            → high
< 24h                       → medium
```

**State transitions**:
```
open ──► acknowledged ──► resolved
  │           │
  ├──► false_positive (won't re-open on next scan)
  └──► suppressed     (snoozed for N days)
```

### `Integration`  *(a configured connector instance)*

| Field             | Type    | Notes                                              |
| ----------------- | ------- | -------------------------------------------------- |
| `id`              | UUID    |                                                    |
| `workspace_id`    | str     |                                                    |
| `connector`       | str     | `"bamboohr"`, `"okta"`, ...                        |
| `kind`            | enum    | `hris` \| `destination`                            |
| `tier`            | enum    | `core` \| `premium`                                |
| `display_name`    | str     | "Acme Corp BambooHR (prod)"                        |
| `enabled`         | bool    |                                                    |
| `config_encrypted`| bytes   | AEAD blob; **never returned in API responses**     |
| `last_sync_at`    | ts?     |                                                    |
| `last_sync_status`| enum    | `success` \| `error` \| `running`                  |
| `last_sync_error` | text?   |                                                    |
| `feature_flags`   | str[]   | per-integration flags                              |

### `Report`  *(a generated evidence pack)*

| Field          | Type    | Notes                                       |
| -------------- | ------- | ------------------------------------------- |
| `id`           | UUID    |                                             |
| `workspace_id` | str     |                                             |
| `kind`         | enum    | `json` \| `csv` \| `html` \| `pdf`          |
| `scope`        | JSONB   | filters used to produce it                  |
| `ghost_count`  | int     |                                             |
| `path`         | str     | local path under `reports/output/`          |
| `sha256`       | str     | content hash (for evidence integrity)       |
| `generated_by_user_id` | UUID FK |                                       |
| `generated_at` | ts      |                                             |

### `AuditEvent`  *(every action Sundown takes)*

Append-only. Each row's `prev_hash` chains to the previous row's `hash`,
making tampering detectable. SOC 2 / ISO 27001 evidence-export ready.

| Field          | Type    | Notes                                       |
| -------------- | ------- | ------------------------------------------- |
| `id`           | UUID    |                                             |
| `workspace_id` | str     |                                             |
| `actor_type`   | enum    | `user` \| `api_key` \| `system`             |
| `actor_id`     | str     |                                             |
| `action`       | str     | `"integration.create"`, `"ghost.ack"`, ...  |
| `target_type`  | str?    | `"integration"`, `"ghost"`, ...             |
| `target_id`    | str?    |                                             |
| `payload`      | JSONB   | small, redacted                             |
| `ip`           | str?    |                                             |
| `user_agent`   | str?    |                                             |
| `prev_hash`    | str     | sha256 of prior row                         |
| `hash`         | str     | sha256 over (prev_hash + canonical payload) |
| `at`           | ts      |                                             |

### `User`  *(local human users)*

| Field             | Type | Notes                                          |
| ----------------- | ---- | ---------------------------------------------- |
| `id`              | UUID |                                                |
| `workspace_id`    | str  |                                                |
| `email`           | str  | unique within workspace                        |
| `password_hash`   | str  | bcrypt                                         |
| `role`            | enum | `viewer` \| `analyst` \| `admin`               |
| `is_active`       | bool |                                                |
| `created_at`      | ts   |                                                |

### `ApiKey`

| Field             | Type | Notes                                          |
| ----------------- | ---- | ---------------------------------------------- |
| `id`              | UUID |                                                |
| `workspace_id`    | str  |                                                |
| `name`            | str  |                                                |
| `prefix`          | str  | first 8 chars of key, shown in UI              |
| `hash`            | str  | bcrypt of full key                             |
| `role`            | enum | `viewer` \| `analyst` \| `admin`               |
| `created_by_user_id` | UUID FK |                                          |
| `last_used_at`    | ts?  |                                                |
| `expires_at`      | ts?  |                                                |
| `revoked_at`      | ts?  |                                                |

API keys look like: `sdn_<32-char-base32>`. The full key is only
returned once, at creation; we store its bcrypt hash.

## Why we model `Match` and `Ghost` separately

Three reasons:

1. **Explainability.** A ghost row knows *which* of the four rules
   produced it, even after the rule chain changes.
2. **Idempotency.** Re-running the engine UPSERTs matches; ghosts are
   then derived from `Match × Person.status == terminated`.
3. **State machine.** A ghost has lifecycle (`acknowledged`,
   `false_positive`, etc.); a match is just evidence.

## Multi-tenant seam

Every table has `workspace_id`. In OSS it's always `"default"`. The
hosted version flips a feature flag to wire request-scoped tenants and
adds row-level security policies in Postgres — no schema changes
required.

## Encryption

`Integration.config_encrypted` uses AES-GCM (via the `cryptography`
package) with a key derived from `SUNDOWN_SECRET_KEY` via HKDF-SHA256.
Rotating the secret re-encrypts existing rows on next write.
