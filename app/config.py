"""Application configuration.

Single source of truth for env-driven config. Read once at startup via
`get_settings()`.
"""
from __future__ import annotations

import contextlib
import os
import secrets
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _bootstrap_secret_key() -> str:
    """Auto-generate and persist a secret key for zero-config first runs.

    Only used when ``SUNDOWN_SECRET_KEY`` is unset and ``SUNDOWN_ENV`` is not
    ``production``. The key is written under the data dir so it survives
    container restarts mounted on a volume. In production, an unset secret
    key is a hard failure (see ``_require_secret_in_prod``).
    """
    data_dir = Path(os.environ.get("SUNDOWN_DATA_DIR", "./data"))
    data_dir.mkdir(parents=True, exist_ok=True)
    key_path = data_dir / ".secret_key"
    if key_path.exists():
        return key_path.read_text(encoding="utf-8").strip()
    key = secrets.token_urlsafe(48)
    key_path.write_text(key, encoding="utf-8")
    with contextlib.suppress(OSError):
        os.chmod(key_path, 0o600)
    return key


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Core ---
    env: Literal["development", "production", "test"] = Field(
        "development", alias="SUNDOWN_ENV"
    )
    log_level: str = Field("INFO", alias="SUNDOWN_LOG_LEVEL")
    host: str = Field("0.0.0.0", alias="SUNDOWN_HOST")
    port: int = Field(8000, alias="SUNDOWN_PORT")

    # --- Database ---
    database_url: str = Field("sqlite:///./data/sundown.db", alias="DATABASE_URL")

    # --- Auth / crypto ---
    secret_key: str = Field(default="", alias="SUNDOWN_SECRET_KEY")
    # 8h is a reasonable default for a self-hosted admin/audit tool: long
    # enough to cover a working day without re-auth, short enough that a
    # stolen token does not become a permanent foothold. Refresh extends.
    jwt_ttl_minutes: int = Field(480, alias="SUNDOWN_JWT_TTL_MINUTES")
    refresh_ttl_days: int = Field(14, alias="SUNDOWN_REFRESH_TTL_DAYS")

    # --- Bootstrap admin ---
    bootstrap_admin_email: str = Field(
        "admin@example.com", alias="SUNDOWN_BOOTSTRAP_ADMIN_EMAIL"
    )
    bootstrap_admin_password: str = Field("", alias="SUNDOWN_BOOTSTRAP_ADMIN_PASSWORD")

    # --- Scanning ---
    scan_interval_minutes: int = Field(60, alias="SUNDOWN_SCAN_INTERVAL_MINUTES")
    digest_hour_utc: int = Field(14, alias="SUNDOWN_DIGEST_HOUR_UTC")

    # --- Notifications ---
    slack_webhook_url: str = Field("", alias="SUNDOWN_SLACK_WEBHOOK_URL")
    notify_email_from: str = Field("", alias="SUNDOWN_NOTIFY_EMAIL_FROM")
    smtp_host: str = Field("", alias="SUNDOWN_SMTP_HOST")
    smtp_port: int = Field(587, alias="SUNDOWN_SMTP_PORT")
    smtp_username: str = Field("", alias="SUNDOWN_SMTP_USERNAME")
    smtp_password: str = Field("", alias="SUNDOWN_SMTP_PASSWORD")
    outbound_webhook_url: str = Field("", alias="SUNDOWN_OUTBOUND_WEBHOOK_URL")
    outbound_webhook_secret: str = Field("", alias="SUNDOWN_OUTBOUND_WEBHOOK_SECRET")

    # --- Multi-tenant seam ---
    default_workspace: str = Field("default", alias="SUNDOWN_DEFAULT_WORKSPACE")

    # --- Feature flags ---
    feature_flags: str = Field("", alias="SUNDOWN_FEATURE_FLAGS")

    # --- Paths ---
    data_dir: Path = Field(Path("./data"))
    reports_dir: Path = Field(Path("./reports/output"))

    @model_validator(mode="after")
    def _resolve_secret(self) -> Settings:
        if self.secret_key:
            if len(self.secret_key) < 16:
                raise ValueError("SUNDOWN_SECRET_KEY must be at least 16 characters")
            return self
        if self.env == "production":
            raise ValueError(
                "SUNDOWN_SECRET_KEY is required when SUNDOWN_ENV=production. "
                "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(48))\""
            )
        # dev / test: auto-bootstrap a persisted key
        object.__setattr__(self, "secret_key", _bootstrap_secret_key())
        return self

    @field_validator("log_level")
    @classmethod
    def _log_level_upper(cls, v: str) -> str:
        return v.upper()

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")

    @property
    def feature_flag_set(self) -> set[str]:
        return {f.strip() for f in self.feature_flags.split(",") if f.strip()}

    def has_feature(self, flag: str) -> bool:
        """Feature flags are opt-in; default off unless listed."""
        return flag in self.feature_flag_set

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    """Test-only: clear the lru_cache so env changes take effect."""
    get_settings.cache_clear()
