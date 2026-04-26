"""Auth DTOs."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, EmailStr, Field

from app.schemas.common import ORMModel


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshRequest(BaseModel):
    refresh_token: str


class UserOut(ORMModel):
    id: str
    workspace_id: str
    email: str
    role: Literal["viewer", "analyst", "admin"]
    is_active: bool
    last_login_at: datetime | None = None
    created_at: datetime


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    role: Literal["viewer", "analyst", "admin"] = "analyst"
    expires_at: datetime | None = None


class ApiKeyCreated(BaseModel):
    """Returned ONCE on creation. Includes the full plaintext key."""

    id: str
    name: str
    prefix: str
    role: Literal["viewer", "analyst", "admin"]
    key: str = Field(description="The full key. Shown ONCE — store it now.")
    expires_at: datetime | None = None


class ApiKeyOut(ORMModel):
    id: str
    workspace_id: str
    name: str
    prefix: str
    role: Literal["viewer", "analyst", "admin"]
    last_used_at: datetime | None = None
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
    created_at: datetime
