"""Auth-hardening tests: password strength, lockout, throttle, jti revocation.

These guard the OSS auth path. SSO/SAML lives in the commercial tier;
this file makes sure the local-auth path we ship is not trivially
brute-forceable, and that "log out" really does log you out.
"""
from __future__ import annotations

from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient

from app.config import get_settings
from app.db import session_scope
from app.models.user import User
from app.security import (
    PasswordTooWeakError,
    hash_password,
    validate_password_strength,
)
from app.security_throttle import (
    LOGIN_ACCOUNT_THROTTLE,
    LOGIN_IP_THROTTLE,
    InMemoryThrottle,
)

# --- password strength validator -----------------------------------------


def test_validate_password_strength_too_short() -> None:
    with pytest.raises(PasswordTooWeakError, match="at least 12"):
        validate_password_strength("Short1!")


def test_validate_password_strength_not_enough_classes() -> None:
    # 12 chars but only one class
    with pytest.raises(PasswordTooWeakError, match="3\\+"):
        validate_password_strength("aaaaaaaaaaaa")
    # 12 chars, two classes (lower + digit)
    with pytest.raises(PasswordTooWeakError, match="3\\+"):
        validate_password_strength("aaaaaa111111")


def test_validate_password_strength_blocklist() -> None:
    # Each must be >= 12 chars and have 3 character classes so they make
    # it past the earlier checks before the blocklist check fires.
    with pytest.raises(PasswordTooWeakError, match="blocklist"):
        validate_password_strength("Password1234")
    with pytest.raises(PasswordTooWeakError, match="blocklist"):
        validate_password_strength("ChangeMe1234")
    with pytest.raises(PasswordTooWeakError, match="blocklist"):
        validate_password_strength("ChangeMe!123")


def test_validate_password_strength_accepts_strong_password() -> None:
    # Should not raise — three classes, length OK, not blocklisted.
    validate_password_strength("Sundown-IsRead0nly!")
    validate_password_strength("Tr0ub4dor&3-staple")


# --- in-memory throttle --------------------------------------------------


def test_throttle_allows_then_blocks() -> None:
    t = InMemoryThrottle(max_attempts=3, window_seconds=60)
    assert t.allow("ip-1") is True
    assert t.allow("ip-1") is True
    assert t.allow("ip-1") is True
    assert t.allow("ip-1") is False
    # Different key still allowed.
    assert t.allow("ip-2") is True


def test_throttle_reset() -> None:
    t = InMemoryThrottle(max_attempts=2, window_seconds=60)
    t.allow("k")
    t.allow("k")
    assert t.allow("k") is False
    t.reset("k")
    assert t.allow("k") is True


# --- login flow integration ----------------------------------------------


@pytest.fixture
def auth_app() -> Generator[TestClient, None, None]:
    """Test app with one user and clean throttle/lockout state."""
    LOGIN_IP_THROTTLE.reset("testclient")
    LOGIN_IP_THROTTLE.reset("unknown")
    LOGIN_ACCOUNT_THROTTLE.reset("alice@example.com")

    from app.main import create_app

    settings = get_settings()
    with session_scope() as db:
        db.add(
            User(
                workspace_id=settings.default_workspace,
                email="alice@example.com",
                password_hash=hash_password("CorrectHorse-Battery9"),
                role="admin",
                is_active=True,
            )
        )

    yield TestClient(create_app())

    LOGIN_IP_THROTTLE.reset("testclient")
    LOGIN_IP_THROTTLE.reset("unknown")
    LOGIN_ACCOUNT_THROTTLE.reset("alice@example.com")


def test_login_success_sets_httponly_cookie(auth_app: TestClient) -> None:
    r = auth_app.post(
        "/api/v1/auth/login",
        json={"email": "alice@example.com", "password": "CorrectHorse-Battery9"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["access_token"]
    assert body["refresh_token"]

    # Cookie set by the server, not by JS.
    set_cookie = r.headers.get("set-cookie", "")
    assert "sundown_token=" in set_cookie
    assert "HttpOnly" in set_cookie
    assert "SameSite=lax" in set_cookie or "SameSite=Lax" in set_cookie


def test_login_lockout_after_threshold(auth_app: TestClient) -> None:
    """5 wrong passwords => 423 Locked. Even a correct password after
    that returns 423 until the cooldown elapses."""
    for _ in range(5):
        r = auth_app.post(
            "/api/v1/auth/login",
            json={"email": "alice@example.com", "password": "wrong-but-long-enough-1!"},
        )
        assert r.status_code == 401, r.text

    r = auth_app.post(
        "/api/v1/auth/login",
        json={"email": "alice@example.com", "password": "CorrectHorse-Battery9"},
    )
    assert r.status_code == 423
    assert "locked" in r.json()["detail"].lower()


def test_login_lockout_persists_in_db(auth_app: TestClient) -> None:
    for _ in range(5):
        auth_app.post(
            "/api/v1/auth/login",
            json={"email": "alice@example.com", "password": "wrong-but-long-enough-1!"},
        )

    with session_scope() as db:
        u = db.query(User).filter(User.email == "alice@example.com").one()
        assert u.failed_login_count >= 5
        assert u.locked_until is not None


def test_login_unknown_user_does_not_leak(auth_app: TestClient) -> None:
    r = auth_app.post(
        "/api/v1/auth/login",
        json={"email": "nobody@example.com", "password": "whatever-12-chars!"},
    )
    assert r.status_code == 401
    # Same generic message as a wrong-password attempt.
    assert r.json()["detail"] == "invalid credentials"


def test_login_ip_throttle_returns_429() -> None:
    """Burst of failed logins from the same IP eventually 429s."""
    LOGIN_IP_THROTTLE.reset("testclient")

    from app.main import create_app

    settings = get_settings()
    with session_scope() as db:
        db.add(
            User(
                workspace_id=settings.default_workspace,
                email="bob@example.com",
                password_hash=hash_password("Strong-Pass-123!"),
                role="admin",
                is_active=True,
            )
        )

    client = TestClient(create_app())
    statuses: list[int] = []
    for _ in range(15):
        r = client.post(
            "/api/v1/auth/login",
            json={"email": "ghost@example.com", "password": "wrong-pass-1234!"},
        )
        statuses.append(r.status_code)

    # The 11th+ attempt within the 60s window should 429.
    assert 429 in statuses, statuses
    LOGIN_IP_THROTTLE.reset("testclient")


# --- refresh token revocation -------------------------------------------


def test_logout_revokes_refresh_token(auth_app: TestClient) -> None:
    r = auth_app.post(
        "/api/v1/auth/login",
        json={"email": "alice@example.com", "password": "CorrectHorse-Battery9"},
    )
    assert r.status_code == 200
    tokens = r.json()
    refresh = tokens["refresh_token"]
    access = tokens["access_token"]

    # Refresh works initially
    r2 = auth_app.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
    assert r2.status_code == 200, r2.text
    new_refresh = r2.json()["refresh_token"]

    # Log out using the most recent refresh token
    r3 = auth_app.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {access}"},
        json={"refresh_token": new_refresh},
    )
    assert r3.status_code == 204, r3.text

    # That same refresh token must now be rejected.
    r4 = auth_app.post("/api/v1/auth/refresh", json={"refresh_token": new_refresh})
    assert r4.status_code == 401
    assert "revoked" in r4.json()["detail"].lower()


def test_ui_logout_revokes_refresh_token(auth_app: TestClient) -> None:
    """The UI sign-out button hits ``/ui/logout`` directly. It must
    revoke the refresh token just like the API endpoint."""
    r = auth_app.post(
        "/api/v1/auth/login",
        json={"email": "alice@example.com", "password": "CorrectHorse-Battery9"},
    )
    refresh = r.json()["refresh_token"]
    access = r.json()["access_token"]

    r2 = auth_app.post(
        "/ui/logout",
        headers={"Authorization": f"Bearer {access}"},
        json={"refresh_token": refresh},
    )
    assert r2.status_code == 204

    r3 = auth_app.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
    assert r3.status_code == 401
