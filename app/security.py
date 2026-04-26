"""JWT, password hashing, API keys, and at-rest encryption.

The same `SUNDOWN_SECRET_KEY` is the root for:
  * JWT signing (HS256)
  * AES-GCM AEAD for `Integration.config_encrypted` (via HKDF-SHA256)

Connector secrets are encrypted at rest. We never log decrypted blobs.
"""
from __future__ import annotations

import base64
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

import bcrypt
import jwt
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.config import get_settings

# --- Passwords -------------------------------------------------------------
#
# bcrypt is the standard. We use it directly (passlib has been
# unmaintained since 2020 and is incompatible with bcrypt 5.x).
#
# bcrypt has a 72-byte input limit. To support long secrets (in
# particular our API keys) we pre-hash with SHA-256 before passing to
# bcrypt — the standard "double-hash" workaround.


def _prep(secret: str) -> bytes:
    import hashlib

    return hashlib.sha256(secret.encode("utf-8")).digest()


def hash_password(password: str) -> str:
    digest = _prep(password)
    return bcrypt.hashpw(digest, bcrypt.gensalt()).decode("ascii")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(_prep(password), hashed.encode("ascii"))
    except Exception:
        return False


# --- JWT -------------------------------------------------------------------

_JWT_ALG = "HS256"


def create_access_token(
    subject: str,
    *,
    role: str,
    workspace_id: str,
    extra: dict[str, Any] | None = None,
    ttl_minutes: int | None = None,
) -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    ttl = ttl_minutes if ttl_minutes is not None else settings.jwt_ttl_minutes
    payload: dict[str, Any] = {
        "sub": subject,
        "role": role,
        "ws": workspace_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ttl)).timestamp()),
        "typ": "access",
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.secret_key, algorithm=_JWT_ALG)


def create_refresh_token(subject: str, *, workspace_id: str) -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    payload = {
        "sub": subject,
        "ws": workspace_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(days=settings.refresh_ttl_days)).timestamp()),
        "typ": "refresh",
    }
    return jwt.encode(payload, settings.secret_key, algorithm=_JWT_ALG)


def decode_token(token: str) -> dict[str, Any]:
    settings = get_settings()
    return jwt.decode(token, settings.secret_key, algorithms=[_JWT_ALG])


# --- API keys --------------------------------------------------------------

API_KEY_PREFIX = "sdn_"
API_KEY_RANDOM_LEN = 32  # base32 chars => 160 bits


def generate_api_key() -> tuple[str, str, str]:
    """Return (full_key, prefix_for_display, hash_for_storage).

    Full key looks like ``sdn_AB12CD34EF56...`` (32 base32 chars).
    Only ever return the full key once, at creation.
    """
    raw = secrets.token_bytes(20)  # 160 bits
    body = base64.b32encode(raw).decode("ascii").rstrip("=")
    full = f"{API_KEY_PREFIX}{body}"
    prefix_display = full[: len(API_KEY_PREFIX) + 8]  # sdn_AB12CD34
    return full, prefix_display, hash_password(full)


def verify_api_key(full_key: str, hashed: str) -> bool:
    if not full_key.startswith(API_KEY_PREFIX):
        return False
    return verify_password(full_key, hashed)


# --- AEAD encryption for connector secrets --------------------------------

_AAD = b"sundown.integration.config.v1"
_NONCE_LEN = 12  # AES-GCM standard


def _derive_key(secret: str, salt: bytes, info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    ).derive(secret.encode("utf-8"))


def encrypt_blob(plaintext: bytes, *, info: bytes = _AAD) -> bytes:
    """Encrypts and prepends a 16-byte salt + 12-byte nonce.

    Layout: [salt(16) | nonce(12) | ciphertext+tag]
    """
    settings = get_settings()
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(_NONCE_LEN)
    key = _derive_key(settings.secret_key, salt, info)
    aead = AESGCM(key)
    ct = aead.encrypt(nonce, plaintext, _AAD)
    return salt + nonce + ct


def decrypt_blob(blob: bytes, *, info: bytes = _AAD) -> bytes:
    settings = get_settings()
    salt, rest = blob[:16], blob[16:]
    nonce, ct = rest[:_NONCE_LEN], rest[_NONCE_LEN:]
    key = _derive_key(settings.secret_key, salt, info)
    aead = AESGCM(key)
    return aead.decrypt(nonce, ct, _AAD)


# --- Outbound webhook signing ---------------------------------------------

def sign_webhook_payload(body: bytes, *, secret: str, timestamp: int) -> str:
    """Returns the value for the ``X-Sundown-Signature`` header.

    Format: ``t=<unix>,v1=<hex(hmac_sha256(secret, t.body))>``
    Replay-protect on the receiving end by rejecting requests where
    ``|now - t| > 300``.
    """
    payload = f"{timestamp}.".encode("ascii") + body
    h = hmac.HMAC(secret.encode("utf-8"), hashes.SHA256())
    h.update(payload)
    sig = h.finalize().hex()
    return f"t={timestamp},v1={sig}"


def verify_webhook_signature(
    body: bytes, header: str, *, secret: str, max_age_s: int = 300
) -> bool:
    try:
        parts = dict(p.split("=", 1) for p in header.split(","))
        ts = int(parts["t"])
        provided = parts["v1"]
    except Exception:
        return False
    now = int(datetime.now(UTC).timestamp())
    if abs(now - ts) > max_age_s:
        return False
    payload = f"{ts}.".encode("ascii") + body
    h = hmac.HMAC(secret.encode("utf-8"), hashes.SHA256())
    h.update(payload)
    expected = h.finalize().hex()
    return secrets.compare_digest(expected, provided)
