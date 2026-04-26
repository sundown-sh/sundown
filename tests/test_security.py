"""Security primitives: passwords, JWT, API keys, AEAD, webhook signing."""
from __future__ import annotations

import time

import pytest

from app.security import (
    API_KEY_PREFIX,
    create_access_token,
    decode_token,
    decrypt_blob,
    encrypt_blob,
    generate_api_key,
    hash_password,
    sign_webhook_payload,
    verify_api_key,
    verify_password,
    verify_webhook_signature,
)


def test_password_hash_roundtrip() -> None:
    h = hash_password("hunter2")
    assert verify_password("hunter2", h)
    assert not verify_password("hunter3", h)


def test_jwt_roundtrip_and_claims() -> None:
    tok = create_access_token("alice@acme.com", role="analyst", workspace_id="default")
    decoded = decode_token(tok)
    assert decoded["sub"] == "alice@acme.com"
    assert decoded["role"] == "analyst"
    assert decoded["ws"] == "default"
    assert decoded["typ"] == "access"


def test_api_key_format_and_verify() -> None:
    full, prefix, hashed = generate_api_key()
    assert full.startswith(API_KEY_PREFIX)
    assert prefix.startswith(API_KEY_PREFIX)
    assert len(prefix) == len(API_KEY_PREFIX) + 8
    assert verify_api_key(full, hashed)
    assert not verify_api_key("sdn_BOGUS", hashed)
    assert not verify_api_key("not-prefixed", hashed)


def test_aead_blob_roundtrip_and_tamper_detection() -> None:
    plaintext = b'{"api_key":"secret-value"}'
    blob = encrypt_blob(plaintext)
    assert blob != plaintext
    assert decrypt_blob(blob) == plaintext

    # Flip a byte in the ciphertext → decryption must fail.
    tampered = bytearray(blob)
    tampered[-1] ^= 0xFF
    with pytest.raises(Exception):
        decrypt_blob(bytes(tampered))


def test_aead_uses_fresh_nonce_per_encryption() -> None:
    """Two encryptions of the same plaintext must NOT match."""
    a = encrypt_blob(b"same")
    b = encrypt_blob(b"same")
    assert a != b


def test_webhook_signature_roundtrip_and_replay_window() -> None:
    secret = "whsec_test"
    body = b'{"event":"ghost.opened"}'
    ts = int(time.time())
    sig = sign_webhook_payload(body, secret=secret, timestamp=ts)
    assert verify_webhook_signature(body, sig, secret=secret)
    # Tampered body fails
    assert not verify_webhook_signature(b'{"x":1}', sig, secret=secret)
    # Old timestamp rejected
    old = sign_webhook_payload(body, secret=secret, timestamp=ts - 999)
    assert not verify_webhook_signature(body, old, secret=secret, max_age_s=60)
