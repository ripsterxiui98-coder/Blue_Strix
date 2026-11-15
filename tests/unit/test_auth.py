"""Unit tests for password hashing, JWT, MFA, rate limit."""

from __future__ import annotations

import pytest
from sqlalchemy.orm import sessionmaker

from bluestrix.core.auth import authenticate_user, create_session, decode_token, revoke_session
from bluestrix.core.database import Base, create_db_engine
from bluestrix.core.mfa import encrypt_secret, decrypt_secret, generate_totp_secret, verify_totp, _totp
from bluestrix.core.models_db import User
from bluestrix.core.rate_limit import check_rate_limit
from bluestrix.core.security import hash_password, verify_password, hash_token


@pytest.fixture()
def db():
    engine = create_db_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    s = Session()
    yield s
    s.close()
    engine.dispose()


def test_password_hash_roundtrip():
    h = hash_password("correct-horse-battery")
    assert h != "correct-horse-battery"
    assert verify_password("correct-horse-battery", h)
    assert not verify_password("wrong", h)


def test_token_hash_not_reversible():
    t = "secret-token-value"
    assert hash_token(t) != t
    assert len(hash_token(t)) == 64


def test_mfa_encrypt_decrypt():
    secret = generate_totp_secret()
    blob = encrypt_secret(secret)
    assert blob != secret
    assert decrypt_secret(blob) == secret


def test_totp_verify():
    secret = generate_totp_secret()
    code = _totp(secret)
    assert verify_totp(secret, code)


def test_rate_limit():
    key = "test:unique:limit"
    for _ in range(5):
        ok, _ = check_rate_limit(key, limit=5, window_seconds=60)
        assert ok
    ok, retry = check_rate_limit(key, limit=5, window_seconds=60)
    assert not ok
    assert retry >= 1


def test_session_create_and_decode(db):
    user = User(
        email="analyst@example.com",
        password_hash=hash_password("strong-password-1"),
        role="security_analyst",
        is_active=True,
        mfa_recovery_hashes=[],
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    pair = create_session(db, user)
    claims = decode_token(pair.access_token)
    assert claims["email"] == "analyst@example.com"
    assert claims["role"] == "security_analyst"
    assert authenticate_user(db, "analyst@example.com", "strong-password-1") is not None
    assert authenticate_user(db, "analyst@example.com", "nope") is None
    assert revoke_session(db, pair.session_id)
