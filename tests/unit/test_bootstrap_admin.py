"""Tests for server-side admin MFA bootstrap (SQLite, no network)."""

from __future__ import annotations

import pytest
from sqlalchemy.orm import sessionmaker

from bluestrix.core import models_db  # noqa: F401
from bluestrix.core.bootstrap import bootstrap_admin_mfa, build_otpauth_uri
from bluestrix.core.database import Base, create_db_engine
from bluestrix.core.exceptions import BlueStrixError
from bluestrix.core.mfa import _totp, decrypt_secret, verify_totp
from bluestrix.core.models_db import User
from bluestrix.core.security import hash_password


@pytest.fixture()
def db(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("BLUESTRIX_JWT_SECRET", "unit-test-jwt-secret-not-for-prod")
    engine = create_db_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, autoflush=False, autocommit=False)()
    yield session
    session.close()
    engine.dispose()


def _user(db, email: str, role: str, mfa_enabled: bool = False) -> None:
    db.add(
        User(
            email=email,
            password_hash=hash_password("correct-horse-battery-staple"),
            role=role,
            is_active=True,
            mfa_enabled=mfa_enabled,
            mfa_recovery_hashes=[],
        )
    )
    db.commit()


def test_bootstrap_issues_working_totp_for_admin(db) -> None:
    _user(db, "owner@example.com", "admin")
    out = bootstrap_admin_mfa(db, "owner@example.com")

    stored = db.query(User).filter_by(email="owner@example.com").one()
    assert stored.mfa_enabled is True
    # Secret is stored encrypted, never in plaintext.
    assert stored.mfa_secret_encrypted != out["totp_secret"]
    assert decrypt_secret(stored.mfa_secret_encrypted) == out["totp_secret"]
    # The printed secret actually verifies a code the authenticator would produce.
    assert verify_totp(out["totp_secret"], _totp(out["totp_secret"]))
    assert len(out["recovery_codes"]) == 8
    assert "otpauth://totp/" in out["otpauth_uri"]


def test_bootstrap_rejects_non_admin(db) -> None:
    _user(db, "analyst@example.com", "security_analyst")
    with pytest.raises(BlueStrixError, match="admin"):
        bootstrap_admin_mfa(db, "analyst@example.com")


def test_bootstrap_rejects_unknown_email(db) -> None:
    with pytest.raises(BlueStrixError, match="no user"):
        bootstrap_admin_mfa(db, "nobody@example.com")


def test_bootstrap_refuses_overwrite_without_force(db) -> None:
    _user(db, "owner@example.com", "admin", mfa_enabled=True)
    with pytest.raises(BlueStrixError, match="already enabled"):
        bootstrap_admin_mfa(db, "owner@example.com")


def test_bootstrap_force_resets_secret(db) -> None:
    _user(db, "owner@example.com", "admin", mfa_enabled=True)
    first = bootstrap_admin_mfa(db, "owner@example.com", force=True)
    second = bootstrap_admin_mfa(db, "owner@example.com", force=True)
    assert first["totp_secret"] != second["totp_secret"]


def test_otpauth_uri_encodes_label() -> None:
    uri = build_otpauth_uri("a b@example.com", "SECRET")
    assert "secret=SECRET" in uri
    assert "BlueStrix%3Aa%20b%40example.com" in uri
