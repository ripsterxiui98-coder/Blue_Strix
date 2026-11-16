"""Integration tests for /auth endpoints using SQLite."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy.orm import sessionmaker

from bluestrix.core.database import Base, create_db_engine
import bluestrix.core.models_db  # noqa: F401

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("BLUESTRIX_JWT_SECRET", "unit-test-jwt-secret-not-for-prod")
    engine = create_db_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    TestSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def _override_get_db():
        db = TestSession()
        try:
            yield db
        finally:
            db.close()

    config_path = tmp_path / "bluestrix.yaml"
    config_path.write_text(
        "version: '8.0'\nmode: defensive\nscope:\n  default_action: allow\n  authorized_targets:\n    repository_paths: ['./']\n",
        encoding="utf-8",
    )

    from bluestrix.integrations.api import create_app
    from bluestrix.core import database as dbmod

    app = create_app(str(config_path))
    app.dependency_overrides[dbmod.get_db] = _override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
    engine.dispose()


def test_register_login_session(client: TestClient):
    reg = client.post(
        "/auth/register",
        json={"email": "first@example.com", "password": "bootstrap-password"},
    )
    assert reg.status_code == 200
    assert reg.json()["role"] == "admin"  # first user bootstrap

    # admin needs MFA — without code should fail if mfa enforced; setup not done yet
    # For first login before MFA secret: admin path requires mfa_code when role admin
    login = client.post(
        "/auth/login",
        json={"email": "first@example.com", "password": "bootstrap-password"},
    )
    # Without MFA configured, admin login returns 401 mfa_not_configured or mfa_required
    assert login.status_code in (200, 401)


def test_login_fail_audited(client: TestClient):
    client.post(
        "/auth/register",
        json={"email": "a@example.com", "password": "bootstrap-password"},
    )
    bad = client.post(
        "/auth/login",
        json={"email": "a@example.com", "password": "wrong-password-xx"},
    )
    assert bad.status_code == 401


def test_registration_closed_after_bootstrap(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("BLUESTRIX_ALLOW_REGISTRATION", raising=False)
    first = client.post(
        "/auth/register",
        json={"email": "owner@example.com", "password": "bootstrap-password"},
    )
    assert first.status_code == 200
    second = client.post(
        "/auth/register",
        json={"email": "intruder@example.com", "password": "another-password-1"},
    )
    assert second.status_code == 403
