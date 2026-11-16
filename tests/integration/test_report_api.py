"""Tests for /triage, /report, /asset/wallet, and /scan/code auth and permissions.

Analysis endpoints need a Bearer token. LLM paths are disabled, so use_llm is always rejected.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from sqlalchemy.orm import sessionmaker

from bluestrix.core.database import Base, create_db_engine
from bluestrix.core import models_db  # noqa: F401
from bluestrix.core.models_db import User

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

JWT_SECRET = "unit-test-jwt-secret-not-for-prod"


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("BLUESTRIX_JWT_SECRET", JWT_SECRET)
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
        "version: '8.0'\nmode: defensive\npolicy:\n  fail_secure: true\nscope:\n  default_action: allow\n  authorized_targets:\n    repository_paths: ['./']\n",
        encoding="utf-8",
    )
    from bluestrix.integrations.api import create_app
    from bluestrix.core import database as dbmod

    app = create_app(str(config_path))
    app.dependency_overrides[dbmod.get_db] = _override_get_db
    app.state.test_session = TestSession
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
    engine.dispose()


def _auth(client: TestClient, role: str) -> dict[str, str]:
    from bluestrix.core.auth import create_session
    from bluestrix.core.security import hash_password

    db = client.app.state.test_session()
    try:
        user = User(
            email=f"{role}-{uuid.uuid4().hex[:8]}@example.com",
            password_hash=hash_password("correct-horse-battery-staple"),
            role=role,
            is_active=True,
            mfa_enabled=False,
            mfa_recovery_hashes=[],
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        pair = create_session(db, user)
        return {"Authorization": f"Bearer {pair.access_token}"}
    finally:
        db.close()


def test_triage_local(client: TestClient):
    res = client.post(
        "/triage",
        headers=_auth(client, "security_analyst"),
        json={
            "findings": [
                {"finding_id": "1", "severity": "HIGH", "title": "oracle deviation", "category": "oracle"}
            ]
        },
    )
    assert res.status_code == 200
    assert res.json()["auto_actions"] == []
    assert res.json()["items"][0]["priority"] <= 2


def test_llm_triage_disabled_even_with_flag(client: TestClient):
    res = client.post(
        "/triage",
        headers=_auth(client, "admin"),
        json={
            "findings": [{"finding_id": "1", "severity": "LOW"}],
            "use_llm": True,
            "human_approved": True,
        },
    )
    assert res.status_code == 403


def test_report_endpoint(client: TestClient):
    res = client.post(
        "/report",
        headers=_auth(client, "security_analyst"),
        json={
            "title": "Unit Report",
            "findings": [
                {"finding_id": "1", "severity": "MEDIUM", "title": "n", "description": "d"}
            ],
        },
    )
    assert res.status_code == 200
    body = res.json()
    assert "executive_summary" in body
    assert "remediation_plan" in body
    assert body["auto_actions"] == []


def test_llm_report_disabled_even_with_flag(client: TestClient):
    res = client.post(
        "/report",
        headers=_auth(client, "admin"),
        json={"title": "t", "findings": [], "use_llm": True, "human_approved": True},
    )
    assert res.status_code == 403


def test_analysis_endpoints_require_token(client: TestClient):
    assert client.post("/triage", json={"findings": []}).status_code == 401
    assert client.post("/report", json={"title": "t", "findings": []}).status_code == 401
    assert client.post("/asset/wallet", json={"address": "0x0", "chain": "evm"}).status_code == 401
    assert client.post("/scan/code", json={"path": "./src"}).status_code == 401


def test_scan_code_needs_view_scans(client: TestClient):
    owner = _auth(client, "protocol_owner")
    res = client.post("/scan/code", headers=owner, json={"path": "./src"})
    assert res.status_code == 403
