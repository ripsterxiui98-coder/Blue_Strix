"""API-level tests for findings and remediation endpoints (SQLite, no live Postgres required).

Write endpoints require a Bearer access token. These tests mint real tokens through the same
session code the login route uses, so the auth path is exercised end to end.
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

    # Minimal config so create_app can load
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


def _auth(client: TestClient, role: str):
    """Create a user with ``role`` and return (headers, session_id) for a real access token."""
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
        return {"Authorization": f"Bearer {pair.access_token}"}, pair.session_id
    finally:
        db.close()


def test_health(client: TestClient) -> None:
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_findings_empty(client: TestClient) -> None:
    resp = client.get("/findings")
    assert resp.status_code == 200
    assert resp.json()["count"] == 0


def test_write_requires_bearer_token(client: TestClient) -> None:
    resp = client.patch("/findings/missing/status", json={"status": "fixed"})
    assert resp.status_code == 401


def test_write_rejects_malformed_token(client: TestClient) -> None:
    resp = client.patch(
        "/findings/missing/status",
        headers={"Authorization": "Bearer not-a-real-token"},
        json={"status": "fixed"},
    )
    assert resp.status_code == 401


def test_operator_header_is_not_identity(client: TestClient) -> None:
    """A client-supplied operator header must not grant or change identity."""
    resp = client.patch(
        "/findings/missing/status",
        headers={"X-BlueStrix-Operator": "admin"},
        json={"status": "fixed"},
    )
    assert resp.status_code == 401


def test_revoked_session_is_rejected(client: TestClient) -> None:
    from bluestrix.core.auth import revoke_session

    headers, session_id = _auth(client, "security_analyst")
    db = client.app.state.test_session()
    try:
        revoke_session(db, session_id)
    finally:
        db.close()
    resp = client.patch("/findings/missing/status", headers=headers, json={"status": "fixed"})
    assert resp.status_code == 401


def test_status_update_needs_permission(client: TestClient) -> None:
    headers, _ = _auth(client, "incident_responder")
    resp = client.patch("/findings/missing/status", headers=headers, json={"status": "fixed"})
    assert resp.status_code == 403


def test_status_update_unknown_finding_is_404_for_analyst(client: TestClient) -> None:
    headers, _ = _auth(client, "security_analyst")
    resp = client.patch("/findings/missing/status", headers=headers, json={"status": "fixed"})
    assert resp.status_code == 404


def test_incident_responder_cannot_propose(client: TestClient) -> None:
    headers, _ = _auth(client, "incident_responder")
    resp = client.post(
        "/remediation/proposals",
        headers=headers,
        json={"finding_id": "BSX-X", "title": "t", "target": "./src", "proposed_change": "c"},
    )
    assert resp.status_code == 403


def test_analyst_cannot_approve(client: TestClient) -> None:
    headers, _ = _auth(client, "security_analyst")
    resp = client.post(
        "/remediation/approvals",
        headers=headers,
        json={"finding_id": "BSX-X", "status": "approved"},
    )
    assert resp.status_code == 403


def test_remediation_flow(client: TestClient) -> None:
    analyst, _ = _auth(client, "security_analyst")
    owner, _ = _auth(client, "protocol_owner")

    create = client.post(
        "/remediation/proposals",
        headers=analyst,
        json={
            "finding_id": "BSX-API-1",
            "title": "Fix pattern",
            "target": "./src",
            "proposed_change": "refactor",
        },
    )
    assert create.status_code == 200
    proposal_id = create.json()["id"]

    listed = client.get("/remediation/proposals")
    assert listed.status_code == 200
    assert listed.json()["count"] >= 1

    approval = client.post(
        "/remediation/approvals",
        headers={**owner, "X-BlueStrix-Approval-Token": "test-token-not-stored-plaintext"},
        json={"finding_id": "BSX-API-1", "proposal_id": proposal_id, "status": "approved"},
    )
    assert approval.status_code == 200
    assert approval.json()["token_stored"] == "hash_only"

    audit = client.get("/audit")
    assert audit.status_code == 200
    assert audit.json()["count"] >= 1
