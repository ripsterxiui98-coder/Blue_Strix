"""API-level tests for findings endpoints (SQLite, no live Postgres required)."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy.orm import sessionmaker

from bluestrix.core.database import Base, create_db_engine
from bluestrix.core import models_db  # noqa: F401

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
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


def test_health(client: TestClient) -> None:
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_findings_empty(client: TestClient) -> None:
    resp = client.get("/findings")
    assert resp.status_code == 200
    assert resp.json()["count"] == 0


def test_write_requires_operator(client: TestClient) -> None:
    resp = client.patch("/findings/missing/status", json={"status": "fixed"})
    assert resp.status_code == 401


def test_remediation_flow(client: TestClient) -> None:
    headers = {
        "X-BlueStrix-Operator": "security_analyst",
        "X-BlueStrix-Approval-Token": "test-token-not-stored-plaintext",
    }
    # seed via repository through a proposal that does not need existing finding
    create = client.post(
        "/remediation/proposals",
        headers=headers,
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
        headers=headers,
        json={"finding_id": "BSX-API-1", "proposal_id": proposal_id, "status": "approved"},
    )
    assert approval.status_code == 200
    assert approval.json()["token_stored"] == "hash_only"

    audit = client.get("/audit")
    assert audit.status_code == 200
    assert audit.json()["count"] >= 1
