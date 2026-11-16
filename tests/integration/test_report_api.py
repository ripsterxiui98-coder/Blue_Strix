from pathlib import Path

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path: Path):
    config_path = tmp_path / "bluestrix.yaml"
    config_path.write_text(
        "version: '8.0'\nmode: defensive\npolicy:\n  fail_secure: true\nscope:\n  default_action: allow\n  authorized_targets:\n    repository_paths: ['./']\n",
        encoding="utf-8",
    )
    from bluestrix.integrations.api import create_app

    app = create_app(str(config_path))
    with TestClient(app) as c:
        yield c


def test_triage_local(client: TestClient):
    res = client.post(
        "/triage",
        json={
            "findings": [
                {"finding_id": "1", "severity": "HIGH", "title": "oracle deviation", "category": "oracle"}
            ]
        },
    )
    assert res.status_code == 200
    assert res.json()["auto_actions"] == []
    assert res.json()["items"][0]["priority"] <= 2


def test_llm_blocked_without_approval(client: TestClient):
    res = client.post(
        "/triage",
        json={"findings": [{"finding_id": "1", "severity": "LOW"}], "use_llm": True},
    )
    assert res.status_code == 403


def test_report_endpoint(client: TestClient):
    res = client.post(
        "/report",
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
