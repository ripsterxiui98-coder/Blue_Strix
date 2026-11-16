from pathlib import Path

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path: Path):
    config_path = tmp_path / "bluestrix.yaml"
    config_path.write_text(
        "version: '8.0'\nmode: defensive\nscope:\n  default_action: allow\n  authorized_targets:\n    repository_paths: ['./']\n",
        encoding="utf-8",
    )
    from bluestrix.integrations.api import create_app

    app = create_app(str(config_path))
    with TestClient(app) as c:
        yield c


def test_risk_score_endpoint(client: TestClient):
    res = client.post(
        "/risk/score",
        json={
            "findings": [
                {
                    "finding_id": "1",
                    "severity": "CRITICAL",
                    "title": "bridge anomaly",
                    "category": "bridge",
                }
            ]
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["count"] == 1
    assert data["auto_actions"] == []
    assert data["ranked"][0]["score"] > 0


def test_attack_path_endpoint(client: TestClient):
    res = client.post(
        "/risk/attack-path",
        json={
            "source": "a",
            "target": "c",
            "graph": {
                "nodes": [
                    {"id": "a", "risk": 0.3},
                    {"id": "b", "risk": 0.6, "kind": "contract"},
                    {"id": "c", "risk": 0.9, "kind": "asset"},
                ],
                "edges": [
                    {"source": "a", "target": "b"},
                    {"source": "b", "target": "c"},
                ],
            },
        },
    )
    assert res.status_code == 200
    body = res.json()
    assert body["path_count"] >= 1
    assert body["auto_actions"] == []
