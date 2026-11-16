from pathlib import Path

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from bluestrix.chains.evm_monitor import TOPIC_OWNERSHIP_TRANSFERRED


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


def test_monitor_evm_endpoint(client: TestClient):
    res = client.post(
        "/monitor/evm",
        json={
            "logs": [
                {
                    "address": "0xcontract",
                    "topics": [
                        TOPIC_OWNERSHIP_TRANSFERRED,
                        "0x" + "0" * 64,
                        "0x" + "0" * 24 + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ],
                    "transactionHash": "0xabc",
                }
            ],
            "owner_contacts": [],
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["incident"]["severity"] == "CRITICAL"
    assert data["incident"]["auto_actions"] == []
    assert any(s["rule_id"] == "ONCHAIN-EVM-OWNER-CHANGE" for s in data["signals"])


def test_monitor_solana_endpoint(client: TestClient):
    res = client.post(
        "/monitor/solana",
        json={"events": [{"type": "authority_change", "program": "X", "signature": "sig"}]},
    )
    assert res.status_code == 200
    assert res.json()["incident"]["severity"] == "CRITICAL"
