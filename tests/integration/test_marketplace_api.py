import json
from pathlib import Path

from bluestrix.plugins.marketplace import Marketplace
from bluestrix.plugins.signing import sign_payload


def test_marketplace_install_rate_review_uninstall(tmp_path: Path):
    catalog = tmp_path / "catalog"
    install = tmp_path / "installed"
    catalog.mkdir()
    pack = {
        "name": "demo-pack",
        "plugin_id": "demo-pack",
        "version": "1.0.0",
        "kind": "custom",
        "rules": [
            {
                "rule_id": "MKT-1",
                "title": "todo",
                "description": "d",
                "severity": "INFO",
                "language": "any",
                "pattern": "TODO",
                "version": "1.0.0",
            }
        ],
    }
    src = catalog / "demo.json"
    src.write_text(json.dumps(pack), encoding="utf-8")

    mkt = Marketplace(catalog_dir=catalog, install_dir=install)
    discovered = mkt.discover(query="demo")
    assert any(p["plugin_id"] == "demo-pack" for p in discovered)

    report = mkt.install(src)
    assert report["load"]["rules_loaded"] == 1
    assert mkt.registry.get("MKT-1") is not None

    assert mkt.rate("demo-pack", 5)["average"] == 5
    rev = mkt.review("demo-pack", "analyst", "Looks good", score=4)
    assert rev["plugin_id"] == "demo-pack"

    removed = mkt.uninstall("demo-pack")
    assert removed["removed"] is True


def test_community_install_requires_signature(tmp_path: Path):
    install = tmp_path / "installed"
    catalog = tmp_path / "catalog"
    catalog.mkdir()
    body = {
        "name": "comm",
        "plugin_id": "comm",
        "version": "1.0.0",
        "kind": "community",
        "rules": [
            {
                "rule_id": "C-9",
                "title": "t",
                "description": "d",
                "severity": "LOW",
                "language": "any",
                "pattern": "X",
            }
        ],
    }
    src = catalog / "comm.json"
    src.write_text(json.dumps(body), encoding="utf-8")
    mkt = Marketplace(catalog_dir=catalog, install_dir=install, require_signature_for_community=True)
    try:
        mkt.install(src, hmac_secret="secret")
        raised = False
    except ValueError:
        raised = True
    assert raised

    body["signature"] = sign_payload({k: v for k, v in body.items() if k != "signature"}, "secret")
    src.write_text(json.dumps(body), encoding="utf-8")
    report = mkt.install(src, hmac_secret="secret")
    assert report["load"]["rules_loaded"] == 1
