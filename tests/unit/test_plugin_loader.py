import json
from pathlib import Path

import pytest

from bluestrix.plugins.loader import PluginLoader, load_plugins_from_directory, validate_manifest
from bluestrix.plugins.signing import sign_payload, verify_rule_pack_signature


def test_validate_manifest():
    assert validate_manifest({"name": "n", "version": "1", "rules": [{"x": 1}]}) == []
    assert "missing name" in validate_manifest({"version": "1", "rules": []})[0]


def test_signature_roundtrip():
    body = {"name": "pack", "version": "1.0.0", "kind": "community", "rules": [{"a": 1}]}
    secret = "test-hmac-secret-not-for-prod"
    sig = sign_payload(body, secret)
    assert verify_rule_pack_signature({**body, "signature": sig}, secret=secret, require_signature=True)
    assert not verify_rule_pack_signature({**body, "signature": "dead"}, secret=secret, require_signature=True)


def test_load_community_requires_sig(tmp_path: Path):
    manifest = {
        "name": "c",
        "version": "1.0.0",
        "kind": "community",
        "rules": [
            {
                "rule_id": "C-1",
                "title": "t",
                "description": "d",
                "severity": "LOW",
                "language": "any",
                "pattern": "TODO",
            }
        ],
    }
    loader = PluginLoader(require_signature_for_community=True)
    with pytest.raises(ValueError, match="signature"):
        loader.load_manifest(manifest, hmac_secret="secret")

    manifest["signature"] = sign_payload(
        {k: v for k, v in manifest.items() if k != "signature"}, "secret"
    )
    report = loader.load_manifest(manifest, hmac_secret="secret")
    assert report["rules_loaded"] == 1


def test_load_directory_example():
    root = Path(__file__).resolve().parents[2] / "plugins" / "community"
    if not root.exists():
        pytest.skip("example pack missing")
    reg, reports = load_plugins_from_directory(root, require_signature_for_community=False)
    assert reports
    assert reg.get("COMMUNITY-SOL-TX-ORIGIN") is not None
