"""Integration-style tests for plugin load + scan without full HTTP stack."""

from bluestrix.plugins.loader import PluginLoader
from bluestrix.plugins.signing import sign_payload


def test_end_to_end_custom_pack_scan():
    manifest = {
        "name": "local-custom",
        "version": "1.0.0",
        "kind": "custom",
        "rules": [
            {
                "rule_id": "CUSTOM-DELEGATECALL",
                "title": "delegatecall usage",
                "description": "delegatecall can be dangerous",
                "severity": "HIGH",
                "language": "solidity",
                "pattern": "delegatecall",
                "recommendation": "Restrict delegatecall targets",
                "cwe_id": "CWE-829",
                "version": "1.0.0",
            }
        ],
    }
    loader = PluginLoader(require_signature_for_community=True)
    loader.load_manifest(manifest)
    findings = loader.registry.scan_content(
        "function x() { target.delegatecall(data); }", language="solidity"
    )
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "CUSTOM-DELEGATECALL"


def test_signed_community_pack():
    rules = [
        {
            "rule_id": "COMM-1",
            "title": "t",
            "description": "d",
            "severity": "INFO",
            "language": "any",
            "pattern": "FIXME",
            "version": "1.0.0",
        }
    ]
    body = {"name": "c", "version": "1", "kind": "community", "rules": rules}
    secret = "integration-secret"
    body["signature"] = sign_payload(body, secret)
    loader = PluginLoader()
    report = loader.load_manifest(body, hmac_secret=secret)
    assert report["signature_ok"] is True
    assert loader.registry.test_rule(
        loader.registry.get("COMM-1"), "FIXME: later"
    )["matched"]
