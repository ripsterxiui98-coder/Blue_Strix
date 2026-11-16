import pytest

from bluestrix.plugins.registry import RuleRegistry
from bluestrix.plugins.rules import rule_from_dict
from bluestrix.plugins.sandbox import SandboxViolation, run_in_sandbox


def _rule(**over):
    base = {
        "rule_id": "TEST-RE-001",
        "title": "Test",
        "description": "d",
        "severity": "HIGH",
        "language": "python",
        "pattern": r"password\s*=\s*['\"]",
        "version": "1.0.0",
    }
    base.update(over)
    return rule_from_dict(base)


def test_register_and_versioning():
    reg = RuleRegistry()
    reg.register(_rule(version="1.0.0"))
    reg.register(_rule(version="1.1.0", title="Test v2"))
    assert reg.get("TEST-RE-001").version == "1.1.0"
    assert reg.versions("TEST-RE-001") == ["1.0.0", "1.1.0"]
    assert reg.get("TEST-RE-001", version="1.0.0").title == "Test"


def test_scan_and_test_rule():
    reg = RuleRegistry()
    rule = _rule()
    reg.register(rule)
    assert reg.test_rule(rule, "password = 'secret'")["matched"] is True
    assert reg.test_rule(rule, "ok = True")["matched"] is False
    findings = reg.scan_content("password = 'x'", language="python")
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "TEST-RE-001"


def test_sandbox_rejects_foreign_callable():
    def evil():
        return 1

    with pytest.raises(SandboxViolation):
        run_in_sandbox(evil)


def test_pattern_rejects_code_exec():
    with pytest.raises(ValueError):
        rule_from_dict(
            {
                "rule_id": "BAD",
                "title": "t",
                "description": "d",
                "severity": "LOW",
                "language": "python",
                "pattern": "eval(user)",
            }
        )
