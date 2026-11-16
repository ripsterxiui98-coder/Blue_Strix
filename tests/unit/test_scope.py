from bluestrix.core.audit import AuditLog
from bluestrix.core.exceptions import ScopeViolationError
from bluestrix.policy.scope import ScopeEnforcer


def make_scope():
    config = {"default_action": "deny",
              "authorized_targets": {"domains": ["example.com"],
                                     "ipv4_cidrs": ["127.0.0.0/8"],
                                     "evm_addresses": ["0x0000000000000000000000000000000000000000"],
                                     "repository_paths": ["./"]}}
    return ScopeEnforcer(config, audit_log=AuditLog("data/test_audit.jsonl"))


def test_authorized_domain():
    assert make_scope().is_authorized("https://example.com/api")


def test_unauthorized_domain_blocked():
    try:
        make_scope().enforce("https://evil.example.net")
    except ScopeViolationError:
        assert True
    else:
        raise AssertionError("Expected ScopeViolationError")


def test_authorized_evm_address():
    assert make_scope().is_authorized("0x0000000000000000000000000000000000000000")
