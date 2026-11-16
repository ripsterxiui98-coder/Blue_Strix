from bluestrix.core.audit_chain import (
    GENESIS_PREV,
    apply_retention_policy,
    build_chained_event,
    detect_tampering,
    verify_chain,
)


def test_chain_valid():
    e1 = build_chained_event(
        actor="a", action="login_success", target="u1", decision="ALLOWED", prev_hash=GENESIS_PREV
    )
    e2 = build_chained_event(
        actor="a",
        action="logout",
        target="u1",
        decision="ALLOWED",
        prev_hash=e1["event_hash"],
    )
    assert verify_chain([e1, e2]).valid
    assert not detect_tampering([e1, e2])


def test_tamper_detection():
    e1 = build_chained_event(
        actor="a", action="x", target="t", decision="ALLOWED", prev_hash=GENESIS_PREV
    )
    e2 = build_chained_event(
        actor="a", action="y", target="t", decision="ALLOWED", prev_hash=e1["event_hash"]
    )
    e2["action"] = "TAMPERED"
    assert detect_tampering([e1, e2])
    result = verify_chain([e1, e2])
    assert not result.valid
    assert result.broken_at == 1


def test_retention_immutable_default():
    events = [{"timestamp": "2020-01-01T00:00:00+00:00"}, {"timestamp": "2099-01-01T00:00:00+00:00"}]
    kept = apply_retention_policy(events, retain_days=30, allow_delete=False)
    assert len(kept) == 2
