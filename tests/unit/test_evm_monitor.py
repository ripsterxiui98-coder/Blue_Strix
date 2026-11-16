from bluestrix.chains.evm_monitor import (
    TOPIC_OWNERSHIP_TRANSFERRED,
    TOPIC_TRANSFER,
    TOPIC_UPGRADED,
    analyze_evm_logs,
    classify_evm_log,
)
from bluestrix.intelligence.incident import classify_severity, create_incident


def test_owner_change_critical():
    log = {
        "address": "0xabc",
        "topics": [
            TOPIC_OWNERSHIP_TRANSFERRED,
            "0x" + "0" * 24 + "1111111111111111111111111111111111111111",
            "0x" + "0" * 24 + "2222222222222222222222222222222222222222",
        ],
        "transactionHash": "0xtx",
    }
    signals = classify_evm_log(log)
    assert any(s.rule_id == "ONCHAIN-EVM-OWNER-CHANGE" for s in signals)
    assert classify_severity(signals) == "CRITICAL"


def test_proxy_upgrade():
    signals = classify_evm_log(
        {"address": "0xp", "topics": [TOPIC_UPGRADED], "transactionHash": "0x1"}
    )
    assert signals[0].rule_id == "ONCHAIN-EVM-PROXY-UPGRADE"


def test_large_transfer():
    amount = 10**22
    log = {
        "address": "0xtoken",
        "topics": [TOPIC_TRANSFER, "0x0", "0x0"],
        "data": hex(amount),
    }
    signals = analyze_evm_logs([log], large_transfer_threshold=10**21)
    assert any(s.rule_id == "ONCHAIN-EVM-LARGE-TRANSFER" for s in signals)


def test_oracle_and_bridge_tags():
    logs = [
        {"address": "0xo", "topics": ["0xdead"], "tags": ["oracle"], "deviation_bps": 500},
        {"address": "0xb", "topics": ["0xbeef"], "tags": ["bridge"], "anomaly": True},
    ]
    signals = analyze_evm_logs(logs)
    ids = {s.rule_id for s in signals}
    assert "ONCHAIN-EVM-ORACLE-DEVIATION" in ids
    assert "ONCHAIN-EVM-BRIDGE-ANOMALY" in ids


def test_incident_no_auto_actions():
    signals = classify_evm_log(
        {"address": "0x", "topics": [TOPIC_OWNERSHIP_TRANSFERRED, "0x0", "0x0"]}
    )
    inc = create_incident(signals, chain="evm", owner_contacts=["ops@example.com"], notify=False)
    assert inc.severity == "CRITICAL"
    assert inc.evidence
    assert "auto-remediation" in inc.notes.lower() or "No auto" in inc.notes
