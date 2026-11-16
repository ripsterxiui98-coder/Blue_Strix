from bluestrix.chains.solana_monitor import analyze_solana_notifications, classify_solana_notification


def test_authority_change():
    signals = classify_solana_notification(
        {"type": "authority_change", "program": "Prog111", "signature": "sig", "new_authority": "Au1"}
    )
    assert signals[0].rule_id == "ONCHAIN-SOL-AUTHORITY-CHANGE"
    assert signals[0].severity == "CRITICAL"


def test_program_upgrade_and_bridge():
    events = [
        {"type": "program_upgrade", "program": "P", "signature": "s1"},
        {"type": "bridge_anomaly", "program": "Bridge", "signature": "s2"},
        {"type": "oracle_deviation", "deviation_bps": 300, "signature": "s3"},
    ]
    signals = analyze_solana_notifications(events)
    ids = {s.rule_id for s in signals}
    assert "ONCHAIN-SOL-PROGRAM-UPGRADE" in ids
    assert "ONCHAIN-SOL-BRIDGE-ANOMALY" in ids
    assert "ONCHAIN-SOL-ORACLE-DEVIATION" in ids
