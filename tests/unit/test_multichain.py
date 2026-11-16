from bluestrix.chains.aptos import analyze_aptos_events
from bluestrix.chains.cosmos import analyze_cosmos_events
from bluestrix.chains.sui import analyze_sui_events
from bluestrix.chains.ton import analyze_ton_events


def test_sui_upgrade():
    s = analyze_sui_events([{"type": "package_upgrade", "package": "0xabc", "digest": "d1"}])
    assert s[0].rule_id == "ONCHAIN-SUI-PACKAGE-UPGRADE"
    assert s[0].severity == "CRITICAL"


def test_aptos_authority():
    s = analyze_aptos_events([{"type": "owner_change", "module": "0x1::x"}])
    assert any(x.rule_id == "ONCHAIN-APTOS-AUTHORITY" for x in s)


def test_ton_code_update():
    s = analyze_ton_events([{"type": "code_update", "address": "EQ..."}])
    assert s[0].rule_id == "ONCHAIN-TON-CODE-UPDATE"


def test_cosmos_ibc_and_upgrade():
    s = analyze_cosmos_events(
        [
            {"type": "software_upgrade", "module": "upgrade", "chain_id": "cosmoshub-4"},
            {"type": "channel_close", "module": "ibc", "anomaly": True},
        ]
    )
    ids = {x.rule_id for x in s}
    assert "ONCHAIN-COSMOS-UPGRADE" in ids
    assert "ONCHAIN-COSMOS-IBC" in ids
