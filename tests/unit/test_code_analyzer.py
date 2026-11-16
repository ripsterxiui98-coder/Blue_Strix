from pathlib import Path

from bluestrix.core.models import CheckStatus, Severity
from bluestrix.intelligence.code.analyzer import CodeIntelligenceEngine


def test_detects_tx_origin(tmp_path: Path):
    contract = tmp_path / "Vulnerable.sol"
    contract.write_text("contract A { function check() public view returns (bool) { return tx.origin == msg.sender; } }")
    findings = CodeIntelligenceEngine().analyze_path(tmp_path)
    assert any(f.metadata.get("rule_id") == "BSX-SOL-004" for f in findings)
