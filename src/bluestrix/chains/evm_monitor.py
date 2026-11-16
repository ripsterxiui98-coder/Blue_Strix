"""EVM read-only event monitoring. Never signs, transfers, or mutates chain state."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Optional, Sequence

# Well-known topic0 (keccak) — stored as constants for offline classification
TOPIC_OWNERSHIP_TRANSFERRED = (
    "0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0"
)
TOPIC_UPGRADED = "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa363578324629cbe65e9c8"
TOPIC_PAUSED = "0x62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a23"
TOPIC_UNPAUSED = "0x5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa"
TOPIC_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
TOPIC_APPROVAL = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c41f65"
TOPIC_ROLE_GRANTED = "0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d"


@dataclass
class ChainSignal:
    rule_id: str
    title: str
    severity: str
    category: str
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""


def _topic0(log: dict[str, Any]) -> str:
    topics = log.get("topics") or []
    if not topics:
        return ""
    t = topics[0]
    if isinstance(t, bytes):
        return "0x" + t.hex()
    s = str(t).lower()
    return s if s.startswith("0x") else "0x" + s


def _addr_from_topic(topic: str) -> str:
    h = topic[2:] if topic.startswith("0x") else topic
    return "0x" + h[-40:].lower()


def classify_evm_log(
    log: dict[str, Any],
    *,
    large_transfer_threshold: int = 10**21,
) -> list[ChainSignal]:
    """Classify a single normalized EVM log (read-only)."""
    signals: list[ChainSignal] = []
    t0 = _topic0(log)
    address = str(log.get("address", "")).lower()
    tx = log.get("transactionHash") or log.get("tx_hash") or ""
    base_ev = {"address": address, "tx": str(tx), "topic0": t0, "logIndex": log.get("logIndex")}

    if t0 == TOPIC_OWNERSHIP_TRANSFERRED:
        topics = log.get("topics") or []
        new_owner = _addr_from_topic(str(topics[2])) if len(topics) > 2 else "unknown"
        signals.append(
            ChainSignal(
                rule_id="ONCHAIN-EVM-OWNER-CHANGE",
                title="Contract ownership transferred",
                severity="CRITICAL",
                category="governance",
                evidence={**base_ev, "new_owner": new_owner},
                recommendation="Verify new owner is an authorized multisig; pause non-essential ops until confirmed.",
            )
        )
    elif t0 == TOPIC_UPGRADED:
        signals.append(
            ChainSignal(
                rule_id="ONCHAIN-EVM-PROXY-UPGRADE",
                title="Proxy implementation upgraded",
                severity="CRITICAL",
                category="upgrade",
                evidence=base_ev,
                recommendation="Diff new implementation bytecode; confirm governance approval and timelock.",
            )
        )
    elif t0 == TOPIC_PAUSED:
        signals.append(
            ChainSignal(
                rule_id="ONCHAIN-EVM-PAUSED",
                title="Contract paused",
                severity="HIGH",
                category="ops",
                evidence=base_ev,
                recommendation="Confirm pause was intentional; monitor for follow-on exploits.",
            )
        )
    elif t0 == TOPIC_UNPAUSED:
        signals.append(
            ChainSignal(
                rule_id="ONCHAIN-EVM-UNPAUSED",
                title="Contract unpaused",
                severity="MEDIUM",
                category="ops",
                evidence=base_ev,
                recommendation="Confirm unpause followed approved incident closure.",
            )
        )
    elif t0 == TOPIC_TRANSFER:
        data = log.get("data") or "0x0"
        try:
            amount = int(str(data), 16) if str(data).startswith("0x") else int(data)
        except ValueError:
            amount = 0
        if amount >= large_transfer_threshold:
            signals.append(
                ChainSignal(
                    rule_id="ONCHAIN-EVM-LARGE-TRANSFER",
                    title="Large token transfer",
                    severity="HIGH",
                    category="transfer",
                    evidence={**base_ev, "amount": amount},
                    recommendation="Validate recipient allowlist and treasury policy.",
                )
            )
    elif t0 == TOPIC_APPROVAL:
        signals.append(
            ChainSignal(
                rule_id="ONCHAIN-EVM-APPROVAL",
                title="Token approval event",
                severity="MEDIUM",
                category="approval",
                evidence=base_ev,
                recommendation="Check spender is known router/vault; revoke unexpected allowances.",
            )
        )
    elif t0 == TOPIC_ROLE_GRANTED:
        signals.append(
            ChainSignal(
                rule_id="ONCHAIN-EVM-ROLE-GRANTED",
                title="Access control role granted",
                severity="HIGH",
                category="governance",
                evidence=base_ev,
                recommendation="Confirm role grant matches governance proposal.",
            )
        )

    # Heuristic: oracle / bridge tags from metadata if provided by indexer
    tags = {str(x).lower() for x in (log.get("tags") or [])}
    if "oracle" in tags and log.get("deviation_bps", 0) and int(log["deviation_bps"]) >= 200:
        signals.append(
            ChainSignal(
                rule_id="ONCHAIN-EVM-ORACLE-DEVIATION",
                title="Oracle price deviation",
                severity="CRITICAL",
                category="oracle",
                evidence={**base_ev, "deviation_bps": log.get("deviation_bps")},
                recommendation="Cross-check secondary oracles; consider circuit breakers.",
            )
        )
    if "bridge" in tags and log.get("anomaly") is True:
        signals.append(
            ChainSignal(
                rule_id="ONCHAIN-EVM-BRIDGE-ANOMALY",
                title="Bridge anomaly signal",
                severity="CRITICAL",
                category="bridge",
                evidence=base_ev,
                recommendation="Halt bridge deposits/withdrawals pending investigation (human decision).",
            )
        )
    if log.get("reentrancy_hint") is True:
        signals.append(
            ChainSignal(
                rule_id="ONCHAIN-EVM-REENTRANCY-HINT",
                title="Possible reentrancy pattern in trace",
                severity="HIGH",
                category="exploit_pattern",
                evidence=base_ev,
                recommendation="Inspect call trace; no automated remediation — human review only.",
            )
        )
    return signals


def analyze_evm_logs(
    logs: Sequence[dict[str, Any]],
    *,
    large_transfer_threshold: int = 10**21,
) -> list[ChainSignal]:
    out: list[ChainSignal] = []
    for log in logs:
        out.extend(classify_evm_log(log, large_transfer_threshold=large_transfer_threshold))
    return out


class EVMMonitor:
    """Optional web3.py-backed poller. Read-only; works offline via analyze_evm_logs."""

    def __init__(self, rpc_url: Optional[str] = None) -> None:
        self.rpc_url = rpc_url or os.getenv("BLUESTRIX_EVM_RPC_URL", "")
        self._w3 = None
        if self.rpc_url:
            try:
                from web3 import Web3  # optional dependency

                self._w3 = Web3(Web3.HTTPProvider(self.rpc_url))
            except Exception:
                self._w3 = None

    @property
    def connected(self) -> bool:
        try:
            return bool(self._w3 and self._w3.is_connected())
        except Exception:
            return False

    def analyze(self, logs: Sequence[dict[str, Any]], **kwargs: Any) -> list[ChainSignal]:
        return analyze_evm_logs(logs, **kwargs)
