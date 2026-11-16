"""Solana read-only monitoring. Never signs transactions or holds keys."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Optional, Sequence

from bluestrix.chains.evm_monitor import ChainSignal


def classify_solana_notification(event: dict[str, Any]) -> list[ChainSignal]:
    signals: list[ChainSignal] = []
    etype = str(event.get("type") or event.get("event") or "").lower()
    program = str(event.get("program") or event.get("programId") or "")
    signature = str(event.get("signature") or event.get("tx") or "")
    base = {"program": program, "signature": signature, "slot": event.get("slot")}

    if etype in {"authority_change", "set_authority", "owner_change"}:
        signals.append(
            ChainSignal(
                rule_id="ONCHAIN-SOL-AUTHORITY-CHANGE",
                title="Solana authority/owner change",
                severity="CRITICAL",
                category="governance",
                evidence={**base, "new_authority": event.get("new_authority")},
                recommendation="Verify authority is expected multisig; freeze program upgrades if compromised.",
            )
        )
    elif etype in {"upgrade", "bpf_loader_upgrade", "program_upgrade"}:
        signals.append(
            ChainSignal(
                rule_id="ONCHAIN-SOL-PROGRAM-UPGRADE",
                title="Program upgrade detected",
                severity="CRITICAL",
                category="upgrade",
                evidence=base,
                recommendation="Review upgrade authority and bytecode hash against approved release.",
            )
        )
    elif etype in {"large_transfer", "token_transfer"}:
        amount = int(event.get("amount") or 0)
        threshold = int(event.get("threshold") or 10**12)
        if amount >= threshold or etype == "large_transfer":
            signals.append(
                ChainSignal(
                    rule_id="ONCHAIN-SOL-LARGE-TRANSFER",
                    title="Large SPL transfer",
                    severity="HIGH",
                    category="transfer",
                    evidence={**base, "amount": amount},
                    recommendation="Validate destination and treasury policy.",
                )
            )
    elif etype in {"oracle_deviation"}:
        signals.append(
            ChainSignal(
                rule_id="ONCHAIN-SOL-ORACLE-DEVIATION",
                title="Oracle deviation (Solana)",
                severity="CRITICAL",
                category="oracle",
                evidence={**base, "deviation_bps": event.get("deviation_bps")},
                recommendation="Cross-check price feeds; human-gated pause only.",
            )
        )
    elif etype in {"bridge_anomaly"}:
        signals.append(
            ChainSignal(
                rule_id="ONCHAIN-SOL-BRIDGE-ANOMALY",
                title="Bridge anomaly (Solana)",
                severity="CRITICAL",
                category="bridge",
                evidence=base,
                recommendation="Notify bridge operators; do not auto-move funds.",
            )
        )
    elif etype in {"suspicious_approval", "delegate_set"}:
        signals.append(
            ChainSignal(
                rule_id="ONCHAIN-SOL-DELEGATE",
                title="Suspicious token delegate/approval",
                severity="MEDIUM",
                category="approval",
                evidence=base,
                recommendation="Review delegate account; revoke if untrusted.",
            )
        )
    return signals


def analyze_solana_notifications(events: Sequence[dict[str, Any]]) -> list[ChainSignal]:
    out: list[ChainSignal] = []
    for e in events:
        out.extend(classify_solana_notification(e))
    return out


class SolanaMonitor:
    def __init__(self, rpc_url: Optional[str] = None) -> None:
        self.rpc_url = rpc_url or os.getenv("BLUESTRIX_SOLANA_RPC_URL", "")

    def analyze(self, events: Sequence[dict[str, Any]]) -> list[ChainSignal]:
        return analyze_solana_notifications(events)
