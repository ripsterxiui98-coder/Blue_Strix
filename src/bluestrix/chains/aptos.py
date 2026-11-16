"""Aptos read-only monitoring helpers."""

from __future__ import annotations

from typing import Any, Sequence

from bluestrix.chains.sui import ChainSignal


def classify_aptos_event(event: dict[str, Any]) -> list[ChainSignal]:
    signals: list[ChainSignal] = []
    etype = str(event.get("type") or event.get("event_type") or "").lower()
    module = str(event.get("module") or event.get("account") or "")
    base = {"module": module, "tx": str(event.get("version") or event.get("tx") or ""), "chain": "aptos"}

    if "upgrade" in etype or etype in {"code_publishing", "module_publish"}:
        signals.append(
            ChainSignal(
                rule_id="ONCHAIN-APTOS-MODULE-PUBLISH",
                title="Aptos module publish/upgrade",
                severity="CRITICAL",
                category="upgrade",
                evidence=base,
                recommendation="Review package metadata and signer against governance.",
            )
        )
    elif "owner" in etype or "authority" in etype:
        signals.append(
            ChainSignal(
                rule_id="ONCHAIN-APTOS-AUTHORITY",
                title="Aptos authority/owner change",
                severity="CRITICAL",
                category="governance",
                evidence=base,
                recommendation="Verify new authority; no auto-remediation.",
            )
        )
    elif etype in {"large_transfer", "withdraw"}:
        signals.append(
            ChainSignal(
                rule_id="ONCHAIN-APTOS-LARGE-TRANSFER",
                title="Large Aptos transfer/withdraw",
                severity="HIGH",
                category="transfer",
                evidence={**base, "amount": event.get("amount")},
                recommendation="Check allowlists and multisig policy.",
            )
        )
    return signals


def analyze_aptos_events(events: Sequence[dict[str, Any]]) -> list[ChainSignal]:
    out: list[ChainSignal] = []
    for e in events:
        out.extend(classify_aptos_event(e))
    return out
