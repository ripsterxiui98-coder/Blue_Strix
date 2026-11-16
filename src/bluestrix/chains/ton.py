"""TON read-only monitoring helpers."""

from __future__ import annotations

from typing import Any, Sequence

from bluestrix.chains.sui import ChainSignal


def classify_ton_event(event: dict[str, Any]) -> list[ChainSignal]:
    signals: list[ChainSignal] = []
    etype = str(event.get("type") or event.get("event_type") or "").lower()
    address = str(event.get("address") or event.get("account") or "")
    base = {"address": address, "lt": event.get("lt"), "chain": "ton"}

    if etype in {"code_update", "upgrade", "contract_deploy"}:
        signals.append(
            ChainSignal(
                rule_id="ONCHAIN-TON-CODE-UPDATE",
                title="TON contract code update/deploy",
                severity="CRITICAL",
                category="upgrade",
                evidence=base,
                recommendation="Compare code hash to approved release; human gate only.",
            )
        )
    elif etype in {"owner_change", "set_admin"}:
        signals.append(
            ChainSignal(
                rule_id="ONCHAIN-TON-ADMIN-CHANGE",
                title="TON admin/owner change",
                severity="CRITICAL",
                category="governance",
                evidence={**base, "new_admin": event.get("new_admin")},
                recommendation="Confirm admin is expected multisig.",
            )
        )
    elif etype in {"large_transfer", "jetton_transfer"}:
        signals.append(
            ChainSignal(
                rule_id="ONCHAIN-TON-LARGE-TRANSFER",
                title="Large TON/Jetton transfer",
                severity="HIGH",
                category="transfer",
                evidence={**base, "amount": event.get("amount")},
                recommendation="Validate destination policy.",
            )
        )
    return signals


def analyze_ton_events(events: Sequence[dict[str, Any]]) -> list[ChainSignal]:
    out: list[ChainSignal] = []
    for e in events:
        out.extend(classify_ton_event(e))
    return out
