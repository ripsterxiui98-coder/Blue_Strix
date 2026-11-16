"""Sui read-only monitoring helpers. Never signs or moves funds."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence


@dataclass
class ChainSignal:
    rule_id: str
    title: str
    severity: str
    category: str
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""


def classify_sui_event(event: dict[str, Any]) -> list[ChainSignal]:
    signals: list[ChainSignal] = []
    etype = str(event.get("type") or event.get("event_type") or "").lower()
    package = str(event.get("package") or event.get("packageId") or "")
    tx = str(event.get("tx") or event.get("digest") or "")
    base = {"package": package, "tx": tx, "chain": "sui"}

    if etype in {"upgrade", "package_upgrade", "publish"}:
        signals.append(
            ChainSignal(
                rule_id="ONCHAIN-SUI-PACKAGE-UPGRADE",
                title="Sui package publish/upgrade",
                severity="CRITICAL",
                category="upgrade",
                evidence=base,
                recommendation="Verify upgrade capability object and bytecode against approved release.",
            )
        )
    elif etype in {"ownership_change", "transfer_object", "set_owner"}:
        signals.append(
            ChainSignal(
                rule_id="ONCHAIN-SUI-OWNER-CHANGE",
                title="Sui object ownership change",
                severity="HIGH",
                category="governance",
                evidence={**base, "new_owner": event.get("new_owner")},
                recommendation="Confirm new owner is expected shared/owned object policy.",
            )
        )
    elif etype in {"large_transfer"}:
        signals.append(
            ChainSignal(
                rule_id="ONCHAIN-SUI-LARGE-TRANSFER",
                title="Large Sui transfer",
                severity="HIGH",
                category="transfer",
                evidence={**base, "amount": event.get("amount")},
                recommendation="Validate treasury policy; human review only.",
            )
        )
    return signals


def analyze_sui_events(events: Sequence[dict[str, Any]]) -> list[ChainSignal]:
    out: list[ChainSignal] = []
    for e in events:
        out.extend(classify_sui_event(e))
    return out
