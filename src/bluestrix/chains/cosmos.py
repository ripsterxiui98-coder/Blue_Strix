"""Cosmos SDK / IBC read-only monitoring helpers."""

from __future__ import annotations

from typing import Any, Sequence

from bluestrix.chains.sui import ChainSignal


def classify_cosmos_event(event: dict[str, Any]) -> list[ChainSignal]:
    signals: list[ChainSignal] = []
    etype = str(event.get("type") or event.get("event_type") or "").lower()
    module = str(event.get("module") or "")
    base = {
        "module": module,
        "tx": str(event.get("txhash") or event.get("tx") or ""),
        "chain": str(event.get("chain_id") or "cosmos"),
    }

    if etype in {"software_upgrade", "upgrade", "gov_proposal_passed"}:
        signals.append(
            ChainSignal(
                rule_id="ONCHAIN-COSMOS-UPGRADE",
                title="Cosmos software upgrade / gov pass",
                severity="HIGH",
                category="upgrade",
                evidence=base,
                recommendation="Confirm proposal id and upgrade plan hash.",
            )
        )
    elif "ibc" in etype or etype in {"ibc_transfer", "channel_close", "client_update"}:
        severity = "CRITICAL" if "close" in etype or event.get("anomaly") else "MEDIUM"
        signals.append(
            ChainSignal(
                rule_id="ONCHAIN-COSMOS-IBC",
                title="IBC-related event",
                severity=severity,
                category="bridge",
                evidence=base,
                recommendation="Investigate channel/client state; no auto fund movement.",
            )
        )
    elif etype in {"large_transfer", "msg_send"} and int(event.get("amount") or 0) >= int(
        event.get("threshold") or 10**18
    ):
        signals.append(
            ChainSignal(
                rule_id="ONCHAIN-COSMOS-LARGE-TRANSFER",
                title="Large bank send",
                severity="HIGH",
                category="transfer",
                evidence={**base, "amount": event.get("amount")},
                recommendation="Check treasury and vesting policies.",
            )
        )
    elif etype in {"authority_change", "authz_grant"}:
        signals.append(
            ChainSignal(
                rule_id="ONCHAIN-COSMOS-AUTHZ",
                title="Authz / authority change",
                severity="HIGH",
                category="governance",
                evidence=base,
                recommendation="Review grantee permissions.",
            )
        )
    return signals


def analyze_cosmos_events(events: Sequence[dict[str, Any]]) -> list[ChainSignal]:
    out: list[ChainSignal] = []
    for e in events:
        out.extend(classify_cosmos_event(e))
    return out
