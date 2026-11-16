"""Incident response playbooks — suggestions only, never auto-execute."""

from __future__ import annotations

from typing import Any

PLAYBOOKS: dict[str, dict[str, Any]] = {
    "ONCHAIN-EVM-OWNER-CHANGE": {
        "name": "Ownership change",
        "steps": [
            "Confirm event on explorer (tx + block).",
            "Identify previous and new owner addresses.",
            "Check if new owner is known protocol multisig.",
            "Notify protocol owner / security contact.",
            "Document evidence in incident record.",
            "Human decision only: pause protocol features if compromised.",
        ],
        "mitigations": [
            "Rotate admin to hardware multisig",
            "Enable timelock on ownership transfers",
        ],
    },
    "ONCHAIN-EVM-PROXY-UPGRADE": {
        "name": "Proxy upgrade",
        "steps": [
            "Capture implementation address before/after.",
            "Bytecode diff vs last approved release.",
            "Verify governance vote / timelock delay elapsed.",
            "Notify stakeholders; no auto-rollback.",
        ],
        "mitigations": ["Require multi-sig + timelock for upgrades"],
    },
    "ONCHAIN-EVM-LARGE-TRANSFER": {
        "name": "Large transfer",
        "steps": [
            "Record amount, from, to, token.",
            "Check allowlist / treasury policy.",
            "Escalate if destination is unknown mixer/CEX deposit.",
        ],
        "mitigations": ["Spending limits", "Allowlisted recipients"],
    },
    "ONCHAIN-EVM-ORACLE-DEVIATION": {
        "name": "Oracle deviation",
        "steps": [
            "Compare primary vs secondary feeds",
            "Check for sandwich / manipulation window",
            "Human-gated circuit breaker only",
        ],
        "mitigations": ["TWAP", "Multi-oracle median"],
    },
    "ONCHAIN-EVM-BRIDGE-ANOMALY": {
        "name": "Bridge anomaly",
        "steps": [
            "Freeze user-facing bridge UI messaging",
            "Coordinate with bridge operators",
            "Do not auto-move or sign bridge txs",
        ],
        "mitigations": ["Rate limits", "Proof verification audits"],
    },
    "ONCHAIN-SOL-AUTHORITY-CHANGE": {
        "name": "Solana authority change",
        "steps": [
            "Confirm signature on explorer",
            "Validate new authority",
            "Notify owner; collect evidence",
        ],
        "mitigations": ["Squads multisig authority"],
    },
    "DEFAULT": {
        "name": "Generic on-chain incident",
        "steps": [
            "Collect tx / slot evidence",
            "Classify severity",
            "Notify owner",
            "Propose human-approved mitigations only",
        ],
        "mitigations": [],
    },
}


def get_playbook(rule_id: str) -> dict[str, Any]:
    return PLAYBOOKS.get(rule_id, PLAYBOOKS["DEFAULT"])
