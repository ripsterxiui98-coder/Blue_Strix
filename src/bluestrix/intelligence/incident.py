"""Incident classification, evidence pack, owner notify — no auto-remediation."""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional, Sequence

from bluestrix.chains.evm_monitor import ChainSignal
from bluestrix.intelligence.playbook import get_playbook

SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def classify_severity(signals: Sequence[ChainSignal]) -> str:
    if not signals:
        return "INFO"
    return max(signals, key=lambda s: SEVERITY_RANK.get(s.severity.upper(), 0)).severity.upper()


@dataclass
class IncidentRecord:
    incident_id: str
    chain: str
    severity: str
    title: str
    status: str = "open"
    signals: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    playbook: dict[str, Any] = field(default_factory=dict)
    mitigations: list[str] = field(default_factory=list)
    notified: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    notes: str = "Read-only incident. No auto-transfer, auto-sign, or auto-remediation."


def collect_evidence(signals: Sequence[ChainSignal]) -> list[dict[str, Any]]:
    return [dict(s.evidence) | {"rule_id": s.rule_id, "title": s.title} for s in signals]


def create_incident(
    signals: Sequence[ChainSignal],
    *,
    chain: str = "evm",
    owner_contacts: Optional[Sequence[str]] = None,
    notify: bool = True,
) -> IncidentRecord:
    severity = classify_severity(signals)
    primary = signals[0] if signals else None
    rule_id = primary.rule_id if primary else "DEFAULT"
    playbook = get_playbook(rule_id)
    title = primary.title if primary else "On-chain incident"
    incident = IncidentRecord(
        incident_id=f"INC-{uuid.uuid4().hex[:12]}",
        chain=chain,
        severity=severity,
        title=title,
        signals=[
            {
                "rule_id": s.rule_id,
                "title": s.title,
                "severity": s.severity,
                "category": s.category,
                "recommendation": s.recommendation,
            }
            for s in signals
        ],
        evidence=collect_evidence(signals),
        playbook={"name": playbook.get("name"), "steps": playbook.get("steps", [])},
        mitigations=list(playbook.get("mitigations") or []),
    )
    if notify and owner_contacts:
        incident.notified = list(owner_contacts)
        try:
            from bluestrix.core.alerting import alert_anomaly

            alert_anomaly(
                f"Incident {incident.incident_id}: {title} ({severity})",
                metadata={"incident_id": incident.incident_id, "chain": chain},
            )
        except Exception:
            # Alerting optional if prior PR not merged
            pass
    return incident


def post_incident_report(incident: IncidentRecord) -> dict[str, Any]:
    """Structured post-incident report skeleton (human completes)."""
    return {
        "incident_id": incident.incident_id,
        "severity": incident.severity,
        "chain": incident.chain,
        "title": incident.title,
        "timeline": [{"at": incident.created_at, "event": "incident_opened"}],
        "evidence": incident.evidence,
        "playbook_followed": incident.playbook,
        "suggested_mitigations": incident.mitigations,
        "notified": incident.notified,
        "auto_actions": [],
        "disclaimer": "BlueStrix does not auto-remediate, auto-sign, or move funds.",
        "record": asdict(incident),
    }
