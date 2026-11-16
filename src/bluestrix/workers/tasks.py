"""Background tasks for on-chain monitoring, audit verification, and alerting.

Celery is optional. Functions can be called synchronously when broker is absent.
"""

from __future__ import annotations

from typing import Any, Optional, Sequence

from bluestrix.chains.evm_monitor import analyze_evm_logs
from bluestrix.chains.solana_monitor import analyze_solana_notifications
from bluestrix.core.alerting import (
    alert_anomaly,
    alert_approval,
    alert_critical_finding,
    evaluate_and_alert_chain,
)
from bluestrix.core.audit_chain import apply_retention_policy, verify_chain
from bluestrix.intelligence.incident import create_incident, post_incident_report

try:
    from celery import Celery

    app = Celery(
        "bluestrix",
        broker="redis://localhost:6379/0",
        backend="redis://localhost:6379/1",
    )
    app.conf.task_always_eager = False
except ImportError:  # pragma: no cover
    app = None  # type: ignore


# --- On-chain monitoring (read-only) ---


def run_evm_monitor(
    logs: Sequence[dict[str, Any]],
    owner_contacts: Optional[list[str]] = None,
) -> dict[str, Any]:
    signals = analyze_evm_logs(logs)
    if not signals:
        return {"signals": 0, "incident": None}
    incident = create_incident(
        signals, chain="evm", owner_contacts=owner_contacts or []
    )
    return {
        "signals": len(signals),
        "severity": incident.severity,
        "incident_id": incident.incident_id,
        "report": post_incident_report(incident),
    }


def run_solana_monitor(
    events: Sequence[dict[str, Any]],
    owner_contacts: Optional[list[str]] = None,
) -> dict[str, Any]:
    signals = analyze_solana_notifications(events)
    if not signals:
        return {"signals": 0, "incident": None}
    incident = create_incident(
        signals, chain="solana", owner_contacts=owner_contacts or []
    )
    return {
        "signals": len(signals),
        "severity": incident.severity,
        "incident_id": incident.incident_id,
        "report": post_incident_report(incident),
    }


# --- Audit integrity + alerting ---


def run_verify_audit_chain(events: Sequence[dict[str, Any]]) -> dict[str, Any]:
    result = verify_chain(events)
    alert = evaluate_and_alert_chain(events)
    return {
        "valid": result.valid,
        "checked": result.checked,
        "broken_at": result.broken_at,
        "reason": result.reason,
        "alert_sent": alert.sent,
        "alert_channels": alert.channels,
    }


def run_alert_critical(finding: dict[str, Any]) -> dict[str, Any]:
    r = alert_critical_finding(finding)
    return {
        "sent": r.sent,
        "channels": r.channels,
        "skipped": r.skipped,
        "reason": r.reason,
    }


def run_alert_approval(finding_id: str, status: str, owner: str) -> dict[str, Any]:
    r = alert_approval(finding_id=finding_id, status=status, owner=owner)
    return {"sent": r.sent, "channels": r.channels, "skipped": r.skipped}


def run_alert_anomaly(
    description: str, metadata: Optional[dict[str, Any]] = None
) -> dict[str, Any]:
    r = alert_anomaly(description, metadata=metadata)
    return {"sent": r.sent, "channels": r.channels, "skipped": r.skipped}


def run_retention_preview(
    events: Sequence[dict[str, Any]], retain_days: int = 365
) -> dict[str, Any]:
    kept = apply_retention_policy(events, retain_days=retain_days, allow_delete=False)
    return {"immutable": True, "count": len(kept), "retain_days": retain_days}


if app is not None:

    @app.task(name="bluestrix.monitor_evm_logs")
    def monitor_evm_logs_task(
        logs: list[dict[str, Any]], owner_contacts: list[str] | None = None
    ):
        return run_evm_monitor(logs, owner_contacts)

    @app.task(name="bluestrix.monitor_solana_events")
    def monitor_solana_events_task(
        events: list[dict[str, Any]], owner_contacts: list[str] | None = None
    ):
        return run_solana_monitor(events, owner_contacts)

    @app.task(name="bluestrix.verify_audit_chain")
    def verify_audit_chain_task(events: list[dict[str, Any]]) -> dict[str, Any]:
        return run_verify_audit_chain(events)

    @app.task(name="bluestrix.alert_critical_finding")
    def alert_critical_finding_task(finding: dict[str, Any]) -> dict[str, Any]:
        return run_alert_critical(finding)
