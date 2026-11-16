"""Background tasks for on-chain monitoring (read-only). Celery optional."""

from __future__ import annotations

from typing import Any, Optional, Sequence

from bluestrix.chains.evm_monitor import analyze_evm_logs
from bluestrix.chains.solana_monitor import analyze_solana_notifications
from bluestrix.intelligence.incident import create_incident, post_incident_report

try:
    from celery import Celery

    app = Celery("bluestrix", broker="redis://localhost:6379/0", backend="redis://localhost:6379/1")
except ImportError:  # pragma: no cover
    app = None  # type: ignore


def run_evm_monitor(logs: Sequence[dict[str, Any]], owner_contacts: Optional[list[str]] = None) -> dict[str, Any]:
    signals = analyze_evm_logs(logs)
    if not signals:
        return {"signals": 0, "incident": None}
    incident = create_incident(signals, chain="evm", owner_contacts=owner_contacts or [])
    return {
        "signals": len(signals),
        "severity": incident.severity,
        "incident_id": incident.incident_id,
        "report": post_incident_report(incident),
    }


def run_solana_monitor(
    events: Sequence[dict[str, Any]], owner_contacts: Optional[list[str]] = None
) -> dict[str, Any]:
    signals = analyze_solana_notifications(events)
    if not signals:
        return {"signals": 0, "incident": None}
    incident = create_incident(signals, chain="solana", owner_contacts=owner_contacts or [])
    return {
        "signals": len(signals),
        "severity": incident.severity,
        "incident_id": incident.incident_id,
        "report": post_incident_report(incident),
    }


if app is not None:

    @app.task(name="bluestrix.monitor_evm_logs")
    def monitor_evm_logs_task(logs: list[dict[str, Any]], owner_contacts: list[str] | None = None):
        return run_evm_monitor(logs, owner_contacts)

    @app.task(name="bluestrix.monitor_solana_events")
    def monitor_solana_events_task(
        events: list[dict[str, Any]], owner_contacts: list[str] | None = None
    ):
        return run_solana_monitor(events, owner_contacts)
