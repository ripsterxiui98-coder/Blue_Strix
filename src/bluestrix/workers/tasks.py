

Celery is optional. Functions can be called synchronously when broker is absent.
"""

from __future__ import annotations

from typing import Any, Optional, Sequence


from bluestrix.core.alerting import (
    alert_anomaly,
    alert_approval,
    alert_critical_finding,
    evaluate_and_alert_chain,
)
from bluestrix.core.audit_chain import apply_retention_policy, verify_chain


try:
    from celery import Celery


    app.conf.task_always_eager = False
except ImportError:  # pragma: no cover
    app = None  # type: ignore



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



def run_alert_approval(finding_id: str, status: str, owner: str) -> dict[str, Any]:
    r = alert_approval(finding_id=finding_id, status=status, owner=owner)
    return {"sent": r.sent, "channels": r.channels, "skipped": r.skipped}



    r = alert_anomaly(description, metadata=metadata)
    return {"sent": r.sent, "channels": r.channels, "skipped": r.skipped}



    kept = apply_retention_policy(events, retain_days=retain_days, allow_delete=False)
    return {"immutable": True, "count": len(kept), "retain_days": retain_days}


if app is not None:


    @app.task(name="bluestrix.verify_audit_chain")
    def verify_audit_chain_task(events: list[dict[str, Any]]) -> dict[str, Any]:
        return run_verify_audit_chain(events)

    @app.task(name="bluestrix.alert_critical_finding")
    def alert_critical_finding_task(finding: dict[str, Any]) -> dict[str, Any]:
        return run_alert_critical(finding)
