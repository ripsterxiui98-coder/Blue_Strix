"""Alert policy: critical findings, approvals, anomalies, audit tampering."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional, Sequence

from bluestrix.core.audit_chain import detect_tampering, verify_chain
from bluestrix.core.notifiers import Notifier, default_notifiers


@dataclass
class AlertResult:
    sent: int = 0
    channels: list[str] = field(default_factory=list)
    skipped: bool = False
    reason: str = ""


def _dispatch(notifiers: Sequence[Notifier], title: str, body: str, severity: str) -> AlertResult:
    result = AlertResult()
    for n in notifiers:
        name = type(n).__name__
        ok = n.send(title, body, severity=severity)
        if ok:
            result.sent += 1
            result.channels.append(name)
    if result.sent == 0:
        result.skipped = True
        result.reason = "no notifier configured or all deliveries failed"
    return result


def alert_critical_finding(
    finding: dict[str, Any],
    notifiers: Optional[Sequence[Notifier]] = None,
) -> AlertResult:
    severity = str(finding.get("severity", "")).upper()
    if severity != "CRITICAL":
        return AlertResult(skipped=True, reason="not critical")
    title = finding.get("title") or finding.get("finding_id") or "Critical finding"
    body = (
        f"id={finding.get('finding_id')}\n"
        f"target={finding.get('target')}\n"
        f"status={finding.get('status')}\n"
        f"{finding.get('description', '')[:500]}"
    )
    return _dispatch(notifiers or default_notifiers(), str(title), body, "CRITICAL")


def alert_approval(
    *,
    finding_id: str,
    status: str,
    owner: str,
    notifiers: Optional[Sequence[Notifier]] = None,
) -> AlertResult:
    title = f"Remediation {status}"
    body = f"finding={finding_id}\nowner={owner}\nstatus={status}"
    sev = "HIGH" if status == "approved" else "INFO"
    return _dispatch(notifiers or default_notifiers(), title, body, sev)


def alert_anomaly(
    description: str,
    *,
    metadata: Optional[dict[str, Any]] = None,
    notifiers: Optional[Sequence[Notifier]] = None,
) -> AlertResult:
    body = description
    if metadata:
        body += f"\nmetadata={metadata}"
    return _dispatch(notifiers or default_notifiers(), "Anomaly detected", body, "HIGH")


def alert_tampering(
    events: Sequence[dict[str, Any]],
    notifiers: Optional[Sequence[Notifier]] = None,
) -> AlertResult:
    result = verify_chain(events)
    if result.valid:
        return AlertResult(skipped=True, reason="chain intact")
    body = (
        f"Audit chain integrity failure.\n"
        f"reason={result.reason}\nbroken_at={result.broken_at}\nchecked={result.checked}"
    )
    return _dispatch(notifiers or default_notifiers(), "Audit tampering detected", body, "CRITICAL")


def evaluate_and_alert_chain(
    events: Sequence[dict[str, Any]],
    notifiers: Optional[Sequence[Notifier]] = None,
) -> AlertResult:
    if detect_tampering(events):
        return alert_tampering(events, notifiers=notifiers)
    return AlertResult(skipped=True, reason="no tampering")
