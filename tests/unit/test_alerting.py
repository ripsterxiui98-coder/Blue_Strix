from bluestrix.core.alerting import (
    alert_anomaly,
    alert_approval,
    alert_critical_finding,
    alert_tampering,
)
from bluestrix.core.audit_chain import GENESIS_PREV, build_chained_event


class CaptureNotifier:
    def __init__(self) -> None:
        self.messages: list[tuple[str, str, str]] = []

    def send(self, title: str, body: str, severity: str = "INFO") -> bool:
        self.messages.append((title, body, severity))
        return True


def test_critical_only():
    n = CaptureNotifier()
    r = alert_critical_finding({"severity": "LOW", "title": "x"}, notifiers=[n])
    assert r.skipped
    r2 = alert_critical_finding(
        {"severity": "CRITICAL", "title": "RCE", "finding_id": "BSX-1", "target": "./x"},
        notifiers=[n],
    )
    assert r2.sent == 1
    assert n.messages[-1][2] == "CRITICAL"


def test_approval_alert():
    n = CaptureNotifier()
    r = alert_approval(finding_id="BSX-1", status="approved", owner="owner", notifiers=[n])
    assert r.sent == 1


def test_anomaly_and_tamper():
    n = CaptureNotifier()
    assert alert_anomaly("spike", notifiers=[n]).sent == 1
    e1 = build_chained_event(actor="a", action="x", target="t", decision="ALLOWED", prev_hash=GENESIS_PREV)
    e2 = build_chained_event(actor="a", action="y", target="t", decision="ALLOWED", prev_hash=e1["event_hash"])
    e2["event_hash"] = "deadbeef"
    r = alert_tampering([e1, e2], notifiers=[n])
    assert r.sent == 1
    assert "tampering" in n.messages[-1][0].lower()
