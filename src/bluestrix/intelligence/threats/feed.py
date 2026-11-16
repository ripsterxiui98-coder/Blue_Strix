from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from bluestrix.core.models import Evidence, Finding, Severity
from bluestrix.security_controls.input_validation import InputValidator


class ThreatFeed:
    def __init__(self, feed_path: str | Path = "data/threat_feed.json") -> None:
        self.feed_path = Path(feed_path)
        self.validator = InputValidator()

    def load(self) -> dict[str, Any]:
        if not self.feed_path.exists():
            return {"version": 1, "indicators": []}
        return json.loads(self.feed_path.read_text(encoding="utf-8"))

    def match(self, target: str) -> list[Finding]:
        target = self.validator.clean_text(target, 512).lower()
        feed = self.load()
        findings = []
        for indicator in feed.get("indicators", []):
            if str(indicator.get("value", "")).lower() == target:
                findings.append(Finding(
                    title=f"Threat indicator match: {indicator.get('type', 'unknown')}",
                    description="Local threat indicator matched target.",
                    severity=Severity(indicator.get("severity", "MEDIUM")),
                    category="threat_intelligence",
                    target=target,
                    evidence=[Evidence(source="local_threat_feed", kind="indicator_match",
                                       value={"type": indicator.get("type"), "value": target})],
                    recommendation="Investigate and correlate before response.",
                    confidence=float(indicator.get("confidence", 0.6)),
                ))
        return findings
