from __future__ import annotations

from collections import defaultdict

from bluestrix.core.models import Finding, Severity


class ThreatCorrelator:
    def correlate(self, findings: list[Finding]) -> list[dict[str, object]]:
        by_target = defaultdict(list)
        for finding in findings:
            by_target[finding.target].append(finding)

        correlations = []
        for target, target_findings in by_target.items():
            categories = {f.category for f in target_findings}
            high = [f for f in target_findings if f.severity in {Severity.HIGH, Severity.CRITICAL}]
            if len(categories) >= 2 and high:
                correlations.append({
                    "target": target,
                    "hypothesis": "Multiple high-impact signals affect same target.",
                    "categories": sorted(categories),
                    "severity": max((f.severity for f in high), key=lambda s: list(Severity).index(s)).value,
                    "finding_ids": [f.finding_id for f in high],
                })
        return correlations
