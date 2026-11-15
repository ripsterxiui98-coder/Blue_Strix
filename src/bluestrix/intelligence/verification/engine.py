from __future__ import annotations

from collections import Counter

from bluestrix.core.models import CheckStatus, Finding, Severity


class VerificationEngine:
    SEVERITY_WEIGHT = {
        Severity.CRITICAL: 40, Severity.HIGH: 25, Severity.MEDIUM: 12,
        Severity.LOW: 5, Severity.INFO: 0,
    }

    def verify(self, findings: list[Finding]) -> list[Finding]:
        for finding in findings:
            if finding.status == CheckStatus.PASS and not finding.evidence:
                finding.status = CheckStatus.INCOMPLETE
                finding.recommendation = "PASS requires evidence; downgraded to INCOMPLETE."
        return findings

    def summarize(self, findings: list[Finding]) -> dict[str, object]:
        severity_counts = Counter(f.severity.value for f in findings)
        status_counts = Counter(f.status.value for f in findings)
        risk = sum(self.SEVERITY_WEIGHT.get(f.severity, 0) for f in findings)
        overall = "CRITICAL" if any(f.severity == Severity.CRITICAL for f in findings) else \
                  "HIGH" if any(f.severity == Severity.HIGH for f in findings) else \
                  "MEDIUM" if any(f.severity == Severity.MEDIUM for f in findings) else \
                  "LOW" if any(f.severity == Severity.LOW for f in findings) else "INFO"
        return {"total_findings": len(findings), "severity_counts": dict(severity_counts),
                "status_counts": dict(status_counts), "aggregate_risk_score": min(risk, 500),
                "overall_risk": overall}
