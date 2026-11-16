from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from bluestrix.core.models import Finding
from bluestrix.intelligence.verification.engine import VerificationEngine


class ReportGenerator:
    def __init__(self, output_directory: str | Path = "reports") -> None:
        self.output_directory = Path(output_directory)
        self.output_directory.mkdir(parents=True, exist_ok=True)
        self.verifier = VerificationEngine()

    def save_json(self, findings: list[Finding], name: str = "findings") -> Path:
        summary = self.verifier.summarize(findings)
        payload = {"generated_at": datetime.now(timezone.utc).isoformat(),
                   "summary": summary,
                   "findings": [f.model_dump(mode="json") for f in findings]}
        output = self.output_directory / f"{name}.json"
        output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return output

    def save_markdown(self, findings: list[Finding], name: str = "SECURITY_REPORT") -> Path:
        summary = self.verifier.summarize(findings)
        lines = ["# BlueStrix v8.0 Security Report", "",
                 f"**Generated:** {datetime.now(timezone.utc).isoformat()}", "",
                 "## Executive summary", "",
                 f"- Total findings: **{summary['total_findings']}**",
                 f"- Overall risk: **{summary['overall_risk']}**", "",
                 "## Findings", ""]
        for finding in findings:
            lines.extend([f"### {finding.finding_id}: {finding.title}", "",
                          f"- **Severity:** {finding.severity.value}",
                          f"- **Status:** {finding.status.value}",
                          f"- **Target:** `{finding.target}`", "",
                          finding.description, ""])
            if finding.recommendation:
                lines.extend(["**Recommendation**", "", finding.recommendation, ""])
        output = self.output_directory / f"{name}.md"
        output.write_text("\n".join(lines), encoding="utf-8")
        return output
