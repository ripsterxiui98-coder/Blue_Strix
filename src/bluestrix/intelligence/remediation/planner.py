from __future__ import annotations

from pathlib import Path
from typing import Any

from bluestrix.core.models import ActionType, Finding, Severity


class RemediationPlanner:
    SAFE_AUTO_FIX_RULES = {"BSX-PY-001", "BSX-TS-002"}

    def create_plan(self, findings: list[Finding], repository_root: str | Path) -> dict[str, Any]:
        proposals = []
        for finding in findings:
            if finding.status.value != "FAIL":
                continue
            rule_id = finding.metadata.get("rule_id")
            proposals.append({
                "finding_id": finding.finding_id,
                "rule_id": rule_id,
                "title": finding.title,
                "severity": finding.severity.value,
                "target": finding.metadata.get("target") or finding.target,
                "line": finding.metadata.get("line"),
                "recommended_change": finding.recommendation,
                "auto_fix_supported": rule_id in self.SAFE_AUTO_FIX_RULES,
                "requires_owner_approval": True,
                "status": "PROPOSED",
            })
        return {
            "repository_root": str(Path(repository_root).resolve()),
            "total_proposals": len(proposals),
            "proposals": proposals,
            "governance": {"action": ActionType.REMEDIATE.value, "approval_required": True},
        }
