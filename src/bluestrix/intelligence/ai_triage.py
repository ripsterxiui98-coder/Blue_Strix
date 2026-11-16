"""AI-assisted triage: local deterministic engine + optional LLM enrichment.

LLM calls require human_approved=True. Never auto-remediates.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Optional, Sequence

SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


@dataclass
class TriageResult:
    finding_id: str
    severity: str
    priority: int
    explanation: str
    attack_path_notes: list[str] = field(default_factory=list)
    remediation_suggestions: list[str] = field(default_factory=list)
    engine: str = "local"
    human_approved_llm: bool = False
    auto_actions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _priority(severity: str) -> int:
    s = severity.upper()
    if s == "CRITICAL":
        return 1
    if s == "HIGH":
        return 2
    if s == "MEDIUM":
        return 3
    if s == "LOW":
        return 4
    return 5


def local_triage(finding: dict[str, Any]) -> TriageResult:
    """Rule-based triage — always available, no external API."""
    sev = str(finding.get("severity") or "INFO").upper()
    if sev not in SEVERITY_ORDER:
        sev = "INFO"
    title = str(finding.get("title") or finding.get("rule_id") or "Finding")
    desc = str(finding.get("description") or "")
    category = str(finding.get("category") or "").lower()
    rule_id = str(finding.get("rule_id") or "")
    fid = str(finding.get("finding_id") or rule_id or "unknown")

    explanation = (
        f"{title} classified as {sev}. "
        f"Category={category or 'general'}. "
        f"{desc[:400] if desc else 'No additional description provided.'}"
    )

    path_notes: list[str] = []
    blob = f"{title} {category} {rule_id}".lower()
    if any(k in blob for k in ("owner", "admin", "authority", "role")):
        path_notes.append("Privileged control path: attacker→compromised key→admin function.")
    if any(k in blob for k in ("proxy", "upgrade")):
        path_notes.append("Upgrade path: governance/key→implementation change→protocol logic.")
    if "oracle" in blob:
        path_notes.append("Oracle path: manipulated feed→dependent module→value extraction risk.")
    if any(k in blob for k in ("bridge", "ibc")):
        path_notes.append("Bridge path: message/ forgery or halt→cross-chain asset exposure.")
    if not path_notes:
        path_notes.append("No specialized attack-path template matched; treat as isolated finding.")

    remediation: list[str] = []
    if finding.get("recommendation"):
        remediation.append(str(finding["recommendation"]))
    remediation.append("Open a remediation proposal for human approval — no auto-apply.")
    remediation.append("Collect on-chain evidence (tx, block, addresses) before changes.")
    if sev in {"HIGH", "CRITICAL"}:
        remediation.append("Notify protocol owner / security_analyst with incident severity.")

    return TriageResult(
        finding_id=fid,
        severity=sev,
        priority=_priority(sev),
        explanation=explanation,
        attack_path_notes=path_notes,
        remediation_suggestions=remediation,
        engine="local",
        human_approved_llm=False,
        auto_actions=[],
    )


def triage_findings(
    findings: Sequence[dict[str, Any]],
    *,
    use_llm: bool = False,
    human_approved: bool = False,
) -> list[dict[str, Any]]:
    results = [local_triage(f).to_dict() for f in findings]
    results.sort(key=lambda r: (r["priority"], r["finding_id"]))

    if use_llm:
        if not human_approved:
            for r in results:
                r["llm_skipped"] = "LLM enrichment requires human_approved=true"
            return results
        try:
            from bluestrix.integrations.openai import try_json_completion

            payload = {
                "findings": [
                    {
                        "finding_id": f.get("finding_id"),
                        "title": f.get("title"),
                        "severity": f.get("severity"),
                        "description": f.get("description"),
                        "category": f.get("category"),
                    }
                    for f in findings
                ]
            }
            messages = [
                {
                    "role": "system",
                    "content": (
                        "You are a defensive blockchain security analyst for BlueStrix. "
                        "Respond ONLY with JSON: {\"items\": [{\"finding_id\": str, "
                        "\"severity\": str, \"explanation\": str, "
                        "\"attack_path_notes\": [str], \"remediation_suggestions\": [str]}]}. "
                        "Never suggest exploits, auto-remediation, or fund movement."
                    ),
                },
                {"role": "user", "content": str(payload)},
            ]
            data = try_json_completion(messages)
            by_id = {str(i.get("finding_id")): i for i in data.get("items") or []}
            for r in results:
                extra = by_id.get(r["finding_id"])
                if not extra:
                    continue
                if extra.get("explanation"):
                    r["explanation"] = str(extra["explanation"])[:2000]
                if extra.get("attack_path_notes"):
                    r["attack_path_notes"] = [str(x) for x in extra["attack_path_notes"][:10]]
                if extra.get("remediation_suggestions"):
                    r["remediation_suggestions"] = [
                        str(x) for x in extra["remediation_suggestions"][:10]
                    ]
                if extra.get("severity") in SEVERITY_ORDER:
                    r["severity"] = str(extra["severity"]).upper()
                    r["priority"] = _priority(r["severity"])
                r["engine"] = "local+llm"
                r["human_approved_llm"] = True
                r["auto_actions"] = []
        except Exception as exc:
            for r in results:
                r["llm_error"] = str(exc)[:300]
    return results
