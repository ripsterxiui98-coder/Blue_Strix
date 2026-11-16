"""Security report generation: executive, technical, remediation, post-incident."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional, Sequence

from bluestrix.intelligence.ai_triage import triage_findings


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def executive_summary(
    findings: Sequence[dict[str, Any]],
    *,
    title: str = "BlueStrix Security Summary",
    triage: Optional[list[dict[str, Any]]] = None,
) -> dict[str, Any]:
    triage = triage or triage_findings(findings)
    counts: dict[str, int] = {}
    for t in triage:
        counts[t["severity"]] = counts.get(t["severity"], 0) + 1
    top = triage[:5]
    narrative = (
        f"Reviewed {len(findings)} finding(s). "
        f"Severity distribution: {counts or {'none': 0}}. "
        f"Highest priority items require human governance before any change."
    )
    return {
        "type": "executive_summary",
        "title": title,
        "generated_at": _utcnow(),
        "finding_count": len(findings),
        "severity_counts": counts,
        "top_priorities": [
            {"finding_id": t["finding_id"], "severity": t["severity"], "priority": t["priority"]}
            for t in top
        ],
        "narrative": narrative,
        "auto_actions": [],
    }


def technical_detail(
    findings: Sequence[dict[str, Any]],
    *,
    triage: Optional[list[dict[str, Any]]] = None,
) -> dict[str, Any]:
    triage = triage or triage_findings(findings)
    by_id = {t["finding_id"]: t for t in triage}
    details = []
    for f in findings:
        fid = str(f.get("finding_id") or f.get("rule_id") or "")
        t = by_id.get(fid) or {}
        details.append(
            {
                "finding_id": fid,
                "title": f.get("title"),
                "severity": t.get("severity") or f.get("severity"),
                "category": f.get("category"),
                "target": f.get("target"),
                "description": f.get("description"),
                "evidence": f.get("evidence") or [],
                "explanation": t.get("explanation"),
                "attack_path_notes": t.get("attack_path_notes") or [],
                "rule_id": f.get("rule_id"),
            }
        )
    return {
        "type": "technical_detail",
        "generated_at": _utcnow(),
        "items": details,
        "auto_actions": [],
    }


def remediation_plan(
    findings: Sequence[dict[str, Any]],
    *,
    triage: Optional[list[dict[str, Any]]] = None,
) -> dict[str, Any]:
    triage = triage or triage_findings(findings)
    steps = []
    for t in triage:
        steps.append(
            {
                "finding_id": t["finding_id"],
                "priority": t["priority"],
                "severity": t["severity"],
                "actions": t.get("remediation_suggestions") or [],
                "requires_human_approval": True,
            }
        )
    return {
        "type": "remediation_plan",
        "generated_at": _utcnow(),
        "steps": steps,
        "policy": "No auto-apply, auto-sign, or fund movement. Proposals only.",
        "auto_actions": [],
    }


def post_incident_report(
    *,
    incident_id: str,
    title: str,
    severity: str,
    timeline: Optional[list[dict[str, Any]]] = None,
    findings: Optional[Sequence[dict[str, Any]]] = None,
    evidence: Optional[list[Any]] = None,
    lessons: Optional[list[str]] = None,
) -> dict[str, Any]:
    findings = list(findings or [])
    triage = triage_findings(findings) if findings else []
    return {
        "type": "post_incident_report",
        "incident_id": incident_id,
        "title": title,
        "severity": severity,
        "generated_at": _utcnow(),
        "timeline": timeline
        or [{"at": _utcnow(), "event": "report_generated", "actor": "bluestrix"}],
        "findings_triage": triage,
        "evidence": evidence or [],
        "lessons_learned": lessons
        or [
            "Keep human approval gates for all state-changing remediation.",
            "Preserve audit trail and evidence packs.",
        ],
        "auto_actions": [],
        "disclaimer": "BlueStrix reports are defensive and evidence-based; not exploit tooling.",
    }


def generate_full_report(
    findings: Sequence[dict[str, Any]],
    *,
    title: str = "BlueStrix Assessment Report",
    use_llm: bool = False,
    human_approved: bool = False,
    incident_id: Optional[str] = None,
) -> dict[str, Any]:
    triage = triage_findings(findings, use_llm=use_llm, human_approved=human_approved)
    return {
        "title": title,
        "generated_at": _utcnow(),
        "triage": triage,
        "executive_summary": executive_summary(findings, title=title, triage=triage),
        "technical_detail": technical_detail(findings, triage=triage),
        "remediation_plan": remediation_plan(findings, triage=triage),
        "post_incident_report": post_incident_report(
            incident_id=incident_id or f"RPT-{len(findings)}",
            title=title,
            severity=(triage[0]["severity"] if triage else "INFO"),
            findings=findings,
        ),
        "auto_actions": [],
    }
