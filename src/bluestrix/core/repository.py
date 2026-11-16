"""Repository layer for BlueStrix findings persistence. Never stores secrets."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any, Optional, Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from bluestrix.core.audit_chain import GENESIS_PREV, build_chained_event
from bluestrix.core.models_db import (
    ApprovalRecord,
    AuditEventRecord,
    FindingRecord,
    RemediationProposal,
    ScanRun,
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def hash_approval_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_scan_run(session: Session, target: str, status: str = "running") -> ScanRun:
    run = ScanRun(target=target, status=status, summary={})
    session.add(run)
    session.commit()
    session.refresh(run)
    return run


def complete_scan_run(
    session: Session,
    scan_run_id: uuid.UUID,
    status: str = "completed",
    summary: Optional[dict[str, Any]] = None,
) -> Optional[ScanRun]:
    run = session.get(ScanRun, scan_run_id)
    if run is None:
        return None
    run.status = status
    run.completed_at = _utcnow()
    if summary is not None:
        run.summary = summary
    session.commit()
    session.refresh(run)
    return run


def save_findings(
    session: Session,
    findings: Sequence[dict[str, Any]],
    scan_run_id: Optional[uuid.UUID] = None,
) -> list[FindingRecord]:
    saved: list[FindingRecord] = []
    for item in findings:
        finding_id = item.get("finding_id") or f"BSX-{uuid.uuid4().hex[:12]}"
        existing = session.scalar(
            select(FindingRecord).where(FindingRecord.finding_id == finding_id)
        )
        if existing:
            existing.title = item.get("title", existing.title)
            existing.description = item.get("description", existing.description)
            existing.severity = str(item.get("severity", existing.severity))
            existing.status = str(item.get("status", existing.status))
            existing.evidence = item.get("evidence", existing.evidence) or []
            existing.metadata_ = item.get("metadata", existing.metadata_) or {}
            existing.updated_at = _utcnow()
            saved.append(existing)
        else:
            record = FindingRecord(
                scan_run_id=scan_run_id,
                finding_id=finding_id,
                rule_id=item.get("rule_id"),
                title=item.get("title", "Untitled"),
                description=item.get("description", ""),
                severity=str(item.get("severity", "INFO")),
                status=str(item.get("status", "open")),
                category=item.get("category", "general"),
                target=item.get("target", ""),
                evidence=item.get("evidence") or [],
                recommendation=item.get("recommendation", ""),
                references=item.get("references") or [],
                confidence=float(item.get("confidence", 0.5)),
                metadata_=item.get("metadata") or {},
            )
            session.add(record)
            saved.append(record)
    session.commit()
    for r in saved:
        session.refresh(r)
    return saved


def list_findings(
    session: Session,
    *,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    target: Optional[str] = None,
    limit: int = 100,
) -> list[FindingRecord]:
    stmt = select(FindingRecord).order_by(FindingRecord.created_at.desc()).limit(limit)
    if status:
        stmt = stmt.where(FindingRecord.status == status)
    if severity:
        stmt = stmt.where(FindingRecord.severity == severity)
    if target:
        stmt = stmt.where(FindingRecord.target == target)
    return list(session.scalars(stmt).all())


def get_finding(session: Session, finding_id: str) -> Optional[FindingRecord]:
    return session.scalar(select(FindingRecord).where(FindingRecord.finding_id == finding_id))


def update_finding_status(
    session: Session, finding_id: str, status: str
) -> Optional[FindingRecord]:
    record = get_finding(session, finding_id)
    if record is None:
        return None
    record.status = status
    record.updated_at = _utcnow()
    session.commit()
    session.refresh(record)
    return record


def _latest_audit_hash(session: Session) -> str:
    stmt = select(AuditEventRecord).order_by(AuditEventRecord.timestamp.desc()).limit(1)
    last = session.scalar(stmt)
    if last is None:
        return GENESIS_PREV
    meta = last.metadata_ or {}
    return str(meta.get("event_hash") or GENESIS_PREV)


def create_audit_event(
    session: Session,
    *,
    actor: str,
    action: str,
    target: str,
    decision: str,
    reason: str = "",
    metadata: Optional[dict[str, Any]] = None,
) -> AuditEventRecord:
    prev = _latest_audit_hash(session)
    chained = build_chained_event(
        actor=actor,
        action=action,
        target=target,
        decision=decision,
        reason=reason,
        metadata=metadata or {},
        prev_hash=prev,
    )
    # Store chain material inside metadata_ to remain schema-compatible
    meta = dict(chained.get("metadata") or {})
    meta["prev_hash"] = chained["prev_hash"]
    meta["event_hash"] = chained["event_hash"]
    meta["chain_timestamp"] = chained["timestamp"]
    event = AuditEventRecord(
        actor=actor,
        action=action,
        target=target,
        decision=decision,
        reason=reason,
        metadata_=meta,
    )
    session.add(event)
    session.commit()
    session.refresh(event)
    return event


def list_audit_events(session: Session, limit: int = 50) -> list[AuditEventRecord]:
    stmt = select(AuditEventRecord).order_by(AuditEventRecord.timestamp.desc()).limit(limit)
    return list(session.scalars(stmt).all())


def list_audit_events_for_chain(session: Session, limit: int = 1000) -> list[dict[str, Any]]:
    """Oldest-first dicts suitable for verify_chain."""
    stmt = select(AuditEventRecord).order_by(AuditEventRecord.timestamp.asc()).limit(limit)
    rows = list(session.scalars(stmt).all())
    out: list[dict[str, Any]] = []
    for r in rows:
        meta = dict(r.metadata_ or {})
        out.append(
            {
                "actor": r.actor,
                "action": r.action,
                "target": r.target,
                "decision": r.decision,
                "reason": r.reason,
                "metadata": {k: v for k, v in meta.items() if k not in {"prev_hash", "event_hash", "chain_timestamp"}},
                "timestamp": meta.get("chain_timestamp") or (r.timestamp.isoformat() if r.timestamp else ""),
                "prev_hash": meta.get("prev_hash", GENESIS_PREV),
                "event_hash": meta.get("event_hash", ""),
            }
        )
    return out


def create_remediation_proposal(
    session: Session,
    *,
    finding_id: str,
    title: str,
    target: str,
    proposed_change: str = "",
    severity: str = "INFO",
    rule_id: Optional[str] = None,
) -> RemediationProposal:
    proposal = RemediationProposal(
        finding_id=finding_id,
        rule_id=rule_id,
        title=title,
        severity=severity,
        target=target,
        proposed_change=proposed_change,
        status="proposed",
    )
    session.add(proposal)
    session.commit()
    session.refresh(proposal)
    return proposal


def list_remediation_proposals(
    session: Session, limit: int = 50
) -> list[RemediationProposal]:
    stmt = (
        select(RemediationProposal)
        .order_by(RemediationProposal.created_at.desc())
        .limit(limit)
    )
    return list(session.scalars(stmt).all())


def create_approval_record(
    session: Session,
    *,
    finding_id: str,
    owner: str,
    status: str = "pending",
    proposal_id: Optional[uuid.UUID] = None,
    approval_token: Optional[str] = None,
    metadata: Optional[dict[str, Any]] = None,
) -> ApprovalRecord:
    token_hash = hash_approval_token(approval_token) if approval_token else None
    record = ApprovalRecord(
        finding_id=finding_id,
        proposal_id=proposal_id,
        owner=owner,
        status=status,
        approved_at=_utcnow() if status == "approved" else None,
        approval_token_hash=token_hash,
        metadata_=metadata or {},
    )
    session.add(record)
    session.commit()
    session.refresh(record)
    return record
