"""Persist scan results, deduplicate findings, and track status over time."""

from __future__ import annotations

import re
import uuid
from typing import Any, Optional, Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from bluestrix.core import repository as repo
from bluestrix.core.models_db import FindingRecord, ScanRun


def _normalize_title(title: str) -> str:
    return re.sub(r"\s+", " ", title.strip().lower())


def dedupe_key(item: dict[str, Any]) -> tuple:
    meta = item.get("metadata") or {}
    line = meta.get("line") or meta.get("line_number")
    return (
        item.get("rule_id") or "",
        item.get("target") or "",
        line,
        _normalize_title(item.get("title") or ""),
    )


def deduplicate_findings(findings: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple] = set()
    result: list[dict[str, Any]] = []
    for item in findings:
        key = dedupe_key(item)
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def save_scan_results(
    session: Session,
    *,
    target: str,
    findings: Sequence[dict[str, Any]],
    summary: Optional[dict[str, Any]] = None,
) -> tuple[ScanRun, list[FindingRecord]]:
    unique = deduplicate_findings(list(findings))
    run = repo.create_scan_run(session, target=target, status="running")
    saved = repo.save_findings(session, unique, scan_run_id=run.id)
    repo.complete_scan_run(
        session,
        run.id,
        status="completed",
        summary=summary or {"count": len(saved)},
    )
    session.refresh(run)
    return run, saved


def compare_with_previous_scan(
    session: Session, target: str, current_findings: Sequence[dict[str, Any]]
) -> dict[str, Any]:
    stmt = (
        select(ScanRun)
        .where(ScanRun.target == target, ScanRun.status == "completed")
        .order_by(ScanRun.completed_at.desc())
        .limit(1)
    )
    previous = session.scalar(stmt)
    current_keys = {dedupe_key(f) for f in current_findings}
    previous_keys: set[tuple] = set()
    if previous is not None:
        prev_records = session.scalars(
            select(FindingRecord).where(FindingRecord.scan_run_id == previous.id)
        ).all()
        for rec in prev_records:
            previous_keys.add(
                dedupe_key(
                    {
                        "rule_id": rec.rule_id,
                        "target": rec.target,
                        "title": rec.title,
                        "metadata": rec.metadata_ or {},
                    }
                )
            )
    new_keys = current_keys - previous_keys
    fixed_keys = previous_keys - current_keys
    return {
        "previous_scan_id": str(previous.id) if previous else None,
        "new_count": len(new_keys),
        "fixed_count": len(fixed_keys),
        "unchanged_count": len(current_keys & previous_keys),
    }


def mark_finding_as_fixed(session: Session, finding_id: str) -> Optional[FindingRecord]:
    return repo.update_finding_status(session, finding_id, "fixed")


def mark_finding_as_false_positive(
    session: Session, finding_id: str
) -> Optional[FindingRecord]:
    return repo.update_finding_status(session, finding_id, "false_positive")
