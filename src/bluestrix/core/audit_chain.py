"""Append-only audit log with hash chaining and tamper detection."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Optional, Sequence

GENESIS_PREV = "0" * 64


def _canonical_payload(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def compute_event_hash(prev_hash: str, payload: dict[str, Any]) -> str:
    material = f"{prev_hash}|{_canonical_payload(payload)}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def build_chained_event(
    *,
    actor: str,
    action: str,
    target: str,
    decision: str,
    reason: str = "",
    metadata: Optional[dict[str, Any]] = None,
    prev_hash: str = GENESIS_PREV,
    timestamp: Optional[datetime] = None,
) -> dict[str, Any]:
    ts = timestamp or datetime.now(timezone.utc)
    body = {
        "actor": actor,
        "action": action,
        "target": target,
        "decision": decision,
        "reason": reason,
        "metadata": metadata or {},
        "timestamp": ts.isoformat(),
    }
    event_hash = compute_event_hash(prev_hash, body)
    return {
        **body,
        "prev_hash": prev_hash,
        "event_hash": event_hash,
    }


@dataclass
class ChainVerificationResult:
    valid: bool
    checked: int
    broken_at: Optional[int] = None
    reason: Optional[str] = None


def verify_chain(events: Sequence[dict[str, Any]]) -> ChainVerificationResult:
    """Verify events ordered oldest → newest."""
    prev = GENESIS_PREV
    for idx, event in enumerate(events):
        expected_prev = event.get("prev_hash")
        if expected_prev != prev:
            return ChainVerificationResult(
                valid=False,
                checked=idx,
                broken_at=idx,
                reason=f"prev_hash mismatch at index {idx}",
            )
        body = {
            "actor": event.get("actor"),
            "action": event.get("action"),
            "target": event.get("target"),
            "decision": event.get("decision"),
            "reason": event.get("reason", ""),
            "metadata": event.get("metadata") or {},
            "timestamp": event.get("timestamp"),
        }
        expected = compute_event_hash(prev, body)
        if event.get("event_hash") != expected:
            return ChainVerificationResult(
                valid=False,
                checked=idx,
                broken_at=idx,
                reason=f"event_hash mismatch at index {idx}",
            )
        prev = event["event_hash"]
    return ChainVerificationResult(valid=True, checked=len(events))


def detect_tampering(events: Sequence[dict[str, Any]]) -> bool:
    """True if chain is broken (tamper or reorder/delete)."""
    return not verify_chain(events).valid


def retention_cutoff_iso(days: int) -> str:
    from datetime import timedelta

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    return cutoff.isoformat()


def apply_retention_policy(
    events: Iterable[dict[str, Any]],
    *,
    retain_days: int = 365,
    allow_delete: bool = False,
) -> list[dict[str, Any]]:
    """Audit logs are immutable by default. Retention only filters for export/archive.

    Physical delete is refused unless allow_delete is explicitly True (ops archive path).
    """
    if not allow_delete:
        return list(events)
    cutoff = retention_cutoff_iso(retain_days)
    return [e for e in events if str(e.get("timestamp", "")) >= cutoff]
