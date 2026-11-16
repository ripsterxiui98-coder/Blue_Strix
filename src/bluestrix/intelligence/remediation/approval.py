from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from bluestrix.core.exceptions import PolicyViolationError
from bluestrix.core.models import ActionType, SecurityDecision


class RemediationApproval:
    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def request(self, finding_id: str, target: str, proposed_change: str, owner: str) -> dict[str, Any]:
        record = {
            "finding_id": finding_id, "target": target, "proposed_change": proposed_change,
            "owner": owner, "status": "PENDING_OWNER_APPROVAL",
            "requested_at": datetime.now(timezone.utc).isoformat(),
        }
        self.records.append(record)
        return record

    def approve(self, finding_id: str, owner: str, approval_token: str) -> SecurityDecision:
        record = self._find(finding_id)
        if record["status"] != "PENDING_OWNER_APPROVAL":
            raise PolicyViolationError("Not pending approval")
        if not approval_token or len(approval_token) < 16:
            raise PolicyViolationError("Valid approval token required")
        record["status"] = "APPROVED"
        record["approved_by"] = owner
        record["approval_token_hash"] = hashlib.sha256(approval_token.encode()).hexdigest()
        return SecurityDecision(allowed=True, reason="Approved", action=ActionType.REMEDIATE,
                                target=record["target"], requires_human_approval=True)

    def _find(self, finding_id: str) -> dict[str, Any]:
        for record in self.records:
            if record["finding_id"] == finding_id:
                return record
        raise ValueError(f"Not found: {finding_id}")
