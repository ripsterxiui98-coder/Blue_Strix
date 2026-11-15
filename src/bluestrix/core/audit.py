from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from bluestrix.core.models import AuditEvent


class AuditLog:
    """Append-only JSON Lines audit log."""

    def __init__(self, path: str | Path = "data/audit.jsonl") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(
        self,
        action: str,
        target: str,
        decision: str,
        reason: str,
        actor: str = "system",
        metadata: dict[str, Any] | None = None,
    ) -> AuditEvent:
        event = AuditEvent(
            actor=actor,
            action=action,
            target=target,
            decision=decision,
            reason=reason,
            metadata=metadata or {},
        )
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event.model_dump(mode="json"), separators=(",", ":")) + "\n")
        return event

    def tail(self, limit: int = 50) -> list[AuditEvent]:
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()[-limit:]
        return [AuditEvent.model_validate_json(line) for line in lines if line.strip()]
