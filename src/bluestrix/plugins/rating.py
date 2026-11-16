"""In-memory / file-backed plugin ratings (1-5). No secrets."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class RatingStore:
    path: Optional[Path] = None
    _data: dict[str, list[int]] = field(default_factory=dict)

    def load(self) -> None:
        if not self.path or not self.path.exists():
            return
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        self._data = {k: [int(x) for x in v] for k, v in raw.items()}

    def save(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._data, indent=2), encoding="utf-8")

    def rate(self, plugin_id: str, score: int) -> dict:
        if score < 1 or score > 5:
            raise ValueError("score must be 1..5")
        self._data.setdefault(plugin_id, []).append(score)
        self.save()
        return self.summary(plugin_id)

    def summary(self, plugin_id: str) -> dict:
        scores = self._data.get(plugin_id) or []
        if not scores:
            return {"plugin_id": plugin_id, "count": 0, "average": None}
        return {
            "plugin_id": plugin_id,
            "count": len(scores),
            "average": round(sum(scores) / len(scores), 2),
        }
