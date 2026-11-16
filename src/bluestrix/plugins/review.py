"""Plugin reviews (text + optional rating). Stored without PII requirement."""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass
class Review:
    review_id: str
    plugin_id: str
    author: str
    body: str
    score: Optional[int] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class ReviewStore:
    path: Optional[Path] = None
    _items: list[dict] = field(default_factory=list)

    def load(self) -> None:
        if not self.path or not self.path.exists():
            return
        self._items = json.loads(self.path.read_text(encoding="utf-8"))

    def save(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._items, indent=2), encoding="utf-8")

    def add(
        self, plugin_id: str, author: str, body: str, score: Optional[int] = None
    ) -> Review:
        if score is not None and (score < 1 or score > 5):
            raise ValueError("score must be 1..5")
        if not body.strip():
            raise ValueError("body required")
        review = Review(
            review_id=str(uuid.uuid4()),
            plugin_id=plugin_id,
            author=author[:128],
            body=body[:4000],
            score=score,
        )
        self._items.append(asdict(review))
        self.save()
        return review

    def list_for(self, plugin_id: str) -> list[dict]:
        return [r for r in self._items if r.get("plugin_id") == plugin_id]
