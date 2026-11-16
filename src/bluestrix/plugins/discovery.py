"""Plugin / rule-pack discovery (local catalog + optional remote index metadata)."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class PluginMeta:
    plugin_id: str
    name: str
    version: str
    description: str = ""
    kind: str = "custom"  # custom | community | builtin
    author: str = ""
    chains: list[str] = field(default_factory=list)
    path: str = ""
    signature_required: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def discover_local_plugins(root: Path | str) -> list[PluginMeta]:
    root = Path(root)
    found: list[PluginMeta] = []
    if not root.exists():
        return found
    for path in sorted(root.rglob("*")):
        if path.suffix.lower() not in {".json", ".yaml", ".yml"}:
            continue
        if path.name.startswith("."):
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(data, dict) or "name" not in data:
            continue
        plugin_id = str(data.get("plugin_id") or data.get("name") or path.stem)
        found.append(
            PluginMeta(
                plugin_id=plugin_id,
                name=str(data.get("name")),
                version=str(data.get("version") or "0.0.0"),
                description=str(data.get("description") or ""),
                kind=str(data.get("kind") or "custom"),
                author=str(data.get("author") or ""),
                chains=list(data.get("chains") or []),
                path=str(path),
                signature_required=str(data.get("kind") or "").lower() == "community",
            )
        )
    return found


def search_plugins(
    catalog: list[PluginMeta],
    *,
    query: Optional[str] = None,
    kind: Optional[str] = None,
    chain: Optional[str] = None,
) -> list[PluginMeta]:
    q = (query or "").lower().strip()
    out: list[PluginMeta] = []
    for p in catalog:
        if kind and p.kind != kind:
            continue
        if chain and chain.lower() not in [c.lower() for c in p.chains] and p.chains:
            continue
        if q and q not in p.name.lower() and q not in p.description.lower() and q not in p.plugin_id.lower():
            continue
        out.append(p)
    return out
