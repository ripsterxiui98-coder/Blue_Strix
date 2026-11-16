"""Plugin marketplace: discover, install, update, uninstall — always via sandbox loader."""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from bluestrix.plugins.discovery import PluginMeta, discover_local_plugins, search_plugins
from bluestrix.plugins.loader import PluginLoader
from bluestrix.plugins.rating import RatingStore
from bluestrix.plugins.registry import RuleRegistry
from bluestrix.plugins.review import ReviewStore


@dataclass
class Marketplace:
    catalog_dir: Path
    install_dir: Path
    registry: RuleRegistry = field(default_factory=RuleRegistry)
    ratings: RatingStore = field(default_factory=RatingStore)
    reviews: ReviewStore = field(default_factory=ReviewStore)
    require_signature_for_community: bool = True

    def __post_init__(self) -> None:
        self.catalog_dir = Path(self.catalog_dir)
        self.install_dir = Path(self.install_dir)
        self.install_dir.mkdir(parents=True, exist_ok=True)
        if self.ratings.path is None:
            self.ratings.path = self.install_dir / ".ratings.json"
            self.ratings.load()
        if self.reviews.path is None:
            self.reviews.path = self.install_dir / ".reviews.json"
            self.reviews.load()

    def discover(self, **filters: Any) -> list[dict[str, Any]]:
        catalog = discover_local_plugins(self.catalog_dir)
        catalog += discover_local_plugins(self.install_dir)
        return [p.to_dict() for p in search_plugins(catalog, **filters)]

    def get_plugin(self, plugin_id: str) -> Optional[PluginMeta]:
        for p in discover_local_plugins(self.catalog_dir) + discover_local_plugins(self.install_dir):
            if p.plugin_id == plugin_id or p.name == plugin_id:
                return p
        return None

    def install(
        self,
        source_path: Path | str,
        *,
        hmac_secret: Optional[str] = None,
    ) -> dict[str, Any]:
        """Copy pack into install_dir and load through PluginLoader (sandbox + signature)."""
        source = Path(source_path)
        if not source.is_file():
            raise FileNotFoundError(str(source))
        dest = self.install_dir / source.name
        shutil.copy2(source, dest)
        loader = PluginLoader(
            self.registry,
            require_signature_for_community=self.require_signature_for_community,
        )
        try:
            report = loader.load_file(dest, hmac_secret=hmac_secret)
        except Exception:
            dest.unlink(missing_ok=True)
            raise
        return {"installed_path": str(dest), "load": report}

    def update(
        self,
        plugin_id: str,
        source_path: Path | str,
        *,
        hmac_secret: Optional[str] = None,
    ) -> dict[str, Any]:
        existing = self.get_plugin(plugin_id)
        if existing and existing.path and Path(existing.path).parent == self.install_dir:
            Path(existing.path).unlink(missing_ok=True)
        return self.install(source_path, hmac_secret=hmac_secret)

    def uninstall(self, plugin_id: str) -> dict[str, Any]:
        meta = self.get_plugin(plugin_id)
        if meta is None:
            return {"removed": False, "reason": "not found"}
        path = Path(meta.path)
        if path.exists() and self.install_dir in path.resolve().parents or path.parent == self.install_dir:
            path.unlink(missing_ok=True)
            return {"removed": True, "path": str(path)}
        return {
            "removed": False,
            "reason": "refusing to delete outside install_dir (catalog is read-only)",
        }

    def rate(self, plugin_id: str, score: int) -> dict:
        return self.ratings.rate(plugin_id, score)

    def review(self, plugin_id: str, author: str, body: str, score: Optional[int] = None) -> dict:
        r = self.reviews.add(plugin_id, author, body, score=score)
        if score is not None:
            self.ratings.rate(plugin_id, score)
        return asdict_review(r)


def asdict_review(r: Any) -> dict:
    from dataclasses import asdict

    return asdict(r)
