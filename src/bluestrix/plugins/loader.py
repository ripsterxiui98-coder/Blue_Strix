"""Load rule packs from disk: validate manifest, signature, register rules."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from bluestrix.plugins.registry import RuleRegistry
from bluestrix.plugins.rules import rule_from_dict
from bluestrix.plugins.signing import verify_rule_pack_signature

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover
    yaml = None


def _read_manifest(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        if yaml is None:
            raise RuntimeError("PyYAML required to load YAML manifests")
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("manifest must be an object")
    return data


def validate_manifest(manifest: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if "name" not in manifest:
        errors.append("missing name")
    if "version" not in manifest:
        errors.append("missing version")
    rules = manifest.get("rules")
    if not isinstance(rules, list) or not rules:
        errors.append("rules must be a non-empty list")
    kind = str(manifest.get("kind") or "custom").lower()
    if kind not in {"custom", "community", "builtin"}:
        errors.append("invalid kind")
    return errors


class PluginLoader:
    def __init(
        self,
        registry: Optional[RuleRegistry] = None,
        *,
        require_signature_for_community: bool = True,
    ) -> None:
        self.registry = registry or RuleRegistry()
        self.require_signature_for_community = require_signature_for_community

    # fix typo - Python __init__
    def __init__(
        self,
        registry: Optional[RuleRegistry] = None,
        *,
        require_signature_for_community: bool = True,
    ) -> None:
        self.registry = registry or RuleRegistry()
        self.require_signature_for_community = require_signature_for_community

    def load_manifest(
        self,
        manifest: dict[str, Any],
        *,
        hmac_secret: Optional[str] = None,
    ) -> dict[str, Any]:
        errors = validate_manifest(manifest)
        if errors:
            raise ValueError("invalid manifest: " + "; ".join(errors))

        kind = str(manifest.get("kind") or "custom").lower()
        require_sig = kind == "community" and self.require_signature_for_community
        if not verify_rule_pack_signature(
            manifest, secret=hmac_secret, require_signature=require_sig
        ):
            raise ValueError("rule pack signature verification failed")

        loaded = 0
        for item in manifest["rules"]:
            if not isinstance(item, dict):
                raise ValueError("each rule must be an object")
            item = dict(item)
            item.setdefault("source", kind if kind != "builtin" else "builtin")
            rule = rule_from_dict(item)
            self.registry.register(rule, replace=True)
            loaded += 1

        return {
            "name": manifest.get("name"),
            "version": manifest.get("version"),
            "kind": kind,
            "rules_loaded": loaded,
            "signature_ok": True,
        }

    def load_file(self, path: Path | str, **kwargs: Any) -> dict[str, Any]:
        path = Path(path)
        manifest = _read_manifest(path)
        return self.load_manifest(manifest, **kwargs)


def load_plugins_from_directory(
    directory: Path | str,
    *,
    registry: Optional[RuleRegistry] = None,
    require_signature_for_community: bool = True,
) -> tuple[RuleRegistry, list[dict[str, Any]]]:
    root = Path(directory)
    loader = PluginLoader(
        registry or RuleRegistry(),
        require_signature_for_community=require_signature_for_community,
    )
    reports: list[dict[str, Any]] = []
    if not root.exists():
        return loader.registry, reports
    for path in sorted(root.rglob("*")):
        if path.suffix.lower() not in {".json", ".yaml", ".yml"}:
            continue
        if path.name.startswith("."):
            continue
        reports.append(loader.load_file(path))
    return loader.registry, reports
