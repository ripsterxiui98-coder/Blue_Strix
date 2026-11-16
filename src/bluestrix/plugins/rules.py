"""Custom security rule model (declarative, versioned)."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

ALLOWED_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
ALLOWED_LANGUAGES = {
    "solidity",
    "python",
    "rust",
    "move",
    "typescript",
    "javascript",
    "go",
    "any",
}


@dataclass(frozen=True)
class SecurityRule:
    rule_id: str
    title: str
    description: str
    severity: str
    language: str
    pattern: str
    recommendation: str = ""
    references: tuple[str, ...] = ()
    cwe_id: Optional[str] = None
    version: str = "1.0.0"
    source: str = "custom"  # custom | community | builtin
    enabled: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["references"] = list(self.references)
        return d


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def rule_from_dict(data: dict[str, Any]) -> SecurityRule:
    rule_id = str(data.get("rule_id") or "").strip()
    title = str(data.get("title") or "").strip()
    description = str(data.get("description") or "").strip()
    severity = str(data.get("severity") or "INFO").upper()
    language = str(data.get("language") or "any").lower()
    pattern = str(data.get("pattern") or "")
    version = str(data.get("version") or "1.0.0")
    source = str(data.get("source") or "custom").lower()

    _require(bool(rule_id), "rule_id is required")
    _require(bool(re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,63}$", rule_id)), "invalid rule_id")
    _require(bool(title), "title is required")
    _require(severity in ALLOWED_SEVERITIES, f"invalid severity: {severity}")
    _require(language in ALLOWED_LANGUAGES, f"invalid language: {language}")
    _require(bool(pattern), "pattern is required")
    _require(len(pattern) <= 4000, "pattern too long")
    # Reject obvious code-exec patterns in declarative rules
    banned = ("__import__", "eval(", "exec(", "os.system", "subprocess", "open(")
    low = pattern.lower()
    _require(not any(b in low for b in banned), "pattern must be declarative (no code execution)")

    refs = data.get("references") or []
    if not isinstance(refs, (list, tuple)):
        refs = [str(refs)]

    return SecurityRule(
        rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        language=language,
        pattern=pattern,
        recommendation=str(data.get("recommendation") or ""),
        references=tuple(str(r) for r in refs),
        cwe_id=str(data["cwe_id"]) if data.get("cwe_id") else None,
        version=version,
        source=source if source in {"custom", "community", "builtin"} else "custom",
        enabled=bool(data.get("enabled", True)),
        metadata=dict(data.get("metadata") or {}),
    )


def match_rule(rule: SecurityRule, content: str, *, language: Optional[str] = None) -> bool:
    """Apply declarative pattern (regex) against content. No code execution."""
    if not rule.enabled:
        return False
    if language and rule.language not in {"any", language.lower()}:
        return False
    try:
        return re.search(rule.pattern, content, flags=re.MULTILINE) is not None
    except re.error:
        return False
