"""Versioned rule registry for builtin, custom, and community rules."""

from __future__ import annotations

from typing import Iterable, Optional

from bluestrix.plugins.rules import SecurityRule, match_rule
from bluestrix.plugins.sandbox import run_in_sandbox, sandboxed_regex_search


class RuleRegistry:
    def __init__(self) -> None:
        self._rules: dict[str, SecurityRule] = {}
        # rule_id -> sorted list of versions (latest last)
        self._versions: dict[str, list[SecurityRule]] = {}

    def register(self, rule: SecurityRule, *, replace: bool = False) -> None:
        key = rule.rule_id
        history = self._versions.setdefault(key, [])
        if any(r.version == rule.version for r in history):
            if not replace:
                raise ValueError(f"rule {key}@{rule.version} already registered")
            history[:] = [r for r in history if r.version != rule.version]
        history.append(rule)
        history.sort(key=lambda r: _version_key(r.version))
        self._rules[key] = history[-1]

    def get(self, rule_id: str, version: Optional[str] = None) -> Optional[SecurityRule]:
        if version is None:
            return self._rules.get(rule_id)
        for r in self._versions.get(rule_id, []):
            if r.version == version:
                return r
        return None

    def list_rules(
        self,
        *,
        source: Optional[str] = None,
        language: Optional[str] = None,
        enabled_only: bool = True,
    ) -> list[SecurityRule]:
        out: list[SecurityRule] = []
        for rule in self._rules.values():
            if enabled_only and not rule.enabled:
                continue
            if source and rule.source != source:
                continue
            if language and rule.language not in {"any", language.lower()}:
                continue
            out.append(rule)
        return sorted(out, key=lambda r: r.rule_id)

    def versions(self, rule_id: str) -> list[str]:
        return [r.version for r in self._versions.get(rule_id, [])]

    def test_rule(self, rule: SecurityRule, sample: str, *, language: Optional[str] = None) -> dict:
        """Test a rule against a sample string inside the sandbox."""

        def _match() -> bool:
            if language and rule.language not in {"any", language.lower()}:
                return False
            m = sandboxed_regex_search(rule.pattern, sample)
            return m is not None

        matched = run_in_sandbox(_match)
        return {
            "rule_id": rule.rule_id,
            "version": rule.version,
            "matched": matched,
            "severity": rule.severity,
        }

    def scan_content(
        self, content: str, *, language: Optional[str] = None
    ) -> list[dict]:
        findings: list[dict] = []
        for rule in self.list_rules(language=language):
            ok = run_in_sandbox(match_rule, rule, content, language=language)
            if ok:
                findings.append(
                    {
                        "rule_id": rule.rule_id,
                        "title": rule.title,
                        "severity": rule.severity,
                        "description": rule.description,
                        "recommendation": rule.recommendation,
                        "cwe_id": rule.cwe_id,
                        "version": rule.version,
                        "source": rule.source,
                    }
                )
        return findings


def _version_key(v: str) -> tuple:
    parts: list = []
    for p in str(v).split("."):
        if p.isdigit():
            parts.append(int(p))
        else:
            parts.append(p)
    return tuple(parts)
