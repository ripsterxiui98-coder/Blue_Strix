from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from bluestrix.core.models import CheckStatus, Evidence, Finding, Severity
from bluestrix.intelligence.code.rules import LANGUAGE_EXTENSIONS, RULES_BY_LANGUAGE
from bluestrix.security_controls.file_integrity import FileIntegrityControl
from bluestrix.security_controls.input_validation import InputValidator


class CodeIntelligenceEngine:
    def __init__(self, max_file_size_mb: int = 10) -> None:
        self.max_file_size_bytes = max_file_size_mb * 1024 * 1024
        self.validator = InputValidator()
        self.integrity = FileIntegrityControl()

    def analyze_path(self, root: str | Path, languages: Iterable[str] | None = None) -> list[Finding]:
        root_path = Path(root).expanduser().resolve()
        if not root_path.exists():
            raise FileNotFoundError(f"Analysis target does not exist: {root_path}")

        selected = set(languages or RULES_BY_LANGUAGE.keys())
        findings: list[Finding] = []

        for file_path in sorted(root_path.rglob("*")):
            if not file_path.is_file():
                continue
            language = LANGUAGE_EXTENSIONS.get(file_path.suffix.lower())
            if not language or language not in selected:
                continue
            if file_path.stat().st_size > self.max_file_size_bytes:
                continue
            try:
                content = file_path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            findings.extend(self._analyze_content(file_path, language, content))

        return findings

    def _analyze_content(self, file_path: Path, language: str, content: str) -> list[Finding]:
        findings = []
        digest = self.integrity.sha256(content.encode("utf-8"))
        for rule in RULES_BY_LANGUAGE.get(language, ()):
            for match in re.finditer(rule.pattern, content, re.MULTILINE):
                line = content.count("\n", 0, match.start()) + 1
                findings.append(Finding(
                    title=rule.title,
                    description=rule.description,
                    severity=rule.severity,
                    status=CheckStatus.FAIL,
                    category="code_intelligence",
                    target=str(file_path),
                    evidence=[
                        Evidence(source="static_analysis", kind="pattern_match",
                                 value=self.validator.truncate(match.group(0), 240),
                                 location=f"{file_path}:{line}"),
                        Evidence(source="file_integrity", kind="sha256", value=digest),
                    ],
                    recommendation=rule.recommendation,
                    references=list(rule.references),
                    confidence=0.65,
                    metadata={"rule_id": rule.rule_id, "language": language, "line": line, "cwe_id": rule.cwe_id},
                ))
        return findings
