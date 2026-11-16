from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from bluestrix.core.exceptions import IntegrationUnavailableError
from bluestrix.core.models import CheckStatus, Evidence, Finding, Severity
from bluestrix.security_controls.input_validation import InputValidator


class SlitherAdapter:
    SEVERITY_MAP = {"High": Severity.HIGH, "Medium": Severity.MEDIUM, "Low": Severity.LOW, "Informational": Severity.INFO}
    CONFIDENCE_MAP = {"High": 0.85, "Medium": 0.70, "Low": 0.55}

    def __init__(self, binary: str = "slither", timeout_seconds: int = 300) -> None:
        self.binary = binary
        self.timeout_seconds = timeout_seconds
        self.validator = InputValidator()

    def is_available(self) -> bool:
        try:
            result = subprocess.run([self.binary, "--version"], capture_output=True, text=True, timeout=15, check=False)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def analyze(self, target: str | Path, extra_args: list[str] | None = None) -> list[Finding]:
        target_path = Path(target).expanduser().resolve()
        if not target_path.exists():
            raise FileNotFoundError(f"Target not found: {target_path}")
        if not self.is_available():
            raise IntegrationUnavailableError("Slither unavailable")

        command = [self.binary, str(target_path), "--json", "-"]
        if extra_args:
            command.extend(self.validator.validate_cli_arguments(extra_args))

        result = subprocess.run(command, capture_output=True, text=True, timeout=self.timeout_seconds, check=False)
        payload = json.loads(result.stdout or "{}")
        if not payload.get("success", False):
            raise RuntimeError(f"Slither failed: {payload.get('error')}")

        return self._normalize(payload, target_path)

    def _normalize(self, payload: dict[str, Any], target_path: Path) -> list[Finding]:
        findings = []
        for detector in payload.get("results", {}).get("detectors", []):
            findings.append(Finding(
                title=self.validator.truncate(str(detector.get("check", "slither-finding")), 180),
                description=self.validator.truncate(str(detector.get("description", "")), 4000),
                severity=self.SEVERITY_MAP.get(str(detector.get("impact", "Informational")), Severity.INFO),
                status=CheckStatus.FAIL,
                category="external_static_analysis",
                target=str(target_path),
                evidence=[Evidence(source="slither", kind="detector_result",
                                   value={"check": detector.get("check"), "impact": detector.get("impact")})],
                recommendation="Review finding in source context.",
                confidence=self.CONFIDENCE_MAP.get(str(detector.get("confidence", "Medium")), 0.65),
                metadata={"engine": "slither", "detector": detector.get("check")},
            ))
        return findings
