from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from bluestrix.core.models import CheckStatus, Finding, Severity
from bluestrix.security_controls.input_validation import InputValidator


@dataclass(frozen=True)
class SecurityControl:
    control_id: str
    name: str
    description: str
    check: Callable[[], Finding]


class ControlRegistry:
    def __init__(self) -> None:
        self.controls: dict[str, SecurityControl] = {}
        self.validator = InputValidator()

    def register(self, control: SecurityControl) -> None:
        control_id = self.validator.validate_identifier(control.control_id)
        if control_id in self.controls:
            raise ValueError(f"Control already registered: {control_id}")
        self.controls[control_id] = control

    def run_all(self) -> list[Finding]:
        findings: list[Finding] = []
        for control in sorted(self.controls.values(), key=lambda item: item.control_id):
            try:
                findings.append(control.check())
            except Exception as exc:
                findings.append(
                    Finding(
                        title=f"Security control failed: {control.name}",
                        description=f"Control {control.control_id} could not complete: {exc}",
                        severity=Severity.MEDIUM,
                        status=CheckStatus.UNAVAILABLE,
                        category="security_control",
                        target=control.control_id,
                        recommendation="Investigate control failure; do not treat an unavailable control as PASS.",
                    )
                )
        return findings

    def status(self) -> dict[str, str]:
        return {control_id: "REGISTERED" for control_id in sorted(self.controls)}
