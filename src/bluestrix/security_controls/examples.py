from __future__ import annotations

from bluestrix.core.models import CheckStatus, Evidence, Finding, Severity
from bluestrix.security_controls.control_registry import ControlRegistry, SecurityControl
from bluestrix.security_controls.runtime_guard import RuntimeGuard
from bluestrix.security_controls.secret_redaction import SecretRedactionControl


def build_default_controls() -> ControlRegistry:
    registry = ControlRegistry()
    runtime_guard = RuntimeGuard()
    redactor = SecretRedactionControl()

    def environment_secret_check() -> Finding:
        try:
            runtime_guard.assert_defensive_environment()
            status = CheckStatus.PASS
            severity = Severity.INFO
            recommendation = "No forbidden critical secret environment variables were detected."
        except Exception as exc:
            status = CheckStatus.FAIL
            severity = Severity.CRITICAL
            recommendation = str(exc)

        return Finding(
            title="Critical secret environment check",
            description="Ensures private-key-like environment variables are not present in the runtime.",
            severity=severity,
            status=status,
            category="secret_protection",
            target="runtime_environment",
            evidence=[Evidence(source="runtime_guard", kind="environment_check", value=status.value)],
            recommendation=recommendation,
            confidence=0.95,
        )

    def redaction_self_test() -> Finding:
        sample = "api_key = 'supersecretvalue123456'"
        redacted = redactor.redact_text(sample)
        passed = "supersecretvalue123456" not in redacted

        return Finding(
            title="Secret redaction self-test",
            description="Validates that the redaction control removes likely secrets from text.",
            severity=Severity.INFO if passed else Severity.HIGH,
            status=CheckStatus.PASS if passed else CheckStatus.FAIL,
            category="security_control",
            target="secret_redaction",
            evidence=[Evidence(source="self_test", kind="redaction_test", value=passed)],
            recommendation=(
                "Redaction control is functioning."
                if passed
                else "Secret redaction failed; block report export and investigate immediately."
            ),
            confidence=0.99,
        )

    registry.register(SecurityControl(
        control_id="BSX-CTRL-001",
        name="Critical secret environment check",
        description="Detects forbidden secret-bearing environment variables.",
        check=environment_secret_check,
    ))

    registry.register(SecurityControl(
        control_id="BSX-CTRL-002",
        name="Secret redaction self-test",
        description="Validates secret redaction behavior.",
        check=redaction_self_test,
    ))

    return registry
