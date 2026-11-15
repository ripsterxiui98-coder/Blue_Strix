from __future__ import annotations

from pathlib import Path

from bluestrix.core.exceptions import PolicyViolationError
from bluestrix.core.models import ActionType, SecurityDecision
from bluestrix.governance.approval import HumanApprovalGate
from bluestrix.policy.scope import ScopeEnforcer


class PolicyEngine:
    """Central policy decision point."""

    def __init__(
        self,
        config: dict,
        scope: ScopeEnforcer,
        approval_gate: HumanApprovalGate | None = None,
    ) -> None:
        self.config = config
        self.scope = scope
        self.approval_gate = approval_gate or HumanApprovalGate()

        if config.get("policy", {}).get("allow_policy_modification_by_ai", True):
            raise PolicyViolationError("AI must not be allowed to modify its own security policy")

    def authorize(
        self,
        action: ActionType,
        target: str,
        approved: bool = False,
    ) -> SecurityDecision:
        self.scope.enforce(target, action=action.value)
        decision = self.approval_gate.evaluate(action, target, approved=approved)

        if not decision.allowed:
            raise PolicyViolationError(decision.reason)

        return decision

    def validate_files(self) -> list[str]:
        policy = self.config.get("policy", {})
        required_files = [
            policy.get("security_constitution"),
            policy.get("scope_policy"),
            policy.get("action_levels"),
            policy.get("data_classification"),
        ]

        errors: list[str] = []
        for file_path in required_files:
            if not file_path:
                errors.append("Missing policy file configuration")
            elif not Path(file_path).exists():
                errors.append(f"Policy file not found: {file_path}")

        return errors
