from __future__ import annotations

from bluestrix.core.models import ActionType, SecurityDecision


class HumanApprovalGate:
    """Human approval gate for potentially state-changing actions."""

    APPROVAL_REQUIRED = {
        ActionType.WRITE,
        ActionType.DEPLOY,
        ActionType.TRANSFER,
        ActionType.SIGN,
        ActionType.EXECUTE,
        ActionType.REMEDIATE,
    }

    def evaluate(self, action: ActionType, target: str, approved: bool = False) -> SecurityDecision:
        requires_approval = action in self.APPROVAL_REQUIRED

        if requires_approval and not approved:
            return SecurityDecision(
                allowed=False,
                reason=f"Action '{action.value}' requires explicit human approval",
                action=action,
                target=target,
                requires_human_approval=True,
            )

        return SecurityDecision(
            allowed=True,
            reason="Action authorized by human approval" if requires_approval else "Read-only action allowed",
            action=action,
            target=target,
            requires_human_approval=requires_approval,
        )
