import pytest

from bluestrix.core.models import ActionType
from bluestrix.governance.approval import HumanApprovalGate


@pytest.mark.parametrize("action", [ActionType.WRITE, ActionType.DEPLOY, ActionType.TRANSFER,
                                    ActionType.SIGN, ActionType.EXECUTE, ActionType.REMEDIATE])
def test_dangerous_actions_require_approval(action):
    decision = HumanApprovalGate().evaluate(action, "target", approved=False)
    assert not decision.allowed
