from __future__ import annotations

from typing import Any

from bluestrix.security_controls.input_validation import InputValidator


class TransactionRiskAnalyzer:
    def __init__(self) -> None:
        self.validator = InputValidator()

    def analyze(self, transaction: dict[str, Any]) -> dict[str, Any]:
        risk = 0
        reasons = []
        value = self._safe_float(transaction.get("value_eth", 0))
        if value >= 1:
            risk += 25
            reasons.append("High-value transfer")
        if transaction.get("is_token_approval"):
            risk += 20
            reasons.append("Token approval requested")
        if transaction.get("unlimited_approval"):
            risk += 30
            reasons.append("Unlimited token approval requested")
        if transaction.get("unknown_contract"):
            risk += 20
            reasons.append("Unknown contract")
        if transaction.get("urgent_request"):
            risk += 15
            reasons.append("Urgency indicator")
        recipient = self.validator.clean_text(str(transaction.get("to", "")), 128)
        if not self.validator.is_probable_blockchain_address(recipient):
            risk += 20
            reasons.append("Invalid recipient format")

        risk = min(risk, 100)
        level = "LOW" if risk < 30 else "MEDIUM" if risk < 60 else "HIGH" if risk < 85 else "CRITICAL"
        return {"risk_score": risk, "risk_level": level, "reasons": reasons,
                "recommendation": "Verify before signing." if risk >= 30 else "Review before signing."}

    def _safe_float(self, value: Any) -> float:
        try:
            return max(0.0, float(value))
        except (TypeError, ValueError):
            return 0.0
