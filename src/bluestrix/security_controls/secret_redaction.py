from __future__ import annotations

import re
from typing import Any

SECRET_PATTERNS = (
    re.compile(r"(?i)(?:api[_-]?key|secret|password|token)\s*[:=]\s*[\"'][^\"']{8,}[\"']"),
    re.compile(r"(?i)(?:private[_-]?key|seed[_-]?phrase|mnemonic)\s*[:=]\s*[\"'][^\"']{8,}[\"']"),
    re.compile(r"\b[0-9a-fA-F]{64}\b"),
)


class SecretRedactionControl:
    REDACTED = "[REDACTED]"

    def redact_text(self, text: str) -> str:
        if not isinstance(text, str):
            return self.REDACTED
        redacted = text
        for pattern in SECRET_PATTERNS:
            redacted = pattern.sub(self.REDACTED, redacted)
        return redacted

    def redact_object(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.redact_text(value)
        if isinstance(value, dict):
            return {key: self.redact_object(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.redact_object(item) for item in value]
        return value
