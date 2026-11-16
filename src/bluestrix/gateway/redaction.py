"""Credential redaction for logs, exception text, and outbound data.

Secrets are redacted by exact value (registered at startup), by known credential shapes
(Bearer tokens, ``sk-`` keys, API-key headers), and by the repository's existing patterns in
``bluestrix.security_controls.secret_redaction``. Redaction is a defense-in-depth layer; code
must still avoid passing secrets into log calls.
"""

from __future__ import annotations

import logging
import re
import threading
import traceback
from typing import Any, Iterable, Mapping

from bluestrix.security_controls.secret_redaction import SecretRedactionControl

REDACTED = "[REDACTED]"
MIN_REGISTERED_LENGTH = 8
SENSITIVE_HEADER_NAMES = frozenset(
    {"authorization", "proxy-authorization", "x-api-key", "api-key", "cookie", "set-cookie"}
)

_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}")
_SK_KEY = re.compile(r"\bsk-[A-Za-z0-9_-]{16,}")
_HEADER_VALUE = re.compile(r"(?i)\b(x-api-key|api-key|authorization)\s*[:=]\s*\S+")
_EXISTING_PATTERNS = SecretRedactionControl()


class SecretRegistry:
    """Thread-safe set of exact secret values to redact from any text."""

    def __init__(self) -> None:
        self._values: set[str] = set()
        self._lock = threading.Lock()

    def register(self, value: str | None) -> None:
        if not value:
            return
        candidate = value.strip()
        if len(candidate) < MIN_REGISTERED_LENGTH:
            return
        with self._lock:
            self._values.add(candidate)

    def register_from_env(self, env: Mapping[str, str], names: Iterable[str]) -> None:
        for name in names:
            self.register(env.get(name))

    def __len__(self) -> int:
        with self._lock:
            return len(self._values)

    def redact(self, text: str) -> str:
        with self._lock:
            values = sorted(self._values, key=len, reverse=True)
        out = str(text)
        for value in values:
            out = out.replace(value, REDACTED)
        out = _BEARER.sub(f"Bearer {REDACTED}", out)
        out = _SK_KEY.sub(REDACTED, out)
        out = _HEADER_VALUE.sub(lambda m: f"{m.group(1)}: {REDACTED}", out)
        return _EXISTING_PATTERNS.redact_text(out)

    def redact_data(self, value: Any) -> Any:
        """Redact nested data: drop sensitive header-like keys, redact string values."""
        if isinstance(value, Mapping):
            cleaned: dict[Any, Any] = {}
            for key, item in value.items():
                if isinstance(key, str) and key.lower() in SENSITIVE_HEADER_NAMES:
                    cleaned[key] = REDACTED
                else:
                    cleaned[key] = self.redact_data(item)
            return cleaned
        if isinstance(value, (list, tuple)):
            return [self.redact_data(item) for item in value]
        if isinstance(value, str):
            return self.redact(value)
        return value

    def safe_error(self, exc: BaseException, limit: int = 200) -> str:
        """Short, credential-free description of an exception."""
        return f"{type(exc).__name__}: {self.redact(str(exc))[:limit]}"


class RedactingFilter(logging.Filter):
    """Logging filter that redacts messages and tracebacks before any handler writes them."""

    def __init__(self, registry: SecretRegistry) -> None:
        super().__init__()
        self.registry = registry

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # malformed format args: keep a redacted raw form
            message = str(record.msg)
        record.msg = self.registry.redact(message)
        record.args = ()
        if record.exc_info:
            rendered = "".join(traceback.format_exception(*record.exc_info))
            record.exc_text = self.registry.redact(rendered)
            record.exc_info = None
        return True
