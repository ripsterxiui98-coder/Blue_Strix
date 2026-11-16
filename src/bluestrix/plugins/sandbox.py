"""Mandatory sandbox for plugin-side evaluation. No network, no FS write, no imports."""

from __future__ import annotations

import re
from typing import Any, Callable, Optional


class SandboxViolation(RuntimeError):
    pass


# Explicitly deny dangerous names if a restricted callable is ever used
_FORBIDDEN_NAMES = frozenset(
    {
        "__import__",
        "eval",
        "exec",
        "open",
        "compile",
        "input",
        "breakpoint",
        "globals",
        "locals",
        "vars",
        "getattr",
        "setattr",
        "delattr",
        "classmethod",
        "staticmethod",
        "type",
        "help",
        "exit",
        "quit",
    }
)


def assert_safe_pattern(pattern: str) -> None:
    if len(pattern) > 4000:
        raise SandboxViolation("pattern exceeds size limit")
    lowered = pattern.lower()
    for name in _FORBIDDEN_NAMES:
        if name in lowered:
            raise SandboxViolation(f"forbidden construct in pattern: {name}")


def run_in_sandbox(
    fn: Callable[..., Any],
    *args: Any,
    timeout_hint_ms: int = 100,
    **kwargs: Any,
) -> Any:
    """Execute a trusted internal callable under policy checks.

    BlueStrix does not eval user Python. Custom rules use declarative regex only.
    This wrapper enforces that plugin callbacks are the known safe matchers.
    """
    name = getattr(fn, "__name__", "")
    module = getattr(fn, "__module__", "")
    if not str(module).startswith("bluestrix.plugins"):
        raise SandboxViolation(
            f"refusing to run non-plugin callable outside sandbox policy: {module}.{name}"
        )
    if timeout_hint_ms <= 0 or timeout_hint_ms > 5000:
        raise SandboxViolation("invalid timeout")
    return fn(*args, **kwargs)


def sandboxed_regex_search(pattern: str, content: str, flags: int = re.MULTILINE) -> Optional[re.Match[str]]:
    assert_safe_pattern(pattern)
    try:
        return re.search(pattern, content, flags=flags)
    except re.error as exc:
        raise SandboxViolation(f"invalid regex: {exc}") from exc
