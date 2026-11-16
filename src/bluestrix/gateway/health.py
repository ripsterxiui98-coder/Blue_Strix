"""Health checks for the AI gateway.

- ``liveness()`` answers "is the process running". No I/O, no secrets, no providers.
- ``readiness(env)`` answers "is configuration valid". It accepts only the environment mapping:
  it has no transport or adapter parameter, so it cannot send a provider request.

Responses never include configuration problem text, which can reveal deployment details to
unauthenticated callers. Problems are available via ``assess_environment`` for server-side logs.
"""

from __future__ import annotations

from typing import Any, Mapping

from bluestrix.gateway.settings import assess_environment, provider_key_status


def liveness() -> dict[str, str]:
    return {"status": "ok"}


def readiness(env: Mapping[str, str]) -> tuple[bool, dict[str, Any]]:
    report = assess_environment(env)
    configured = sum(1 for present in provider_key_status(env).values() if present)
    body: dict[str, Any] = {
        "status": "ready" if report.ok else "not_ready",
        "environment": report.environment.value,
        "checks": {
            "configuration": "ok" if report.ok else "invalid",
            "ai_providers_configured": configured,
        },
    }
    return report.ok, body
