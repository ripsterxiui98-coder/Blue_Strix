"""BlueStrix AI gateway foundation: settings validation, redaction, health, bounded adapter.

Not wired into the API or the AIRouter in this change. See docs/ai-gateway/architecture.md.
"""

from bluestrix.gateway.adapter import (
    GatewayAdapter,
    HttpxTransport,
    Transport,
    TransportError,
    TransportResponse,
    TransportTimeout,
    resolve_api_key,
)
from bluestrix.gateway.health import liveness, readiness
from bluestrix.gateway.redaction import REDACTED, RedactingFilter, SecretRegistry
from bluestrix.gateway.settings import (
    Environment,
    EnvironmentReport,
    GatewaySettings,
    assess_environment,
    provider_key_status,
    validate_base_url,
    validate_environment,
)

__all__ = [
    "Environment",
    "EnvironmentReport",
    "GatewayAdapter",
    "GatewaySettings",
    "HttpxTransport",
    "REDACTED",
    "RedactingFilter",
    "SecretRegistry",
    "Transport",
    "TransportError",
    "TransportResponse",
    "TransportTimeout",
    "assess_environment",
    "liveness",
    "provider_key_status",
    "readiness",
    "resolve_api_key",
    "validate_base_url",
    "validate_environment",
]
