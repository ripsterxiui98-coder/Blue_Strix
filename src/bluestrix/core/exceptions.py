class BlueStrixError(Exception):
    """Base exception for BlueStrix."""


class PolicyViolationError(BlueStrixError):
    """Raised when an operation violates security policy."""


class ScopeViolationError(PolicyViolationError):
    """Raised when a target is outside authorized scope."""


class ConfigurationError(BlueStrixError):
    """Raised when configuration is invalid or incomplete."""


class IntegrationUnavailableError(BlueStrixError):
    """Raised when an optional integration is unavailable."""
