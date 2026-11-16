"""Environment validation for the BlueStrix AI gateway (fail-secure).

Rules:
- BLUESTRIX_ENV must be ``development``, ``test``, or ``production``. Unset or unknown values are
  reported as a problem and evaluated with production rules.
- Production requires strong, distinct secrets. Placeholder values and the ephemeral dev JWT
  secret are rejected.
- Error text names environment variables only. It never contains secret values.
- Base URLs for AI providers must be https and must match a fixed host allowlist (SSRF guard).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Mapping
from urllib.parse import urlsplit

from bluestrix.core.exceptions import ConfigurationError
from bluestrix.security_controls.runtime_guard import RuntimeGuard

PLACEHOLDER_VALUES = frozenset(
    {"", "change-me", "changeme", "change-me-generate-a-long-random-string"}
)
MIN_SECRET_LENGTH = 32
MIN_TIMEOUT_SECONDS = 1.0
MAX_TIMEOUT_SECONDS = 120.0
DEFAULT_TIMEOUT_SECONDS = 30.0
MAX_RETRIES_CAP = 3
DEFAULT_MAX_RETRIES = 1

# Provider hosts the gateway is allowed to call. Anything else is rejected (SSRF guard).
PROVIDER_HOST_ALLOWLIST = frozenset(
    {"model.inferx.net", "api.openai.com", "api.anthropic.com", "api.groq.com", "api.meta.ai"}
)

# Provider name -> environment variable that holds its API key. Keys are never stored in YAML.
PROVIDER_KEY_ENV_VARS: dict[str, str] = {
    "deepseek": "DEEPSEEK_API_KEY",
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "groq": "GROQ_API_KEY",
    "meta": "MODEL_API_KEY",
}


class Environment(str, Enum):
    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


@dataclass(frozen=True)
class GatewaySettings:
    """Validated, non-secret gateway settings. Contains no credential values."""

    environment: Environment
    mode: str
    execution: str
    timeout_seconds: float
    max_retries: int
    warnings: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class EnvironmentReport:
    """Result of assessing an environment mapping. ``problems`` never contains values."""

    environment: Environment
    problems: tuple[str, ...]
    warnings: tuple[str, ...]
    settings: GatewaySettings | None

    @property
    def ok(self) -> bool:
        return not self.problems and self.settings is not None


def is_placeholder(value: str | None) -> bool:
    return (value or "").strip().lower() in PLACEHOLDER_VALUES


def validate_base_url(url: str, *, allowed_hosts: frozenset[str] = PROVIDER_HOST_ALLOWLIST) -> str:
    """Return a normalized base URL or raise ConfigurationError (no URL echo in the message)."""
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise ConfigurationError("base URL is malformed") from exc
    if parts.scheme != "https":
        raise ConfigurationError("base URL must use https")
    if parts.username or parts.password:
        raise ConfigurationError("base URL must not contain credentials")
    host = (parts.hostname or "").lower()
    if not host or host not in allowed_hosts:
        raise ConfigurationError("base URL host is not on the provider allowlist")
    if parts.port not in (None, 443):
        raise ConfigurationError("base URL must use the default https port")
    return url.rstrip("/")


def _check_strong_secret(env: Mapping[str, str], name: str, problems: list[str]) -> None:
    value = (env.get(name) or "").strip()
    if is_placeholder(value):
        problems.append(f"{name} is missing or a placeholder")
    elif len(value) < MIN_SECRET_LENGTH:
        problems.append(f"{name} must be at least {MIN_SECRET_LENGTH} characters")


def _parse_number(
    env: Mapping[str, str],
    name: str,
    default: float,
    low: float,
    high: float,
    problems: list[str],
) -> float:
    raw = (env.get(name) or "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        problems.append(f"{name} must be a number")
        return default
    if not low <= value <= high:
        problems.append(f"{name} must be between {low:g} and {high:g}")
        return default
    return value


def assess_environment(env: Mapping[str, str]) -> EnvironmentReport:
    """Evaluate an environment mapping without raising. Use this for readiness checks."""
    problems: list[str] = []
    warnings: list[str] = []

    raw_env = (env.get("BLUESTRIX_ENV") or "").strip().lower()
    valid_envs = {e.value for e in Environment}
    if raw_env in valid_envs:
        environment = Environment(raw_env)
    else:
        environment = Environment.PRODUCTION
        problems.append(
            "BLUESTRIX_ENV is unset or invalid; set development, test, or production "
            "(production rules apply until then)"
        )

    for key in sorted(RuntimeGuard.FORBIDDEN_ENV_KEYS):
        if (env.get(key) or "").strip():
            problems.append(f"{key} must not be set anywhere in the gateway environment")

    mode = (env.get("BLUESTRIX_MODE") or "defensive").strip()
    execution = (env.get("BLUESTRIX_EXECUTION") or "restricted").strip()
    if mode != "defensive":
        problems.append("BLUESTRIX_MODE must be defensive")
    if execution != "restricted":
        problems.append("BLUESTRIX_EXECUTION must be restricted")

    if environment is Environment.PRODUCTION:
        _check_strong_secret(env, "BLUESTRIX_JWT_SECRET", problems)
        _check_strong_secret(env, "BLUESTRIX_MFA_KEY", problems)
        if (env.get("BLUESTRIX_DEV_JWT_SECRET") or "").strip():
            problems.append("BLUESTRIX_DEV_JWT_SECRET must not be set in production")
        jwt_value = (env.get("BLUESTRIX_JWT_SECRET") or "").strip()
        mfa_value = (env.get("BLUESTRIX_MFA_KEY") or "").strip()
        if (
            jwt_value
            and mfa_value
            and jwt_value == mfa_value
            and not is_placeholder(jwt_value)
        ):
            problems.append("BLUESTRIX_MFA_KEY must differ from BLUESTRIX_JWT_SECRET")
        database_url = (env.get("DATABASE_URL") or "").strip()
        if not database_url:
            problems.append("DATABASE_URL is required in production")
        elif "change-me" in database_url:
            problems.append("DATABASE_URL contains a placeholder password")
    else:
        for name in ("BLUESTRIX_JWT_SECRET", "BLUESTRIX_MFA_KEY"):
            if is_placeholder(env.get(name)):
                warnings.append(
                    f"{name} is unset or a placeholder (acceptable only outside production)"
                )

    timeout = _parse_number(
        env,
        "BLUESTRIX_AI_TIMEOUT_SECONDS",
        DEFAULT_TIMEOUT_SECONDS,
        MIN_TIMEOUT_SECONDS,
        MAX_TIMEOUT_SECONDS,
        problems,
    )
    retries_raw = _parse_number(
        env, "BLUESTRIX_AI_MAX_RETRIES", DEFAULT_MAX_RETRIES, 0, MAX_RETRIES_CAP, problems
    )

    base_url = (env.get("DEEPSEEK_BASE_URL") or "").strip()
    if base_url:
        try:
            validate_base_url(base_url)
        except ConfigurationError as exc:
            problems.append(f"DEEPSEEK_BASE_URL: {exc}")

    settings: GatewaySettings | None = None
    if not problems:
        settings = GatewaySettings(
            environment=environment,
            mode=mode,
            execution=execution,
            timeout_seconds=timeout,
            max_retries=int(retries_raw),
            warnings=tuple(warnings),
        )
    return EnvironmentReport(
        environment=environment,
        problems=tuple(problems),
        warnings=tuple(warnings),
        settings=settings,
    )


def validate_environment(env: Mapping[str, str]) -> GatewaySettings:
    """Return validated settings or raise ConfigurationError listing variable names only."""
    report = assess_environment(env)
    if not report.ok:
        raise ConfigurationError("invalid gateway configuration: " + "; ".join(report.problems))
    if report.settings is None:  # pragma: no cover - guarded by report.ok above
        raise ConfigurationError("invalid gateway configuration")
    return report.settings


def provider_key_status(env: Mapping[str, str]) -> dict[str, bool]:
    """Report whether each provider key is configured. Never returns the key itself."""
    return {
        provider: not is_placeholder(env.get(var))
        for provider, var in PROVIDER_KEY_ENV_VARS.items()
    }
