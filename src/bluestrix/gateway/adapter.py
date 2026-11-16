"""Bounded OpenAI-compatible adapter for the AI gateway (DeepSeek/InferX, OpenAI, Groq).

Responsibilities of this layer:
- Base-URL allowlist (https only, fixed hosts) before any request is built.
- Per-request timeout, clamped to a safe range.
- Retry limited to transient failures (timeouts, connection errors, 429, 5xx).
  Client errors such as 401 or 400 are never retried.
- Errors are short fixed codes or redacted text. Headers and response bodies are never echoed.

Cross-provider fallback is NOT done here. ``bluestrix.ai.router.AIRouter`` is the single
fallback layer; this adapter is one provider it can call.

The transport is injected, so unit tests use fakes and never open a network connection.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional, Protocol

from bluestrix.ai.providers import CompletionResult, ProviderConfig
from bluestrix.gateway.redaction import SecretRegistry
from bluestrix.gateway.settings import (
    DEFAULT_MAX_RETRIES,
    DEFAULT_TIMEOUT_SECONDS,
    MAX_RETRIES_CAP,
    MAX_TIMEOUT_SECONDS,
    MIN_TIMEOUT_SECONDS,
    is_placeholder,
    validate_base_url,
)

TRANSIENT_STATUS_CODES = frozenset({429, 500, 502, 503, 504})
BACKOFF_SECONDS = 0.5


class TransportError(Exception):
    """Transport failed. The message must already be credential-free."""


class TransportTimeout(TransportError):
    """The provider did not answer within the timeout."""


@dataclass(frozen=True)
class TransportResponse:
    status_code: int
    body: Any


class Transport(Protocol):
    def post_json(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        payload: Mapping[str, Any],
        timeout: float,
    ) -> TransportResponse: ...


class HttpxTransport:
    """Production transport. httpx is imported at call time so importing this module is cheap."""

    def post_json(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        payload: Mapping[str, Any],
        timeout: float,
    ) -> TransportResponse:
        import httpx

        try:
            with httpx.Client(timeout=timeout, follow_redirects=False) as client:
                response = client.post(url, headers=dict(headers), json=dict(payload))
        except httpx.TimeoutException:
            raise TransportTimeout("provider request timed out") from None
        except httpx.HTTPError as exc:
            raise TransportError(f"transport error: {type(exc).__name__}") from None
        try:
            body: Any = response.json()
        except ValueError:
            body = None
        return TransportResponse(status_code=response.status_code, body=body)


def resolve_api_key(env: Mapping[str, str], key_env_name: str) -> Optional[str]:
    """Return the key from the given environment mapping, or None for missing/placeholder."""
    if not key_env_name:
        return None
    value = (env.get(key_env_name) or "").strip()
    return None if is_placeholder(value) else value


def _estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


class GatewayAdapter:
    """One OpenAI-compatible provider with bounded timeout and retry."""

    def __init__(
        self,
        config: ProviderConfig,
        *,
        transport: Transport,
        api_key: Optional[str],
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_retries: int = DEFAULT_MAX_RETRIES,
        sleep: Callable[[float], None] = time.sleep,
        registry: Optional[SecretRegistry] = None,
    ) -> None:
        self.config = config
        self.name = config.name
        self._base_url = validate_base_url(config.base_url)
        self._api_key = api_key if api_key and not is_placeholder(api_key) else None
        self._timeout = min(max(float(timeout_seconds), MIN_TIMEOUT_SECONDS), MAX_TIMEOUT_SECONDS)
        self._max_retries = min(max(int(max_retries), 0), MAX_RETRIES_CAP)
        self._transport = transport
        self._sleep = sleep
        self._registry = registry or SecretRegistry()
        if self._api_key:
            self._registry.register(self._api_key)

    def __repr__(self) -> str:
        # Deliberately omits the API key.
        return f"GatewayAdapter(name={self.name!r}, model={self.config.model!r})"

    @property
    def timeout_seconds(self) -> float:
        return self._timeout

    @property
    def max_attempts(self) -> int:
        return self._max_retries + 1

    def complete(self, messages: list[dict[str, str]], **kwargs: Any) -> CompletionResult:
        if not self._api_key:
            return self._failure("missing_api_key")

        url = f"{self._base_url}/chat/completions"
        payload = {
            "model": self.config.model,
            "messages": messages,
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
            "temperature": kwargs.get("temperature", 0.1),
        }
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

        last_error = "unknown_error"
        for attempt in range(self.max_attempts):
            retryable = False
            try:
                response = self._transport.post_json(
                    url, headers=headers, payload=payload, timeout=self._timeout
                )
            except TransportTimeout:
                last_error, retryable = "timeout", True
            except TransportError as exc:
                last_error, retryable = self._registry.redact(str(exc))[:200], True
            else:
                if response.status_code == 200:
                    return self._parse(response.body, messages)
                last_error = f"http_{response.status_code}"
                retryable = response.status_code in TRANSIENT_STATUS_CODES

            if not retryable:
                break
            if attempt < self.max_attempts - 1:
                self._sleep(BACKOFF_SECONDS * (attempt + 1))

        return self._failure(last_error)

    def _parse(self, body: Any, messages: list[dict[str, str]]) -> CompletionResult:
        try:
            text = str(body["choices"][0]["message"]["content"] or "")
        except (KeyError, IndexError, TypeError):
            return self._failure("unexpected_response")
        if not text:
            return self._failure("empty_response")

        usage = body.get("usage") or {}
        prompt_text = " ".join(str(m.get("content", "")) for m in messages)
        tin = int(usage.get("prompt_tokens") or _estimate_tokens(prompt_text))
        tout = int(usage.get("completion_tokens") or _estimate_tokens(text))
        cost = (tin / 1000.0) * self.config.cost_per_1k_input + (
            tout / 1000.0
        ) * self.config.cost_per_1k_output
        return CompletionResult(
            text=text,
            provider=self.name,
            model=self.config.model,
            input_tokens=tin,
            output_tokens=tout,
            cost_usd=cost,
        )

    def _failure(self, code: str) -> CompletionResult:
        return CompletionResult(
            text="",
            provider=self.name,
            model=self.config.model,
            error=code,
        )
