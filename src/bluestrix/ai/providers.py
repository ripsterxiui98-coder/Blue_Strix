"""Provider adapters for the AI router. Keys only from environment."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol

import httpx


@dataclass
class ProviderConfig:
    name: str
    enabled: bool = True
    priority: int = 100
    base_url: str = ""
    model: str = ""
    max_tokens: int = 1000
    cost_per_1k_input: float = 0.0
    cost_per_1k_output: float = 0.0
    api_key_env: str = ""

    def api_key(self) -> Optional[str]:
        if not self.api_key_env:
            return None
        key = os.getenv(self.api_key_env, "").strip()
        if not key or key in {"change-me", "changeme"}:
            return None
        return key


@dataclass
class CompletionResult:
    text: str
    provider: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    cached: bool = False
    error: Optional[str] = None


class LLMProvider(Protocol):
    name: str

    def complete(self, messages: list[dict[str, str]], **kwargs: Any) -> CompletionResult: ...


def _estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


def _cost(cfg: ProviderConfig, tin: int, tout: int) -> float:
    return (tin / 1000.0) * cfg.cost_per_1k_input + (tout / 1000.0) * cfg.cost_per_1k_output


class OpenAICompatibleProvider:
    """OpenAI-compatible chat completions (OpenAI, Groq, DeepSeek/InferX)."""

    def __init__(self, config: ProviderConfig) -> None:
        self.config = config
        self.name = config.name

    def complete(self, messages: list[dict[str, str]], **kwargs: Any) -> CompletionResult:
        key = self.config.api_key()
        if not key:
            return CompletionResult(
                text="",
                provider=self.name,
                model=self.config.model,
                error=f"missing api key env {self.config.api_key_env}",
            )
        url = self.config.base_url.rstrip("/") + "/chat/completions"
        payload = {
            "model": self.config.model,
            "messages": messages,
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
            "temperature": kwargs.get("temperature", 0.1),
        }
        headers = {
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        }
        try:
            with httpx.Client(timeout=kwargs.get("timeout", 60.0)) as client:
                res = client.post(url, headers=headers, json=payload)
                res.raise_for_status()
                data = res.json()
            text = str(data["choices"][0]["message"]["content"])
            usage = data.get("usage") or {}
            tin = int(usage.get("prompt_tokens") or _estimate_tokens(str(messages)))
            tout = int(usage.get("completion_tokens") or _estimate_tokens(text))
            return CompletionResult(
                text=text,
                provider=self.name,
                model=self.config.model,
                input_tokens=tin,
                output_tokens=tout,
                cost_usd=_cost(self.config, tin, tout),
            )
        except Exception as exc:
            return CompletionResult(
                text="",
                provider=self.name,
                model=self.config.model,
                error=str(exc)[:500],
            )


class AnthropicProvider:
    def __init__(self, config: ProviderConfig) -> None:
        self.config = config
        self.name = config.name

    def complete(self, messages: list[dict[str, str]], **kwargs: Any) -> CompletionResult:
        key = self.config.api_key()
        if not key:
            return CompletionResult(
                text="",
                provider=self.name,
                model=self.config.model,
                error=f"missing api key env {self.config.api_key_env}",
            )
        system = ""
        chat: list[dict[str, str]] = []
        for m in messages:
            if m.get("role") == "system":
                system = m.get("content") or ""
            else:
                chat.append({"role": m.get("role", "user"), "content": m.get("content", "")})
        url = self.config.base_url.rstrip("/") + "/v1/messages"
        payload: dict[str, Any] = {
            "model": self.config.model,
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
            "messages": chat or [{"role": "user", "content": ""}],
        }
        if system:
            payload["system"] = system
        headers = {
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        try:
            with httpx.Client(timeout=kwargs.get("timeout", 60.0)) as client:
                res = client.post(url, headers=headers, json=payload)
                res.raise_for_status()
                data = res.json()
            parts = data.get("content") or []
            text = "".join(str(p.get("text", "")) for p in parts if isinstance(p, dict))
            usage = data.get("usage") or {}
            tin = int(usage.get("input_tokens") or _estimate_tokens(str(messages)))
            tout = int(usage.get("output_tokens") or _estimate_tokens(text))
            return CompletionResult(
                text=text,
                provider=self.name,
                model=self.config.model,
                input_tokens=tin,
                output_tokens=tout,
                cost_usd=_cost(self.config, tin, tout),
            )
        except Exception as exc:
            return CompletionResult(
                text="",
                provider=self.name,
                model=self.config.model,
                error=str(exc)[:500],
            )


class LocalProvider:
    """Deterministic local triage text — zero cost fallback."""

    def __init__(self, config: ProviderConfig) -> None:
        self.config = config
        self.name = config.name

    def complete(self, messages: list[dict[str, str]], **kwargs: Any) -> CompletionResult:
        user = ""
        for m in reversed(messages):
            if m.get("role") == "user":
                user = m.get("content") or ""
                break
        text = (
            "[local-triage] Defensive analysis only. "
            "No auto-remediation. Review findings with human governance. "
            f"Context excerpt: {user[:500]}"
        )
        return CompletionResult(
            text=text,
            provider="local",
            model="local-triage",
            input_tokens=_estimate_tokens(user),
            output_tokens=_estimate_tokens(text),
            cost_usd=0.0,
        )


def build_provider(config: ProviderConfig) -> LLMProvider:
    name = config.name.lower()
    if name == "local":
        return LocalProvider(config)
    if name == "anthropic":
        return AnthropicProvider(config)
    # openai, groq, deepseek (InferX OpenAI-compatible)
    return OpenAICompatibleProvider(config)
