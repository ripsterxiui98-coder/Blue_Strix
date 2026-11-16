"""AI router: priority providers, fallback, quota, budget, cooldown, cache."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from bluestrix.ai.providers import (
    CompletionResult,
    ProviderConfig,
    build_provider,
)

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover
    yaml = None


@dataclass
class RouterState:
    spend_usd: float = 0.0
    calls: int = 0
    provider_failures: dict[str, float] = field(default_factory=dict)  # name -> cooldown_until
    cache: dict[str, tuple[float, CompletionResult]] = field(default_factory=dict)


def load_router_config(path: str | Path | None = None) -> dict[str, Any]:
    path = Path(path or "config/ai_router.yaml")
    if path.exists() and yaml is not None:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return data if isinstance(data, dict) else {}
    # Built-in defaults including DeepSeek priority 1
    return {
        "budget_usd_daily": 5.0,
        "cache_ttl_seconds": 3600,
        "cooldown_seconds": 30,
        "providers": [
            {
                "name": "deepseek",
                "enabled": True,
                "priority": 1,
                "base_url": "https://model.inferx.net/endpoints/v1",
                "model": "deepseek-v4.1-flash-1017",
                "max_tokens": 1000,
                "cost_per_1k_input": 0.00005,
                "cost_per_1k_output": 0.0002,
                "api_key_env": "DEEPSEEK_API_KEY",
            },
            {
                "name": "openai",
                "enabled": True,
                "priority": 2,
                "base_url": "https://api.openai.com/v1",
                "model": "gpt-4o-mini",
                "max_tokens": 1000,
                "cost_per_1k_input": 0.00015,
                "cost_per_1k_output": 0.0006,
                "api_key_env": "OPENAI_API_KEY",
            },
            {
                "name": "anthropic",
                "enabled": True,
                "priority": 3,
                "base_url": "https://api.anthropic.com",
                "model": "claude-3-5-haiku-latest",
                "max_tokens": 1000,
                "cost_per_1k_input": 0.0008,
                "cost_per_1k_output": 0.004,
                "api_key_env": "ANTHROPIC_API_KEY",
            },
            {
                "name": "groq",
                "enabled": True,
                "priority": 4,
                "base_url": "https://api.groq.com/openai/v1",
                "model": "llama-3.1-8b-instant",
                "max_tokens": 1000,
                "cost_per_1k_input": 0.00005,
                "cost_per_1k_output": 0.00008,
                "api_key_env": "GROQ_API_KEY",
            },
            {
                "name": "local",
                "enabled": True,
                "priority": 100,
                "base_url": "",
                "model": "local-triage",
                "max_tokens": 0,
                "cost_per_1k_input": 0.0,
                "cost_per_1k_output": 0.0,
                "api_key_env": "",
            },
        ],
    }


def _configs_from_data(data: dict[str, Any]) -> list[ProviderConfig]:
    out: list[ProviderConfig] = []
    for item in data.get("providers") or []:
        if not isinstance(item, dict):
            continue
        out.append(
            ProviderConfig(
                name=str(item.get("name") or "unknown"),
                enabled=bool(item.get("enabled", True)),
                priority=int(item.get("priority") or 100),
                base_url=str(item.get("base_url") or ""),
                model=str(item.get("model") or ""),
                max_tokens=int(item.get("max_tokens") or 1000),
                cost_per_1k_input=float(item.get("cost_per_1k_input") or 0),
                cost_per_1k_output=float(item.get("cost_per_1k_output") or 0),
                api_key_env=str(item.get("api_key_env") or ""),
            )
        )
    out.sort(key=lambda c: c.priority)
    return out


def _cache_key(messages: list[dict[str, str]]) -> str:
    raw = json.dumps(messages, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class AIRouter:
    def __init__(
        self,
        config: Optional[dict[str, Any]] = None,
        *,
        providers: Optional[list[Any]] = None,
    ) -> None:
        self.config = config or load_router_config()
        self.budget = float(self.config.get("budget_usd_daily") or 5.0)
        self.cache_ttl = int(self.config.get("cache_ttl_seconds") or 3600)
        self.cooldown = float(self.config.get("cooldown_seconds") or 30)
        self.state = RouterState()
        if providers is not None:
            self._providers = providers
            self._provider_configs = []
        else:
            self._provider_configs = _configs_from_data(self.config)
            self._providers = [
                build_provider(c) for c in self._provider_configs if c.enabled
            ]

    def ordered_provider_names(self) -> list[str]:
        if self._provider_configs:
            return [c.name for c in self._provider_configs if c.enabled]
        return [getattr(p, "name", "?") for p in self._providers]

    def _in_cooldown(self, name: str) -> bool:
        until = self.state.provider_failures.get(name, 0.0)
        return time.time() < until

    def _mark_failure(self, name: str) -> None:
        self.state.provider_failures[name] = time.time() + self.cooldown

    def complete(
        self,
        messages: list[dict[str, str]],
        *,
        use_cache: bool = True,
        **kwargs: Any,
    ) -> CompletionResult:
        key = _cache_key(messages)
        if use_cache and key in self.state.cache:
            ts, cached = self.state.cache[key]
            if time.time() - ts <= self.cache_ttl:
                cached.cached = True
                return cached

        if self.state.spend_usd >= self.budget:
            # Force local-only when budget exhausted
            for p in self._providers:
                if getattr(p, "name", "") == "local":
                    result = p.complete(messages, **kwargs)
                    result.error = (result.error or "") + " budget_exhausted"
                    return result

        last: Optional[CompletionResult] = None
        for provider in self._providers:
            name = getattr(provider, "name", "unknown")
            if self._in_cooldown(name) and name != "local":
                continue
            result = provider.complete(messages, **kwargs)
            last = result
            if result.error:
                self._mark_failure(name)
                continue
            if not result.text and name != "local":
                self._mark_failure(name)
                continue
            self.state.spend_usd += result.cost_usd
            self.state.calls += 1
            if use_cache:
                self.state.cache[key] = (time.time(), result)
            return result

        return last or CompletionResult(
            text="",
            provider="none",
            model="",
            error="all providers failed",
        )

    def quota_snapshot(self) -> dict[str, Any]:
        return {
            "spend_usd": round(self.state.spend_usd, 6),
            "budget_usd_daily": self.budget,
            "calls": self.state.calls,
            "cache_entries": len(self.state.cache),
            "providers": self.ordered_provider_names(),
        }
