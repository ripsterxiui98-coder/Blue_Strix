"""DeepSeek client via InferX OpenAI-compatible endpoint."""

from __future__ import annotations

import os
from typing import Any, Optional

from bluestrix.ai.providers import CompletionResult, OpenAICompatibleProvider, ProviderConfig

DEFAULT_BASE_URL = "https://model.inferx.net/endpoints/v1"
DEFAULT_MODEL = "deepseek-v4.1-flash-1017"


def deepseek_config(
    *,
    base_url: Optional[str] = None,
    model: Optional[str] = None,
    priority: int = 1,
) -> ProviderConfig:
    return ProviderConfig(
        name="deepseek",
        enabled=True,
        priority=priority,
        base_url=base_url
        or os.getenv("DEEPSEEK_BASE_URL", DEFAULT_BASE_URL),
        model=model or os.getenv("DEEPSEEK_MODEL", DEFAULT_MODEL),
        max_tokens=1000,
        cost_per_1k_input=0.00005,
        cost_per_1k_output=0.0002,
        api_key_env="DEEPSEEK_API_KEY",
    )


def complete_deepseek(
    messages: list[dict[str, str]],
    **kwargs: Any,
) -> CompletionResult:
    provider = OpenAICompatibleProvider(deepseek_config())
    return provider.complete(messages, **kwargs)
