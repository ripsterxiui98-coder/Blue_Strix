"""Optional OpenAI client. API key only from environment — never committed."""

from __future__ import annotations

import json
import os
from typing import Any, Optional

import httpx

OPENAI_API_URL = os.getenv("BLUESTRIX_OPENAI_API_URL", "https://api.openai.com/v1/chat/completions")
DEFAULT_MODEL = os.getenv("BLUESTRIX_OPENAI_MODEL", "gpt-4o-mini")


def get_api_key() -> Optional[str]:
    key = os.getenv("OPENAI_API_KEY") or os.getenv("BLUESTRIX_OPENAI_API_KEY")
    if not key or key.strip() in {"", "change-me"}:
        return None
    return key.strip()


def chat_completion(
    messages: list[dict[str, str]],
    *,
    model: Optional[str] = None,
    temperature: float = 0.1,
    timeout: float = 60.0,
) -> str:
    """Call OpenAI Chat Completions. Raises RuntimeError if key missing."""
    api_key = get_api_key()
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY / BLUESTRIX_OPENAI_API_KEY not configured")
    payload = {
        "model": model or DEFAULT_MODEL,
        "temperature": temperature,
        "messages": messages,
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    with httpx.Client(timeout=timeout) as client:
        res = client.post(OPENAI_API_URL, headers=headers, json=payload)
        res.raise_for_status()
        data = res.json()
    try:
        return str(data["choices"][0]["message"]["content"])
    except (KeyError, IndexError, TypeError) as exc:
        raise RuntimeError(f"unexpected OpenAI response: {data!r}") from exc


def try_json_completion(messages: list[dict[str, str]], **kwargs: Any) -> dict[str, Any]:
    text = chat_completion(messages, **kwargs)
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
    return json.loads(text)
