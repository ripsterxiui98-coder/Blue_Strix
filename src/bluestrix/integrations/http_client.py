from __future__ import annotations

from typing import Any

import httpx


class SafeHttpClient:
    def __init__(self, timeout_seconds: int = 15, user_agent: str = "BlueStrix/8.0") -> None:
        self.timeout_seconds = timeout_seconds
        self.user_agent = user_agent

    def post_json(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        with httpx.Client(timeout=self.timeout_seconds,
                          headers={"User-Agent": self.user_agent, "Content-Type": "application/json"},
                          follow_redirects=False) as client:
            response = client.post(url, json=payload)
            response.raise_for_status()
            return response.json()

    def get_json(self, url: str) -> dict[str, Any]:
        with httpx.Client(timeout=self.timeout_seconds, headers={"User-Agent": self.user_agent},
                          follow_redirects=False) as client:
            response = client.get(url)
            response.raise_for_status()
            return response.json()
