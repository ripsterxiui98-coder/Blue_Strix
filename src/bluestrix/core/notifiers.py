"""Outbound alert delivery. Webhook URLs come only from environment variables."""

from __future__ import annotations

import os
from typing import Any, Protocol

import httpx


class Notifier(Protocol):
    def send(self, title: str, body: str, severity: str = "INFO") -> bool: ...


def _post_json(url: str, payload: dict[str, Any], timeout: float = 10.0) -> bool:
    if not url:
        return False
    try:
        with httpx.Client(timeout=timeout) as client:
            res = client.post(url, json=payload)
            return 200 <= res.status_code < 300
    except Exception:
        return False


def _post_form(url: str, data: dict[str, Any], timeout: float = 10.0) -> bool:
    if not url:
        return False
    try:
        with httpx.Client(timeout=timeout) as client:
            res = client.post(url, data=data)
            return 200 <= res.status_code < 300
    except Exception:
        return False


class TelegramNotifier:
    def __init__(self, bot_token: str | None = None, chat_id: str | None = None) -> None:
        self.bot_token = bot_token or os.getenv("BLUESTRIX_TELEGRAM_BOT_TOKEN", "")
        self.chat_id = chat_id or os.getenv("BLUESTRIX_TELEGRAM_CHAT_ID", "")

    def send(self, title: str, body: str, severity: str = "INFO") -> bool:
        if not self.bot_token or not self.chat_id:
            return False
        text = f"*[BlueStrix {severity}]* {title}\n{body}"
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        return _post_json(url, {"chat_id": self.chat_id, "text": text, "parse_mode": "Markdown"})


class DiscordNotifier:
    def __init__(self, webhook_url: str | None = None) -> None:
        self.webhook_url = webhook_url or os.getenv("BLUESTRIX_DISCORD_WEBHOOK_URL", "")

    def send(self, title: str, body: str, severity: str = "INFO") -> bool:
        return _post_json(
            self.webhook_url,
            {
                "content": None,
                "embeds": [
                    {
                        "title": f"[{severity}] {title}",
                        "description": body[:2000],
                        "color": 0xE11D48 if severity == "CRITICAL" else 0x0EA5E9,
                    }
                ],
            },
        )


class SlackNotifier:
    def __init__(self, webhook_url: str | None = None) -> None:
        self.webhook_url = webhook_url or os.getenv("BLUESTRIX_SLACK_WEBHOOK_URL", "")

    def send(self, title: str, body: str, severity: str = "INFO") -> bool:
        return _post_json(
            self.webhook_url,
            {"text": f"*[BlueStrix {severity}]* {title}\n{body}"},
        )


def default_notifiers() -> list[Notifier]:
    return [TelegramNotifier(), DiscordNotifier(), SlackNotifier()]
