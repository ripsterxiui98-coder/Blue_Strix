from __future__ import annotations

import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self, max_events: int = 60, window_seconds: int = 60) -> None:
        if max_events <= 0 or window_seconds <= 0:
            raise ValueError("Rate limiter parameters must be positive")
        self.max_events = max_events
        self.window_seconds = window_seconds
        self.events: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        bucket = self.events[key]
        while bucket and now - bucket[0] > self.window_seconds:
            bucket.popleft()
        if len(bucket) >= self.max_events:
            return False
        bucket.append(now)
        return True

    def retry_after_seconds(self, key: str) -> int:
        bucket = self.events.get(key)
        if not bucket or len(bucket) < self.max_events:
            return 0
        return max(0, int(self.window_seconds - (time.monotonic() - bucket[0])))
