"""Login / MFA / reset rate limiting. Redis preferred; in-memory fallback."""

from __future__ import annotations

import os
import time
from collections import defaultdict
from threading import Lock
from typing import Optional

_lock = Lock()
_buckets: dict[str, list[float]] = defaultdict(list)


def _redis_client():
    url = os.getenv("REDIS_URL") or os.getenv("BLUESTRIX_REDIS_URL")
    if not url:
        return None
    try:
        import redis  # type: ignore

        return redis.Redis.from_url(url, decode_responses=True)
    except Exception:
        return None


def check_rate_limit(
    key: str,
    *,
    limit: int = 5,
    window_seconds: int = 300,
) -> tuple[bool, int]:
    """Return (allowed, retry_after_seconds)."""
    client = _redis_client()
    now = time.time()
    full_key = f"bluestrix:rl:{key}"

    if client is not None:
        try:
            pipe = client.pipeline()
            pipe.zremrangebyscore(full_key, 0, now - window_seconds)
            pipe.zadd(full_key, {str(now): now})
            pipe.zcard(full_key)
            pipe.expire(full_key, window_seconds)
            _, _, count, _ = pipe.execute()
            if int(count) > limit:
                return False, window_seconds
            return True, 0
        except Exception:
            pass

    with _lock:
        hits = [t for t in _buckets[full_key] if t > now - window_seconds]
        if len(hits) >= limit:
            _buckets[full_key] = hits
            retry = int(window_seconds - (now - hits[0])) if hits else window_seconds
            return False, max(retry, 1)
        hits.append(now)
        _buckets[full_key] = hits
        return True, 0
