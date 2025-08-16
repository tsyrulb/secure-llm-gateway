# api/middleware/rate_limit.py
from __future__ import annotations

import time

try:
    from redis.asyncio import Redis
except Exception:  # redis is optional for local/dev
    Redis = None  # type: ignore[misc,assignment]

from fastapi import Request

# In-memory fallback: key -> (count, window_start_epoch_seconds)
_inmem: dict[str, tuple[int, float]] = {}

REDIS_URL = None  # set via env/config if you want to use Redis


def _inmem_hit(key: str, limit: int, window_seconds: int) -> None:
    now = time.time()
    count, start = _inmem.get(key, (0, now))
    # reset window if expired
    if now - start >= window_seconds:
        count, start = 0, now
    count += 1
    _inmem[key] = (count, start)
    if count > limit:
        raise RuntimeError("rate limit exceeded")


def get_redis() -> Redis | None:  # pyright: ignore[reportInvalidTypeForm]
    """Create a Redis client if REDIS_URL is configured and redis is available."""
    if REDIS_URL and Redis is not None:
        # mypy knows Redis is not None in this branch
        return Redis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)
    return None


async def rate_limit(request: Request) -> None:
    """
    Simple token-bucket-ish limit: 5 req / 1s per tenant.
    If Redis is available, use it; otherwise fall back to in-memory.
    """
    tenant = request.state.tenant if hasattr(request.state, "tenant") else "anon"
    key = f"rl:{tenant}"
    limit = 5
    window = 1

    r = get_redis()
    if r is None:
        _inmem_hit(key, limit, window)
        return

    # Redis path
    pipe = r.pipeline()
    pipe.incr(key)
    pipe.expire(key, window)
    count, _ = await pipe.execute()
    if int(count) > limit:
        raise RuntimeError("rate limit exceeded")
