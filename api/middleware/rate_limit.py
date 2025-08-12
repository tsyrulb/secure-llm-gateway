import os
import time
from typing import Optional
from fastapi import Request, HTTPException, status

# Optional Redis support
try:
    from redis import asyncio as aioredis  # type: ignore
except Exception:  # pragma: no cover
    aioredis = None  # type: ignore

WINDOW = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
MAX_REQ = int(os.getenv("RATE_LIMIT_MAX_REQUESTS", "60"))
REDIS_URL = os.getenv("REDIS_URL")

# In-memory fallback store: {key: [(ts1), (ts2), ...]}
# NOTE: For single-process dev/testing only.
_inmem = {}

async def _incr_redis(key: str) -> int:
    assert aioredis is not None
    r = aioredis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)
    # Use a single key per window bucket
    bucket = int(time.time()) // WINDOW
    k = f"rl:{key}:{bucket}"
    pipe = r.pipeline()
    pipe.incr(k, 1)
    pipe.expire(k, WINDOW + 5)
    count, _ = await pipe.execute()
    return int(count)

def _incr_inmem(key: str) -> int:
    now = time.time()
    bucket = int(now) // WINDOW
    k = f"{key}:{bucket}"
    _inmem.setdefault(k, 0)
    _inmem[k] += 1
    # best-effort cleanup of older buckets
    for oldk in list(_inmem.keys()):
        if oldk.endswith(f":{bucket-2}"):
            _inmem.pop(oldk, None)
    return _inmem[k]

async def rate_limit(request: Request, tenant: Optional[dict] = None) -> None:
    # key by tenant if present, else client host
    ident = (tenant or {}).get("id") or request.client.host or "anon"
    key = f"{ident}"
    if REDIS_URL and aioredis is not None:
        count = await _incr_redis(key)
    else:
        count = _incr_inmem(key)
    if count > MAX_REQ:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded ({count}/{MAX_REQ} in {WINDOW}s)"
        )
