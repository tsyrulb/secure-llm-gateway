import logging
import os
from typing import Any

import httpx

log = logging.getLogger("uvicorn.error")


def _normalize(res: Any) -> list[str]:
    if res is None:
        return []
    if isinstance(res, list):
        return [str(x) for x in res]
    if isinstance(res, bool):
        return ["policy deny"] if res else []
    if isinstance(res, set):
        return [str(x) for x in res]
    if isinstance(res, str):
        return [res]
    if isinstance(res, dict):
        out: list[str] = []
        for k, v in res.items():
            if isinstance(v, bool) and v:
                out.append(k)
            elif isinstance(v, list | set):
                out.extend([str(x) for x in v])
            elif isinstance(v, str):
                out.append(v)
        return out
    return [str(res)]


async def opa_deny(input_doc: dict[str, Any]) -> list[str]:
    """
    Query OPA for deny reasons. Empty list => allow.
    Fail-closed behavior is controlled by OPA_FAIL_CLOSED (default: true).
    """
    url = os.getenv("OPA_URL")
    fail_closed = os.getenv("OPA_FAIL_CLOSED", "true").lower() in ("1", "true", "yes", "on")
    timeout_s = float(os.getenv("OPA_TIMEOUT", "8"))

    if not url:
        if fail_closed:
            return ["OPA URL not set"]
        return []

    try:
        async with httpx.AsyncClient(timeout=timeout_s) as client:
            r = await client.post(url, json={"input": input_doc})
            data = r.json()  # parse before raise_for_status so we can log bodies on 4xx/5xx
            log.info(f"OPA status={r.status_code} data={data}")
            r.raise_for_status()

        result = data.get("result")
        denies = _normalize(result)

        if not denies and result is None and fail_closed:
            # Path exists but returned null/no result — treat as deny in fail-closed
            return ["OPA returned no result"]
        return denies

    except Exception as e:
        log.exception(f"OPA call failed: {e}")
        if fail_closed:
            return ["OPA unreachable"]
        return []
