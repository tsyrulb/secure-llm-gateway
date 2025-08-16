import os
from typing import Any

import httpx

OPENAI_API = os.getenv("OPENAI_API_BASE", "https://api.openai.com/v1")
OPENAI_KEY = os.getenv("OPENAI_API_KEY")


async def _openai_chat(messages: list[dict[str, str]], model: str, max_tokens: int) -> str:
    url = f"{OPENAI_API}/chat/completions"
    headers = {"Authorization": f"Bearer {OPENAI_KEY}"}
    payload = {"model": model, "messages": messages, "max_tokens": max_tokens}
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(url, headers=headers, json=payload)
        r.raise_for_status()
        data = r.json()
    try:
        return data["choices"][0]["message"]["content"]
    except Exception:
        return str(data)


async def generate_completion(
    messages: list[dict[str, str]],
    model: str,
    max_tokens: int,
    context: dict[str, Any] | None,
    tenant: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    # Find the last user message, or None
    last_user = next((m for m in reversed(messages) if m.get("role") == "user"), None)

    # Safely get the content, providing a default if last_user is None
    last_content = last_user.get("content", "(no input)") if last_user else "(no input)"

    if model == "stub" or (model.startswith("openai:") and not OPENAI_KEY):
        answer = f"[stub:{tenant.get('id', 'tenant')}] {last_content}"
        meta = {"citations": (context or {}).get("provenance", [])}
        return answer, meta

    if model.startswith("openai:"):
        base = model.split(":", 1)[1]
        text = await _openai_chat(messages, base, max_tokens)
        return text, {"citations": (context or {}).get("provenance", [])}

    return f"[unknown-model] {last_content}", {"citations": []}
