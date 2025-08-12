import os
from typing import Any, Dict, List, Optional, Tuple
import httpx

OPENAI_API = os.getenv("OPENAI_API_BASE", "https://api.openai.com/v1")
OPENAI_KEY = os.getenv("OPENAI_API_KEY")

async def _openai_chat(messages: List[Dict[str, str]], model: str, max_tokens: int) -> str:
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
        return str(data)  # fallback

async def generate_completion(
    messages: List[Dict[str, str]],
    model: str,
    max_tokens: int,
    context: Optional[Dict[str, Any]],
    tenant: Dict[str, Any],
) -> Tuple[str, Dict[str, Any]]:
    if model == "stub" or (model.startswith("openai:") and not OPENAI_KEY):
        last_user = next((m for m in reversed(messages) if m.get("role") == "user"), None)
        answer = f"[stub:{tenant.get('id','tenant')}] {last_user.get('content','(no input)')}"
        meta = {"citations": context.get("provenance", []) if context else []}
        return answer, meta

    if model.startswith("openai:"):
        base = model.split(":", 1)[1]
        text = await _openai_chat(messages, base, max_tokens)
        return text, {"citations": context.get("provenance", []) if context else []}

    last_user = next((m for m in reversed(messages) if m.get("role") == "user"), None)
    return f"[unknown-model] {last_user.get('content','(no input)')}", {"citations": []}
