from fastapi import FastAPI, Depends, HTTPException, Body, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, ValidationError
from typing import List, Optional, Dict, Any, Union
import os
import time
import logging
import httpx
import importlib

from api.firewall.context_firewall import (
    sanitize_and_validate_context,
    ContextInput,
    SanitizedContext,
)
from api.firewall.response_validator import (
    validate_and_filter_response,
    ExpectedResponse,
)
from api.providers.openai_provider import generate_completion
from api.auth.token import get_current_tenant
from api.telemetry.otel_setup import setup_otel
from api.middleware.rate_limit import rate_limit

# -------- Policy selection (LOCAL if OPA_URL not set; else OPA) --------
if os.getenv("OPA_URL"):
    from api.policy.opa_client import opa_deny  # OPA service
    POLICY_SOURCE = "OPA"
else:
    from api.policy.local_policy import local_policy_deny as opa_deny  # local fallback
    POLICY_SOURCE = "LOCAL"

log = logging.getLogger("uvicorn.error")
log.info(f"Policy source: {POLICY_SOURCE} (func={opa_deny.__name__} module={opa_deny.__module__})")
try:
    mod = importlib.import_module(opa_deny.__module__)
    log.info(f"Policy module file: {getattr(mod, '__file__', 'unknown')}")
except Exception:
    pass

# -------- App --------
app = FastAPI(title="Secure LLM Gateway (FastAPI)")

# CORS: default "*" but allow override via env CORS_ORIGINS="https://a.com,https://b.com"
allow_origins = [o.strip() for o in os.getenv("CORS_ORIGINS", "*").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

setup_otel(app)

# -------- Models --------
class ChatMessage(BaseModel):
    role: str = Field(..., pattern="^(system|user|assistant|tool)$")
    content: str

class ChatContextChunk(BaseModel):
    id: str
    content: str

class ChatContext(BaseModel):
    source: Optional[str] = None
    chunks: List[ChatContextChunk] = Field(default_factory=list)

class ChatRequest(BaseModel):
    model: str
    messages: List[ChatMessage]
    max_tokens: Optional[int] = 512
    context: Optional[ChatContext] = None

class ChatRequestWrapper(BaseModel):
    req: ChatRequest  # allows {"req": {...}} shape

class ChatResponse(BaseModel):
    answer: str
    citations: List[str] = Field(default_factory=list)
    meta: Dict[str, Any] = Field(default_factory=dict)

# -------- Health / Ready --------
@app.get("/healthz")
def healthz():
    return {"ok": True, "ts": int(time.time())}

async def _probe_opa():
    """
    When OPA_URL is set, verify OPA is reachable and the policy path responds.
    Returns: {"mode": "LOCAL"} or {"mode":"OPA","opa_ok":bool,"policy_ok":bool}
    """
    url = os.getenv("OPA_URL")
    if not url:
        return {"mode": "LOCAL"}

    # derive base for /health from OPA_URL (which is usually .../v1/data/<pkg>/<rule>)
    base = url.split("/v1/data/")[0] if "/v1/data/" in url else url
    opa_ok = False
    policy_ok = False
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            hr = await client.get(f"{base}/health")
            opa_ok = hr.status_code == 200
            pr = await client.post(url, json={"input": {"tenant": "__probe__", "model": "stub", "max_tokens": 1, "egress_url": ""}})
            pj = {}
            try:
                pj = pr.json()
            except Exception:
                pj = {}
            policy_ok = (pr.status_code == 200) and isinstance(pj, dict) and ("result" in pj)
    except Exception:
        opa_ok = False
        policy_ok = False

    return {"mode": "OPA", "opa_ok": opa_ok, "policy_ok": policy_ok}

@app.get("/readyz")
async def readyz():
    probe = await _probe_opa()
    if probe.get("mode") == "LOCAL":
        return {"ready": True, "mode": "LOCAL"}
    is_ready = probe.get("opa_ok") and probe.get("policy_ok")
    return {"ready": bool(is_ready), **probe}

# -------- (Optional) Dev-only debug routes --------
if os.getenv("ENABLE_DEBUG_ROUTES") == "1":
    @app.post("/_echo")
    def echo(x: dict = Body(...)):
        return {"got": x}

    @app.post("/_policy_debug")
    async def policy_debug(payload: Dict[str, Any]):
        denies = await opa_deny(payload)
        return {"input": payload, "denies": denies}

# -------- Core endpoint --------

@app.post("/v1/chat/completions", response_model=ChatResponse)
async def chat_completions(
    request: Request,                            
    tenant = Depends(get_current_tenant),
    _ = Depends(rate_limit),
):
    # 1) Read raw JSON body safely
    try:
        body = await request.json()
        if not isinstance(body, dict):
            raise ValueError("JSON must be an object")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    # 2) Normalize supported shapes: {..} or {"req":{..}} or {"payload":{..}}
    payload = body.get("req") or body.get("payload") or body

    # 3) Validate into ChatRequest
    try:
        req = ChatRequest.model_validate(payload)
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=e.errors())

    # --- the rest of your existing logic stays the same ---
    if req.max_tokens and req.max_tokens > 2048:
        raise HTTPException(status_code=400, detail="max_tokens too large")
    if not req.messages:
        raise HTTPException(status_code=400, detail="messages required")
    if len(req.messages) > 50:
        raise HTTPException(status_code=400, detail="too many messages")
    total_chars = sum(len(m.content or "") for m in req.messages)
    if total_chars > 8000:
        raise HTTPException(status_code=400, detail="request too large")
    for m in req.messages:
        if len(m.content or "") > 4000:
            raise HTTPException(status_code=400, detail="message too large")

    allowed_models = [m.strip() for m in os.getenv("ALLOWED_MODELS","stub,openai:gpt-4o,openai:gpt-4o-mini").split(",") if m.strip()]
    if req.model not in allowed_models:
        raise HTTPException(status_code=403, detail=f"Model {req.model} not allowed for this tenant")

    sanitized_ctx: Optional[SanitizedContext] = None
    if req.context:
        try:
            sanitized_ctx = sanitize_and_validate_context(ContextInput(**req.context.model_dump()))
        except ValidationError as e:
            raise HTTPException(status_code=400, detail=f"Invalid context: {e}")

    opa_input = {
        "tenant": tenant.get("id"),
        "model": req.model,
        "max_tokens": req.max_tokens or 512,
        "egress_url": os.getenv("DEFAULT_EGRESS_URL",""),
    }
    logging.getLogger("uvicorn.error").info(f"opa_input={opa_input}")
    denies = await opa_deny(opa_input)
    logging.getLogger("uvicorn.error").info(f"policy={POLICY_SOURCE} tenant={tenant.get('id')} model={req.model} denies={denies}")
    if denies:
        raise HTTPException(status_code=403, detail={"policy_denied": denies})

    raw_answer, raw_meta = await generate_completion(
        messages=[m.model_dump() for m in req.messages],
        model=req.model,
        max_tokens=req.max_tokens or 512,
        context=sanitized_ctx.model_dump() if sanitized_ctx else None,
        tenant=tenant,
    )
    expected = ExpectedResponse(answer=raw_answer, citations=raw_meta.get("citations", []))
    safe_resp = validate_and_filter_response(expected)
    return ChatResponse(answer=safe_resp.answer, citations=safe_resp.citations, meta=raw_meta)
