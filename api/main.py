# api/main.py
import logging
import time
import httpx
import importlib
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, Body, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
from typing import List, Optional, Dict, Any

from api.config import settings
from api.auth.token import get_current_tenant
from api.firewall.context_firewall import sanitize_and_validate_context, ContextInput, SanitizedContext
from api.firewall.response_validator import validate_and_filter_response, ExpectedResponse
from api.middleware.rate_limit import rate_limit
from api.providers.openai_provider import generate_completion
from api.telemetry.otel_setup import setup_otel

log = logging.getLogger(__name__)

if settings.OPA_URL:
    from api.policy.opa_client import opa_deny
    POLICY_SOURCE = "OPA"
else:
    from api.policy.local_policy import local_policy_deny as opa_deny
    POLICY_SOURCE = "LOCAL"

@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("Starting Secure LLM Gateway...")
    log.info(f"Policy source: {POLICY_SOURCE} (module={opa_deny.__module__})")
    if not settings.JWT_SECRET:
        log.warning("JWT_SECRET is not set. Only 'dev-token' will be accepted for authentication.")
    yield
    log.info("Shutting down Secure LLM Gateway.")

app = FastAPI(title="Secure LLM Gateway (FastAPI)", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
setup_otel(app)

# --- Pydantic Models ---
class ChatMessage(BaseModel):
    role: str = Field(..., pattern="^(system|user|assistant|tool)$")
    content: str
    @field_validator('content')
    def content_length_must_be_valid(cls, v):
        if len(v) > settings.SINGLE_MESSAGE_CHARS_LIMIT:
            raise ValueError(f"A single message cannot exceed {settings.SINGLE_MESSAGE_CHARS_LIMIT} characters.")
        return v

# --- THIS IS THE FIX ---
# The following models are now correctly defined, resolving the AttributeError.
class ChatContextChunk(BaseModel):
    id: str
    content: str

class ChatContext(BaseModel):
    source: Optional[str] = None
    chunks: List[ChatContextChunk] = Field(default_factory=list)

class ChatRequest(BaseModel):
    model: str
    messages: List[ChatMessage]
    max_tokens: Optional[int] = Field(default=512, le=settings.MAX_TOKENS_LIMIT)
    context: Optional[ChatContext] = None # <-- This now correctly uses ChatContext
    @field_validator('model')
    def model_must_be_allowed(cls, v):
        if v not in settings.ALLOWED_MODELS:
            raise ValueError(f"Model '{v}' is not in the list of allowed models.")
        return v
    @field_validator('messages')
    def messages_must_be_valid(cls, v):
        if not v:
            raise ValueError("The 'messages' list cannot be empty.")
        if len(v) > settings.MAX_MESSAGES_LIMIT:
            raise ValueError(f"Cannot process more than {settings.MAX_MESSAGES_LIMIT} messages in a single request.")
        total_chars = sum(len(m.content) for m in v)
        if total_chars > settings.TOTAL_MESSAGE_CHARS_LIMIT:
            raise ValueError(f"Total character count of all messages exceeds the limit of {settings.TOTAL_MESSAGE_CHARS_LIMIT}.")
        return v

class ChatResponse(BaseModel):
    answer: str
    citations: List[str] = Field(default_factory=list)
    meta: Dict[str, Any] = Field(default_factory=dict)

# --- Health Endpoints ---
@app.get("/healthz", tags=["Health"])
def healthz(): return {"ok": True, "timestamp": int(time.time())}

@app.get("/readyz", tags=["Health"])
async def readyz():
    probe = {"mode": POLICY_SOURCE, "ready": True}
    if POLICY_SOURCE == "OPA":
        try:
            async with httpx.AsyncClient(timeout=3) as client:
                opa_base_url = settings.OPA_URL.split("/v1/data/")[0]
                health_res = await client.get(f"{opa_base_url}/health")
                policy_res = await client.post(settings.OPA_URL, json={"input": {"tenant": "__probe__"}})
                probe["opa_health_ok"] = health_res.status_code == 200
                probe["opa_policy_ok"] = policy_res.status_code == 200 and "result" in policy_res.json()
                probe["ready"] = probe["opa_health_ok"] and probe["opa_policy_ok"]
        except Exception as e:
            log.error(f"Readiness check for OPA failed: {e}")
            probe["ready"] = False
            probe["error"] = str(e)
    return probe

# --- Core Chat Completions Endpoint ---
@app.post("/v1/chat/completions", response_model=ChatResponse, tags=["LLM"])
async def chat_completions(
    request: Request,
    tenant: dict = Depends(get_current_tenant),
    _rate_limit: None = Depends(rate_limit),
):
    try:
        body = await request.json()
        payload = body.get("req") or body.get("payload") or body

        try:
            req = ChatRequest.model_validate(payload)
        except Exception as e:
            log.warning(f"Request validation failed: {e}")
            raise HTTPException(status_code=422, detail=str(e))

        sanitized_ctx: Optional[SanitizedContext] = None
        if req.context:
            try:
                # The firewall's input model is created from the request's context model.
                context_input_data = ContextInput(**req.context.model_dump())
                sanitized_ctx = sanitize_and_validate_context(context_input_data)
            except ValueError as e:
                log.warning(f"Invalid context blocked by firewall for tenant '{tenant.get('id')}': {e}")
                raise HTTPException(status_code=400, detail=str(e))

        opa_input = {
            "tenant": tenant.get("id"), "model": req.model,
            "max_tokens": req.max_tokens, "egress_url": settings.DEFAULT_EGRESS_URL,
        }
        denies = await opa_deny(opa_input)
        
        if denies:
            log.warning("Policy denied request", extra={"event_type": "policy_denial", "tenant": tenant.get("id"), "model": req.model, "reasons": denies})
            raise HTTPException(status_code=403, detail={"policy_denied": denies})

        raw_answer, raw_meta = await generate_completion(
            messages=[m.model_dump() for m in req.messages], model=req.model,
            max_tokens=req.max_tokens, context=sanitized_ctx.model_dump() if sanitized_ctx else None,
            tenant=tenant,
        )

        expected = ExpectedResponse(answer=raw_answer, citations=raw_meta.get("citations", []))
        safe_resp = validate_and_filter_response(expected)

        return ChatResponse(answer=safe_resp.answer, citations=safe_resp.citations, meta=raw_meta)

    except HTTPException:
        raise
    except Exception as e:
        log.error(f"An unexpected error occurred: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal Server Error")