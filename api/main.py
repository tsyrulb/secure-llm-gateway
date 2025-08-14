# api/main.py
import logging
import time
import httpx
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, Body, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, ValidationError, field_validator
from typing import List, Optional, Dict, Any

from api.config import Settings, get_settings
from api.auth.token import get_current_tenant
from api.firewall.context_firewall import sanitize_and_validate_context, ContextInput, SanitizedContext
from api.firewall.response_validator import validate_and_filter_response, ExpectedResponse
from api.middleware.rate_limit import rate_limit
from api.providers.openai_provider import generate_completion
from api.telemetry.otel_setup import setup_otel

log = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    log.info("Starting Secure LLM Gateway...")
    POLICY_SOURCE = "OPA" if settings.OPA_URL else "LOCAL"
    log.info(f"Policy source: {POLICY_SOURCE}")
    if not settings.JWT_SECRET:
        log.warning("JWT_SECRET is not set. Only 'dev-token' will be accepted.")
    yield
    log.info("Shutting down Secure LLM Gateway.")

app = FastAPI(title="Secure LLM Gateway (FastAPI)", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
setup_otel(app)

class ChatMessage(BaseModel):
    role: str = Field(..., pattern="^(system|user|assistant|tool)$")
    content: str

    @field_validator('content')
    def content_length_must_be_valid(cls, v):
        if len(v) > get_settings().SINGLE_MESSAGE_CHARS_LIMIT:
            raise ValueError("Single message character limit exceeded.")
        return v

class ChatContextChunk(BaseModel):
    id: str
    content: str

class ChatContext(BaseModel):
    source: Optional[str] = None
    chunks: List[ChatContextChunk] = Field(default_factory=list)

class ChatRequest(BaseModel):
    model: str
    messages: List[ChatMessage]
    max_tokens: Optional[int] = Field(default=512)
    context: Optional[ChatContext] = None

    @field_validator('model')
    def model_must_be_allowed(cls, v):
        if v not in get_settings().ALLOWED_MODELS:
            raise ValueError(f"Model '{v}' is not in the list of allowed models.")
        return v

    @field_validator('messages')
    def messages_must_be_valid(cls, v):
        if not v or len(v) > get_settings().MAX_MESSAGES_LIMIT:
            raise ValueError("Invalid number of messages.")
        total_chars = sum(len(m.content) for m in v if m.content is not None)
        if total_chars > get_settings().TOTAL_MESSAGE_CHARS_LIMIT:
            raise ValueError("Total character limit exceeded.")
        return v

class ChatResponse(BaseModel):
    answer: str
    citations: List[str] = Field(default_factory=list)
    meta: Dict[str, Any] = Field(default_factory=dict)

@app.get("/healthz", tags=["Health"])
def healthz(): return {"ok": True, "timestamp": int(time.time())}

@app.get("/readyz", tags=["Health"])
async def readyz(settings: Settings = Depends(get_settings)):
    probe = {"mode": "OPA" if settings.OPA_URL else "LOCAL", "ready": True}
    return probe

@app.post("/v1/chat/completions", response_model=ChatResponse, tags=["LLM"])
async def chat_completions(
    request: Request,
    tenant: dict = Depends(get_current_tenant),
    _rate_limit: None = Depends(rate_limit),
    settings: Settings = Depends(get_settings),
):
    try:
        body = await request.json()
        payload = body.get("req") or body
        req = ChatRequest.model_validate(payload)

        sanitized_ctx: Optional[SanitizedContext] = None
        if req.context:
            try:
                sanitized_ctx = sanitize_and_validate_context(
                    ContextInput(**req.context.model_dump()),
                    allowed_origins=settings.ALLOWED_CONTEXT_ORIGINS,
                    risk_threshold=settings.CONTEXT_FIREWALL_RISK_THRESHOLD,
                )
            except ValidationError as e:
                raise HTTPException(status_code=400, detail=f"Invalid context: {e}")
            except ValueError as e:
                # test checks for 400 when origin disallowed or risk too high
                raise HTTPException(status_code=400, detail=str(e))

        if settings.OPA_URL:
            from api.policy.opa_client import opa_deny
        else:
            from api.policy.local_policy import local_policy_deny as opa_deny
        opa_input = {"tenant": tenant.get("id"), "model": req.model}
        denies = await opa_deny(opa_input)
        if denies:
            raise HTTPException(status_code=403, detail={"policy_denied": denies})

        raw_answer, raw_meta = await generate_completion(
            messages=[m.model_dump() for m in req.messages], model=req.model, max_tokens=req.max_tokens,
            context=sanitized_ctx.model_dump() if sanitized_ctx else None, tenant=tenant,
        )
        safe_resp = validate_and_filter_response(ExpectedResponse(answer=raw_answer, citations=raw_meta.get("citations",[])))
        return ChatResponse(answer=safe_resp.answer, citations=safe_resp.citations, meta=raw_meta)

    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Unexpected error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal Server Error")