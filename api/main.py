# api/main.py
import logging
import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, ValidationError, field_validator

from api.auth.token import get_current_tenant
from api.config import Settings, get_settings
from api.firewall.context_firewall import (
    ContextInput,
    SanitizedContext,
    sanitize_and_validate_context,
)
from api.firewall.response_validator import ExpectedResponse, validate_and_filter_response
from api.middleware.rate_limit import rate_limit
from api.providers.openai_provider import generate_completion
from api.telemetry.otel_setup import setup_otel

log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    settings = get_settings()
    log.info("Starting Secure LLM Gateway...")
    POLICY_SOURCE = "OPA" if settings.OPA_URL else "LOCAL"
    log.info(f"Policy source: {POLICY_SOURCE}")
    if not settings.JWT_SECRET:
        log.warning("JWT_SECRET is not set. Only 'dev-token' will be accepted.")
    yield
    log.info("Shutting down Secure LLM Gateway.")


app = FastAPI(title="Secure LLM Gateway (FastAPI)", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
setup_otel(app)


class ChatMessage(BaseModel):
    role: str = Field(..., pattern="^(system|user|assistant|tool)$")
    content: str

    @field_validator("content")
    @classmethod
    def content_length_must_be_valid(cls, v: str) -> str:
        if len(v) > get_settings().SINGLE_MESSAGE_CHARS_LIMIT:
            raise ValueError("Single message character limit exceeded.")
        return v


class ChatContextChunk(BaseModel):
    id: str
    content: str


class ChatContext(BaseModel):
    source: str | None = None
    chunks: list[ChatContextChunk] = Field(default_factory=list)


class ChatRequest(BaseModel):
    model: str
    messages: list[ChatMessage]
    max_tokens: int | None = Field(default=512)
    context: ChatContext | None = None

    @field_validator("model")
    @classmethod
    def model_must_be_allowed(cls, v: str) -> str:
        if v not in get_settings().ALLOWED_MODELS:
            raise ValueError(f"Model '{v}' is not in the list of allowed models.")
        return v

    @field_validator("messages")
    @classmethod
    def messages_must_be_valid(cls, v: list[ChatMessage]) -> list[ChatMessage]:
        if not v or len(v) > get_settings().MAX_MESSAGES_LIMIT:
            raise ValueError("Invalid number of messages.")
        total_chars = sum(len(m.content) for m in v if m.content is not None)
        if total_chars > get_settings().TOTAL_MESSAGE_CHARS_LIMIT:
            raise ValueError("Total character limit exceeded.")
        return v


class ChatResponse(BaseModel):
    answer: str
    citations: list[str] = Field(default_factory=list)
    meta: dict[str, Any] = Field(default_factory=dict)


@app.get("/healthz", tags=["Health"])
def healthz() -> dict[str, Any]:
    return {"ok": True, "timestamp": int(time.time())}


@app.get("/readyz", tags=["Health"])
async def readyz(settings: Settings = Depends(get_settings)) -> dict[str, Any]:
    probe = {"mode": "OPA" if settings.OPA_URL else "LOCAL", "ready": True}
    return probe


@app.post("/v1/chat/completions", response_model=ChatResponse, tags=["LLM"])
async def chat_completions(
    request: Request,
    tenant: dict = Depends(get_current_tenant),
    _rate_limit: None = Depends(rate_limit),
    settings: Settings = Depends(get_settings),
) -> ChatResponse:
    try:
        body = await request.json()
        payload = body.get("req") or body
        req = ChatRequest.model_validate(payload)

        sanitized_ctx: SanitizedContext | None = None
        if req.context:
            try:
                sanitized_ctx = sanitize_and_validate_context(
                    ContextInput(**req.context.model_dump()),
                    allowed_origins=settings.ALLOWED_CONTEXT_ORIGINS,
                    risk_threshold=settings.CONTEXT_FIREWALL_RISK_THRESHOLD,
                )
            except ValidationError as e:
                raise HTTPException(status_code=400, detail=f"Invalid context: {e}") from e
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e)) from e

        if settings.OPA_URL:
            from api.policy.opa_client import opa_deny
        else:
            from api.policy.local_policy import local_policy_deny as opa_deny
        opa_input = {"tenant": tenant.get("id"), "model": req.model}
        denies = await opa_deny(opa_input)
        if denies:
            raise HTTPException(status_code=403, detail={"policy_denied": denies})

        raw_answer, raw_meta = await generate_completion(
            messages=[m.model_dump() for m in req.messages],
            model=req.model,
            max_tokens=req.max_tokens or 512,  # <-- FIX IS HERE
            context=sanitized_ctx.model_dump() if sanitized_ctx else None,
            tenant=tenant,
        )
        safe_resp = validate_and_filter_response(
            ExpectedResponse(answer=raw_answer, citations=raw_meta.get("citations", []))
        )
        return ChatResponse(answer=safe_resp.answer, citations=safe_resp.citations, meta=raw_meta)

    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Unexpected error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal Server Error") from e
