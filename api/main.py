# api/main.py
import logging
import time
import httpx
import importlib
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, Body, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator, model_validator
from typing import List, Optional, Dict, Any

# --- Centralized Configuration ---
# Import the single settings instance. All configuration is now managed in api/config.py
from api.config import settings

# --- Core Application Components ---
from api.auth.token import get_current_tenant
from api.firewall.context_firewall import sanitize_and_validate_context, ContextInput, SanitizedContext
from api.firewall.response_validator import validate_and_filter_response, ExpectedResponse
from api.middleware.rate_limit import rate_limit
from api.providers.openai_provider import generate_completion
from api.telemetry.otel_setup import setup_otel

# --- Structured Logging Setup ---
# It's best practice to get the logger for the current module
log = logging.getLogger(__name__)

# --- Policy Engine Selection ---
# The policy engine is selected based on whether OPA_URL is configured.
if settings.OPA_URL:
    from api.policy.opa_client import opa_deny
    POLICY_SOURCE = "OPA"
else:
    from api.policy.local_policy import local_policy_deny as opa_deny
    POLICY_SOURCE = "LOCAL"

# --- Application Lifespan Management ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Handles application startup and shutdown events.
    This is the recommended way to manage resources in modern FastAPI.
    """
    # Startup Logic
    log.info("Starting Secure LLM Gateway...")
    log.info(f"Policy source: {POLICY_SOURCE} (module={opa_deny.__module__})")
    
    # Fail-fast check: Ensure a JWT secret is set if not using a simple dev token.
    # This prevents the app from running in a misconfigured state.
    if not settings.JWT_SECRET:
        log.warning("JWT_SECRET is not set. Only 'dev-token' will be accepted for authentication.")
    
    yield
    
    # Shutdown Logic
    log.info("Shutting down Secure LLM Gateway.")


# --- FastAPI App Initialization ---
app = FastAPI(
    title="Secure LLM Gateway (FastAPI)",
    lifespan=lifespan  # Use the new lifespan manager
)

# Add CORS middleware based on settings from the config file.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Instrument the app with OpenTelemetry if an endpoint is configured.
setup_otel(app)


# --- Pydantic Models with Integrated Validation ---
# Validation logic is now co-located with the data models, cleaning up the endpoint code.

class ChatMessage(BaseModel):
    role: str = Field(..., pattern="^(system|user|assistant|tool)$")
    content: str

    @field_validator('content')
    @classmethod
    def content_length_must_be_valid(cls, v):
        if len(v) > settings.SINGLE_MESSAGE_CHARS_LIMIT:
            raise ValueError(f"A single message cannot exceed {settings.SINGLE_MESSAGE_CHARS_LIMIT} characters.")
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
    max_tokens: Optional[int] = Field(default=512, le=settings.MAX_TOKENS_LIMIT) # Use 'le' for less-than-or-equal validation
    context: Optional[ChatContext] = None

    @field_validator('model')
    @classmethod
    def model_must_be_allowed(cls, v):
        if v not in settings.ALLOWED_MODELS:
            raise ValueError(f"Model '{v}' is not in the list of allowed models.")
        return v

    @field_validator('messages')
    @classmethod
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


# --- Health and Readiness Endpoints ---
@app.get("/healthz", tags=["Health"])
def healthz():
    return {"ok": True, "timestamp": int(time.time())}

@app.get("/readyz", tags=["Health"])
async def readyz():
    """Checks readiness of the gateway and its dependencies (like OPA)."""
    probe = {"mode": POLICY_SOURCE, "ready": True}
    if POLICY_SOURCE == "OPA":
        try:
            async with httpx.AsyncClient(timeout=3) as client:
                # Check if OPA server is reachable and policy path exists
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


# --- Optional Debugging Endpoints ---
if settings.ENABLE_DEBUG_ROUTES:
    @app.post("/_echo", tags=["Debug"])
    def echo(x: dict = Body(...)):
        return {"received_payload": x}

    @app.post("/_policy_debug", tags=["Debug"])
    async def policy_debug(payload: Dict[str, Any]):
        denies = await opa_deny(payload)
        return {"input": payload, "denies": denies}


# --- Core Chat Completions Endpoint ---
@app.post("/v1/chat/completions", response_model=ChatResponse, tags=["LLM"])
async def chat_completions(
    request: Request,
    tenant: dict = Depends(get_current_tenant),
    _rate_limit: None = Depends(rate_limit),
):
    """
    Main endpoint for processing chat requests.
    It applies security checks, policy enforcement, and response filtering.
    """
    try:
        # 1. Safely parse and validate the incoming request body.
        # Pydantic now handles most of the validation automatically.
        body = await request.json()
        payload = body.get("req") or body.get("payload") or body
        req = ChatRequest.model_validate(payload)

    except Exception as e:
        # Catches JSON parsing errors and Pydantic validation errors.
        log.warning(f"Request validation failed: {e}", extra={"tenant": tenant.get("id"), "error_details": str(e)})
        raise HTTPException(status_code=422, detail=f"Invalid request payload: {e}")

    # 2. Sanitize the context to prevent prompt injection.
    sanitized_ctx: Optional[SanitizedContext] = None
    if req.context:
        try:
            sanitized_ctx = sanitize_and_validate_context(ContextInput(**req.context.model_dump()))
        except ValueError as e:
            log.warning(f"Invalid context provided by tenant '{tenant.get('id')}': {e}")
            raise HTTPException(status_code=400, detail=f"Invalid context: {e}")

    # 3. Enforce security policies using OPA or local rules.
    opa_input = {
        "tenant": tenant.get("id"),
        "model": req.model,
        "max_tokens": req.max_tokens,
        "egress_url": settings.DEFAULT_EGRESS_URL,
    }
    denies = await opa_deny(opa_input)
    
    if denies:
        # Log security events in a structured format for easier monitoring.
        log.warning(
            "Policy denied request",
            extra={
                "event_type": "policy_denial",
                "tenant": tenant.get("id"),
                "model": req.model,
                "reasons": denies,
            }
        )
        raise HTTPException(status_code=403, detail={"policy_denied": denies})

    # 4. Generate the completion from the LLM provider.
    raw_answer, raw_meta = await generate_completion(
        messages=[m.model_dump() for m in req.messages],
        model=req.model,
        max_tokens=req.max_tokens,
        context=sanitized_ctx.model_dump() if sanitized_ctx else None,
        tenant=tenant,
    )

    # 5. Validate and filter the response for sensitive data.
    expected = ExpectedResponse(answer=raw_answer, citations=raw_meta.get("citations", []))
    safe_resp = validate_and_filter_response(expected)

    return ChatResponse(answer=safe_resp.answer, citations=safe_resp.citations, meta=raw_meta)
