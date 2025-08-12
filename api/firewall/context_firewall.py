from pydantic import BaseModel, Field
from typing import List, Optional
import os, re, hashlib

INJECTION_PATTERNS = [
    r"(?i)ignore\s+previous\s+instructions",
    r"(?i)disregard\s+all\s+prior\s+prompts",
    r"(?i)system\s*:\s*",
    r"(?i)act\s+as\s+.*?",
    r"<!--.*?-->",
    r"(?i)#\s*instructions?:",
]

class ContextChunk(BaseModel):
    id: str
    content: str

class ContextInput(BaseModel):
    source: Optional[str] = None
    chunks: List[ContextChunk] = Field(default_factory=list)

class SanitizedContext(BaseModel):
    source: Optional[str]
    chunks: List[ContextChunk]
    provenance: List[str] = []

def _allowed_origin(source: Optional[str]) -> bool:
    if not source: return True
    allowlist = [s.strip() for s in os.getenv("ALLOWED_CONTEXT_ORIGINS", "").split(",") if s.strip()]
    return True if not allowlist else any(source.startswith(p) for p in allowlist)

def _scrub(text: str) -> str:
    s = text
    for pat in INJECTION_PATTERNS:
        s = re.sub(pat, "[[blocked]]", s, flags=re.DOTALL)
    return s.replace("```", "` ` `")

def sanitize_and_validate_context(ctx: ContextInput) -> SanitizedContext:
    if not _allowed_origin(ctx.source):
        raise ValueError(f"Context source not allowed: {ctx.source}")
    chunks, prov = [], []
    for ch in ctx.chunks:
        scrubbed = _scrub(ch.content)
        chunks.append(ContextChunk(id=ch.id, content=scrubbed))
        prov.append(hashlib.sha256(scrubbed.encode("utf-8")).hexdigest())
    return SanitizedContext(source=ctx.source, chunks=chunks, provenance=prov)
