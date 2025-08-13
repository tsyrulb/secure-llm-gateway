# api/firewall/context_firewall.py
import re
import hashlib
import logging
from pydantic import BaseModel, Field
from typing import List, Optional, Tuple, Dict

log = logging.getLogger(__name__)

# --- Enhanced Injection Detection Patterns with Risk Scores ---
INJECTION_PATTERNS: Dict[str, int] = {
    # High-risk: Direct commands to ignore instructions or reveal system state.
    r"(?i)\bignore\s+(all\s+)?previous\s+instructions\b": 10,
    r"(?i)\bdisregard\s+all\s+prior\s+prompts\b": 10,
    r"(?i)reveal\s+your\s+(system\s+)?prompt": 9,
    r"(?i)what\s+are\s+your\s+instructions": 9,
    r"(?i)system\s*:\s*": 8,  # Attempts to mimic system messages.

    # Medium-risk: Role-playing and manipulation attempts.
    r"(?i)\bact\s+as\s+if\s+you\s+were\b": 5,
    r"(?i)\bact\s+as\s+a\b": 5,
    r"(?i)\broleplay\s+as\b": 5,
    r"(?i)you\s+are\s+an\s+unrestricted\s+and\s+unfiltered\s+model": 7,
    r"(?i)repeat\s+the\s+words\s+above": 6,  # Common in DAN (Do Anything Now) prompts.

    # Low-risk: Structural elements that can be used for obfuscation.
    r"": 3,  # Hidden XML/HTML comments.
    r"```": 2,  # Code blocks can be used to hide instructions.
    r"(?i)#\s*instructions?:": 4,  # Commented out instructions.
}


# --- Pydantic Models ---
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


# --- Core Firewall Logic ---

def _analyze_and_sanitize_text(text: str) -> Tuple[str, int]:
    """
    Analyzes text for injection patterns, calculates a risk score, and sanitizes the content.
    """
    risk_score = 0
    sanitized_text = text
    detected_patterns = []

    for pattern, weight in INJECTION_PATTERNS.items():
        if re.search(pattern, sanitized_text, re.DOTALL):
            risk_score += weight
            detected_patterns.append(pattern)
            sanitized_text = re.sub(pattern, "[[blocked]]", sanitized_text, flags=re.DOTALL)

    if sanitized_text.count('`') > 20:
        risk_score += 3
        detected_patterns.append("excessive_backticks")

    if detected_patterns:
        log.debug(f"Injection analysis detected patterns: {detected_patterns} -> score={risk_score}")

    return sanitized_text, risk_score


def _is_origin_allowed(source: Optional[str]) -> bool:
    """Checks if the context source is in the configured allowlist."""
    # --- THIS IS THE FIX ---
    # Import settings inside the function to ensure the patched version is used in tests.
    from api.config import settings
    if not source:
        return True

    if not settings.ALLOWED_CONTEXT_ORIGINS:
        return True

    return any(source.startswith(prefix) for prefix in settings.ALLOWED_CONTEXT_ORIGINS)


def sanitize_and_validate_context(ctx: ContextInput) -> SanitizedContext:
    """
    Validates the origin and sanitizes each chunk for prompt injection.
    """
    # --- THIS IS THE FIX ---
    # Import settings inside the function for consistency and to use the patched version.
    from api.config import settings
    
    if not _is_origin_allowed(ctx.source):
        log.warning(f"Context source '{ctx.source}' is not in the allowlist.")
        raise ValueError(f"Context source not allowed: {ctx.source}")

    sanitized_chunks = []
    provenance_hashes = []

    for chunk in ctx.chunks:
        sanitized_content, risk_score = _analyze_and_sanitize_text(chunk.content)

        if risk_score >= settings.CONTEXT_FIREWALL_RISK_THRESHOLD:
            log.warning(
                f"High-risk content detected in context chunk '{chunk.id}' from source '{ctx.source}'. "
                f"Score: {risk_score}/{settings.CONTEXT_FIREWALL_RISK_THRESHOLD}."
            )
            raise ValueError(
                f"High-risk content detected in context chunk '{chunk.id}'. "
                "The content has been blocked due to potential prompt injection."
            )

        sanitized_chunks.append(ContextChunk(id=chunk.id, content=sanitized_content))
        prov_hash = hashlib.sha256(sanitized_content.encode("utf-8")).hexdigest()
        provenance_hashes.append(prov_hash)

    return SanitizedContext(
        source=ctx.source,
        chunks=sanitized_chunks,
        provenance=provenance_hashes
    )