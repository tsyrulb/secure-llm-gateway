import re
from typing import List
from pydantic import BaseModel, Field

class ExpectedResponse(BaseModel):
    answer: str
    citations: List[str] = Field(default_factory=list)

# --- Secret redaction (example patterns, extend for your org) ---
SECRET_PATTERNS = [
    # Generic API key-looking strings (very rough heuristic)
    r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
    # AWS-style access keys (simplified)
    r"\bAKIA[0-9A-Z]{16}\b",
    # Bearer tokens (JWT-ish)
    r"(?i)bearer\s+[A-Za-z0-9\-_.=]+",
]

def _redact_secrets(text: str) -> str:
    s = text
    for pat in SECRET_PATTERNS:
        s = re.sub(pat, "[[secret]]", s)
    return s

# --- PII redaction (lightweight demo patterns; tune as needed) ---
PII_PATTERNS = [
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",  # emails
    r"(?<!\d)(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,3}\)?[-.\s]?)?\d{3,4}[-.\s]?\d{4}(?!\d)",  # phones
    # add country-specific IDs as needed (keep conservative to reduce false positives)
]

def _redact_pii(text: str) -> str:
    s = text
    for pat in PII_PATTERNS:
        s = re.sub(pat, "[[pii]]", s)
    return s

def validate_and_filter_response(resp: ExpectedResponse) -> ExpectedResponse:
    """
    Apply output security filters (secrets + PII). You can extend this to
    include content policy checks, URL allowlists, etc.
    """
    safe = _redact_secrets(resp.answer)
    safe = _redact_pii(safe)
    return ExpectedResponse(answer=safe, citations=list(resp.citations))
