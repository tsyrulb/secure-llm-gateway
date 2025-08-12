import re
from typing import List
from pydantic import BaseModel, Field

class ExpectedResponse(BaseModel):
    answer: str
    citations: List[str] = Field(default_factory=list)

# --- Secret redaction patterns ---
SECRET_PATTERNS = [
    # Catches common prefixes like sk_, pk_, rk_, etc.
    r"\b((sk|pk|rk)[_-]?[a-zA-Z0-9]{24,})\b",
    
    # --- THIS IS THE FIX ---
    # This pattern is now more flexible and doesn't require the keyword to be at the start.
    # It will match "my api_key = ..."
    r"(?i)\b(api[_-]?key|secret|token)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}['\"]?",

    # Original patterns are still valuable.
    r"\bAKIA[0-9A-Z]{16}\b",
    r"(?i)bearer\s+[A-Za-z0-9\-_.=]+",
]

def _redact_secrets(text: str) -> str:
    s = text
    for pat in SECRET_PATTERNS:
        s = re.sub(pat, "[[secret]]", s)
    return s

# --- PII redaction patterns ---
PII_PATTERNS = [
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",  # emails
    r"(?<!\d)(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,3}\)?[-.\s]?)?\d{3,4}[-.\s]?\d{4}(?!\d)",  # phones
]

def _redact_pii(text: str) -> str:
    s = text
    for pat in PII_PATTERNS:
        s = re.sub(pat, "[[pii]]", s)
    return s

def validate_and_filter_response(resp: ExpectedResponse) -> ExpectedResponse:
    safe = _redact_secrets(resp.answer)
    safe = _redact_pii(safe)
    return ExpectedResponse(answer=safe, citations=list(resp.citations))
