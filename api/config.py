# api/config.py
from pydantic_settings import BaseSettings
from typing import List, Optional
from functools import lru_cache

class Settings(BaseSettings):
    """
    Centralized application configuration.
    """
    CORS_ORIGINS: List[str] = ["*"]
    ENABLE_DEBUG_ROUTES: bool = False
    DEFAULT_EGRESS_URL: str = ""
    JWT_SECRET: Optional[str] = None
    OPA_URL: Optional[str] = None
    OPA_FAIL_CLOSED: bool = True
    OPA_TIMEOUT: float = 8.0
    ALLOWED_MODELS: List[str] = ["stub", "openai:gpt-4o", "openai:gpt-4o-mini"]
    MAX_TOKENS_LIMIT: int = 2048
    MAX_MESSAGES_LIMIT: int = 50
    TOTAL_MESSAGE_CHARS_LIMIT: int = 8000
    SINGLE_MESSAGE_CHARS_LIMIT: int = 4000
    CONTEXT_FIREWALL_RISK_THRESHOLD: int = 10
    ALLOWED_CONTEXT_ORIGINS: List[str] = []
    OTEL_EXPORTER_OTLP_ENDPOINT: Optional[str] = None

@lru_cache()
def get_settings():
    return Settings()