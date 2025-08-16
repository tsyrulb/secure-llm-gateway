# api/config.py
from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Centralized application configuration.
    """

    CORS_ORIGINS: list[str] = ["*"]
    ENABLE_DEBUG_ROUTES: bool = False
    DEFAULT_EGRESS_URL: str = ""
    JWT_SECRET: str | None = None
    OPA_URL: str | None = None
    OPA_FAIL_CLOSED: bool = True
    OPA_TIMEOUT: float = 8.0
    ALLOWED_MODELS: list[str] = ["stub", "openai:gpt-4o", "openai:gpt-4o-mini"]
    MAX_TOKENS_LIMIT: int = 2048
    MAX_MESSAGES_LIMIT: int = 50
    TOTAL_MESSAGE_CHARS_LIMIT: int = 8000
    SINGLE_MESSAGE_CHARS_LIMIT: int = 4000
    CONTEXT_FIREWALL_RISK_THRESHOLD: int = 10
    ALLOWED_CONTEXT_ORIGINS: list[str] = []
    OTEL_EXPORTER_OTLP_ENDPOINT: str | None = None


@lru_cache
def get_settings() -> Settings:
    return Settings()
