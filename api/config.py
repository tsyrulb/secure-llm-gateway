# api/config.py
from pydantic_settings import BaseSettings
from typing import List, Optional

class Settings(BaseSettings):
    """
    Centralized application configuration using Pydantic's BaseSettings.
    Settings are loaded from environment variables.
    """
    # --- Application Settings ---
    CORS_ORIGINS: List[str] = ["*"]
    ENABLE_DEBUG_ROUTES: bool = False
    DEFAULT_EGRESS_URL: str = ""

    # --- Security & Policy ---
    JWT_SECRET: Optional[str] = None
    OPA_URL: Optional[str] = None
    OPA_FAIL_CLOSED: bool = True
    OPA_TIMEOUT: float = 8.0

    # --- Model & Request Validation ---
    ALLOWED_MODELS: List[str] = ["stub", "openai:gpt-4o", "openai:gpt-4o-mini"]
    MAX_TOKENS_LIMIT: int = 2048
    MAX_MESSAGES_LIMIT: int = 50
    TOTAL_MESSAGE_CHARS_LIMIT: int = 8000
    SINGLE_MESSAGE_CHARS_LIMIT: int = 4000

    # --- THIS IS THE FIX ---
    # Add the missing firewall settings so they can be configured and patched in tests.
    CONTEXT_FIREWALL_RISK_THRESHOLD: int = 10
    ALLOWED_CONTEXT_ORIGINS: List[str] = []

    # --- Telemetry ---
    OTEL_EXPORTER_OTLP_ENDPOINT: Optional[str] = None

# Create a single, importable instance of the settings
settings = Settings()
