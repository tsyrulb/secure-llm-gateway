import os
import importlib

def setup_otel(app) -> None:
    if not os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT"):
        return
    try:
        mod = importlib.import_module("opentelemetry.instrumentation.fastapi")
        FastAPIInstrumentor = getattr(mod, "FastAPIInstrumentor")
        FastAPIInstrumentor.instrument_app(app)
    except Exception:
        return
