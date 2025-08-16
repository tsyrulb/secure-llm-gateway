import importlib
import os

from fastapi import FastAPI


def setup_otel(app: FastAPI) -> None:
    if not os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT"):
        return
    try:
        mod = importlib.import_module("opentelemetry.instrumentation.fastapi")
        FastAPIInstrumentor = mod.FastAPIInstrumentor
        FastAPIInstrumentor.instrument_app(app)
    except Exception:
        return
