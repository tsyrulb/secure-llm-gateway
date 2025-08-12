# Dockerfile
FROM python:3.11-slim-bookworm
# Safer defaults
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Patch OS CVEs and install curl for HEALTHCHECK
RUN apt-get update \
 && apt-get -y upgrade --no-install-recommends \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

# Create least-privileged user
RUN addgroup --system app && adduser --system --ingroup app app

# Install Python deps first for better layer caching
COPY --chown=app:app requirements.txt .
RUN python -m pip install --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

# Copy source
COPY --chown=app:app . .

USER app
EXPOSE 8000

# Simple, robust healthcheck (no heredoc)
HEALTHCHECK --interval=30s --timeout=3s --retries=5 \
  CMD curl -fsS http://127.0.0.1:8000/readyz >/dev/null || exit 1

CMD ["uvicorn","api.main:app","--host","0.0.0.0","--port","8000"]
