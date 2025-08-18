
---

# Secure LLM Gateway

A **FastAPI** gateway that sits in front of LLM providers and enforces **policy, safety, and observability**. It implements:

* **Auth** via JWT (multi-tenant, “dev” token for local use)
* **Policy enforcement** (Open Policy Agent (OPA) or local policy)
* **Context firewall** for retrieval-augmented generation (RAG) sources
* **Response validator** with PII/secret redaction
* **Rate limiting** (in-memory or Redis)
* **Telemetry** (OpenTelemetry)
* **DevSecOps guardrails** (pre-commit: Black, Ruff, MyPy, Bandit, detect-secrets)
* **Docker** / **Docker Compose**
* **CI** with smoke tests and type/lint/security checks

> The goal is to provide a secure, testable reference for gating LLM usage in production.

---

## Contents

* [Quick start](#quick-start)
* [Architecture & flow](#architecture--flow)
* [API](#api)
* [Configuration](#configuration)
* [Local development](#local-development)
* [Testing & quality](#testing--quality)
* [Running the smoke suite](#running-the-smoke-suite)
* [Policy (OPA vs. local)](#policy-opa-vs-local)
* [Context firewall](#context-firewall)
* [Response validation & redaction](#response-validation--redaction)
* [Rate limiting](#rate-limiting)
* [Telemetry](#telemetry)
* [Security notes](#security-notes)
* [Production deployment](#production-deployment)
* [Troubleshooting](#troubleshooting)
* [Roadmap / Ideas](#roadmap--ideas)
* [License](#license)

---

## Quick start

### Prerequisites

* Python 3.11+
* (Optional) Docker & Docker Compose
* PowerShell (for the smoke script on Windows/GitHub Actions runner with pwsh)

### Run locally (without Docker)

```bash
python -m venv .venv
. .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Start the API
uvicorn api.main:app --reload --port 8000
```

Health checks:

```bash
curl http://127.0.0.1:8000/healthz
curl http://127.0.0.1:8000/readyz
```

Call completions (uses the “stub” model in tests/dev):

```bash
curl -X POST http://127.0.0.1:8000/v1/chat/completions \
  -H "Authorization: Bearer dev-token" \
  -H "Content-Type: application/json" \
  -d '{"model":"stub","messages":[{"role":"user","content":"hello"}]}'
```

### Run with Docker Compose

```bash
docker compose up --build
# API defaults to http://127.0.0.1:8000
```

There’s also a `docker-compose.prod.yml` example for a more production-like stack.

---

## Architecture & flow

High-level request pipeline:

1. **Auth**: `Authorization: Bearer <token>` → tenant extracted/validated
2. **Request validation**: size limits, allowed model list, message count/cap
3. **Context firewall (RAG)**: validates `context.source` and scans chunks for prompt-injection/high-risk cues
4. **Policy check**: OPA (if configured) or local policy → may **deny** models/egress
5. **Provider call**: current code includes a stub + OpenAI provider scaffolding
6. **Response validation**: redacts **PII** and **secret tokens**
7. **Rate limit**: in-memory or Redis
8. **Telemetry**: request/response spans

Key modules:

* `api/main.py` — FastAPI app & endpoints
* `api/auth/token.py` — JWT / dev-token handling
* `api/policy/local_policy.py` and `api/policy/opa_client.py`
* `api/firewall/context_firewall.py` — source allowlist & risk scoring
* `api/firewall/response_validator.py` — redaction rules
* `api/middleware/rate_limit.py` — RL via memory/Redis
* `api/providers/openai_provider.py` — provider adapter (stub/openai)
* `api/telemetry/otel_setup.py` — OpenTelemetry wiring
* `scripts/run-smoke.ps1` & `scripts/make_jwt.py` — CI/local smoke harness

---

## API

### `GET /healthz`

Simple liveness probe.

### `GET /readyz`

Readiness probe showing policy mode:

```json
{ "mode": "OPA" | "LOCAL", "ready": true }
```

### `POST /v1/chat/completions`

Request body:

```json
{
  "model": "stub",
  "messages": [
    { "role": "user", "content": "hello" }
  ],
  "max_tokens": 512,
  "context": {
    "source": "kb://approved/file.md",
    "chunks": [{ "id": "1", "content": "..." }]
  }
}
```

Response:

```json
{
  "answer": "string",
  "citations": ["..."],
  "meta": { "provider": "stub" }
}
```

Auth:

* Local/dev: `Authorization: Bearer dev-token`
* Trusted tenants: JWT signed with `JWT_SECRET` (see `scripts/make_jwt.py`)

---

## Configuration

Environment variables (see `api/config.py`):

* `JWT_SECRET` — required for real JWTs (dev token still works without)
* `ALLOWED_MODELS` — comma-separated allowlist (e.g. `stub,openai:gpt-4o`)
* `ALLOWED_CONTEXT_ORIGINS` — allowlist prefixes for RAG sources, e.g. `kb://approved/`
* `CONTEXT_FIREWALL_RISK_THRESHOLD` — integer threshold (higher → stricter)
* `OPA_URL` — if set, gateway asks OPA for `deny` decisions
* `REDIS_URL` — if set, enables Redis rate limiting (`redis://host:6379/0`, etc.)
* Rate-limit defaults are defined in middleware (`limit=5/window=1s` for anon) and can be adjusted if needed.

You can put values in a `.env` for local runs.

---

## Local development

### Install & run

```bash
pip install -r requirements.txt
uvicorn api.main:app --reload
```

### Pre-commit hooks

```bash
pre-commit install
pre-commit run --all-files
```

Hooks include:

* `black` (format)
* `ruff` (lint + format)
* `mypy` (type check) with pinned stub deps
* `bandit` (security lints)
* `detect-secrets` (with `.secrets.baseline`)

### Tests

```bash
pytest -q
```

You should see all tests pass once your environment is set up.

---

## Testing & quality

* **Unit/functional tests** in `tests/`
* **Smoke test** (`scripts/run-smoke.ps1`) used both locally and in CI:

  * Health & readiness
  * Policy deny/allow
  * Size/message caps
  * Context firewall handling
  * Response redaction
  * (Optional) rate limit

---

## Running the smoke suite

From a local PowerShell (or GitHub Actions pwsh):

```bash
./scripts/run-smoke.ps1
```

It will:

* Create a trusted JWT using `scripts/make_jwt.py` (signed by `JWT_SECRET`)
* Exercise the API and summarize **PASS/FAIL** checks

If you’re on Linux/Mac and don’t want to use PowerShell, you can replicate requests with `curl` (the script is just convenience).

---

## Policy (OPA vs. local)

* **Local policy**: `api/policy/local_policy.py` — fast, easy to extend in Python for dev/test.
* **OPA**: set `OPA_URL`, run an OPA sidecar, and define Rego policies. The app calls `POST /v1/data/gateway/deny` with `{tenant, model}`.

This allows you to ship the same app to prod and swap policies centrally without redeploying.

---

## Context firewall

When `context` is provided:

* **Origin allowlist** via `ALLOWED_CONTEXT_ORIGINS` (e.g., `kb://approved/`)
* **Risk scoring** on chunk text for prompt-injection cues (e.g., *ignore previous instructions*, *reveal your prompt*, etc.)
* Requests with disallowed origins or high risk are rejected with **HTTP 400**.

Types:

* `ContextInput`, `SanitizedContext` in `api/firewall/context_firewall.py`

---

## Response validation & redaction

The validator (`api/firewall/response_validator.py`) scans generated responses and **redacts**:

* Emails & phone numbers (PII)
* Common API key patterns (e.g., `sk_...`)
* Bearer tokens
* AWS access key formats, etc.

If validation fails, the gateway returns a sanitized response to the client.

---

## Rate limiting

Middleware: `api/middleware/rate_limit.py`

* **In-memory** fallback (good for tests/dev)
* **Redis** if `REDIS_URL` is set:

  * Per-tenant / per-IP keys
  * Sliding window per simple counters (implementation stays intentionally minimal)

You can adjust limits/windows in the middleware to meet your needs.

---

## Telemetry

`api/telemetry/otel_setup.py` wires **OpenTelemetry** so you can export traces/metrics to your preferred backend (e.g., OTLP). Configure via standard OTEL env vars in your deployment.

---

## Security notes

* Never commit real secrets. This repo uses **detect-secrets** with a `.secrets.baseline`. Update it when changing files:

  ```bash
  python -m detect_secrets scan > .secrets.baseline
  git add .secrets.baseline
  ```
* `bandit` runs in pre-commit to catch common Python security issues.
* JWT validation is strict in non-dev mode. For local dev, `dev-token` is allowed.

---

## Production deployment

* Build the image:

  ```bash
  docker build -t secure-llm-gateway:latest .
  ```
* Compose (see `docker-compose.prod.yml`) or deploy to your platform (Kubernetes, ECS, etc.)
* Provide:

  * `JWT_SECRET`
  * `OPA_URL` (optional, recommended for prod)
  * `REDIS_URL` (recommended)
  * OTEL env for telemetry (optional)

Expose `8000` behind your API gateway or ingress, and wire TLS at the edge.

---

## Troubleshooting

* `422 Unprocessable Entity` on `/v1/chat/completions`:

  * Ensure `Content-Type: application/json`
  * Endpoint expects JSON body (the app also supports `{"req": {...}}` wrapper).
* Rate-limit failures in tests:

  * The in-memory limiter is tight by default; tests already avoid flakiness, but if you parallelize you may want Redis.
* OPA denies everything:

  * Check your Rego policy; run OPA with logs; verify payload `{tenant, model}`.

---

## Roadmap / Ideas

* Provider plugins (Azure OpenAI, Anthropic, Vertex, etc.)
* Per-tenant policy bundles
* Egress allowlist & audit for tools/functions
* Structured redaction reports for compliance
* Richer context firewall (LLM-based heuristics, embeddings)
* Async batching & caching layer

---

## License

MIT (or your preferred license). See `LICENSE` file if present.

---
