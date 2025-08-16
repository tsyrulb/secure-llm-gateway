import logging
from typing import Any

log = logging.getLogger("uvicorn.error")


async def local_policy_deny(input_doc: dict[str, Any]) -> list[str]:
    """
    Local fallback policy. Return a list of deny messages (empty => allow).
    """
    denies: list[str] = []

    tenant = str(input_doc.get("tenant", "")).strip()
    model = str(input_doc.get("model", "")).strip()
    max_t = int(input_doc.get("max_tokens") or 0)
    eurl = str(input_doc.get("egress_url") or "").strip()

    # normalize
    tenant_l = tenant.lower()
    model_l = model.lower()

    # 1) Block gpt-4o (and variants) for non-trusted tenants
    if "openai:gpt-4o" in model_l and tenant_l != "trusted_tenant":
        denies.append("gpt-4o only allowed for trusted tenants")

    # 2) Cap tokens
    if max_t > 2048:
        denies.append("max_tokens exceeds policy cap")

    # 3) Egress allowlist example (only if provided)
    if eurl and not eurl.startswith("https://api.my-allowlist.com/"):
        denies.append(f"egress blocked: {eurl}")

    # DEBUG: print exactly what we evaluated
    log.info(
        "local_policy input tenant=%r model=%r max_tokens=%s egress_url=%r -> denies=%r",
        tenant,
        model,
        max_t,
        eurl,
        denies,
    )
    return denies
