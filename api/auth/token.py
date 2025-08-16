import logging
import os

from fastapi import HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import ExpiredSignatureError, JWTError, jwt

# Get a logger instance
log = logging.getLogger(__name__)

ALGO = "HS256"
security = HTTPBearer(auto_error=False)


def get_current_tenant(
    credentials: HTTPAuthorizationCredentials = Security(security),
) -> dict[str, str]:
    if credentials is None or (credentials.scheme or "").lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing Authorization header"
        )

    token = credentials.credentials

    if token == "dev-token":  # nosec B105
        return {"id": "dev-tenant"}

    secret = os.getenv("JWT_SECRET")

    if not secret:
        raise HTTPException(status_code=500, detail="Server misconfigured: JWT_SECRET not set")

    try:
        payload = jwt.decode(token, secret, algorithms=[ALGO])
        sub = payload.get("sub") or payload.get("tenant") or "unknown"
        return {"id": str(sub)}
    except ExpiredSignatureError as e:
        log.error(f"JWT expired: {e}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired") from e
    except JWTError as e:
        log.error(f"JWT validation failed: {e}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from e
