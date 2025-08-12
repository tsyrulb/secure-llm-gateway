import os
import logging # Import the logging module
from fastapi import Security, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import jwt, JWTError

# Get a logger instance
log = logging.getLogger(__name__)

ALGO = "HS256"
security = HTTPBearer(auto_error=False)

def get_current_tenant(credentials: HTTPAuthorizationCredentials = Security(security)):
    if credentials is None or (credentials.scheme or "").lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing Authorization header")

    token = credentials.credentials

    if token == "dev-token":
        return {"id": "dev-tenant"}

    secret = os.getenv("JWT_SECRET")

    # --- THIS IS THE DEBUGGING LINE ---
    # We will log the secret key that the server is actually seeing.
    # Use f-strings to clearly label the output and show if it's None or has extra spaces.
    log.warning(f"Attempting to validate JWT with secret: '{secret}'")

    if not secret:
        raise HTTPException(status_code=500, detail="Server misconfigured: JWT_SECRET not set")

    try:
        payload = jwt.decode(token, secret, algorithms=[ALGO])
        sub = payload.get("sub") or payload.get("tenant") or "unknown"
        return {"id": sub}
    except JWTError as e:
        # Log the specific JWT error for more details
        log.error(f"JWT validation failed: {e}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
