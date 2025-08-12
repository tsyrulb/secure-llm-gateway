import os  
from fastapi import Security, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import jwt, JWTError

# This module is now self-contained and does not import from api.config

ALGO = "HS256"
security = HTTPBearer(auto_error=False)

def get_current_tenant(credentials: HTTPAuthorizationCredentials = Security(security)):
    """
    Accepts either:
      - dev-token  -> maps to tenant 'dev-tenant'
      - JWT (HS256, secret from the JWT_SECRET environment variable)
    """
    if credentials is None or (credentials.scheme or "").lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing Authorization header")

    token = credentials.credentials

    # Simple dev mode
    if token == "dev-token":
        return {"id": "dev-tenant"}

    # This is the most reliable method and avoids any import-order conflicts.
    secret = os.getenv("JWT_SECRET")
    if not secret:
        raise HTTPException(status_code=500, detail="Server misconfigured: JWT_SECRET not set")

    try:
        payload = jwt.decode(token, secret, algorithms=[ALGO])
        sub = payload.get("sub") or payload.get("tenant") or "unknown"
        return {"id": sub}
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")