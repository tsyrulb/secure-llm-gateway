from fastapi import Security, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import jwt, JWTError
import os

ALGO = "HS256"
security = HTTPBearer(auto_error=False)

def get_current_tenant(credentials: HTTPAuthorizationCredentials = Security(security)):
    """
    Accepts either:
      - dev-token  -> maps to tenant 'dev-tenant'
      - JWT (HS256, secret from JWT_SECRET) with 'sub' or 'tenant' claim
    """
    if credentials is None or (credentials.scheme or "").lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing Authorization header")

    token = credentials.credentials

    # Simple dev mode
    if token == "dev-token":
        return {"id": "dev-tenant"}

    secret = os.getenv("JWT_SECRET")
    if not secret:
        raise HTTPException(status_code=500, detail="Server misconfigured: JWT_SECRET not set")

    try:
        payload = jwt.decode(token, secret, algorithms=[ALGO])
        sub = payload.get("sub") or payload.get("tenant") or "unknown"
        return {"id": sub}
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
