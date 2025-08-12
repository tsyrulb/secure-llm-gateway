# scripts/make_jwt.py
import sys, os, json, time, hmac, hashlib, base64

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def sign(secret: str, msg: bytes) -> str:
    return b64url(hmac.new(secret.encode(), msg, hashlib.sha256).digest())

def make_jwt(sub: str, secret: str, ttl: int = 3600) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    payload = {"sub": sub, "iat": now, "exp": now + ttl}
    h = b64url(json.dumps(header, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig = sign(secret, f"{h}.{p}".encode())
    return f"{h}.{p}.{sig}"

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scripts/make_jwt.py <subject> [secret]", file=sys.stderr)
        sys.exit(1)
    sub = sys.argv[1]
    secret = sys.argv[2] if len(sys.argv) > 2 else os.getenv("JWT_SECRET", "dev-secret")
    print(make_jwt(sub, secret))
