from slowapi import Limiter
from starlette.requests import Request

def get_real_ip(request: Request) -> str:
    """Get client IP from X-Forwarded-For header (Railway proxy) or fall back to remote address."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        # First IP in X-Forwarded-For is the real client IP
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"

limiter = Limiter(key_func=get_real_ip)
