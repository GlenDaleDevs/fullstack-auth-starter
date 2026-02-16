import os
import asyncio
import logging
from pathlib import Path
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from slowapi.errors import RateLimitExceeded
from sqlalchemy import text
from .database import engine, Base, SessionLocal
from . import models
from .routers import auth
from .limiter import limiter
from .logging_config import setup_logging

load_dotenv()

# Setup logging before anything else
setup_logging()
logger = logging.getLogger(__name__)

APP_NAME = os.getenv("APP_NAME", "App")

# Create database tables
Base.metadata.create_all(bind=engine)

@asynccontextmanager
async def lifespan(app):
    logger.info("Starting background tasks")
    cleanup_task = asyncio.create_task(cleanup_verification_codes())
    blacklist_task = asyncio.create_task(cleanup_blacklisted_tokens())
    yield
    logger.info("Shutting down background tasks")
    cleanup_task.cancel()
    blacklist_task.cancel()

# Custom rate limit handler
def custom_rate_limit_handler(request: Request, exc: RateLimitExceeded):
    retry_after = 60
    return JSONResponse(
        status_code=429,
        content={
            "detail": "Too many requests. Please try again shortly.",
            "retry_after": retry_after
        },
        headers={"Retry-After": str(retry_after)}
    )

# Create the FastAPI app
is_production = os.getenv("ENVIRONMENT", "").lower() == "production"
app = FastAPI(
    title=f"{APP_NAME} API",
    lifespan=lifespan,
    docs_url=None if is_production else "/docs",
    redoc_url=None if is_production else "/redoc",
    openapi_url=None if is_production else "/openapi.json",
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, custom_rate_limit_handler)

# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.headers.get("x-forwarded-proto") == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "img-src 'self' data:; "
        "font-src 'self' https://fonts.gstatic.com; "
        "connect-src 'self'; "
        "frame-ancestors 'none'"
    )
    return response

# Request size limit middleware
@app.middleware("http")
async def limit_request_size(request: Request, call_next):
    if request.method in ("POST", "PUT", "PATCH"):
        content_length = request.headers.get("content-length")
        try:
            if content_length and int(content_length) > 1_048_576:  # 1MB
                return JSONResponse(status_code=413, content={"detail": "Request body too large"})
        except ValueError:
            return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length header"})
    return await call_next(request)

# CORS - allowed origins for frontend
allowed_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

if os.getenv("FORCE_HTTPS", "").lower() == "true":
    app.add_middleware(HTTPSRedirectMiddleware)

# Include auth router
app.include_router(auth.router, prefix="/api", tags=["auth"])

# Background task: cleanup expired verification codes and stale unverified accounts
async def cleanup_verification_codes():
    while True:
        await asyncio.sleep(3600)  # Every hour
        db = SessionLocal()
        try:
            now = datetime.now(timezone.utc)

            expired_codes = db.query(models.User).filter(
                models.User.verification_code.isnot(None),
                models.User.verification_code_expires < now
            ).update({
                "verification_code": None,
                "verification_code_expires": None
            }, synchronize_session=False)

            if expired_codes > 0:
                logger.info(f"Expired {expired_codes} verification code(s)")

            # Delete stale unverified accounts (24+ hours old)
            cutoff_time = now - timedelta(hours=24)
            deleted = db.query(models.User).filter(
                models.User.email_verified == False,
                models.User.created_at < cutoff_time
            ).delete(synchronize_session=False)

            db.commit()

            if deleted > 0:
                logger.info(f"Deleted {deleted} stale unverified account(s)")

        except Exception as e:
            logger.error(f"Error in verification cleanup: {e}")
            db.rollback()
        finally:
            db.close()

# Background task: cleanup expired blacklisted tokens
async def cleanup_blacklisted_tokens():
    while True:
        await asyncio.sleep(3600)  # Every hour
        db = SessionLocal()
        try:
            now = datetime.now(timezone.utc)
            deleted = db.query(models.BlacklistedToken).filter(
                models.BlacklistedToken.expires_at < now
            ).delete(synchronize_session=False)
            if deleted > 0:
                logger.info(f"Cleaned up {deleted} expired blacklisted token(s)")
            db.commit()
        except Exception as e:
            logger.error(f"Error cleaning up blacklisted tokens: {e}")
            db.rollback()
        finally:
            db.close()

# Health check
@app.get("/api/health")
@limiter.limit("30/minute")
def health_check(request: Request):
    try:
        db = SessionLocal()
        db.execute(text("SELECT 1"))
        db.close()
        return {"status": "healthy", "database": "connected"}
    except Exception:
        return JSONResponse(status_code=503, content={"status": "unhealthy", "database": "unreachable"})

# Serve frontend static files
DIST_DIR = Path(__file__).resolve().parent.parent.parent / "dist"

if DIST_DIR.is_dir():
    app.mount("/assets", StaticFiles(directory=DIST_DIR / "assets"), name="assets")

    @app.get("/{path:path}")
    async def serve_spa(path: str):
        file_path = DIST_DIR / path
        if file_path.is_file():
            return FileResponse(file_path)
        return FileResponse(DIST_DIR / "index.html")
