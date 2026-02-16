from fastapi import APIRouter, Depends, HTTPException, status, Header, Request
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import Optional
from datetime import timedelta, datetime, timezone
import secrets
import re
import logging
import hmac
from .. import models, schemas, auth
from ..database import get_db
from ..limiter import limiter
from ..email import send_verification_email, send_password_reset_email

logger = logging.getLogger(__name__)


def utcnow():
    """Return timezone-naive UTC now (safe for SQLite comparison)."""
    return datetime.utcnow()


def generate_verification_code() -> str:
    """Generate a 6-digit verification code."""
    return str(secrets.randbelow(900000) + 100000)

router = APIRouter()


# Dependency to get current user from Authorization header
def get_current_user(
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
) -> int:
    """Extract user_id from Bearer token in Authorization header"""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )

    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication format"
        )

    token = parts[1]
    user_id = auth.get_current_user_id(token)

    # Check blacklist (only for tokens with jti)
    payload = auth.verify_token(token)
    jti = payload.get("jti") if payload else None
    if jti:
        blacklisted = db.query(models.BlacklistedToken).filter(
            models.BlacklistedToken.jti == jti
        ).first()
        if blacklisted:
            logger.warning(f"Blacklisted token used: jti={jti}, user_id={user_id}")
            raise HTTPException(status_code=401, detail="Token has been revoked")

    return user_id


@router.post("/auth/signup", response_model=schemas.SignupResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
def signup(request: Request, user: schemas.UserCreate, db: Session = Depends(get_db)):
    """Create a new user account (requires email verification)"""

    existing_email = db.query(models.User).filter(func.lower(models.User.email) == user.email.lower()).first()
    if existing_email:
        if existing_email.email_verified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="An account with this email or username already exists"
            )
        else:
            db.delete(existing_email)
            db.flush()

    existing_username = db.query(models.User).filter(func.lower(models.User.username) == user.username.lower()).first()
    if existing_username:
        if existing_username.email_verified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="An account with this email or username already exists"
            )
        else:
            db.delete(existing_username)
            db.flush()

    verification_code = generate_verification_code()
    code_expires = utcnow() + timedelta(minutes=15)

    hashed_password = auth.hash_password(user.password)
    new_user = models.User(
        email=user.email,
        username=user.username,
        hashed_password=hashed_password,
        email_verified=False,
        verification_code=verification_code,
        verification_code_expires=code_expires
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    try:
        send_verification_email(user.email, verification_code, user.username)
    except Exception as e:
        logger.error(f"Failed to send verification email to {user.email}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send verification email. Please try again."
        )

    return {
        "message": "Account created. Please check your email for verification code.",
        "email": user.email,
        "requires_verification": True
    }


@router.get("/auth/check-username", response_model=schemas.UsernameCheckResponse)
@limiter.limit("20/minute")
def check_username(request: Request, username: str, db: Session = Depends(get_db)):
    """Check if a username is available"""

    if not re.match(r"^[a-zA-Z0-9_]+$", username):
        return {
            "username": username,
            "available": False,
            "reason": "Username must be 3-20 characters using letters, numbers, and underscores only"
        }

    if len(username) < 3 or len(username) > 20:
        return {
            "username": username,
            "available": False,
            "reason": "Username must be 3-20 characters using letters, numbers, and underscores only"
        }

    existing = db.query(models.User).filter(
        func.lower(models.User.username) == username.lower(),
        models.User.email_verified == True
    ).first()

    return {
        "username": username,
        "available": existing is None
    }


@router.post("/auth/login", response_model=schemas.Token)
@limiter.limit("10/minute")
def login(request: Request, credentials: schemas.UserLogin, db: Session = Depends(get_db)):
    """Login with email or username"""

    identifier_lower = credentials.identifier.lower()
    user = db.query(models.User).filter(
        (func.lower(models.User.email) == identifier_lower) |
        (func.lower(models.User.username) == identifier_lower)
    ).first()

    if not user:
        auth.verify_password("dummy", "$2b$12$LJ3m4ys3Lg2HvSSvfOEqWOsonRUKDSCMIYPSYzPF1vFfGo/MlJl5e")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )

    if user.locked_until:
        if utcnow() < user.locked_until:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account temporarily locked. Try again later."
            )
        else:
            user.failed_login_attempts = 0
            user.locked_until = None
            db.commit()

    if not auth.verify_password(credentials.password, user.hashed_password):
        user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
        logger.warning(f"Failed login for: {credentials.identifier[:50]}")
        if user.failed_login_attempts >= 10:
            user.locked_until = utcnow() + timedelta(minutes=15)
            logger.warning(f"Account locked: {credentials.identifier[:50]}")
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )

    if not user.email_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email not verified. Please verify your email first."
        )

    if user.failed_login_attempts:
        user.failed_login_attempts = 0
        user.locked_until = None
        db.commit()

    access_token = auth.create_access_token(
        data={"sub": str(user.id)},
        expires_delta=timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user
    }


@router.post("/auth/logout")
@limiter.limit("10/minute")
def logout(
    request: Request,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):
    """Logout and blacklist current token"""
    if not authorization:
        return {"message": "Logged out"}

    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return {"message": "Logged out"}

    token = parts[1]
    payload = auth.verify_token(token)
    if not payload:
        return {"message": "Logged out"}

    jti = payload.get("jti")
    if not jti:
        return {"message": "Logged out"}

    try:
        expires_at = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        blacklisted = models.BlacklistedToken(jti=jti, expires_at=expires_at)
        db.add(blacklisted)
        db.commit()
    except Exception:
        db.rollback()

    return {"message": "Logged out"}


@router.post("/auth/verify-email", response_model=schemas.Token)
@limiter.limit("5/minute")
def verify_email(request: Request, data: schemas.VerifyEmailRequest, db: Session = Depends(get_db)):
    """Verify email with 6-digit code"""

    user = db.query(models.User).filter(func.lower(models.User.email) == data.email.lower()).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification request"
        )

    if user.email_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification request"
        )

    if user.locked_until and utcnow() < user.locked_until:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account temporarily locked. Try again later."
        )

    if user.verification_attempts >= 5:
        user.verification_code = None
        user.verification_code_expires = None
        user.verification_attempts = 0
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Too many failed attempts. Please request a new verification code."
        )

    if user.verification_code_expires and utcnow() > user.verification_code_expires:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification code expired. Please request a new one."
        )

    if not hmac.compare_digest(user.verification_code or "", data.code):
        user.verification_attempts = (user.verification_attempts or 0) + 1
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code"
        )

    user.email_verified = True
    user.verification_code = None
    user.verification_code_expires = None
    user.verification_attempts = 0
    db.commit()
    db.refresh(user)

    access_token = auth.create_access_token(
        data={"sub": str(user.id)},
        expires_delta=timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user
    }


@router.post("/auth/resend-code", response_model=schemas.SignupResponse)
@limiter.limit("3/minute")
def resend_code(request: Request, data: schemas.ResendCodeRequest, db: Session = Depends(get_db)):
    """Resend verification code to email"""

    user = db.query(models.User).filter(func.lower(models.User.email) == data.email.lower()).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid request"
        )

    if user.email_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid request"
        )

    if user.locked_until and utcnow() < user.locked_until:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account temporarily locked. Try again later."
        )

    verification_code = generate_verification_code()
    code_expires = utcnow() + timedelta(minutes=15)

    user.verification_code = verification_code
    user.verification_code_expires = code_expires
    db.commit()

    try:
        send_verification_email(user.email, verification_code, user.username)
    except Exception as e:
        logger.error(f"Failed to send verification email to {user.email}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send verification email. Please try again."
        )

    return {
        "message": "Verification code sent. Please check your email.",
        "email": user.email,
        "requires_verification": True
    }


@router.post("/auth/forgot-password")
@limiter.limit("3/minute")
def forgot_password(request: Request, data: schemas.ForgotPasswordRequest, db: Session = Depends(get_db)):
    """Request password reset code (anti-enumeration protection)"""

    search_email = data.email.strip().lower()
    user = db.query(models.User).filter(func.lower(models.User.email) == search_email).first()

    if not user or not user.email_verified:
        return {"message": "If an account exists with that email, a reset code has been sent."}

    reset_code = generate_verification_code()
    code_expires = utcnow() + timedelta(minutes=15)

    user.verification_code = reset_code
    user.verification_code_expires = code_expires
    db.commit()

    try:
        send_password_reset_email(user.email, reset_code, user.username)
    except Exception as e:
        logger.error(f"Failed to send password reset email to {user.email}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send reset email. Please try again."
        )

    return {"message": "If an account exists with that email, a reset code has been sent."}


@router.post("/auth/reset-password")
@limiter.limit("5/minute")
def reset_password(request: Request, data: schemas.ResetPasswordRequest, db: Session = Depends(get_db)):
    """Reset password with verification code"""

    user = db.query(models.User).filter(func.lower(models.User.email) == data.email.lower()).first()
    if not user or not user.email_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset code"
        )

    if user.locked_until and utcnow() < user.locked_until:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account temporarily locked. Try again later."
        )

    if user.verification_attempts >= 5:
        user.verification_code = None
        user.verification_code_expires = None
        user.verification_attempts = 0
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Too many failed attempts. Please request a new reset code."
        )

    if not user.verification_code_expires or utcnow() > user.verification_code_expires:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Reset code expired. Please request a new one."
        )

    if not hmac.compare_digest(user.verification_code or "", data.code):
        user.verification_attempts = (user.verification_attempts or 0) + 1
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset code"
        )

    user.hashed_password = auth.hash_password(data.new_password)

    user.verification_code = None
    user.verification_code_expires = None
    user.verification_attempts = 0
    db.commit()

    return {"message": "Password reset successful. You can now log in."}


@router.put("/auth/change-password")
@limiter.limit("5/minute")
def change_password(
    request: Request,
    data: schemas.ChangePasswordRequest,
    db: Session = Depends(get_db),
    user_id: int = Depends(get_current_user)
):
    """Change password for authenticated user"""

    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    if user.locked_until and utcnow() < user.locked_until:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account temporarily locked. Try again later."
        )

    if not auth.verify_password(data.current_password, user.hashed_password):
        user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
        logger.warning(f"Failed password change attempt for user {user_id}")
        if user.failed_login_attempts >= 10:
            user.locked_until = utcnow() + timedelta(minutes=15)
            logger.warning(f"Account locked after failed password changes: user {user_id}")
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )

    if user.failed_login_attempts:
        user.failed_login_attempts = 0
        user.locked_until = None

    user.hashed_password = auth.hash_password(data.new_password)

    try:
        token = request.headers.get("authorization", "").split()[-1]
        token_payload = auth.verify_token(token)
        if token_payload and token_payload.get("jti"):
            expires_at = datetime.fromtimestamp(token_payload["exp"], tz=timezone.utc)
            blacklisted = models.BlacklistedToken(
                jti=token_payload["jti"], expires_at=expires_at
            )
            db.add(blacklisted)
    except Exception:
        pass

    db.commit()

    return {"message": "Password changed successfully"}


@router.get("/auth/me", response_model=schemas.UserResponse)
def get_me(
    db: Session = Depends(get_db),
    user_id: int = Depends(get_current_user)
):
    """Get current user profile based on JWT token"""
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.post("/auth/delete-account")
@limiter.limit("3/minute")
def delete_account(
    request: Request,
    data: schemas.DeleteAccountRequest,
    db: Session = Depends(get_db),
    user_id: int = Depends(get_current_user)
):
    """Delete user account (irreversible)"""

    try:
        user = db.query(models.User).filter(models.User.id == user_id).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        if not auth.verify_password(data.password, user.hashed_password):
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
            if user.failed_login_attempts >= 10:
                user.locked_until = utcnow() + timedelta(minutes=15)
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect password"
            )

        db.delete(user)
        db.commit()

        return {"message": "Account deleted successfully"}

    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to delete account for user {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete account"
        )
