import bcrypt
import os
import uuid
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from typing import Optional

# Load environment variables
load_dotenv()
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

# JWT (JSON Web Token) configuration
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY environment variable is not set. Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\"")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Hash a password using bcrypt directly
def hash_password(password: str) -> str:
    """Takes a plain text password and returns the bcrypt hash"""
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')

# Verify a password against a hash
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Checks if the plain password matches the hashed password"""
    password_bytes = plain_password.encode('utf-8')
    hashed_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(password_bytes, hashed_bytes)

# Create a JWT access token
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Creates a JWT token that expires after a certain time"""
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)

    to_encode.update({"exp": expire, "jti": str(uuid.uuid4())})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Verify a JWT token and extract the data
def verify_token(token: str):
    """Decodes and verifies a JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None

# Get current user from token (for FastAPI dependency injection)
def get_current_user_id(token: str) -> int:
    """Extracts user_id from JWT token. Raises exception if invalid."""
    from fastapi import HTTPException, status

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )

    payload = verify_token(token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token"
        )

    user_id = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload"
        )

    return int(user_id)
