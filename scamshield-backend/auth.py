"""
ScamShield Auth Utilities
- Password hashing with bcrypt (direct, no passlib wrapper)
- JWT creation and validation
- FastAPI dependency guards (require_auth, require_admin, require_superadmin)
- Role constants
"""

import os
import bcrypt
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, Cookie, status
from jose import JWTError, jwt

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
SECRET_KEY = os.getenv("SECRET_KEY", "changeme-use-a-real-secret-in-production-32bytes")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("TOKEN_EXPIRE_MINUTES", "480"))  # 8 hours

# ---------------------------------------------------------------------------
# Password hashing (direct bcrypt, avoids passlib/bcrypt version conflicts)
# ---------------------------------------------------------------------------

def hash_password(plain: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(plain.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    """Decode and validate a JWT. Raises HTTPException on failure."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session. Please log in again.",
        )


# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------
ROLE_SUPERADMIN = "superadmin"
ROLE_ADMIN = "admin"
ROLE_USER = "user"
ROLE_GUEST = "guest"

ROLE_HIERARCHY = {
    ROLE_SUPERADMIN: 100,
    ROLE_ADMIN: 50,
    ROLE_USER: 10,
    ROLE_GUEST: 0,
}


def role_gte(role: str, min_role: str) -> bool:
    return ROLE_HIERARCHY.get(role, 0) >= ROLE_HIERARCHY.get(min_role, 0)


# ---------------------------------------------------------------------------
# FastAPI dependency: get current user from cookie
# ---------------------------------------------------------------------------
def get_current_user(
    access_token: Optional[str] = Cookie(default=None),
):
    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated. Please log in.",
        )
    return decode_token(access_token)


def require_auth(user=Depends(get_current_user)):
    """Any authenticated user."""
    return user


def require_admin(user=Depends(get_current_user)):
    """Admin or superadmin only."""
    if not role_gte(user.get("role", ""), ROLE_ADMIN):
        raise HTTPException(status_code=403, detail="Admin access required.")
    return user


def require_superadmin(user=Depends(get_current_user)):
    """Superadmin only."""
    if user.get("role") != ROLE_SUPERADMIN:
        raise HTTPException(status_code=403, detail="Super Admin access required.")
    return user


# ---------------------------------------------------------------------------
# Permission system
# ---------------------------------------------------------------------------
ALL_PERMISSIONS = [
    "view_stats",
    "view_history",
    "clear_history",
    "manage_users",
    "view_audit_log",
    "manage_settings",
    "view_errors",
    "view_analytics",
    "manage_integrations",
]

SUPERADMIN_PERMISSIONS = ALL_PERMISSIONS  # super admin has everything

DEFAULT_ADMIN_PERMISSIONS = [
    "view_stats",
    "view_history",
    "view_analytics",
]


def has_permission(user: dict, permission: str) -> bool:
    if user.get("role") == ROLE_SUPERADMIN:
        return True
    perms = user.get("permissions", [])
    return permission in perms
