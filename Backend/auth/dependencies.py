"""
auth/dependencies.py — FastAPI dependency functions for JWT-based auth.

Provides:
  get_db()             — yields the pymongo database instance
  get_current_user()   — decode Bearer JWT, return verified user doc
  require_role(*roles) — dependency factory that enforces RBAC
  get_request_ip()     — extract real client IP (respects X-Forwarded-For)
"""

import logging
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer

logger = logging.getLogger(__name__)

# OAuth2 scheme — reads Bearer token from Authorization header.
# tokenUrl is informational only (used by Swagger UI).
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)


# ---------------------------------------------------------------------------
# Database dependency
# ---------------------------------------------------------------------------

def get_db():
    """
    Yield the pymongo database object.

    Returns None if MongoDB is unavailable (graceful degradation).
    Import here to avoid circular imports (backend.py imports auth router
    which imports this module).

    If the startup connection attempt failed (e.g. the machine's network
    was still settling when the backend process started), MONGO_OK stays
    False forever unless something retries it -- previously only /health
    did that, so every auth endpoint stayed permanently "database offline"
    until a manual restart even after connectivity came back. This is a
    plain sync function, so FastAPI runs it in its worker threadpool rather
    than on the event loop -- safe to do a blocking reconnect attempt here
    without stalling other requests.
    """
    # Lazy import from backend to avoid circular dependency at module load time.
    # backend.py sets MONGO_OK and _db at startup.
    try:
        from backend import _db, MONGO_OK  # noqa: PLC0415
        if MONGO_OK and _db is not None:
            return _db
    except ImportError:
        return None

    # Fast path missed -- try one reconnect before giving up.
    try:
        from backend import _ensure_db_connected  # noqa: PLC0415
        if _ensure_db_connected():
            from backend import _db as _db_reconnected  # noqa: PLC0415
            return _db_reconnected
        return None
    except ImportError:
        return None


# ---------------------------------------------------------------------------
# Current user dependency
# ---------------------------------------------------------------------------

async def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    db=Depends(get_db),
) -> dict:
    """
    Decode the Bearer JWT and return the MongoDB user document.

    Raises:
      401 — missing token, invalid signature, expired token
      403 — account locked
    """
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated — provide a Bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Import here to avoid circular imports at module load
    from auth.security import decode_token  # noqa: PLC0415
    from config import settings             # noqa: PLC0415

    payload = decode_token(token, settings.jwt_secret_key, settings.jwt_algorithm)

    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id: Optional[str] = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing subject",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if db is None:
        # MongoDB unavailable — cannot verify user; deny access
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service unavailable (database offline)",
        )

    try:
        from bson import ObjectId                       # noqa: PLC0415
        user = db["users"].find_one({"_id": ObjectId(user_id)})
    except Exception:
        user = None

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check account lockout
    from datetime import datetime, timezone            # noqa: PLC0415
    locked_until = user.get("locked_until")
    if locked_until is not None:
        now = datetime.now(timezone.utc)
        # Handle both tz-aware and naive datetimes stored in MongoDB
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)
        if now < locked_until:
            unlock_str = locked_until.strftime("%Y-%m-%dT%H:%M:%SZ")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Account locked until {unlock_str}",
            )

    return user


# ---------------------------------------------------------------------------
# Role-based access control dependency factory
# ---------------------------------------------------------------------------

def require_role(*roles: str):
    """
    Return a FastAPI dependency that enforces role membership.

    Usage:
        @app.get("/admin/...", dependencies=[Depends(require_role("admin"))])

    Supported roles: "admin", "analyst", "viewer"
    Admins implicitly pass any role check.
    """
    async def _check(user: dict = Depends(get_current_user)) -> dict:
        user_role: str = user.get("role", "viewer")
        # Admin bypasses all role restrictions
        if user_role == "admin":
            return user
        if user_role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Insufficient privileges. "
                    f"Required: {list(roles)}, your role: {user_role}"
                ),
            )
        return user

    return _check


# ---------------------------------------------------------------------------
# IP extraction helper
# ---------------------------------------------------------------------------

def get_request_ip(request: Request) -> str:
    """
    Extract the real client IP address.

    Checks X-Forwarded-For (first entry) before falling back to
    request.client.host so the limiter works correctly behind a reverse proxy.
    """
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        # X-Forwarded-For may be a comma-separated list; first is the client
        return forwarded_for.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"
