"""
auth/security.py — Cryptographic utilities for Cyber Sentinel XDR auth layer.

Provides:
  - bcrypt password hashing / verification
  - HS256 JWT creation and decoding (access, refresh, 2fa_pending tokens)
  - TOTP (Time-based One-Time Password) helpers via pyotp
  - QR code generation for TOTP enrollment via qrcode + Pillow

NEVER log passwords, raw tokens, or TOTP secrets anywhere in this module.
"""

import base64
import io
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import HTTPException, status

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lazy imports — raise clear errors if optional deps are missing
# ---------------------------------------------------------------------------

def _require_jose():
    try:
        from jose import JWTError, jwt as _jwt
        return _jwt, JWTError
    except ImportError:
        raise RuntimeError(
            "python-jose is required for JWT support. "
            "Run: pip install python-jose[cryptography]"
        )


def _require_bcrypt():
    try:
        import bcrypt as _bcrypt_mod
        return _bcrypt_mod
    except ImportError:
        raise RuntimeError(
            "bcrypt is required for password hashing. "
            "Run: pip install passlib[bcrypt]"
        )


def _require_pyotp():
    try:
        import pyotp
        return pyotp
    except ImportError:
        raise RuntimeError(
            "pyotp is required for TOTP/MFA support. "
            "Run: pip install pyotp"
        )


def _require_qrcode():
    try:
        import qrcode
        return qrcode
    except ImportError:
        raise RuntimeError(
            "qrcode[pil] is required for QR code generation. "
            "Run: pip install qrcode[pil] pillow"
        )


# ---------------------------------------------------------------------------
# Password hashing — using bcrypt directly (passlib 1.7.4 is incompatible
# with bcrypt >= 4.0 due to the __about__ removal in newer bcrypt).
# ---------------------------------------------------------------------------

def hash_password(plain: str, rounds: int = 12) -> str:
    """
    Return a bcrypt hash of *plain*.

    rounds must be >= 12.  The plain text is UTF-8 encoded and truncated to
    72 bytes before hashing (bcrypt's hard limit).
    """
    if rounds < 12:
        raise ValueError("bcrypt rounds must be >= 12")
    _bcrypt = _require_bcrypt()
    plain_bytes = plain.encode("utf-8")[:72]
    salt = _bcrypt.gensalt(rounds=rounds)
    return _bcrypt.hashpw(plain_bytes, salt).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Return True if *plain* matches *hashed* (timing-safe bcrypt compare)."""
    _bcrypt = _require_bcrypt()
    try:
        plain_bytes = plain.encode("utf-8")[:72]
        hashed_bytes = hashed.encode("utf-8") if isinstance(hashed, str) else hashed
        return _bcrypt.checkpw(plain_bytes, hashed_bytes)
    except Exception:
        # Malformed hash or wrong encoding — treat as failure
        return False


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def create_access_token(
    data: dict,
    secret: str,
    algorithm: str = "HS256",
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Create a short-lived HS256 access token.

    Required *data* keys: sub (user_id str), role.
    A fresh *jti* (UUID4) and *type="access"* are always injected.
    Default expiry is 15 minutes if *expires_delta* is not provided.
    """
    _jwt, _ = _require_jose()
    payload = dict(data)
    payload["jti"] = str(uuid.uuid4())
    payload["type"] = "access"
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    payload["exp"] = expire
    return _jwt.encode(payload, secret, algorithm=algorithm)


def create_refresh_token(
    data: dict,
    secret: str,
    algorithm: str = "HS256",
    expires_days: int = 7,
) -> tuple[str, str]:
    """
    Create a long-lived HS256 refresh token.

    Returns (token_string, jti) so the caller can store jti in the session doc.
    A fresh *jti* (UUID4) and *type="refresh"* are always injected.
    """
    _jwt, _ = _require_jose()
    jti = str(uuid.uuid4())
    payload = dict(data)
    payload["jti"] = jti
    payload["type"] = "refresh"
    expire = datetime.now(timezone.utc) + timedelta(days=expires_days)
    payload["exp"] = expire
    token = _jwt.encode(payload, secret, algorithm=algorithm)
    return token, jti


def create_temp_2fa_token(
    user_id: str,
    secret: str,
    algorithm: str = "HS256",
    expires_minutes: int = 5,
) -> str:
    """
    Create a short-lived token used only during the 2FA verification step.
    type="2fa_pending" — not accepted as an access token anywhere else.
    """
    _jwt, _ = _require_jose()
    payload = {
        "sub": user_id,
        "type": "2fa_pending",
        "jti": str(uuid.uuid4()),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=expires_minutes),
    }
    return _jwt.encode(payload, secret, algorithm=algorithm)


def decode_token(token: str, secret: str, algorithm: str = "HS256") -> dict:
    """
    Decode and validate a JWT.

    Raises HTTPException(401) on:
      - Expired tokens
      - Invalid signature
      - Malformed token
    Returns the payload dict on success.
    """
    _jwt, JWTError = _require_jose()
    try:
        payload = _jwt.decode(token, secret, algorithms=[algorithm])
        return payload
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


# ---------------------------------------------------------------------------
# TOTP / 2FA helpers
# ---------------------------------------------------------------------------

def generate_totp_secret() -> str:
    """Generate a random BASE32 TOTP secret suitable for pyotp."""
    pyotp = _require_pyotp()
    return pyotp.random_base32()


def get_totp_uri(secret: str, email: str, issuer: str = "CyberSentinelXDR") -> str:
    """Return an otpauth:// URI for enrollment in an authenticator app."""
    pyotp = _require_pyotp()
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name=issuer)


def verify_totp(secret: str, code: str) -> bool:
    """
    Return True if *code* is the valid TOTP token for the current 30-second
    window only.  No clock-skew window is allowed — the code currently shown
    in Google Authenticator is the only accepted code.
    """
    pyotp = _require_pyotp()
    totp = pyotp.TOTP(secret)
    try:
        return totp.verify(code, valid_window=0)
    except Exception:
        return False


def create_password_reset_token(
    user_id: str,
    secret: str,
    algorithm: str = "HS256",
    expires_minutes: int = 10,
) -> tuple[str, str]:
    """
    Create a short-lived password reset JWT.

    Returns (token_string, jti).
    type="password_reset" — rejected by every other verification path.
    The caller must store a bcrypt hash of the returned token_string in
    the `password_reset_tokens` MongoDB collection.
    """
    _jwt, _ = _require_jose()
    jti = str(uuid.uuid4())
    payload = {
        "sub": user_id,
        "type": "password_reset",
        "jti": jti,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=expires_minutes),
    }
    token = _jwt.encode(payload, secret, algorithm=algorithm)
    return token, jti


def generate_qr_code_base64(uri: str) -> str:
    """
    Generate a QR code PNG for the given OTP URI and return it as a
    base64-encoded string suitable for embedding in a data: URL.
    """
    qrcode = _require_qrcode()
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return base64.b64encode(buf.read()).decode("ascii")
