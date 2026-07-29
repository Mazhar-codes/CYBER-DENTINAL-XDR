"""
auth/models.py — Pydantic models and MongoDB document shapes
for Cyber Sentinel XDR authentication layer.

MongoDB collections:
  users                  — registered user accounts
  sessions               — active login sessions (refresh token tracking)
  audit_logs             — immutable audit trail
  password_reset_tokens  — one-time password recovery tokens (10 min TTL)
  mfa_recovery_requests  — admin-reviewed MFA recovery requests
"""

import re
from datetime import datetime
from typing import Any, List, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator


# ---------------------------------------------------------------------------
# MongoDB document shapes (plain dicts — used for type-hinting only)
# ---------------------------------------------------------------------------
# UserDocument = {
#     "_id":                ObjectId,
#     "username":           str,
#     "email":              str,
#     "password_hash":      str,          # bcrypt, 12 rounds
#     "role":               "admin" | "analyst" | "viewer",
#     "created_at":         datetime,
#     "last_login":         datetime | None,
#     "failed_attempts":    int,
#     "locked_until":       datetime | None,
#     "two_factor_enabled": bool,
#     "two_factor_secret":  str | None,   # BASE32 TOTP secret (store encrypted at rest)
# }
#
# SessionDocument = {
#     "_id":                  ObjectId,
#     "user_id":              str,        # str(user["_id"])
#     "jti":                  str,        # JWT ID — used for blacklisting
#     "ip_address":           str,
#     "device":               str,        # User-Agent truncated to 512 chars
#     "login_time":           datetime,
#     "is_active":            bool,
#     "refresh_token_hash":   str,        # bcrypt hash of refresh token
# }
#
# AuditLogDocument = {
#     "_id":       ObjectId,
#     "user":      str,                   # username or "anonymous"
#     "action":    str,                   # e.g. "login_success"
#     "timestamp": datetime,
#     "ip":        str,
#     "status":    "success" | "failure",
#     "detail":    str | None,
# }


# ---------------------------------------------------------------------------
# Password strength validator (reused across request models)
# ---------------------------------------------------------------------------
_PASSWORD_SYMBOL_RE = re.compile(r'[!@#$%^&*()\-_=+\[\]{};:\'",.<>/?\\|`~]')


def _validate_password_strength(value: str) -> str:
    """Raise ValueError with a human-readable message if the password is too weak."""
    errors: list[str] = []
    if len(value) < 8:
        errors.append("at least 8 characters")
    if not any(c.isupper() for c in value):
        errors.append("at least one uppercase letter")
    if not any(c.islower() for c in value):
        errors.append("at least one lowercase letter")
    if not any(c.isdigit() for c in value):
        errors.append("at least one digit")
    if not _PASSWORD_SYMBOL_RE.search(value):
        errors.append("at least one special character (!@#$%^&*…)")
    if errors:
        raise ValueError("Password must contain: " + ", ".join(errors))
    return value


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    username: str = Field(
        ...,
        min_length=3,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_\-\.]+$",
        description="3–64 chars; letters, digits, _, -, . only",
    )
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        return _validate_password_strength(v)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1, max_length=128)


class RefreshRequest(BaseModel):
    refresh_token: str


class MFAVerifyRequest(BaseModel):
    otp_code: str = Field(..., min_length=6, max_length=8, description="6-digit TOTP code")


class MFA2FALoginRequest(BaseModel):
    """Used to verify the 2FA step after /auth/login returns requires_2fa=true."""
    temp_token: str
    otp_code: Optional[str] = Field(None, min_length=6, max_length=8)
    backup_code: Optional[str] = Field(None, min_length=6, max_length=12,
                                       description="One-time backup code (XXXX-XXXX) as alternative to OTP")
    trust_device: bool = Field(False, description="Remember this device for the configured trust period")


class DisableMFARequest(BaseModel):
    otp_code: str = Field(..., min_length=6, max_length=8)


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    device_token: Optional[str] = None  # set when trust_device=True after 2FA


class Requires2FAResponse(BaseModel):
    requires_2fa: bool = True
    temp_token: str
    # Set when this is a first-time TOTP setup (user had no secret yet)
    requires_setup: bool = False
    secret: Optional[str] = None
    qr_code_url: Optional[str] = None
    qr_code_base64: Optional[str] = None
    backup_codes: List[str] = Field(default_factory=list)


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    role: str
    two_factor_enabled: bool
    created_at: datetime
    last_login: Optional[datetime] = None


class MFASetupResponse(BaseModel):
    secret: str
    qr_code_url: str
    qr_code_base64: str         # base64-encoded PNG of the QR code
    backup_codes: List[str] = []  # shown once — user must save these


class BackupCodesResponse(BaseModel):
    backup_codes: List[str]
    count: int
    message: str = "Store these codes securely. Each can only be used once."


# ---------------------------------------------------------------------------
# Password recovery request/response models
# ---------------------------------------------------------------------------

class ForgotPasswordRequest(BaseModel):
    email: EmailStr


_STRONG_PASSWORD_RE = re.compile(
    r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()\-_=+\[\]{};:\'",.<>/?\\|`~]).{12,128}$'
)


def _validate_strong_password(value: str) -> str:
    """Enforce enterprise-grade password policy: min 12 chars, upper+lower+digit+special."""
    errors: list[str] = []
    if len(value) < 12:
        errors.append("at least 12 characters")
    if not any(c.isupper() for c in value):
        errors.append("at least one uppercase letter")
    if not any(c.islower() for c in value):
        errors.append("at least one lowercase letter")
    if not any(c.isdigit() for c in value):
        errors.append("at least one digit")
    if not re.search(r'[!@#$%^&*()\-_=+\[\]{};:\'",.<>/?\\|`~]', value):
        errors.append("at least one special character (!@#$%^&*…)")
    if errors:
        raise ValueError("Password must contain: " + ", ".join(errors))
    return value


class ResetPasswordRequest(BaseModel):
    token: str = Field(..., min_length=1, description="Raw reset token from the reset link")
    new_password: str = Field(..., min_length=12, max_length=128)
    mfa_code: Optional[str] = Field(None, min_length=6, max_length=8, description="TOTP code (if 2FA enabled)")
    backup_code: Optional[str] = Field(None, min_length=6, max_length=12, description="Backup code (alternative to TOTP)")

    @field_validator("new_password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        return _validate_strong_password(v)


# ---------------------------------------------------------------------------
# MFA recovery request/response models
# ---------------------------------------------------------------------------

class MFARecoveryRequestPayload(BaseModel):
    email: EmailStr
    reason: str = Field(
        ...,
        min_length=10,
        max_length=500,
        description="Reason for recovery (e.g. 'Lost authenticator device')",
    )


class MFARecoveryActionPayload(BaseModel):
    action: str = Field(..., description="'approve' or 'deny'")

    @field_validator("action")
    @classmethod
    def validate_action(cls, v: str) -> str:
        if v not in ("approve", "deny"):
            raise ValueError("action must be 'approve' or 'deny'")
        return v


# ---------------------------------------------------------------------------
# Backup code status response
# ---------------------------------------------------------------------------

class BackupCodeStatusResponse(BaseModel):
    remaining: int
    total: int
    message: str


class TrustedDeviceInfo(BaseModel):
    id: str
    ip_address: str
    user_agent: str
    trusted_until: datetime
    created_at: datetime


# ---------------------------------------------------------------------------
# Change-password request model
# ---------------------------------------------------------------------------

class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1, max_length=128)
    new_password: str = Field(..., min_length=8, max_length=128)

    @field_validator("new_password")
    @classmethod
    def new_password_strength(cls, v: str) -> str:
        return _validate_password_strength(v)


# ---------------------------------------------------------------------------
# Admin user creation request model
# ---------------------------------------------------------------------------

_VALID_ROLES = {"viewer", "analyst", "admin"}


class AdminCreateUserRequest(BaseModel):
    username: str = Field(
        ...,
        min_length=3,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_\-\.]+$",
        description="3–64 chars; letters, digits, _, -, . only",
    )
    email: EmailStr
    password: str = Field(..., min_length=12, max_length=128)
    role: str = Field(..., description="One of: viewer, analyst, admin")

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        return _validate_strong_password(v)

    @field_validator("role")
    @classmethod
    def role_valid(cls, v: str) -> str:
        if v not in _VALID_ROLES:
            raise ValueError(f"role must be one of: {', '.join(sorted(_VALID_ROLES))}")
        return v


# ---------------------------------------------------------------------------
# Internal helper: build UserResponse from a MongoDB user document
# ---------------------------------------------------------------------------

def user_doc_to_response(doc: dict) -> UserResponse:
    return UserResponse(
        id=str(doc["_id"]),
        username=doc["username"],
        email=doc["email"],
        role=doc["role"],
        two_factor_enabled=doc.get("two_factor_enabled", False),
        created_at=doc["created_at"],
        last_login=doc.get("last_login"),
    )
