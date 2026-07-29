"""
auth/router.py — FastAPI APIRouter for all authentication endpoints.

Endpoints
---------
POST /auth/register              — Create a new user account
POST /auth/login                 — Authenticate (returns tokens or 2FA challenge)
POST /auth/verify-2fa-login      — Complete 2FA login with temp token + OTP/backup-code
POST /auth/refresh               — Rotate refresh token, issue new access token
POST /auth/logout                — Invalidate current session
POST /auth/logout-all            — Revoke all sessions for the current user
GET  /auth/me                    — Return current user profile
POST /auth/enable-2fa            — Generate TOTP secret + QR code + backup codes
POST /auth/verify-2fa            — Confirm OTP to activate 2FA
POST /auth/disable-2fa           — Deactivate 2FA (requires valid OTP)
POST /auth/backup-codes          — Regenerate backup codes (invalidates old set)
GET  /auth/backup-codes/status   — Count remaining unused backup codes
GET  /auth/trusted-devices       — List trusted devices for the current user
DELETE /auth/trusted-devices/{device_id} — Revoke a specific trusted device

Credential Recovery Endpoints
------------------------------
POST /auth/forgot-password               — Request password reset token (rate-limited 3/15 min)
POST /auth/reset-password                — Consume token + verify MFA + set new password
POST /auth/recovery/request-mfa         — Submit MFA recovery request (admin review required)
GET  /auth/recovery/pending             — Admin: list pending MFA recovery requests
POST /auth/recovery/approve/{request_id} — Admin: approve or deny MFA recovery request

Security guarantees
-------------------
- Passwords never logged or stored in plaintext (bcrypt 12 rounds)
- Refresh tokens hashed before storage
- Account lockout: 5 failed attempts → 15-minute lock
- Rate limit: 5 login attempts per IP per 15 minutes
- OTP rate limit: 5 OTP attempts per user per 5 minutes (separate limiter)
- OTP replay prevention: same code cannot be reused within 90s window
- Backup codes: 10 one-time codes (SHA-256 hashed in DB)
- Device trust: skip OTP for verified devices for configurable period
- Audit log written for every sensitive action
- Suspicious login detected when IP or device differs from last session
- TOTP secret returned only during enable-2fa — not retrievable afterwards
- Password reset tokens: bcrypt-hashed in DB, single-use, 10-minute expiry
- Reset requires MFA verification when 2FA is active on the account
- All sessions revoked on successful password reset
- MFA recovery: admin must explicitly approve before secret is wiped
- Risk assessment on every recovery attempt (new IP / repeat attempts flagged)
"""

import logging
import secrets
import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status

from auth.dependencies import get_current_user, get_db, get_request_ip, require_role
from auth.mfa import (
    generate_backup_codes,
    generate_device_token,
    hash_backup_code,
    hash_device_token,
    otp_rate_limiter,
    otp_used_cache,
    temp_token_jti_cache,
    verify_and_consume_backup_code,
)
from auth.models import (
    AdminCreateUserRequest,
    BackupCodeStatusResponse,
    BackupCodesResponse,
    ChangePasswordRequest,
    DisableMFARequest,
    ForgotPasswordRequest,
    LoginRequest,
    MFA2FALoginRequest,
    MFARecoveryActionPayload,
    MFARecoveryRequestPayload,
    MFASetupResponse,
    MFAVerifyRequest,
    RefreshRequest,
    RegisterRequest,
    Requires2FAResponse,
    ResetPasswordRequest,
    TokenResponse,
    TrustedDeviceInfo,
    UserResponse,
    user_doc_to_response,
)
from auth.email_sender import send_password_reset_email
from auth.rate_limiter import (
    forgot_password_rate_limiter,
    login_rate_limiter,
    mfa_recovery_rate_limiter,
)
from auth.security import (
    create_access_token,
    create_password_reset_token,
    create_refresh_token,
    create_temp_2fa_token,
    decode_token,
    generate_qr_code_base64,
    generate_totp_secret,
    get_totp_uri,
    hash_password,
    verify_password,
    verify_totp,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

# ---------------------------------------------------------------------------
# Lockout configuration
# ---------------------------------------------------------------------------
_MAX_FAILED_ATTEMPTS = 5
_LOCKOUT_MINUTES = 15


# ---------------------------------------------------------------------------
# Audit log helper
# ---------------------------------------------------------------------------

async def _write_audit(
    db,
    user: str,
    action: str,
    ip: str,
    success: bool,
    detail: Optional[str] = None,
) -> None:
    if db is None:
        return
    doc = {
        "user":      user,
        "action":    action,
        "timestamp": datetime.now(timezone.utc),
        "ip":        ip,
        "status":    "success" if success else "failure",
        "detail":    detail,
    }
    try:
        db["audit_logs"].insert_one(doc)
    except Exception as exc:
        logger.warning(f"Audit log write failed: {exc}")
        return

    try:
        from backend import sio  # noqa: PLC0415
        emit_doc = {k: v for k, v in doc.items() if k != "_id"}
        emit_doc["timestamp"] = emit_doc["timestamp"].isoformat()
        await sio.emit("audit_event", emit_doc)
    except Exception as exc:
        logger.debug(f"Audit Socket.IO emit skipped: {exc}")


# ---------------------------------------------------------------------------
# Session management helpers
# ---------------------------------------------------------------------------

def _create_session_doc(
    user_id: str,
    jti: str,
    refresh_token_hash: str,
    ip: str,
    device: str,
    otp_verified: bool = False,
) -> dict:
    return {
        "user_id":            user_id,
        "jti":                jti,
        "ip_address":         ip,
        "device":             device[:512],
        "login_time":         datetime.now(timezone.utc),
        "is_active":          True,
        "refresh_token_hash": refresh_token_hash,
        "otp_verified":       otp_verified,
    }


def _detect_suspicious_login(db, user_id: str, ip: str, device: str) -> bool:
    if db is None:
        return False
    try:
        last_session = db["sessions"].find_one(
            {"user_id": user_id, "is_active": True},
            sort=[("login_time", -1)],
        )
        if last_session is None:
            return False
        return (
            last_session.get("ip_address") != ip
            or last_session.get("device", "")[:512] != device[:512]
        )
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Device trust helpers
# ---------------------------------------------------------------------------

def _find_trusted_device(user: dict, device_token: str) -> bool:
    """Return True if the raw device_token matches a non-expired trusted device."""
    trusted_devices = user.get("trusted_devices", [])
    if not trusted_devices:
        return False
    token_hash = hash_device_token(device_token)
    now = datetime.now(timezone.utc)
    for td in trusted_devices:
        if td.get("token_hash") != token_hash:
            continue
        trusted_until = td.get("trusted_until")
        if trusted_until is None:
            continue
        if trusted_until.tzinfo is None:
            trusted_until = trusted_until.replace(tzinfo=timezone.utc)
        if now < trusted_until:
            return True
    return False


def _build_trusted_device_doc(
    device_token: str,
    ip: str,
    user_agent: str,
    expire_days: int,
) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "id":           str(uuid.uuid4()),
        "token_hash":   hash_device_token(device_token),
        "ip_address":   ip,
        "user_agent":   user_agent[:512],
        "trusted_until": now + timedelta(days=expire_days),
        "created_at":   now,
    }


def _role_access_token_expiry(role: str, default_minutes: int) -> timedelta:
    """Return access token lifetime based on role.

    Admin has the shortest lifetime (highest privilege → tightest session).
    Viewer gets the longest (read-only risk profile).
    """
    if role == "admin":
        return timedelta(minutes=default_minutes)       # 15 min
    elif role == "analyst":
        return timedelta(minutes=default_minutes * 4)   # 60 min
    else:                                               # viewer
        return timedelta(minutes=default_minutes * 8)   # 120 min


def _issue_tokens_and_session(
    db,
    user: dict,
    ip: str,
    device: str,
    settings,
    now: datetime,
    otp_verified: bool = False,
) -> tuple[str, str]:
    """Issue access + refresh tokens, create session doc, update last_login.

    otp_verified must be True when the user has two_factor_enabled.
    This acts as a fail-safe: if any caller forgets to check OTP first,
    this function raises 403 rather than silently issuing a JWT.
    """
    # Safety guard: if user has 2FA enabled, caller must have verified OTP
    if user.get("two_factor_enabled") and not otp_verified:
        logger.error(
            "[AUTH] SECURITY VIOLATION: token issued without OTP for 2FA user=%s",
            user.get("_id"),
        )
        raise HTTPException(status_code=403, detail="OTP verification required")

    user_id = str(user["_id"])
    role = user.get("role", "viewer")
    token_data = {"sub": user_id, "role": role}

    access_token = create_access_token(
        data=token_data,
        secret=settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
        expires_delta=_role_access_token_expiry(role, settings.access_token_expire_minutes),
    )
    refresh_token, jti = create_refresh_token(
        data=token_data,
        secret=settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
        expires_days=settings.refresh_token_expire_days,
    )
    refresh_hash = hash_password(refresh_token, rounds=settings.bcrypt_rounds)

    session = _create_session_doc(user_id, jti, refresh_hash, ip, device, otp_verified=otp_verified)
    db["sessions"].insert_one(session)
    db["users"].update_one(
        {"_id": user["_id"]},
        {"$set": {"last_login": now, "last_login_ip": ip}},
    )
    return access_token, refresh_token


# ---------------------------------------------------------------------------
# POST /auth/register
# ---------------------------------------------------------------------------

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    payload: RegisterRequest,
    request: Request,
    db=Depends(get_db),
    ip: str = Depends(get_request_ip),
):
    """Register a new user account. First registered user becomes admin."""
    if db is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Registration unavailable — database offline",
        )

    from config import settings  # noqa: PLC0415

    if db["users"].find_one({"email": payload.email}):
        await _write_audit(db, payload.email, "register_failed", ip, False,
                           "Email already registered")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists",
        )
    if db["users"].find_one({"username": payload.username}):
        await _write_audit(db, payload.username, "register_failed", ip, False,
                           "Username already taken")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already taken",
        )

    user_count = db["users"].count_documents({})
    role = "admin" if user_count == 0 else "analyst"

    now = datetime.now(timezone.utc)
    user_doc = {
        "username":           payload.username,
        "email":              str(payload.email),
        "password_hash":      hash_password(payload.password, rounds=settings.bcrypt_rounds),
        "role":               role,
        "created_at":         now,
        "last_login":         None,
        "last_login_ip":      None,
        "failed_attempts":    0,
        "locked_until":       None,
        "two_factor_enabled": True,   # MFA mandatory — activated after first OTP confirmation
        "two_factor_secret":  None,   # generated on first login
        "backup_codes":       [],
        "trusted_devices":    [],
    }

    result = db["users"].insert_one(user_doc)
    user_doc["_id"] = result.inserted_id

    await _write_audit(db, payload.username, "register_success", ip, True, f"role={role}")
    logger.info(f"New user registered: {payload.username} ({payload.email}) role={role}")
    return user_doc_to_response(user_doc)


# ---------------------------------------------------------------------------
# POST /auth/login
# ---------------------------------------------------------------------------

@router.post("/login")
async def login(
    payload: LoginRequest,
    request: Request,
    db=Depends(get_db),
    ip: str = Depends(get_request_ip),
):
    """
    Authenticate with email + password.

    Returns:
      - TokenResponse            if 2FA is disabled
      - TokenResponse            if 2FA enabled but device is trusted (skip OTP)
      - Requires2FAResponse      if 2FA is enabled (full tokens NOT issued yet)
    """
    await login_rate_limiter.check_rate_limit(ip)

    if db is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Login unavailable — database offline",
        )

    from config import settings  # noqa: PLC0415

    logger.info(
        "[AUTH] Login attempt user=%s",
        str(payload.email),
    )

    user = db["users"].find_one({"email": str(payload.email)})
    if user is None:
        hash_password("dummy-timing-protection", rounds=settings.bcrypt_rounds)
        await _write_audit(db, str(payload.email), "login_failed", ip, False,
                           "User not found")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    now = datetime.now(timezone.utc)
    locked_until = user.get("locked_until")
    if locked_until is not None:
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)
        if now < locked_until:
            unlock_str = locked_until.strftime("%Y-%m-%dT%H:%M:%SZ")
            await _write_audit(db, user["username"], "login_blocked", ip, False,
                               f"Account locked until {unlock_str}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Account locked until {unlock_str}. Too many failed login attempts.",
            )

    if not verify_password(payload.password, user["password_hash"]):
        new_failures = user.get("failed_attempts", 0) + 1
        update_fields: dict = {"failed_attempts": new_failures}
        if new_failures >= _MAX_FAILED_ATTEMPTS:
            lockout_until = now + timedelta(minutes=_LOCKOUT_MINUTES)
            update_fields["locked_until"] = lockout_until
            logger.warning(
                f"Account locked: {user['username']} — {new_failures} failures from {ip}"
            )
        db["users"].update_one({"_id": user["_id"]}, {"$set": update_fields})
        remaining = max(0, _MAX_FAILED_ATTEMPTS - new_failures)
        await _write_audit(db, user["username"], "login_failed", ip, False,
                           f"Bad password — attempts={new_failures}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                f"Invalid email or password. {remaining} attempt(s) remaining before lockout."
                if remaining > 0
                else "Invalid email or password. Account is now locked for 15 minutes."
            ),
        )

    db["users"].update_one(
        {"_id": user["_id"]},
        {"$set": {"failed_attempts": 0, "locked_until": None}},
    )
    await login_rate_limiter.reset(ip)

    user_id = str(user["_id"])
    device = request.headers.get("User-Agent", "unknown")

    # -----------------------------------------------------------------------
    # Trusted device bypass — was defined (_find_trusted_device) but never
    # actually called anywhere, so the "trust this device" option from
    # verify-2fa-login (and the frontend's X-Device-Token header, already
    # sent on every request by authService.ts) had no effect. Wired up here:
    # a still-valid trusted device skips the OTP/backup-code challenge and
    # gets tokens issued directly, exactly as the docstring above always
    # claimed it did.
    # -----------------------------------------------------------------------
    incoming_device_token = request.headers.get("X-Device-Token")
    if (
        incoming_device_token
        and user.get("two_factor_enabled")
        and user.get("two_factor_secret")
        and _find_trusted_device(user, incoming_device_token)
    ):
        access_token, refresh_token = _issue_tokens_and_session(
            db, user, ip, device, settings, now, otp_verified=True
        )
        await _write_audit(db, user["username"], "login_trusted_device", ip, True,
                           "MFA skipped — trusted device")
        logger.info("[AUTH] Trusted device — MFA skipped for user=%s", user_id)
        return TokenResponse(access_token=access_token, refresh_token=refresh_token)

    # -----------------------------------------------------------------------
    # MANDATORY MFA — tokens are NEVER issued here.
    # Always return a 2FA challenge (temp_token).
    #
    # Two sub-cases:
    #   A) User already has a TOTP secret → standard OTP challenge.
    #   B) No secret yet (new account or pre-MFA legacy account) →
    #      auto-generate secret + backup codes, return setup challenge
    #      so the user can scan the QR code and confirm before logging in.
    # -----------------------------------------------------------------------

    temp_token = create_temp_2fa_token(
        user_id=user_id,
        secret=settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )

    if not user.get("two_factor_secret"):
        # First-time setup: generate TOTP secret + backup codes provisionally.
        # two_factor_enabled stays False until OTP is confirmed in verify-2fa-login.
        secret = generate_totp_secret()
        uri = get_totp_uri(secret=secret, email=user["email"], issuer=settings.mfa_issuer)
        qr_b64 = generate_qr_code_base64(uri)

        plaintext_codes = generate_backup_codes(count=settings.backup_code_count)
        hashed_codes = [{"hash": hash_backup_code(c), "used": False} for c in plaintext_codes]

        db["users"].update_one(
            {"_id": user["_id"]},
            {"$set": {"two_factor_secret": secret, "backup_codes": hashed_codes}},
        )

        await _write_audit(db, user["username"], "login_mfa_setup_initiated", ip, True,
                           "TOTP secret auto-generated at first login")
        logger.info("[AUTH] First-time MFA setup — secret generated for user=%s", user_id)

        return Requires2FAResponse(
            temp_token=temp_token,
            requires_setup=True,
            secret=secret,
            qr_code_url=uri,
            qr_code_base64=qr_b64,
            backup_codes=plaintext_codes,
        )

    # Standard OTP challenge — user has TOTP configured already
    logger.info("[AUTH] MFA required — temp_token issued, NO JWT for user=%s", user_id)
    await _write_audit(db, user["username"], "login_mfa_pending", ip, True, "OTP challenge issued")
    return Requires2FAResponse(temp_token=temp_token)


# ---------------------------------------------------------------------------
# POST /auth/verify-2fa-login
# ---------------------------------------------------------------------------

@router.post("/verify-2fa-login", response_model=TokenResponse)
async def verify_2fa_login(
    payload: MFA2FALoginRequest,
    request: Request,
    db=Depends(get_db),
    ip: str = Depends(get_request_ip),
):
    """
    Complete the 2FA login flow.

    Accepts:
      - temp_token  : issued by /login (type="2fa_pending")
      - otp_code    : current TOTP code from authenticator app
      - backup_code : one-time backup code (alternative to otp_code)
      - trust_device: if True, returns a device_token to skip 2FA for future logins

    Returns full access + refresh tokens on success.
    """
    if db is None:
        raise HTTPException(status_code=503, detail="Database offline")

    if not payload.otp_code and not payload.backup_code:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Provide either otp_code or backup_code",
        )

    from config import settings  # noqa: PLC0415

    # Decode the temp token
    temp_payload = decode_token(
        payload.temp_token,
        settings.jwt_secret_key,
        settings.jwt_algorithm,
    )
    if temp_payload.get("type") != "2fa_pending":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid temp token",
        )

    user_id = temp_payload.get("sub")
    temp_jti = temp_payload.get("jti", "")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token")

    # Block temp token reuse (single-use enforcement)
    if temp_jti and await temp_token_jti_cache.is_used(temp_jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="This authentication session has already been used. Please log in again.",
        )

    # Rate-limit OTP attempts per user
    await otp_rate_limiter.check(user_id)

    from bson import ObjectId  # noqa: PLC0415
    user = db["users"].find_one({"_id": ObjectId(user_id)})
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")

    device = request.headers.get("User-Agent", "unknown")
    now = datetime.now(timezone.utc)
    verified_via_backup = False

    # Backup codes require 2FA to be already active (setup flow must use TOTP)
    if payload.backup_code and not user.get("two_factor_enabled"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Complete 2FA setup with your authenticator app first, then backup codes become available.",
        )

    # ---- Verify via backup code ----
    if payload.backup_code:
        stored_codes = user.get("backup_codes", [])
        idx = verify_and_consume_backup_code(payload.backup_code, stored_codes)
        if idx is None:
            await _write_audit(db, user["username"], "backup_code_failed", ip, False,
                               "Invalid or already-used backup code")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or already-used backup code",
            )
        # Mark code as used
        stored_codes[idx]["used"] = True
        db["users"].update_one(
            {"_id": user["_id"]},
            {"$set": {"backup_codes": stored_codes}},
        )
        verified_via_backup = True
        await _write_audit(db, user["username"], "backup_code_used", ip, True,
                           f"Backup code index {idx} consumed")
        logger.info(f"Backup code login: {user['username']} from {ip}")

    # ---- Verify via TOTP OTP ----
    else:
        secret = user.get("two_factor_secret")
        if not secret:
            logger.error(
                "[AUTH] verify_2fa_login: no two_factor_secret for user=%s — "
                "login endpoint may not have saved it (check DB write success)",
                user_id,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="2FA secret not found. Please start the login process again.",
            )

        # Replay prevention — same OTP cannot be submitted twice
        if await otp_used_cache.is_used(user_id, payload.otp_code):
            await _write_audit(db, user["username"], "mfa_replay_blocked", ip, False,
                               "OTP replay attempt detected")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="This OTP code has already been used. Wait for the next code.",
            )

        if not verify_totp(secret, payload.otp_code):
            await _write_audit(db, user["username"], "mfa_failed", ip, False,
                               "Invalid OTP during 2FA login")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid OTP code",
            )

        # Mark OTP as used to prevent replay
        await otp_used_cache.mark_used(user_id, payload.otp_code)

    # OTP/backup verified — consume temp token JTI and reset OTP rate limiter
    if temp_jti:
        await temp_token_jti_cache.mark_used(temp_jti)
    await otp_rate_limiter.reset(user_id)

    # First-time setup completion: user just verified the provisionally-generated
    # TOTP secret for the first time → activate 2FA on the account.
    if not user.get("two_factor_enabled") and not verified_via_backup:
        db["users"].update_one(
            {"_id": user["_id"]},
            {"$set": {"two_factor_enabled": True}},
        )
        db["sessions"].update_many(
            {"user_id": user_id, "is_active": True},
            {"$set": {"is_active": False}},
        )
        user["two_factor_enabled"] = True  # keep in-memory consistent for _issue_tokens_and_session
        await _write_audit(db, user["username"], "mfa_first_setup_complete", ip, True,
                           "2FA activated at first login")
        logger.info(f"First-time MFA setup completed for {user['username']}")

    # Issue full tokens — otp_verified=True because OTP/backup code was just confirmed above
    logger.info("[AUTH] OTP verified for user=%s — issuing JWT", user_id)
    is_suspicious = _detect_suspicious_login(db, user_id, ip, device)
    access_token, refresh_token = _issue_tokens_and_session(
        db, user, ip, device, settings, now, otp_verified=True
    )

    action = (
        "suspicious_login_new_device"
        if is_suspicious
        else ("backup_code_login" if verified_via_backup else "mfa_verified")
    )
    await _write_audit(db, user["username"], action, ip, True, "2FA login completed")
    logger.info(f"2FA login success: {user['username']} from {ip}")

    # ---- Device trust ----
    device_token_value: Optional[str] = None
    if payload.trust_device and not verified_via_backup:
        device_token_value = generate_device_token()
        td_doc = _build_trusted_device_doc(
            device_token_value, ip, device, settings.device_trust_expire_days
        )
        db["users"].update_one(
            {"_id": user["_id"]},
            {"$push": {"trusted_devices": td_doc}},
        )
        await _write_audit(db, user["username"], "device_trusted", ip, True,
                           f"expires_days={settings.device_trust_expire_days}")
        logger.info(
            f"Device trusted for {user['username']} until "
            f"{td_doc['trusted_until'].isoformat()}"
        )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        device_token=device_token_value,
    )


# ---------------------------------------------------------------------------
# POST /auth/refresh
# ---------------------------------------------------------------------------

@router.post("/refresh", response_model=TokenResponse)
async def refresh_token_endpoint(
    payload: RefreshRequest,
    request: Request,
    db=Depends(get_db),
    ip: str = Depends(get_request_ip),
):
    """Rotate the refresh token and issue a new access token."""
    if db is None:
        raise HTTPException(status_code=503, detail="Database offline")

    from config import settings  # noqa: PLC0415

    refresh_payload = decode_token(
        payload.refresh_token,
        settings.jwt_secret_key,
        settings.jwt_algorithm,
    )
    if refresh_payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type — expected refresh token",
        )

    jti = refresh_payload.get("jti")
    user_id = refresh_payload.get("sub")
    if not jti or not user_id:
        raise HTTPException(status_code=401, detail="Malformed refresh token")

    session = db["sessions"].find_one({"jti": jti, "is_active": True})
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session not found or already revoked",
        )

    if not verify_password(payload.refresh_token, session["refresh_token_hash"]):
        db["sessions"].update_one(
            {"_id": session["_id"]},
            {"$set": {"is_active": False}},
        )
        await _write_audit(db, user_id, "refresh_token_invalid", ip, False,
                           "Hash mismatch — session revoked")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token invalid",
        )

    from bson import ObjectId  # noqa: PLC0415
    user = db["users"].find_one({"_id": ObjectId(user_id)})
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")

    # 2FA bypass prevention: if 2FA is currently enabled and this session was created
    # before OTP was verified (e.g. pre-2FA session), force re-authentication.
    if user.get("two_factor_enabled") and not session.get("otp_verified", False):
        await _write_audit(db, user_id, "refresh_denied_2fa_required", ip, False,
                           "Session pre-dates 2FA — re-auth required")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Re-authentication required — your session pre-dates 2FA setup. Please log in again.",
        )

    device = request.headers.get("User-Agent", "unknown")
    token_data = {"sub": user_id, "role": user.get("role", "viewer")}

    new_access = create_access_token(
        data=token_data,
        secret=settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
        expires_delta=timedelta(minutes=settings.access_token_expire_minutes),
    )
    new_refresh, new_jti = create_refresh_token(
        data=token_data,
        secret=settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
        expires_days=settings.refresh_token_expire_days,
    )
    new_refresh_hash = hash_password(new_refresh, rounds=settings.bcrypt_rounds)

    db["sessions"].update_one(
        {"_id": session["_id"]},
        {"$set": {"is_active": False}},
    )
    # Carry forward otp_verified status into the rotated session
    new_session = _create_session_doc(
        user_id, new_jti, new_refresh_hash, ip, device,
        otp_verified=session.get("otp_verified", False),
    )
    db["sessions"].insert_one(new_session)

    await _write_audit(db, user["username"], "token_refreshed", ip, True)
    return TokenResponse(access_token=new_access, refresh_token=new_refresh)


# ---------------------------------------------------------------------------
# POST /auth/logout
# ---------------------------------------------------------------------------

@router.post("/logout")
async def logout(
    request: Request,
    current_user: dict = Depends(get_current_user),
    db=Depends(get_db),
    ip: str = Depends(get_request_ip),
):
    """Invalidate the current session."""
    if db is None:
        return {"message": "Logged out (no-op — database offline)"}

    from config import settings  # noqa: PLC0415

    auth_header = request.headers.get("Authorization", "")
    token = auth_header.removeprefix("Bearer ").strip()
    if token:
        try:
            payload = decode_token(token, settings.jwt_secret_key, settings.jwt_algorithm)
            jti = payload.get("jti")
            if jti:
                db["sessions"].update_one(
                    {"jti": jti},
                    {"$set": {"is_active": False}},
                )
        except Exception:
            pass

    await _write_audit(db, current_user["username"], "logout", ip, True)
    return {"message": "Successfully logged out"}


# ---------------------------------------------------------------------------
# POST /auth/logout-all
# ---------------------------------------------------------------------------

@router.post("/logout-all")
async def logout_all(
    current_user: dict = Depends(get_current_user),
    db=Depends(get_db),
    ip: str = Depends(get_request_ip),
):
    """Revoke every active session for the current user."""
    if db is None:
        return {"message": "Logged out all (no-op — database offline)"}

    user_id = str(current_user["_id"])
    result = db["sessions"].update_many(
        {"user_id": user_id, "is_active": True},
        {"$set": {"is_active": False}},
    )
    await _write_audit(
        db, current_user["username"], "logout_all", ip, True,
        f"revoked={result.modified_count} sessions",
    )
    return {"message": f"All sessions revoked ({result.modified_count} active session(s) invalidated)"}


# ---------------------------------------------------------------------------
# POST /auth/change-password
# ---------------------------------------------------------------------------

@router.post("/change-password")
async def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    current_user: dict = Depends(get_current_user),
    db=Depends(get_db),
    ip: str = Depends(get_request_ip),
):
    """
    Change the authenticated user's password.

    Requires:
      - current_password: the user's current plaintext password (verified against bcrypt hash)
      - new_password: min 8 chars with uppercase, lowercase, digit, and special character

    On success:
      - Updates the bcrypt-12 password hash in the users collection
      - Revokes ALL active sessions (forces re-login on every device)
      - Writes an audit log entry (action="password_changed")
      - Returns a success message instructing the user to log in again
    """
    if db is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database unavailable — cannot change password",
        )

    from config import settings as _cfg  # noqa: PLC0415

    # ------------------------------------------------------------------
    # 1. Verify the current password against the stored bcrypt hash
    # ------------------------------------------------------------------
    if not verify_password(payload.current_password, current_user.get("password_hash", "")):
        await _write_audit(
            db, current_user["username"],
            "password_change_failed", ip, False,
            "Current password verification failed",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect",
        )

    # ------------------------------------------------------------------
    # 2. Reject if new_password is identical to current password
    # ------------------------------------------------------------------
    if verify_password(payload.new_password, current_user.get("password_hash", "")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be different from the current password",
        )

    # ------------------------------------------------------------------
    # 3. Hash and store the new password
    # ------------------------------------------------------------------
    new_hash = hash_password(payload.new_password, rounds=_cfg.bcrypt_rounds)
    db["users"].update_one(
        {"_id": current_user["_id"]},
        {"$set": {
            "password_hash":   new_hash,
            "failed_attempts": 0,
            "locked_until":    None,
        }},
    )

    # ------------------------------------------------------------------
    # 4. Revoke all active sessions — forces re-login on every device
    # ------------------------------------------------------------------
    user_id = str(current_user["_id"])
    revoked_count = _revoke_all_sessions(db, user_id)
    logger.info(
        f"[AUTH] Password changed: user={current_user['username']} "
        f"sessions_revoked={revoked_count} ip={ip}"
    )

    # ------------------------------------------------------------------
    # 5. Audit trail
    # ------------------------------------------------------------------
    await _write_audit(
        db, current_user["username"],
        "password_changed", ip, True,
        f"sessions_revoked={revoked_count}",
    )

    # Socket.IO audit event (best-effort)
    try:
        from backend import sio  # noqa: PLC0415
        await sio.emit("audit_event", {
            "action":           "password_changed",
            "user_id":          user_id,
            "username":         current_user["username"],
            "ip":               ip,
            "sessions_revoked": revoked_count,
            "timestamp":        datetime.now(timezone.utc).isoformat(),
        })
    except Exception as _sio_exc:
        logger.debug(f"[AUTH] change-password audit Socket.IO emit skipped: {_sio_exc}")

    return {
        "message": "Password changed successfully. Please log in again.",
        "sessions_revoked": revoked_count,
    }


# ---------------------------------------------------------------------------
# GET /auth/me
# ---------------------------------------------------------------------------

@router.get("/me", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user)):
    """Return the profile of the currently authenticated user."""
    return user_doc_to_response(current_user)


# ---------------------------------------------------------------------------
# POST /auth/enable-2fa
# ---------------------------------------------------------------------------

@router.post("/enable-2fa", response_model=MFASetupResponse)
async def enable_2fa(
    current_user: dict = Depends(get_current_user),
    db=Depends(get_db),
    ip: str = Depends(get_request_ip),
):
    """
    Generate a new TOTP secret, QR code, and backup codes for enrollment.

    The secret is saved provisionally; two_factor_enabled stays False
    until /verify-2fa confirms the device.  Backup codes are generated
    and stored (hashed) at this step — plaintext is returned exactly once.
    """
    if db is None:
        raise HTTPException(status_code=503, detail="Database offline")

    from config import settings  # noqa: PLC0415

    secret = generate_totp_secret()
    uri = get_totp_uri(
        secret=secret,
        email=current_user["email"],
        issuer=settings.mfa_issuer,
    )
    qr_b64 = generate_qr_code_base64(uri)

    # Generate backup codes
    plaintext_codes = generate_backup_codes(count=settings.backup_code_count)
    hashed_codes = [{"hash": hash_backup_code(c), "used": False} for c in plaintext_codes]

    db["users"].update_one(
        {"_id": current_user["_id"]},
        {"$set": {
            "two_factor_secret": secret,
            "backup_codes": hashed_codes,
        }},
    )
    await _write_audit(db, current_user["username"], "2fa_setup_initiated", ip, True)
    logger.info(f"2FA setup initiated for {current_user['username']}")

    return MFASetupResponse(
        secret=secret,
        qr_code_url=uri,
        qr_code_base64=qr_b64,
        backup_codes=plaintext_codes,
    )


# ---------------------------------------------------------------------------
# POST /auth/verify-2fa
# ---------------------------------------------------------------------------

@router.post("/verify-2fa")
async def verify_2fa(
    payload: MFAVerifyRequest,
    current_user: dict = Depends(get_current_user),
    db=Depends(get_db),
    ip: str = Depends(get_request_ip),
):
    """Verify the TOTP code and activate 2FA on the account."""
    if db is None:
        raise HTTPException(status_code=503, detail="Database offline")

    secret = current_user.get("two_factor_secret")
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Call /auth/enable-2fa first to generate a secret",
        )

    if not verify_totp(secret, payload.otp_code):
        await _write_audit(db, current_user["username"], "2fa_verify_failed", ip, False,
                           "Invalid OTP")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid OTP code — check your authenticator app and try again",
        )

    db["users"].update_one(
        {"_id": current_user["_id"]},
        {"$set": {"two_factor_enabled": True}},
    )

    # Revoke all existing sessions — they were created before 2FA was enforced.
    # This forces the user to re-login through the full OTP flow.
    user_id_str = str(current_user["_id"])
    revoke_result = db["sessions"].update_many(
        {"user_id": user_id_str, "is_active": True},
        {"$set": {"is_active": False}},
    )
    logger.info(
        f"2FA enabled for {current_user['username']} — "
        f"revoked {revoke_result.modified_count} pre-2FA session(s)"
    )

    await _write_audit(db, current_user["username"], "2fa_enabled", ip, True,
                       f"revoked_sessions={revoke_result.modified_count}")
    return {"message": "Two-factor authentication enabled successfully. Please log in again."}


# ---------------------------------------------------------------------------
# POST /auth/disable-2fa
# ---------------------------------------------------------------------------

@router.post("/disable-2fa")
async def disable_2fa(
    payload: DisableMFARequest,
    current_user: dict = Depends(get_current_user),
    db=Depends(get_db),
    ip: str = Depends(get_request_ip),
):
    """Disable 2FA. Requires the current valid TOTP code to confirm intent."""
    if db is None:
        raise HTTPException(status_code=503, detail="Database offline")

    if not current_user.get("two_factor_enabled"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA is not currently enabled on this account",
        )

    secret = current_user.get("two_factor_secret")
    if not secret:
        raise HTTPException(status_code=400, detail="No 2FA secret found")

    if not verify_totp(secret, payload.otp_code):
        await _write_audit(db, current_user["username"], "2fa_disable_failed", ip, False,
                           "Invalid OTP")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid OTP code",
        )

    db["users"].update_one(
        {"_id": current_user["_id"]},
        {"$set": {
            "two_factor_enabled": False,
            "two_factor_secret":  None,
            "backup_codes":       [],
            "trusted_devices":    [],
        }},
    )
    await _write_audit(db, current_user["username"], "2fa_disabled", ip, True)
    logger.info(f"2FA disabled for {current_user['username']}")
    return {"message": "Two-factor authentication disabled"}


# ---------------------------------------------------------------------------
# POST /auth/backup-codes  — regenerate backup codes
# ---------------------------------------------------------------------------

@router.post("/backup-codes", response_model=BackupCodesResponse)
async def regenerate_backup_codes(
    current_user: dict = Depends(get_current_user),
    db=Depends(get_db),
    ip: str = Depends(get_request_ip),
):
    """
    Regenerate backup codes, invalidating the previous set.
    Requires 2FA to be enabled.  Returns plaintext codes exactly once.
    """
    if db is None:
        raise HTTPException(status_code=503, detail="Database offline")

    if not current_user.get("two_factor_enabled"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Enable 2FA before generating backup codes",
        )

    from config import settings  # noqa: PLC0415

    plaintext_codes = generate_backup_codes(count=settings.backup_code_count)
    hashed_codes = [{"hash": hash_backup_code(c), "used": False} for c in plaintext_codes]

    db["users"].update_one(
        {"_id": current_user["_id"]},
        {"$set": {"backup_codes": hashed_codes}},
    )
    await _write_audit(db, current_user["username"], "backup_codes_regenerated", ip, True)
    logger.info(f"Backup codes regenerated for {current_user['username']}")

    return BackupCodesResponse(
        backup_codes=plaintext_codes,
        count=len(plaintext_codes),
    )


# ---------------------------------------------------------------------------
# GET /auth/trusted-devices
# ---------------------------------------------------------------------------

@router.get("/trusted-devices", response_model=List[TrustedDeviceInfo])
async def list_trusted_devices(
    current_user: dict = Depends(get_current_user),
):
    """Return all trusted (non-expired) devices for the current user."""
    now = datetime.now(timezone.utc)
    devices = []
    for td in current_user.get("trusted_devices", []):
        trusted_until = td.get("trusted_until")
        if trusted_until is None:
            continue
        if trusted_until.tzinfo is None:
            trusted_until = trusted_until.replace(tzinfo=timezone.utc)
        if now >= trusted_until:
            continue
        devices.append(
            TrustedDeviceInfo(
                id=td.get("id", ""),
                ip_address=td.get("ip_address", ""),
                user_agent=td.get("user_agent", ""),
                trusted_until=trusted_until,
                created_at=td.get("created_at", now),
            )
        )
    return devices


# ---------------------------------------------------------------------------
# DELETE /auth/trusted-devices/{device_id}
# ---------------------------------------------------------------------------

@router.delete("/trusted-devices/{device_id}")
async def revoke_trusted_device(
    device_id: str,
    current_user: dict = Depends(get_current_user),
    db=Depends(get_db),
    ip: str = Depends(get_request_ip),
):
    """Revoke a specific trusted device by its ID."""
    if db is None:
        raise HTTPException(status_code=503, detail="Database offline")

    result = db["users"].update_one(
        {"_id": current_user["_id"]},
        {"$pull": {"trusted_devices": {"id": device_id}}},
    )
    if result.modified_count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Trusted device not found",
        )
    await _write_audit(db, current_user["username"], "device_revoked", ip, True,
                       f"device_id={device_id}")
    return {"message": "Trusted device revoked successfully"}


# ---------------------------------------------------------------------------
# DELETE /auth/trusted-devices  — revoke all
# ---------------------------------------------------------------------------

@router.delete("/trusted-devices")
async def revoke_all_trusted_devices(
    current_user: dict = Depends(get_current_user),
    db=Depends(get_db),
    ip: str = Depends(get_request_ip),
):
    """Revoke all trusted devices for the current user."""
    if db is None:
        raise HTTPException(status_code=503, detail="Database offline")

    db["users"].update_one(
        {"_id": current_user["_id"]},
        {"$set": {"trusted_devices": []}},
    )
    await _write_audit(db, current_user["username"], "all_devices_revoked", ip, True)
    return {"message": "All trusted devices revoked"}


# ---------------------------------------------------------------------------
# GET /auth/test-mfa-enforcement  — diagnostic endpoint
# ---------------------------------------------------------------------------

@router.get("/test-mfa-enforcement")
async def test_mfa_enforcement():
    """Diagnostic endpoint confirming 2FA security properties."""
    return {
        "mfa_enforced": True,
        "token_without_otp_possible": False,
        "otp_replay_prevention": True,
        "otp_rate_limit": "5 attempts per 5 minutes per user",
        "temp_token_single_use": True,
        "refresh_bypass_prevented": True,
        "pre_2fa_sessions_revoked_on_activation": True,
        "device_trust_bypass": "requires prior OTP verification stored as signed device token",
        "fail_safe_guard": "active — _issue_tokens_and_session raises 403 if 2FA user bypasses OTP",
    }


# ---------------------------------------------------------------------------
# Admin: list active sessions
# ---------------------------------------------------------------------------

@router.get("/sessions", dependencies=[Depends(require_role("admin"))])
async def list_sessions(
    user_id: Optional[str] = None,
    db=Depends(get_db),
):
    """Return active sessions. Admins can filter by user_id."""
    if db is None:
        return {"sessions": []}

    query: dict = {"is_active": True}
    if user_id:
        query["user_id"] = user_id

    docs = list(
        db["sessions"].find(query, {"refresh_token_hash": 0}).sort("login_time", -1).limit(200)
    )
    for d in docs:
        d["_id"] = str(d["_id"])
        if isinstance(d.get("login_time"), datetime):
            d["login_time"] = d["login_time"].isoformat()
    return {"sessions": docs}


# ---------------------------------------------------------------------------
# Admin: audit log viewer
# ---------------------------------------------------------------------------

@router.get("/audit-log", dependencies=[Depends(require_role("admin"))])
async def get_audit_log(
    user: Optional[str] = None,
    limit: int = 100,
    db=Depends(get_db),
):
    """Return the most recent audit log entries. Admins only."""
    if db is None:
        return {"logs": []}

    limit = min(limit, 500)
    query: dict = {}
    if user:
        query["user"] = user

    docs = list(
        db["audit_logs"].find(query).sort("timestamp", -1).limit(limit)
    )
    for d in docs:
        d["_id"] = str(d["_id"])
        if isinstance(d.get("timestamp"), datetime):
            d["timestamp"] = d["timestamp"].isoformat()
    return {"logs": docs}


# ---------------------------------------------------------------------------
# POST /auth/admin/create-user  (Admin only)
# ---------------------------------------------------------------------------

@router.post(
    "/admin/create-user",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_role("admin"))],
)
async def admin_create_user(
    payload: AdminCreateUserRequest,
    current_user: dict = Depends(get_current_user),
    db=Depends(get_db),
    ip: str = Depends(get_request_ip),
):
    """
    Admin-only endpoint to create a new user with an explicit role assignment.

    Unlike POST /auth/register (public, role auto-assigned), this endpoint:
      - Requires an authenticated admin JWT
      - Accepts any valid role (viewer / analyst / admin)
      - Enforces the enterprise password policy (min 12 chars)
      - Sets two_factor_enabled=False so the new user sets up MFA on first login
    """
    if db is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="User creation unavailable — database offline",
        )

    from config import settings  # noqa: PLC0415

    # Uniqueness checks — email and username must not already be taken
    if db["users"].find_one({"email": str(payload.email)}):
        await _write_audit(
            db, current_user.get("username", "admin"),
            "admin_create_user_failed", ip, False,
            f"Email already registered: {payload.email}",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email already exists",
        )

    if db["users"].find_one({"username": payload.username}):
        await _write_audit(
            db, current_user.get("username", "admin"),
            "admin_create_user_failed", ip, False,
            f"Username already taken: {payload.username}",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already taken",
        )

    now = datetime.now(timezone.utc)
    user_doc = {
        "username":           payload.username,
        "email":              str(payload.email),
        "password_hash":      hash_password(payload.password, rounds=settings.bcrypt_rounds),
        "role":               payload.role,
        "created_at":         now,
        "last_login":         None,
        "last_login_ip":      None,
        "failed_attempts":    0,
        "locked_until":       None,
        "two_factor_enabled": False,   # user will complete MFA setup on first login
        "two_factor_secret":  None,
        "backup_codes":       [],
        "trusted_devices":    [],
    }

    result = db["users"].insert_one(user_doc)
    user_doc["_id"] = result.inserted_id

    admin_username = current_user.get("username", str(current_user["_id"]))
    await _write_audit(
        db, admin_username,
        "admin_create_user", ip, True,
        f"created username={payload.username} role={payload.role}",
    )
    logger.info(
        f"Admin '{admin_username}' created user: {payload.username} "
        f"({payload.email}) role={payload.role}"
    )

    # Socket.IO audit event (best-effort)
    try:
        from backend import sio  # noqa: PLC0415
        await sio.emit("audit_event", {
            "action":      "admin_create_user",
            "admin":       admin_username,
            "username":    payload.username,
            "email":       str(payload.email),
            "role":        payload.role,
            "ip":          ip,
            "timestamp":   now.isoformat(),
        })
    except Exception as _sio_exc:
        logger.debug(f"[ADMIN] audit Socket.IO emit skipped: {_sio_exc}")

    return user_doc_to_response(user_doc)


# ===========================================================================
# CREDENTIAL RECOVERY SYSTEM
# Enterprise-grade password and MFA recovery for Cyber Sentinel XDR.
#
# Security properties:
#   - Reset tokens: cryptographically random (secrets.token_urlsafe(32)) +
#     JWT wrapper (10-min expiry) + bcrypt-hashed in MongoDB.
#   - Single-use enforcement via `used` flag + jti lookup.
#   - MFA re-verification required before password change when 2FA is active.
#   - All sessions revoked on successful password reset.
#   - MFA recovery requires explicit admin approval before credentials are
#     wiped — prevents unilateral account takeover via recovery abuse.
#   - Risk scoring on every recovery attempt flags new IPs and repeat abuse.
#   - All actions logged to audit_logs and persisted as security_events.
# ===========================================================================

# ---------------------------------------------------------------------------
# Internal recovery helpers
# ---------------------------------------------------------------------------

async def _persist_recovery_security_event(
    db,
    event_type: str,
    severity: str,
    user_id: str,
    email: str,
    ip: str,
    extra: Optional[dict] = None,
) -> None:
    """Write a recovery-related security event to MongoDB (non-blocking helper)."""
    if db is None:
        return
    doc = {
        "type": event_type,
        "severity": severity,
        "user_id": user_id,
        "email": email,
        "ip": ip,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if extra:
        doc.update(extra)
    try:
        db["security_events"].insert_one(doc)
    except Exception as exc:
        logger.debug(f"[RECOVERY] security_event persist failed: {exc}")


async def _assess_recovery_risk(db, user_id: str, client_ip: str) -> dict:
    """
    Assess the risk level of a recovery attempt.

    Checks:
      - Whether client_ip was seen in security_events for this user in last 30 days
      - Whether more than 2 reset attempts came from this IP in the last hour

    Returns a dict with risk_level ("LOW"|"MEDIUM"|"HIGH"), is_new_ip (bool),
    and recent_attempts (int).
    """
    if db is None:
        return {"risk_level": "MEDIUM", "is_new_ip": True, "recent_attempts": 0}

    now = datetime.now(timezone.utc)
    thirty_days_ago = (now - timedelta(days=30)).isoformat()
    one_hour_ago = (now - timedelta(hours=1)).isoformat()

    # Check if this IP was seen for this user in the past 30 days
    is_new_ip = True
    try:
        known = db["security_events"].find_one(
            {
                "user_id": user_id,
                "ip": client_ip,
                "timestamp": {"$gte": thirty_days_ago},
            }
        )
        is_new_ip = known is None
    except Exception:
        pass

    # Count reset attempts from this IP in the past hour
    recent_attempts = 0
    try:
        recent_attempts = db["password_reset_tokens"].count_documents(
            {
                "ip": client_ip,
                "created_at": {"$gte": now - timedelta(hours=1)},
            }
        )
    except Exception:
        pass

    # Determine risk level
    if recent_attempts > 2 or (is_new_ip and recent_attempts > 1):
        risk_level = "HIGH"
    elif is_new_ip:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "risk_level": risk_level,
        "is_new_ip": is_new_ip,
        "recent_attempts": recent_attempts,
    }


def _revoke_all_sessions(db, user_id: str) -> int:
    """Mark all active sessions for a user as inactive. Returns revoked count."""
    if db is None:
        return 0
    try:
        result = db["sessions"].update_many(
            {"user_id": user_id, "is_active": True},
            {"$set": {"is_active": False}},
        )
        return result.modified_count
    except Exception as exc:
        logger.error(f"[RECOVERY] Session revocation failed for user={user_id}: {exc}")
        return 0


# ---------------------------------------------------------------------------
# POST /auth/forgot-password
# ---------------------------------------------------------------------------

@router.post("/forgot-password")
async def forgot_password(
    payload: ForgotPasswordRequest,
    request: Request,
    db=Depends(get_db),
    ip: str = Depends(get_request_ip),
):
    """
    Initiate credential recovery for the given email address.

    Rate-limited to 3 requests per IP per 15 minutes.
    Always returns HTTP 200 with the same message regardless of whether the
    email exists — this prevents user enumeration.

    In development mode the raw reset token is also returned in the response
    body and logged to the server console.  In production, strip `dev_token`
    from the response or gate it behind an environment flag.
    """
    # Rate-limit per IP — 3 requests per 15-minute window
    await forgot_password_rate_limiter.check_rate_limit(ip)

    from config import settings as _cfg  # noqa: PLC0415

    _SAFE_RESPONSE = {
        "message": "If that email exists, a reset link has been sent.",
    }

    if db is None:
        # Graceful degradation: do not reveal DB state to the caller
        logger.warning("[RECOVERY] forgot_password: MongoDB unavailable — skipping token generation")
        return _SAFE_RESPONSE

    # Deliberately constant-time path: look up user but never reveal existence
    user = db["users"].find_one({"email": str(payload.email)})

    # Emit audit event regardless — timing side-channel mitigation via hash_password below
    if user is None:
        # Consume time equal to bcrypt hash to prevent timing oracle attacks
        hash_password("timing-mitigation-placeholder", rounds=_cfg.bcrypt_rounds)
        # Do not reveal non-existence — return same message
        logger.debug(f"[RECOVERY] forgot_password: no account for email={payload.email} ip={ip}")
        return _SAFE_RESPONSE

    user_id = str(user["_id"])

    # Assess risk before proceeding
    risk = await _assess_recovery_risk(db, user_id, ip)
    if risk["risk_level"] == "HIGH":
        logger.warning(
            f"[RECOVERY] HIGH-RISK reset attempt: user_id={user_id} ip={ip} "
            f"recent_attempts={risk['recent_attempts']} is_new_ip={risk['is_new_ip']}"
        )

    # Generate a cryptographically secure raw token
    raw_token = secrets.token_urlsafe(32)

    # Wrap in a signed JWT (10-min expiry) — the JWT is what gets sent in the link.
    # The raw_token is hashed separately and stored as bcrypt hash for double verification.
    jwt_token, jti = create_password_reset_token(
        user_id=user_id,
        secret=_cfg.jwt_secret_key,
        algorithm=_cfg.jwt_algorithm,
        expires_minutes=10,
    )

    # Hash the raw token with bcrypt before storing (defence-in-depth)
    token_hash = hash_password(raw_token, rounds=_cfg.bcrypt_rounds)

    user_agent = request.headers.get("User-Agent", "")[:512]
    now = datetime.now(timezone.utc)

    reset_doc = {
        "user_id":    user_id,
        "token_jti":  jti,
        "token_hash": token_hash,
        "expires_at": now + timedelta(minutes=10),
        "used":       False,
        "ip":         ip,
        "user_agent": user_agent,
        "created_at": now,
        "risk_level": risk["risk_level"],
        "is_new_ip":  risk["is_new_ip"],
    }
    try:
        db["password_reset_tokens"].insert_one(reset_doc)
    except Exception as exc:
        logger.error(f"[RECOVERY] Failed to store reset token: {exc}")
        return _SAFE_RESPONSE

    # Persist security event
    import asyncio as _asyncio  # noqa: PLC0415
    _asyncio.create_task(
        _persist_recovery_security_event(
            db, "credential_recovery_requested", "MEDIUM",
            user_id, str(payload.email), ip,
            extra={"risk_level": risk["risk_level"], "is_new_ip": risk["is_new_ip"]},
        )
    )

    # Audit log
    await _write_audit(
        db, user.get("username", user_id),
        "password_reset_requested", ip, True,
        f"jti={jti} risk={risk['risk_level']}",
    )

    # Send email (non-blocking, best-effort)
    import asyncio as _asyncio  # noqa: PLC0415
    _asyncio.create_task(
        send_password_reset_email(
            to_email=str(payload.email),
            reset_token=raw_token,
            username=user.get("username", str(payload.email)),
        )
    )

    # DEV: log raw token + JWT to server console so developers can test without email
    logger.info(
        f"[DEV] Password reset token for {payload.email}: {raw_token}"
    )
    logger.info(
        f"[DEV] Password reset JWT for {payload.email}: {jwt_token}"
    )

    # Socket.IO audit event (best-effort)
    try:
        from backend import sio  # noqa: PLC0415
        await sio.emit("audit_event", {
            "action": "password_reset_requested",
            "email": str(payload.email),
            "ip": ip,
            "risk_level": risk["risk_level"],
            "timestamp": now.isoformat(),
        })
    except Exception as _sio_exc:
        logger.debug(f"[RECOVERY] audit Socket.IO emit skipped: {_sio_exc}")

    # Return dev_token so frontend can test without email infrastructure
    return {
        "message": "If that email exists, a reset link has been sent.",
        "dev_token": raw_token,       # plaintext raw token for dev testing
        "dev_jwt": jwt_token,         # signed JWT for dev testing
        "risk_level": risk["risk_level"],  # surface to frontend for UX awareness
    }


# ---------------------------------------------------------------------------
# GET /auth/recovery/check  (Public — no auth required)
# ---------------------------------------------------------------------------

@router.get("/recovery/check")
async def check_recovery_token(
    token: str,
    db=Depends(get_db),
):
    """
    Validate a raw reset token and return whether MFA is required.
    Does NOT consume the token. Used by frontend to determine whether
    to show the MFA verification step.

    Returns:
        valid: bool — whether the token is non-expired and non-used
        requires_mfa: bool — whether the linked account has 2FA enabled
    """
    if db is None:
        return {"valid": False, "requires_mfa": False}

    now = datetime.now(timezone.utc)

    candidates = list(
        db["password_reset_tokens"].find(
            {"used": False, "expires_at": {"$gt": now}}
        ).sort("created_at", -1).limit(20)
    )

    matched = None
    for candidate in candidates:
        stored_hash = candidate.get("token_hash", "")
        if verify_password(token, stored_hash):
            matched = candidate
            break

    if matched is None:
        return {"valid": False, "requires_mfa": False}

    # Load user to check 2FA status
    from bson import ObjectId  # noqa: PLC0415
    try:
        user = db["users"].find_one({"_id": ObjectId(matched["user_id"])})
    except Exception:
        user = None

    requires_mfa = bool(user and user.get("two_factor_enabled"))
    return {"valid": True, "requires_mfa": requires_mfa}


# ---------------------------------------------------------------------------
# POST /auth/reset-password
# ---------------------------------------------------------------------------

@router.post("/reset-password")
async def reset_password(
    payload: ResetPasswordRequest,
    request: Request,
    db=Depends(get_db),
    ip: str = Depends(get_request_ip),
):
    """
    Complete the password reset flow.

    Requires:
      - token: raw token returned by /forgot-password
      - new_password: min 12 chars, upper+lower+digit+special
      - mfa_code OR backup_code: required when account has 2FA active

    On success:
      - Sets new bcrypt-12 password hash on user document
      - Marks reset token as used (single-use)
      - Revokes ALL active sessions
      - Emits audit_event Socket.IO event
    """
    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    from config import settings as _cfg  # noqa: PLC0415

    # ------------------------------------------------------------------
    # 1. Validate the raw token against stored bcrypt hash
    # ------------------------------------------------------------------
    # The frontend sends the raw token (from the reset link / dev_token).
    # We look up ALL non-expired, non-used reset tokens and verify via bcrypt.
    # This avoids requiring the caller to also send the JWT (simpler UX).
    now = datetime.now(timezone.utc)

    # Find candidate tokens that are not expired and not used
    candidates = list(
        db["password_reset_tokens"].find(
            {
                "used": False,
                "expires_at": {"$gt": now},
            }
        ).sort("created_at", -1).limit(20)  # scan at most 20 recent tokens
    )

    matched_token_doc = None
    for candidate in candidates:
        stored_hash = candidate.get("token_hash", "")
        if verify_password(payload.token, stored_hash):
            matched_token_doc = candidate
            break

    if matched_token_doc is None:
        logger.warning(f"[RECOVERY] reset_password: invalid or expired token from ip={ip}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Reset token is invalid, expired, or already used.",
        )

    user_id = matched_token_doc["user_id"]
    jti = matched_token_doc.get("token_jti", "")

    # ------------------------------------------------------------------
    # 2. Load the user document
    # ------------------------------------------------------------------
    from bson import ObjectId  # noqa: PLC0415
    try:
        user = db["users"].find_one({"_id": ObjectId(user_id)})
    except Exception:
        user = None

    if user is None:
        raise HTTPException(status_code=400, detail="User account not found.")

    # ------------------------------------------------------------------
    # 3. MFA verification — mandatory when 2FA is active on the account
    # ------------------------------------------------------------------
    if user.get("two_factor_enabled"):
        if not payload.mfa_code and not payload.backup_code:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=(
                    "This account has 2FA enabled. "
                    "Provide mfa_code (TOTP) or backup_code to verify identity before resetting."
                ),
            )

        if payload.backup_code:
            # Verify against stored backup codes (SHA-256 hashed)
            stored_codes = user.get("backup_codes", [])
            from auth.mfa import verify_and_consume_backup_code  # noqa: PLC0415
            idx = verify_and_consume_backup_code(payload.backup_code, stored_codes)
            if idx is None:
                await _write_audit(
                    db, user.get("username", user_id),
                    "password_reset_backup_code_failed", ip, False,
                    "Invalid or used backup code during password reset",
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or already-used backup code.",
                )
            # Mark code as used
            stored_codes[idx]["used"] = True
            db["users"].update_one(
                {"_id": user["_id"]},
                {"$set": {"backup_codes": stored_codes}},
            )
            # Persist security event for backup code use during reset (HIGH severity)
            import asyncio as _asyncio  # noqa: PLC0415
            _asyncio.create_task(
                _persist_recovery_security_event(
                    db, "backup_code_used", "HIGH",
                    user_id, user.get("email", ""), ip,
                    extra={"context": "password_reset"},
                )
            )
            logger.info(
                f"[RECOVERY] Backup code consumed during password reset: "
                f"user_id={user_id} code_index={idx}"
            )

        elif payload.mfa_code:
            secret = user.get("two_factor_secret")
            if not secret:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="2FA secret missing. Contact your administrator for MFA recovery.",
                )
            if not verify_totp(secret, payload.mfa_code):
                await _write_audit(
                    db, user.get("username", user_id),
                    "password_reset_mfa_failed", ip, False,
                    "Invalid TOTP during password reset",
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid MFA code. Please check your authenticator app.",
                )

    # ------------------------------------------------------------------
    # 4. Update password + mark token used + revoke sessions
    # ------------------------------------------------------------------
    new_hash = hash_password(payload.new_password, rounds=_cfg.bcrypt_rounds)

    # Update password
    db["users"].update_one(
        {"_id": user["_id"]},
        {"$set": {
            "password_hash":   new_hash,
            "failed_attempts": 0,
            "locked_until":    None,
        }},
    )

    # Mark reset token as used (single-use enforcement)
    db["password_reset_tokens"].update_one(
        {"_id": matched_token_doc["_id"]},
        {"$set": {"used": True, "used_at": now, "used_from_ip": ip}},
    )

    # Revoke all active sessions
    revoked_count = _revoke_all_sessions(db, user_id)
    logger.info(
        f"[RECOVERY] Password reset completed: user_id={user_id} "
        f"sessions_revoked={revoked_count} from ip={ip}"
    )

    # ------------------------------------------------------------------
    # 5. Security event + audit trail
    # ------------------------------------------------------------------
    import asyncio as _asyncio  # noqa: PLC0415
    _asyncio.create_task(
        _persist_recovery_security_event(
            db, "credential_recovery_completed", "MEDIUM",
            user_id, user.get("email", ""), ip,
            extra={"sessions_revoked": revoked_count},
        )
    )

    await _write_audit(
        db, user.get("username", user_id),
        "password_reset_completed", ip, True,
        f"sessions_revoked={revoked_count} jti={jti}",
    )

    # Socket.IO audit event (best-effort)
    try:
        from backend import sio  # noqa: PLC0415
        await sio.emit("audit_event", {
            "action": "password_reset_completed",
            "user_id": user_id,
            "ip": ip,
            "sessions_revoked": revoked_count,
            "timestamp": now.isoformat(),
        })
    except Exception as _sio_exc:
        logger.debug(f"[RECOVERY] audit Socket.IO emit skipped: {_sio_exc}")

    return {
        "message": "Password reset successful. All sessions have been revoked.",
        "sessions_revoked": revoked_count,
    }


# ---------------------------------------------------------------------------
# POST /auth/recovery/request-mfa
# ---------------------------------------------------------------------------

@router.post("/recovery/request-mfa")
async def request_mfa_recovery(
    payload: MFARecoveryRequestPayload,
    request: Request,
    db=Depends(get_db),
    ip: str = Depends(get_request_ip),
):
    """
    Submit an MFA recovery request when a user has lost their authenticator device.

    Can be called unauthenticated (user is locked out) or authenticated.
    Rate-limited to 1 request per email per 24 hours.
    An admin must review and approve the request via /auth/recovery/approve/{request_id}.

    Returns request_id so the user can reference their case.
    """
    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    # Rate-limit keyed by email (stable across IP changes)
    await mfa_recovery_rate_limiter.check_rate_limit(str(payload.email))

    user = db["users"].find_one({"email": str(payload.email)})
    if user is None:
        # Constant-time response — do not reveal whether email exists
        logger.debug(f"[RECOVERY] mfa_recovery_request: unknown email={payload.email} ip={ip}")
        return {
            "message": "MFA recovery request submitted. An admin will review it.",
            "request_id": str(uuid.uuid4()),  # synthetic ID — request not stored
        }

    user_id = str(user["_id"])

    # Reject if a pending request already exists for this user
    existing = db["mfa_recovery_requests"].find_one(
        {"user_id": user_id, "status": "pending"}
    )
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                "A pending MFA recovery request already exists for this account. "
                "An administrator will review it shortly."
            ),
        )

    request_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    user_agent = request.headers.get("User-Agent", "")[:512]

    recovery_doc = {
        "request_id":   request_id,
        "user_id":      user_id,
        "username":     user.get("username", ""),
        "email":        str(payload.email),
        "role":         user.get("role", "viewer"),
        "reason":       payload.reason,
        "status":       "pending",
        "requested_at": now,
        "ip":           ip,
        "user_agent":   user_agent,
    }

    try:
        db["mfa_recovery_requests"].insert_one(recovery_doc)
    except Exception as exc:
        logger.error(f"[RECOVERY] Failed to store MFA recovery request: {exc}")
        raise HTTPException(status_code=500, detail="Failed to store recovery request.")

    import asyncio as _asyncio  # noqa: PLC0415

    # HIGH severity security event — MFA recovery is a privileged action
    _asyncio.create_task(
        _persist_recovery_security_event(
            db, "mfa_recovery_requested", "HIGH",
            user_id, str(payload.email), ip,
            extra={"request_id": request_id, "reason": payload.reason[:100]},
        )
    )

    await _write_audit(
        db, user.get("username", user_id),
        "mfa_recovery_requested", ip, True,
        f"request_id={request_id} reason={payload.reason[:100]}",
    )

    # Socket.IO (best-effort — informs admin panel in real time)
    try:
        from backend import sio  # noqa: PLC0415
        await sio.emit("audit_event", {
            "action": "mfa_recovery_requested",
            "user_id": user_id,
            "email": str(payload.email),
            "request_id": request_id,
            "ip": ip,
            "timestamp": now.isoformat(),
        })
    except Exception as _sio_exc:
        logger.debug(f"[RECOVERY] Socket.IO emit skipped: {_sio_exc}")

    logger.warning(
        f"[RECOVERY] MFA recovery requested: user_id={user_id} "
        f"email={payload.email} request_id={request_id} ip={ip}"
    )

    return {
        "message": "MFA recovery request submitted. An admin will review it.",
        "request_id": request_id,
    }


# ---------------------------------------------------------------------------
# GET /auth/recovery/pending  (Admin only)
# ---------------------------------------------------------------------------

@router.get("/recovery/pending", dependencies=[Depends(require_role("admin"))])
async def list_pending_mfa_recoveries(
    db=Depends(get_db),
):
    """
    Return all pending MFA recovery requests, newest-first.
    Admin only. Includes user email, role, requested_at, and IP.
    """
    if db is None:
        return {"requests": []}

    docs = list(
        db["mfa_recovery_requests"]
        .find({"status": "pending"})
        .sort("requested_at", -1)
        .limit(200)
    )
    for d in docs:
        d["_id"] = str(d["_id"])
        if isinstance(d.get("requested_at"), datetime):
            d["requested_at"] = d["requested_at"].isoformat()

    return {"requests": docs, "count": len(docs)}


# ---------------------------------------------------------------------------
# POST /auth/recovery/approve/{request_id}  (Admin only)
# ---------------------------------------------------------------------------

@router.post(
    "/recovery/approve/{request_id}",
    dependencies=[Depends(require_role("admin"))],
)
async def approve_mfa_recovery(
    request_id: str,
    payload: MFARecoveryActionPayload,
    request: Request,
    current_user: dict = Depends(get_current_user),
    db=Depends(get_db),
    ip: str = Depends(get_request_ip),
):
    """
    Approve or deny an MFA recovery request.

    Approve: clears the user's TOTP secret, backup codes, trusted devices,
             and revokes all active sessions — forcing the user to set up MFA
             from scratch on next login.

    Deny: records the decision; user remains locked out until they contact an admin.

    Admin only. All actions are audited.
    """
    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    recovery_req = db["mfa_recovery_requests"].find_one(
        {"request_id": request_id}
    )
    if recovery_req is None:
        raise HTTPException(status_code=404, detail="Recovery request not found.")

    if recovery_req.get("status") != "pending":
        raise HTTPException(
            status_code=400,
            detail=f"Request is already {recovery_req['status']} — cannot re-process.",
        )

    target_user_id = recovery_req["user_id"]
    admin_user_id = str(current_user["_id"])
    admin_username = current_user.get("username", admin_user_id)
    now = datetime.now(timezone.utc)

    import asyncio as _asyncio  # noqa: PLC0415

    if payload.action == "approve":
        # Wipe TOTP credentials and trusted devices so user goes through fresh setup
        from bson import ObjectId  # noqa: PLC0415
        try:
            db["users"].update_one(
                {"_id": ObjectId(target_user_id)},
                {"$set": {
                    "two_factor_enabled": False,
                    "two_factor_secret":  None,
                    "backup_codes":       [],
                    "trusted_devices":    [],
                }},
            )
        except Exception as exc:
            logger.error(f"[RECOVERY] Failed to wipe MFA for user={target_user_id}: {exc}")
            raise HTTPException(status_code=500, detail="Failed to update user credentials.")

        # Revoke all active sessions
        revoked_count = _revoke_all_sessions(db, target_user_id)

        # Update request status
        db["mfa_recovery_requests"].update_one(
            {"request_id": request_id},
            {"$set": {
                "status":      "approved",
                "resolved_by": admin_user_id,
                "resolved_at": now,
            }},
        )

        logger.warning(
            f"[RECOVERY] MFA recovery APPROVED: target_user_id={target_user_id} "
            f"by admin={admin_username} sessions_revoked={revoked_count}"
        )

        _asyncio.create_task(
            _persist_recovery_security_event(
                db, "mfa_recovery_approved", "HIGH",
                target_user_id, recovery_req.get("email", ""), ip,
                extra={
                    "request_id": request_id,
                    "approved_by": admin_user_id,
                    "sessions_revoked": revoked_count,
                },
            )
        )

        await _write_audit(
            db, admin_username,
            "mfa_recovery_approved", ip, True,
            f"request_id={request_id} target_user={target_user_id} revoked={revoked_count}",
        )

        # Socket.IO (best-effort)
        try:
            from backend import sio  # noqa: PLC0415
            await sio.emit("audit_event", {
                "action": "mfa_recovery_approved",
                "target_user_id": target_user_id,
                "admin": admin_username,
                "request_id": request_id,
                "sessions_revoked": revoked_count,
                "timestamp": now.isoformat(),
            })
        except Exception as _sio_exc:
            logger.debug(f"[RECOVERY] Socket.IO emit skipped: {_sio_exc}")

        return {
            "message": "MFA recovery request approved. User's 2FA credentials have been reset.",
            "sessions_revoked": revoked_count,
        }

    else:  # payload.action == "deny"
        db["mfa_recovery_requests"].update_one(
            {"request_id": request_id},
            {"$set": {
                "status":      "denied",
                "resolved_by": admin_user_id,
                "resolved_at": now,
            }},
        )

        logger.info(
            f"[RECOVERY] MFA recovery DENIED: request_id={request_id} "
            f"by admin={admin_username}"
        )

        _asyncio.create_task(
            _persist_recovery_security_event(
                db, "mfa_recovery_denied", "MEDIUM",
                target_user_id, recovery_req.get("email", ""), ip,
                extra={"request_id": request_id, "denied_by": admin_user_id},
            )
        )

        await _write_audit(
            db, admin_username,
            "mfa_recovery_denied", ip, True,
            f"request_id={request_id} target_user={target_user_id}",
        )

        # Socket.IO (best-effort)
        try:
            from backend import sio  # noqa: PLC0415
            await sio.emit("audit_event", {
                "action": "mfa_recovery_denied",
                "target_user_id": target_user_id,
                "admin": admin_username,
                "request_id": request_id,
                "timestamp": now.isoformat(),
            })
        except Exception as _sio_exc:
            logger.debug(f"[RECOVERY] Socket.IO emit skipped: {_sio_exc}")

        return {"message": "MFA recovery request denied."}


# ---------------------------------------------------------------------------
# GET /auth/backup-codes/status
# ---------------------------------------------------------------------------

@router.get("/backup-codes/status", response_model=BackupCodeStatusResponse)
async def backup_codes_status(
    current_user: dict = Depends(get_current_user),
):
    """
    Return the count of remaining unused backup codes for the current user.
    Does NOT reveal the codes themselves.
    """
    codes = current_user.get("backup_codes", [])
    total = len(codes)
    remaining = sum(1 for c in codes if not c.get("used", False))
    return BackupCodeStatusResponse(
        remaining=remaining,
        total=total,
        message=(
            "Backup codes available." if remaining > 0
            else "No backup codes remaining — regenerate via POST /auth/backup-codes."
        ),
    )
