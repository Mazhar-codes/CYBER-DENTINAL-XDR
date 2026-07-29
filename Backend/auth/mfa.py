"""
auth/mfa.py — Enterprise MFA utilities for Cyber Sentinel XDR.

Provides:
  - UsedOTPCache       : in-memory replay-prevention cache (prevents OTP reuse)
  - OTPRateLimiter     : per-user OTP submission throttle (separate from login limiter)
  - generate_backup_codes / hash_backup_code / verify_and_consume_backup_code
  - generate_device_token / hash_device_token
"""

import asyncio
import hashlib
import secrets
import string
import time
from collections import defaultdict
from typing import Optional

from fastapi import HTTPException, status


# ---------------------------------------------------------------------------
# OTP Replay Prevention
# ---------------------------------------------------------------------------

class UsedOTPCache:
    """
    Track consumed TOTP codes per user to prevent replay attacks within
    the same 30-second window.

    Each entry expires after `ttl_seconds` (30 s — one TOTP step).
    Entries are purged lazily.
    """

    def __init__(self, ttl_seconds: int = 30) -> None:
        self._ttl = ttl_seconds
        self._used: dict[tuple[str, str], float] = {}
        self._lock = asyncio.Lock()

    async def is_used(self, user_id: str, otp: str) -> bool:
        now = time.monotonic()
        async with self._lock:
            self._purge(now)
            return (user_id, otp) in self._used

    async def mark_used(self, user_id: str, otp: str) -> None:
        now = time.monotonic()
        async with self._lock:
            self._used[(user_id, otp)] = now + self._ttl
            self._purge(now)

    def _purge(self, now: float) -> None:
        expired = [k for k, exp in self._used.items() if exp <= now]
        for k in expired:
            del self._used[k]


otp_used_cache = UsedOTPCache(ttl_seconds=30)


# ---------------------------------------------------------------------------
# OTP-specific rate limiter  (keyed by user_id, not IP)
# ---------------------------------------------------------------------------

class OTPRateLimiter:
    """
    Allow at most `max_attempts` OTP submissions per user_id per window.
    Keyed by user_id so VPN/proxy changes do not reset the limit.
    """

    def __init__(self, max_attempts: int = 5, window_seconds: int = 300) -> None:
        self._max = max_attempts
        self._window = window_seconds
        self._attempts: dict[str, list[float]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def check(self, user_id: str) -> None:
        now = time.monotonic()
        cutoff = now - self._window
        async with self._lock:
            self._attempts[user_id] = [t for t in self._attempts[user_id] if t > cutoff]
            if len(self._attempts[user_id]) >= self._max:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many OTP attempts. Try again in 5 minutes.",
                )
            self._attempts[user_id].append(now)

    async def reset(self, user_id: str) -> None:
        async with self._lock:
            self._attempts.pop(user_id, None)


otp_rate_limiter = OTPRateLimiter(max_attempts=5, window_seconds=300)


# ---------------------------------------------------------------------------
# Backup codes
# ---------------------------------------------------------------------------

_BACKUP_CODE_CHARS = string.ascii_uppercase + string.digits


def generate_backup_codes(count: int = 10) -> list[str]:
    """
    Generate `count` one-time backup codes in XXXX-XXXX format.
    Returns plaintext list — caller must show to user exactly once.
    """
    codes: list[str] = []
    for _ in range(count):
        seg1 = "".join(secrets.choice(_BACKUP_CODE_CHARS) for _ in range(4))
        seg2 = "".join(secrets.choice(_BACKUP_CODE_CHARS) for _ in range(4))
        codes.append(f"{seg1}-{seg2}")
    return codes


def hash_backup_code(code: str) -> str:
    """Return a SHA-256 hex digest of the normalised backup code."""
    normalised = code.upper().replace("-", "").replace(" ", "")
    return hashlib.sha256(normalised.encode("utf-8")).hexdigest()


def verify_and_consume_backup_code(
    plain: str,
    stored_codes: list[dict],
) -> Optional[int]:
    """
    Verify *plain* against stored backup code dicts (each: {"hash": str, "used": bool}).

    Returns the index of the matching unused code, or None on failure.
    The caller marks the code used in MongoDB after this returns.
    """
    normalised = plain.upper().replace("-", "").replace(" ", "")
    candidate_hash = hashlib.sha256(normalised.encode("utf-8")).hexdigest()
    for idx, entry in enumerate(stored_codes):
        if not entry.get("used", False) and entry.get("hash") == candidate_hash:
            return idx
    return None


# ---------------------------------------------------------------------------
# Temp-token (2fa_pending) JTI blacklist
# Prevents reuse of the same temp token across multiple OTP attempts after success.
# TTL matches the temp token's 5-minute lifetime.
# ---------------------------------------------------------------------------

class UsedJTICache:
    """
    Single-use enforcement for 2fa_pending temp token JTIs.
    After a successful verify-2fa-login, the JTI is recorded here
    for its remaining lifetime so it cannot be replayed.
    """

    def __init__(self, ttl_seconds: int = 360) -> None:
        self._ttl = ttl_seconds
        self._used: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def is_used(self, jti: str) -> bool:
        now = time.monotonic()
        async with self._lock:
            self._purge(now)
            return jti in self._used

    async def mark_used(self, jti: str) -> None:
        now = time.monotonic()
        async with self._lock:
            self._used[jti] = now + self._ttl
            self._purge(now)

    def _purge(self, now: float) -> None:
        expired = [k for k, exp in self._used.items() if exp <= now]
        for k in expired:
            del self._used[k]


temp_token_jti_cache = UsedJTICache(ttl_seconds=360)


# ---------------------------------------------------------------------------
# Device trust tokens
# ---------------------------------------------------------------------------

def generate_device_token() -> str:
    """Generate a 32-byte URL-safe random device trust token (shown to client once)."""
    return secrets.token_urlsafe(32)


def hash_device_token(token: str) -> str:
    """Return a SHA-256 hex digest of the device token for safe DB storage."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
