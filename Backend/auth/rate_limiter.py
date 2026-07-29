"""
auth/rate_limiter.py — In-memory sliding-window rate limiter for auth endpoints.

No Redis required.  Uses a per-IP deque of attempt timestamps.
Thread-safe for asyncio (single-threaded event loop); an asyncio.Lock is used
for correctness in case of concurrent coroutines.

Limits:
  /auth/login   — 5 attempts per IP per 15 minutes
"""

import asyncio
import logging
import time
from collections import defaultdict, deque
from typing import Deque

from fastapi import HTTPException, status

logger = logging.getLogger(__name__)


class LoginRateLimiter:
    """
    Sliding-window rate limiter.

    Parameters
    ----------
    max_attempts : int
        Maximum allowed attempts in the window (default 5).
    window_seconds : int
        Length of the sliding window in seconds (default 900 = 15 min).
    """

    def __init__(self, max_attempts: int = 5, window_seconds: int = 900) -> None:
        self._max = max_attempts
        self._window = window_seconds
        # ip -> deque of monotonic timestamps of recent attempts
        self._attempts: dict[str, Deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def check_rate_limit(self, ip: str) -> None:
        """
        Raise HTTPException(429) if *ip* has exceeded the rate limit.
        Otherwise record the current attempt and return.
        """
        now = time.monotonic()
        async with self._lock:
            dq = self._attempts[ip]
            # Evict timestamps outside the current window
            cutoff = now - self._window
            while dq and dq[0] <= cutoff:
                dq.popleft()

            if len(dq) >= self._max:
                oldest = dq[0]
                retry_after = int(self._window - (now - oldest)) + 1
                logger.warning(
                    f"Rate limit hit for IP {ip} — {len(dq)} attempts in window"
                )
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=(
                        f"Too many login attempts. "
                        f"Try again in {retry_after} seconds."
                    ),
                    headers={"Retry-After": str(retry_after)},
                )

            # Record this attempt
            dq.append(now)

    async def reset(self, ip: str) -> None:
        """
        Clear the rate-limit counter for *ip* (called on successful login).
        """
        async with self._lock:
            self._attempts.pop(ip, None)

    def current_count(self, ip: str) -> int:
        """Return the number of tracked attempts for *ip* in the current window."""
        now = time.monotonic()
        dq = self._attempts.get(ip, deque())
        cutoff = now - self._window
        return sum(1 for t in dq if t > cutoff)


# Module-level singleton — imported by router.py
login_rate_limiter = LoginRateLimiter(max_attempts=5, window_seconds=900)

# Password reset — max 3 requests per IP per 15 minutes
forgot_password_rate_limiter = LoginRateLimiter(max_attempts=3, window_seconds=900)

# MFA recovery — max 1 request per user-key per 24 hours
# Keyed by user email (not IP) so VPN changes don't reset the limit.
# Reuses LoginRateLimiter since the interface is identical.
mfa_recovery_rate_limiter = LoginRateLimiter(max_attempts=1, window_seconds=86_400)
