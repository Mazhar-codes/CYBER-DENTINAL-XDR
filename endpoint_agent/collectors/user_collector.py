"""
user_collector.py — Active user session telemetry for Cyber Sentinel XDR endpoint agent.

Reports the currently logged-in user and all active interactive sessions as
reported by psutil.users().  This feeds the user-behavior layer on the backend
with lightweight session context without requiring Winlogbeat to be configured.
"""

import logging
import os
from datetime import datetime
from typing import Any

import psutil

logger = logging.getLogger(__name__)


def _safe_getlogin() -> str:
    """Return the login name of the current process owner, with fallback."""
    try:
        return os.getlogin()
    except OSError:
        return os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"


async def collect_user() -> dict[str, Any]:
    """
    Return a snapshot of active user sessions on this endpoint.

    The function is declared async for uniform awaiting in the telemetry loop.

    Returns:
        {
            "current_user": str,
            "active_sessions": [
                {
                    "user": str,
                    "terminal": str,
                    "host": str,
                    "started": float,   # Unix timestamp (epoch seconds)
                },
                ...
            ],
            "session_count": int,
        }
    """
    current_user = _safe_getlogin()
    active_sessions: list[dict[str, Any]] = []

    try:
        for user_entry in psutil.users():
            try:
                active_sessions.append(
                    {
                        "user": user_entry.name or "",
                        "terminal": user_entry.terminal or "",
                        "host": user_entry.host or "",
                        "started": datetime.fromtimestamp(user_entry.started).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        ),
                    }
                )
            except Exception as exc:
                logger.debug("Skipping malformed user entry: %s", exc)
                continue
    except Exception as exc:
        logger.warning("psutil.users() failed: %s", exc)

    return {
        "current_user": current_user,
        "sessions": active_sessions,
        "session_count": len(active_sessions),
    }
