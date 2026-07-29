"""
identity.py — Endpoint identity persistence for Cyber Sentinel XDR.

On first run a UUID-based identity block is generated from the local host and
written to endpoint_config.json next to this file.  Subsequent runs load that
file so the endpoint_id is stable across restarts.
"""

import json
import logging
import os
import platform
import socket
import uuid
from pathlib import Path

import psutil

logger = logging.getLogger(__name__)

AGENT_VERSION = "1.0.0"

# endpoint_config.json lives next to identity.py (i.e. inside endpoint_agent/)
_CONFIG_PATH = Path(__file__).parent / "endpoint_config.json"

# Interface names that are always loopback and must be skipped
_LOOPBACK_NAMES = {"lo", "loopback"}


def _detect_local_ip() -> str:
    """Return the primary local IPv4 address without opening a real connection."""
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return "127.0.0.1"


def detect_network_interface() -> str:
    """
    Detect the primary active network interface name on this host.

    Selection priority (first match wins):
      1. Any UP, non-loopback interface whose name contains "Ethernet"
      2. Any UP, non-loopback interface whose name contains "Wi-Fi"
      3. Any UP, non-loopback interface whose name contains "Wireless"
      4. First UP, non-loopback interface (alphabetical)
      5. Hard fallback: "Ethernet"

    Returns the interface name string exactly as reported by the OS
    (e.g. "Ethernet", "Ethernet 2", "Local Area Connection").
    """
    try:
        stats = psutil.net_if_stats()
    except Exception as exc:
        logger.warning("net_if_stats() failed: %s — falling back to 'Ethernet'", exc)
        return "Ethernet"

    # Collect all UP, non-loopback interface names
    candidates: list[str] = []
    for name, stat in stats.items():
        if not stat.isup:
            continue
        if name.lower() in _LOOPBACK_NAMES or name.lower().startswith("loopback"):
            continue
        candidates.append(name)

    if not candidates:
        logger.warning(
            "No UP non-loopback interfaces found via psutil — falling back to 'Ethernet'"
        )
        return "Ethernet"

    # Priority 1 — Ethernet
    for name in candidates:
        if "ethernet" in name.lower():
            logger.debug("Detected network interface (Ethernet priority): %r", name)
            return name

    # Priority 2 — Wi-Fi
    for name in candidates:
        if "wi-fi" in name.lower() or "wifi" in name.lower():
            logger.debug("Detected network interface (Wi-Fi priority): %r", name)
            return name

    # Priority 3 — Wireless
    for name in candidates:
        if "wireless" in name.lower():
            logger.debug("Detected network interface (Wireless priority): %r", name)
            return name

    # Priority 4 — first alphabetically
    chosen = sorted(candidates)[0]
    logger.debug("Detected network interface (first UP non-loopback): %r", chosen)
    return chosen


def _build_identity() -> dict:
    """Generate a fresh identity block from the current host."""
    return {
        "endpoint_id": str(uuid.uuid4()),
        "hostname": socket.gethostname(),
        "ip_address": _detect_local_ip(),
        "os": platform.system(),
        "os_version": platform.version(),
        "username": _safe_getlogin(),
        "agent_version": AGENT_VERSION,
        "network_interface": detect_network_interface(),
    }


def _safe_getlogin() -> str:
    """os.getlogin() can fail in some service contexts; fall back gracefully."""
    try:
        return os.getlogin()
    except OSError:
        return os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"


def _load_identity() -> dict | None:
    """Load identity from disk; return None if the file is absent or corrupt."""
    if not _CONFIG_PATH.exists():
        return None
    try:
        with _CONFIG_PATH.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        # endpoint_id is the only field that must never be regenerated — all
        # others can be backfilled below from live system calls.
        if "endpoint_id" not in data:
            logger.warning("endpoint_config.json missing endpoint_id — regenerating")
            return None

        # Backfill fields that may be absent in configs written by older agent
        # versions.  We refresh the values rather than using stale/empty ones.
        dirty = False
        if not data.get("hostname"):
            data["hostname"] = socket.gethostname()
            dirty = True
        if not data.get("ip_address"):
            data["ip_address"] = _detect_local_ip()
            dirty = True
        if not data.get("os"):
            data["os"] = platform.system()
            dirty = True
        if not data.get("os_version"):
            data["os_version"] = platform.version()
            dirty = True
        if not data.get("username"):
            data["username"] = _safe_getlogin()
            dirty = True
        if not data.get("agent_version"):
            data["agent_version"] = AGENT_VERSION
            dirty = True
        if dirty:
            logger.info(
                "endpoint_config.json was missing fields — backfilled and re-saved"
            )
            _save_identity(data)

        return data
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to load endpoint_config.json: %s — regenerating", exc)
        return None


def _save_identity(identity: dict) -> None:
    """Persist identity to disk.  Failure is logged but never raised."""
    try:
        _CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with _CONFIG_PATH.open("w", encoding="utf-8") as fh:
            json.dump(identity, fh, indent=2)
        logger.info("Endpoint identity saved to %s", _CONFIG_PATH)
    except OSError as exc:
        logger.warning("Could not save endpoint_config.json: %s", exc)


# Module-level cache so repeated calls in the same process are free
_cached_identity: dict | None = None


def get_identity() -> dict:
    """
    Return the stable endpoint identity dict.

    Load order:
      1. In-process cache (fastest, used after first call)
      2. endpoint_config.json on disk
      3. Freshly generated identity (also written to disk for next run)
    """
    global _cached_identity  # noqa: PLW0603

    if _cached_identity is not None:
        return _cached_identity

    identity = _load_identity()
    if identity is None:
        identity = _build_identity()
        _save_identity(identity)
        logger.info(
            "New endpoint registered — id=%s  host=%s",
            identity["endpoint_id"],
            identity["hostname"],
        )
    else:
        logger.info(
            "Loaded existing identity — id=%s  host=%s",
            identity["endpoint_id"],
            identity["hostname"],
        )
        # Backfill network_interface for configs written before this field existed
        if "network_interface" not in identity:
            identity["network_interface"] = detect_network_interface()
            _save_identity(identity)
            logger.info(
                "Backfilled network_interface=%r into endpoint_config.json",
                identity["network_interface"],
            )

    _cached_identity = identity
    return identity
