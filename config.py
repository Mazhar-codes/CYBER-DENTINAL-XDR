"""
Shared config for Cyber Sentinel XDR demo scripts.
Reads from the same .env as the backend (project root preferred).
"""
import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    _env_root = Path(__file__).parent / ".env"
    _env_backend = Path(__file__).parent / "Backend" / ".env"
    if _env_root.exists():
        load_dotenv(_env_root, override=False)
    elif _env_backend.exists():
        load_dotenv(_env_backend, override=False)
except ImportError:
    pass

BACKEND_URL: str = os.getenv("REACT_APP_BACKEND_URL", os.getenv("BACKEND_URL", "http://192.168.1.5:8000")).rstrip("/")
API_KEY:     str = os.getenv("XDR_API_KEY", "changeme-dev-key")
HEADERS:     dict = {"X-API-Key": API_KEY, "Content-Type": "application/json"}


def get_real_endpoint() -> dict:
    """
    Fetch the first online (or most-recently-seen) endpoint from the backend registry.
    Returns a dict with keys: endpoint_id, hostname, ip_address.
    Falls back to the local machine's own identity if no endpoint is registered.
    """
    import socket
    import requests as _req

    fallback = {
        "endpoint_id": "local",
        "hostname":    socket.gethostname(),
        "ip_address":  "127.0.0.1",
    }

    try:
        r = _req.get(f"{BACKEND_URL}/endpoint/list", headers=HEADERS, timeout=5)
        if not r.ok:
            return fallback
        data = r.json()
        endpoints = data if isinstance(data, list) else data.get("endpoints", [])
        if not endpoints:
            return fallback

        # Prefer online endpoints; fall back to most-recently-seen
        online = [e for e in endpoints if e.get("status") == "online"]
        chosen = online[0] if online else endpoints[0]
        return {
            "endpoint_id": chosen.get("endpoint_id", "local"),
            "hostname":    chosen.get("hostname", fallback["hostname"]),
            "ip_address":  chosen.get("ip_address", fallback["ip_address"]),
        }
    except Exception:
        return fallback
