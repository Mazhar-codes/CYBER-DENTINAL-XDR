"""
collectors — telemetry collection sub-package for Cyber Sentinel XDR endpoint agent.

Each module exposes a single top-level async function that returns a dict.
All modules are designed to be safe: they catch every exception internally
and return an empty/partial structure rather than propagating errors to the
caller.
"""

from .network_collector import collect_network
from .system_collector import collect_system
from .user_collector import collect_user
from .malware_collector import collect_malware

__all__ = [
    "collect_network",
    "collect_system",
    "collect_user",
    "collect_malware",
]
