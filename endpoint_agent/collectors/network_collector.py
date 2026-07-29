"""
network_collector.py — Network telemetry for Cyber Sentinel XDR endpoint agent.

Collects:
  - Active TCP/UDP connections (remote-address only, max 50)
  - Interface-level I/O counters
  - Connections to known suspicious ports flagged for SOC attention
"""

import logging
from typing import Any

import psutil

logger = logging.getLogger(__name__)

# Ports that, when found in an active outbound connection, warrant flagging.
SUSPICIOUS_PORTS: set[int] = {
    22,     # SSH (unusual for Windows workstations)
    23,     # Telnet
    135,    # RPC endpoint mapper (lateral movement)
    139,    # NetBIOS session service
    445,    # SMB (lateral movement / ransomware)
    1433,   # MS SQL Server (data exfil risk)
    3389,   # RDP (remote access / brute force)
    4444,   # Metasploit default listener
    5900,   # VNC
    6666,   # IRC / generic C2
    8080,   # Alternate HTTP (proxy / C2 beaconing)
    8443,   # Alternate HTTPS
    31337,  # Classic "elite" backdoor port
}

_EMPTY_RESULT: dict[str, Any] = {
    "connections": [],
    "bytes_sent": 0,
    "bytes_recv": 0,
    "suspicious_ports": [],
}


async def collect_network() -> dict[str, Any]:
    """
    Return a snapshot of active network connections and I/O counters.

    The function is declared async so it can be awaited uniformly by the
    telemetry loop, even though psutil calls are synchronous.  For a truly
    non-blocking implementation the caller should run this in an executor;
    at 5-second intervals the blocking time (~10 ms) is negligible.

    Returns:
        {
            "connections": [{"laddr", "raddr", "status", "pid"}, ...],
            "bytes_sent": int,
            "bytes_recv": int,
            "suspicious_ports": [int, ...],   # ports seen in active connections
        }
    """
    connections: list[dict[str, Any]] = []
    suspicious_ports_seen: set[int] = set()

    try:
        raw_conns = psutil.net_connections(kind="inet")
    except Exception as exc:
        logger.warning("net_connections() failed: %s", exc)
        raw_conns = []

    for conn in raw_conns:
        try:
            # Skip connections with no remote address (listening sockets)
            if not conn.raddr:
                continue

            raddr_str = f"{conn.raddr.ip}:{conn.raddr.port}"
            laddr_str = (
                f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
            )

            connections.append(
                {
                    "laddr": laddr_str,
                    "raddr": raddr_str,
                    "status": conn.status,
                    "pid": conn.pid,
                }
            )

            # Flag suspicious remote ports
            if conn.raddr.port in SUSPICIOUS_PORTS:
                suspicious_ports_seen.add(conn.raddr.port)

        except Exception as exc:
            logger.debug("Skipping malformed connection entry: %s", exc)
            continue

    # Cap at 50 connections to keep the payload bounded
    connections = connections[:50]

    # I/O counters — aggregate across all interfaces
    bytes_sent = 0
    bytes_recv = 0
    packets_sent = 0
    packets_recv = 0
    try:
        io = psutil.net_io_counters()
        bytes_sent = io.bytes_sent
        bytes_recv = io.bytes_recv
        packets_sent = io.packets_sent
        packets_recv = io.packets_recv
    except Exception as exc:
        logger.warning("net_io_counters() failed: %s", exc)

    return {
        "connections":      connections,
        "bytes_sent":       bytes_sent,
        "bytes_recv":       bytes_recv,
        "packets_sent":     packets_sent,
        "packets_recv":     packets_recv,
        "suspicious_ports": sorted(suspicious_ports_seen),
    }
