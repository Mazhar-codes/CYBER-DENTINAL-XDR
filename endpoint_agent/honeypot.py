"""
honeypot.py — Endpoint deception honeypot for Cyber Sentinel XDR (Phase 1).

Opens a small set of *decoy* TCP ports on the endpoint. Nothing legitimate ever
connects to these ports, so ANY inbound connection is a high-confidence signal
of scanning, probing, or lateral movement targeting this host.

Safety: this is a PASSIVE deception sensor. It never executes anything, never
runs attacker input, and only reads a small, size-capped preview of the first
bytes (a banner-grab) before closing the socket. It optionally emits a static,
harmless service banner to look convincing and elicit attacker interaction.

Lifecycle: created and started by the endpoint agent, stopped when the agent
stops — so it shares the agent's Start/Stop lifecycle with no separate control.

Hits are buffered in-memory (deduplicated per attacker+port over a short window)
and drained by the agent each cycle to POST to the backend.
"""
from __future__ import annotations

import asyncio
import logging
import os
from collections import deque
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger("xdr-agent.honeypot")

# Decoy ports: commonly attacked services that a normal workstation is NOT
# running. Deliberately excludes 445/3389 (SMB/RDP) which are usually bound by
# real Windows services — a bind-check skips anything already in use anyway.
_DEFAULT_PORTS = [23, 21, 2222, 3306, 1433, 5900, 8080]

# Service label + a static, harmless banner per decoy port. Banners make the
# decoy look like a real service so scanners engage further; they contain no
# code and elicit no exploit path.
_SERVICE_MAP: dict[int, tuple[str, bytes]] = {
    21:   ("ftp",    b"220 (vsFTPd 3.0.3)\r\n"),
    23:   ("telnet", b"\r\nUbuntu 20.04 LTS\r\nlogin: "),
    2222: ("ssh",    b"SSH-2.0-OpenSSH_7.4\r\n"),
    3306: ("mysql",  b""),   # binary handshake — just log, no banner
    1433: ("mssql",  b""),
    5900: ("vnc",    b"RFB 003.008\n"),
    8080: ("http",   b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n\r\n"),
}

_READ_LIMIT = 512          # max bytes read from a connection (banner-grab cap)
_READ_TIMEOUT = 3.0        # seconds to wait for attacker input before closing
_DEDUP_WINDOW = 5.0        # collapse repeat hits from same ip+port within N s
_MAX_BUFFERED_HITS = 500   # ring buffer cap so a flood can't exhaust memory


def _parse_ports(raw: str) -> list[int]:
    ports: list[int] = []
    for tok in raw.split(","):
        tok = tok.strip()
        if not tok:
            continue
        try:
            p = int(tok)
            if 1 <= p <= 65535:
                ports.append(p)
        except ValueError:
            continue
    return ports


class Honeypot:
    """Async multi-port TCP honeypot. Buffers hits for the agent to drain."""

    def __init__(self, ports: Optional[list[int]] = None):
        env_ports = os.environ.get("XDR_HONEYPOT_PORTS", "").strip()
        self.ports = ports or (_parse_ports(env_ports) if env_ports else list(_DEFAULT_PORTS))
        self._servers: list[asyncio.AbstractServer] = []
        self._hits: deque = deque(maxlen=_MAX_BUFFERED_HITS)
        self._last_seen: dict[tuple, float] = {}   # (ip, port) -> monotonic ts
        self._running = False

    # ------------------------------------------------------------------
    @property
    def active_ports(self) -> list[int]:
        return [s.sockets[0].getsockname()[1] for s in self._servers if s.sockets]

    def _record_hit(self, decoy_port: int, service: str, ip: str,
                    aport: int, preview: bytes) -> None:
        """Buffer a hit, collapsing rapid repeats from the same source+port."""
        loop = asyncio.get_event_loop()
        now = loop.time()
        key = (ip, decoy_port)
        last = self._last_seen.get(key, -1e9)
        self._last_seen[key] = now

        safe_preview = ""
        if preview:
            # Printable-only, truncated repr — never store raw attacker bytes verbatim
            safe_preview = "".join(
                chr(b) if 32 <= b < 127 else "." for b in preview[:120]
            )

        if now - last < _DEDUP_WINDOW and self._hits:
            # Same attacker hammering the same port — bump the most recent match
            for h in reversed(self._hits):
                if h["attacker_ip"] == ip and h["decoy_port"] == decoy_port:
                    h["count"] += 1
                    h["last_seen"] = datetime.now(timezone.utc).isoformat()
                    if safe_preview and not h.get("data_preview"):
                        h["data_preview"] = safe_preview
                    return

        self._hits.append({
            "decoy_port":    decoy_port,
            "service":       service,
            "attacker_ip":   ip,
            "attacker_port": aport,
            "timestamp":     datetime.now(timezone.utc).isoformat(),
            "last_seen":     datetime.now(timezone.utc).isoformat(),
            "data_preview":  safe_preview,
            "count":         1,
        })
        log.warning(
            "HONEYPOT HIT — %s:%d probed decoy port %d (%s)",
            ip, aport, decoy_port, service,
        )

    def _make_handler(self, decoy_port: int, service: str, banner: bytes):
        async def _handle(reader: asyncio.StreamReader,
                          writer: asyncio.StreamWriter) -> None:
            peer = writer.get_extra_info("peername") or ("unknown", 0)
            ip, aport = str(peer[0]), int(peer[1]) if len(peer) > 1 else 0
            preview = b""
            try:
                if banner:
                    writer.write(banner)
                    try:
                        await asyncio.wait_for(writer.drain(), timeout=_READ_TIMEOUT)
                    except (asyncio.TimeoutError, Exception):
                        pass
                try:
                    preview = await asyncio.wait_for(
                        reader.read(_READ_LIMIT), timeout=_READ_TIMEOUT
                    )
                except (asyncio.TimeoutError, Exception):
                    preview = b""
            finally:
                self._record_hit(decoy_port, service, ip, aport, preview)
                try:
                    writer.close()
                except Exception:
                    pass
        return _handle

    # ------------------------------------------------------------------
    async def start(self) -> None:
        """Bind a listener on every configured decoy port that is free."""
        if os.environ.get("XDR_HONEYPOT_ENABLED", "true").lower() not in ("1", "true", "yes"):
            log.info("Honeypot disabled via XDR_HONEYPOT_ENABLED.")
            return
        for port in self.ports:
            service, banner = _SERVICE_MAP.get(port, (f"tcp/{port}", b""))
            try:
                server = await asyncio.start_server(
                    self._make_handler(port, service, banner),
                    host="0.0.0.0", port=port,
                )
                self._servers.append(server)
            except OSError as exc:
                # Port already in use (a real service) or permission denied — skip it.
                log.info("Honeypot: skipping port %d (%s) — %s", port, service, exc)
        self._running = bool(self._servers)
        if self._running:
            log.info("Honeypot active on decoy ports: %s", self.active_ports)
        else:
            log.warning("Honeypot started but bound no ports (all in use?).")

    async def stop(self) -> None:
        for server in self._servers:
            try:
                server.close()
                await server.wait_closed()
            except Exception:
                pass
        self._servers.clear()
        self._running = False
        log.info("Honeypot stopped.")

    def drain_hits(self) -> list[dict]:
        """Return and clear all buffered hits (called by the agent each cycle)."""
        out = list(self._hits)
        self._hits.clear()
        return out
