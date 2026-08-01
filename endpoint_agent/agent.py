#!/usr/bin/env python3
"""
Cyber Sentinel XDR — Endpoint Telemetry Agent  v1.0.0

Runs on each monitored Windows endpoint.  Every tick it:
  1. Collects network, system, user, and malware-indicator telemetry via psutil.
  2. POSTs the payload to the XDR backend at /endpoint/ingest.
  3. Polls /endpoint/commands/{endpoint_id} for pending SOAR commands.
  4. Executes each command and ACKs the result to /endpoint/command/ack.

The two loops (telemetry and command) run as concurrent asyncio tasks so a
slow backend response on one loop does not block the other.

Usage
-----
  python agent.py
  python agent.py --backend-url http://192.168.1.100:8000 --api-key <key>
  python agent.py --simulate          # safe: commands logged but not executed
  python agent.py --collect-interval 10 --command-interval 5

Environment variables (override CLI defaults)
---------------------------------------------
  XDR_BACKEND_URL       Backend base URL      (default: http://localhost:8000)
  XDR_API_KEY           API key header value  (default: changeme-dev-key)
  XDR_COLLECT_INTERVAL  Telemetry interval s  (default: 5)
  XDR_COMMAND_INTERVAL  Command poll interval s (default: 3)
"""

import argparse
import asyncio
import json
import logging
import os
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

# ---------------------------------------------------------------------------
# Path bootstrap — allow running as `python agent.py` from any working dir
# by ensuring the package root is on sys.path.
# ---------------------------------------------------------------------------
_AGENT_DIR = Path(__file__).resolve().parent
if str(_AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENT_DIR))

from identity import get_identity                                 # noqa: E402
from sender import send_telemetry, post_json                      # noqa: E402
from honeypot import Honeypot                                     # noqa: E402
from command_listener import (                                    # noqa: E402
    acknowledge_command,
    check_and_warn_admin,
    execute_command,
    poll_commands,
)
from collectors import (                                          # noqa: E402
    collect_malware,
    collect_network,
    collect_system,
    collect_user,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stdout,
)
log = logging.getLogger("xdr-agent")

# Quieten httpx connection-level noise at INFO; still visible at DEBUG.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

# ---------------------------------------------------------------------------
# Module-level health state — updated by the telemetry and command loops
# so the health endpoint always reflects the latest activity.
# ---------------------------------------------------------------------------

_start_time: datetime = datetime.now(timezone.utc)
_last_telemetry_sent: datetime | None = None
_last_command_poll: datetime | None = None

# Populated by _main() once identity is resolved so the health handler can
# read it without any import-time dependency on a specific config file.
_health_identity: dict = {}


# ---------------------------------------------------------------------------
# Health HTTP server (built-in http.server — no new dependencies)
# ---------------------------------------------------------------------------

_AGENT_VERSION = "1.0.0"
_ISOLATION_FLAG_PATH = Path(__file__).resolve().parent / "isolation_flag.txt"


class _HealthHandler(BaseHTTPRequestHandler):
    """Minimal HTTP/1.1 handler that serves GET /health as JSON."""

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/health":
            self.send_response(404)
            self.end_headers()
            return

        now = datetime.now(timezone.utc)
        uptime = int((now - _start_time).total_seconds())

        body = json.dumps(
            {
                "status": "running",
                "endpoint_id": _health_identity.get("endpoint_id", ""),
                "hostname": _health_identity.get("hostname", ""),
                "uptime_seconds": uptime,
                "last_telemetry_sent": (
                    _last_telemetry_sent.isoformat() if _last_telemetry_sent else None
                ),
                "last_command_poll": (
                    _last_command_poll.isoformat() if _last_command_poll else None
                ),
                "isolation_active": _ISOLATION_FLAG_PATH.exists(),
                "version": _AGENT_VERSION,
            },
            indent=2,
        ).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:  # noqa: N802
        # Redirect access log to the module logger at DEBUG level so it does
        # not pollute the agent's INFO output during normal operation.
        log.debug("health-server: " + fmt, *args)


class _QuietHealthServer(ThreadingHTTPServer):
    """Threaded health server that swallows port-scanner noise.

    This host also runs the deception honeypot, so it is a deliberate scan
    target. When a scanner (nmap) or any probe resets the connection mid-request,
    http.server raises ConnectionResetError/BrokenPipeError from readline/write.
    The stock ``handle_error`` dumps a full traceback to stderr for every such
    probe — dozens per scan — which looks like a crash but is only expected
    scan traffic. We drop those quietly and keep serving.
    """

    daemon_threads = True

    def handle_error(self, request, client_address) -> None:  # noqa: D401
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionResetError, ConnectionAbortedError,
                            BrokenPipeError, TimeoutError)):
            return
        super().handle_error(request, client_address)


def _start_health_server(port: int) -> None:
    """
    Start the health HTTP server in a daemon thread.

    Using a daemon thread (rather than a third asyncio task) keeps the
    implementation entirely dependency-free: http.server is synchronous and
    wrapping it in asyncio would require run_in_executor plumbing.  A daemon
    thread exits automatically when the main process terminates.
    """
    try:
        server = _QuietHealthServer(("0.0.0.0", port), _HealthHandler)
        log.info("Health server listening on http://0.0.0.0:%d/health", port)
        server.serve_forever()
    except OSError as exc:
        log.warning("Health server could not bind to port %d: %s", port, exc)
    except Exception as exc:
        log.error("Health server error: %s", exc)


# ---------------------------------------------------------------------------
# CLI / env configuration
# ---------------------------------------------------------------------------

_DEFAULTS = {
    "backend_url":      "http://localhost:8000",
    "api_key":          "changeme-dev-key",
    "collect_interval": 5.0,
    "command_interval": 3.0,
}


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Cyber Sentinel XDR — Endpoint Telemetry & Response Agent",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument(
        "--backend-url",
        default=os.environ.get("XDR_BACKEND_URL", _DEFAULTS["backend_url"]),
        help="XDR backend base URL",
    )
    p.add_argument(
        "--api-key",
        default=os.environ.get("XDR_API_KEY", _DEFAULTS["api_key"]),
        help="API key sent in X-API-Key header",
    )
    p.add_argument(
        "--collect-interval",
        type=float,
        default=float(os.environ.get("XDR_COLLECT_INTERVAL", _DEFAULTS["collect_interval"])),
        metavar="SECONDS",
        help="How often to collect and ship telemetry",
    )
    p.add_argument(
        "--command-interval",
        type=float,
        default=float(os.environ.get("XDR_COMMAND_INTERVAL", _DEFAULTS["command_interval"])),
        metavar="SECONDS",
        help="How often to poll for pending SOAR commands",
    )
    p.add_argument(
        "--simulate",
        action="store_true",
        default=False,
        help=(
            "Safe mode: log every command but never execute OS-level actions "
            "(netsh, taskkill, file moves, etc.)"
        ),
    )
    p.add_argument(
        "--health-port",
        type=int,
        default=int(os.environ.get("XDR_AGENT_HEALTH_PORT", "8765")),
        metavar="PORT",
        help="TCP port for the agent health endpoint (GET /health)",
    )
    return p.parse_args()


# ---------------------------------------------------------------------------
# Telemetry loop
# ---------------------------------------------------------------------------


async def _telemetry_loop(
    identity: dict,
    backend_url: str,
    api_key: str,
    interval: float,
) -> None:
    """
    Collect all telemetry categories and POST the combined payload every
    `interval` seconds.

    The four collector coroutines are awaited concurrently with
    asyncio.gather() so they run in parallel — the total wall-clock cost is
    roughly max(collector latencies) rather than their sum.
    """
    global _last_telemetry_sent

    log.info("Telemetry loop started — interval=%.1f s", interval)

    while True:
        try:
            # Collect all four categories concurrently
            network, system, user, malware = await asyncio.gather(
                collect_network(),
                collect_system(),
                collect_user(),
                collect_malware(),
            )

            payload: dict = {
                "endpoint": identity,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "network": network,
                "system": system,
                "user": user,
                "malware": malware,
                # Backend expects a dict; an absent key or empty list causes 422.
                "winlogbeat_events": {},
            }

            ok = await send_telemetry(payload, backend_url, api_key)

            # Always stamp the timestamp so health endpoint reflects activity
            _last_telemetry_sent = datetime.now(timezone.utc)

            if ok:
                log.info(
                    "Telemetry sent — CPU:%.1f%%  MEM:%.1f%%  CONNS:%d  SUSP:%d",
                    system.get("cpu_percent", 0.0),
                    system.get("memory_percent", 0.0),
                    len(network.get("connections", [])),
                    len(malware.get("suspicious", [])),
                )
            else:
                log.warning("Telemetry send failed — will retry next tick")

        except asyncio.CancelledError:
            log.info("Telemetry loop cancelled.")
            raise
        except Exception as exc:
            log.error("Unexpected telemetry loop error: %s", exc, exc_info=True)

        await asyncio.sleep(interval)


# ---------------------------------------------------------------------------
# Command loop
# ---------------------------------------------------------------------------


async def _command_loop(
    identity: dict,
    backend_url: str,
    api_key: str,
    interval: float,
    simulate: bool,
) -> None:
    """
    Poll for pending SOAR commands every `interval` seconds, execute each,
    and acknowledge the result to the backend.

    Execution is serialised within a single poll cycle (commands are processed
    one at a time) so that conflicting actions (e.g., isolate followed by
    unblock) are applied in the order the backend intended.
    """
    global _last_command_poll

    endpoint_id = identity["endpoint_id"]
    sim_tag = " [SIMULATE]" if simulate else ""
    log.info("Command loop started — interval=%.1f s%s", interval, sim_tag)

    while True:
        try:
            commands = await poll_commands(endpoint_id, backend_url, api_key)

            # Stamp after every successful poll (even when the list is empty)
            _last_command_poll = datetime.now(timezone.utc)

            for cmd in commands:
                action = cmd.get("action", "?")
                target = cmd.get("target", "")
                log.info(
                    "Received command — action=%r target=%r command_id=%s",
                    action, target, cmd.get("command_id", ""),
                )

                result = await execute_command(cmd, simulate=simulate)

                # Annotate with endpoint context and execution timestamp
                result["endpoint_id"] = endpoint_id
                result["executed_at"] = datetime.now(timezone.utc).isoformat()

                log.info(
                    "Command result — action=%r success=%s msg=%s",
                    action,
                    result.get("success"),
                    result.get("message", ""),
                )

                await acknowledge_command(result, backend_url, api_key)

        except asyncio.CancelledError:
            log.info("Command loop cancelled.")
            raise
        except Exception as exc:
            log.error("Unexpected command loop error: %s", exc, exc_info=True)

        await asyncio.sleep(interval)


# ---------------------------------------------------------------------------
# Honeypot loop — drains decoy-port hits and ships them to the backend
# ---------------------------------------------------------------------------


async def _honeypot_loop(
    honeypot: Honeypot,
    identity: dict,
    backend_url: str,
    api_key: str,
    interval: float = 3.0,
) -> None:
    """Every `interval` seconds, drain buffered honeypot hits and POST them to
    /endpoint/honeypot. A hit on a decoy port is a high-confidence intrusion
    signal, so these are sent promptly and independently of the telemetry loop."""
    endpoint_id = identity["endpoint_id"]
    hostname = identity.get("hostname", "")
    log.info("Honeypot loop started — decoy ports: %s", honeypot.active_ports or "(none bound)")
    while True:
        try:
            hits = honeypot.drain_hits()
            if hits:
                payload = {
                    "endpoint_id": endpoint_id,
                    "hostname": hostname,
                    "hits": hits,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                ok, _ = await post_json("/endpoint/honeypot", payload, backend_url, api_key)
                if ok:
                    log.warning("Reported %d honeypot hit(s) to backend.", len(hits))
                else:
                    # Re-buffer nothing (avoid unbounded growth); a repeat probe
                    # will regenerate a hit. Just log the miss.
                    log.warning("Honeypot report failed — %d hit(s) dropped this cycle.", len(hits))
        except asyncio.CancelledError:
            log.info("Honeypot loop cancelled.")
            raise
        except Exception as exc:
            log.error("Unexpected honeypot loop error: %s", exc, exc_info=True)
        await asyncio.sleep(interval)


# ---------------------------------------------------------------------------
# Banner + startup
# ---------------------------------------------------------------------------


def _print_banner(identity: dict, args: argparse.Namespace) -> None:
    sep = "=" * 64
    log.info(sep)
    log.info("  Cyber Sentinel XDR — Endpoint Agent v1.0.0")
    log.info(sep)
    log.info("  Endpoint ID : %s", identity["endpoint_id"])
    log.info("  Hostname    : %s", identity["hostname"])
    log.info("  IP Address  : %s", identity["ip_address"])
    # Truncate very long OS version strings
    os_ver = identity.get("os_version", "")[:50]
    log.info("  OS          : %s %s", identity["os"], os_ver)
    log.info("  User        : %s", identity["username"])
    log.info("  Backend URL : %s", args.backend_url)
    log.info(
        "  API Key     : %s",
        args.api_key[:8] + "***" if len(args.api_key) > 8 else "***",
    )
    log.info("  Telemetry   : every %.1f s", args.collect_interval)
    log.info("  Commands    : every %.1f s", args.command_interval)
    log.info("  Health port : %d  (GET http://localhost:%d/health)", args.health_port, args.health_port)
    log.info("  Simulate    : %s", args.simulate)
    if args.simulate:
        log.warning("  *** SIMULATE MODE — no OS actions will be executed ***")
    if args.api_key == _DEFAULTS["api_key"]:
        log.warning(
            "  *** Default API key in use — set XDR_API_KEY for production ***"
        )
    log.info(sep)


# ---------------------------------------------------------------------------
# Disconnect notification
# ---------------------------------------------------------------------------


async def _notify_disconnect(identity: dict, backend_url: str, api_key: str) -> None:
    """Send a best-effort disconnect notification so the backend marks this endpoint offline immediately."""
    import httpx
    endpoint_id = identity.get("endpoint_id", "")
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            await client.post(
                f"{backend_url}/endpoint/disconnect",
                json={"endpoint_id": endpoint_id},
                headers={"X-API-Key": api_key},
            )
        log.info("Disconnect notification sent to backend.")
    except Exception as exc:
        log.debug("Disconnect notification failed (backend may already be down): %s", exc)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


async def _main() -> None:
    global _health_identity

    args = _parse_args()
    identity = get_identity()

    # Expose identity to the health handler before starting the server thread
    _health_identity = identity

    _print_banner(identity, args)

    # Warn early if not elevated — netsh/net SOAR actions require Administrator.
    check_and_warn_admin()

    # Start the health HTTP server in a daemon thread so it does not block the
    # asyncio event loop.  The daemon flag ensures it exits when the process
    # exits — no explicit shutdown needed.
    health_thread = Thread(
        target=_start_health_server,
        args=(args.health_port,),
        daemon=True,
        name="xdr-health-server",
    )
    health_thread.start()

    # Start the deception honeypot (shares the agent lifecycle — no separate
    # control). Binds only free decoy ports; disabled via XDR_HONEYPOT_ENABLED.
    honeypot = Honeypot()
    try:
        await honeypot.start()
    except Exception as exc:
        log.error("Honeypot failed to start (continuing without it): %s", exc)

    # Run all loops concurrently; if any raises an uncaught exception the whole
    # gather propagates it so the process exits with a non-zero code
    # (Task Scheduler / NSSM will restart it).
    try:
        await asyncio.gather(
            _telemetry_loop(identity, args.backend_url, args.api_key, args.collect_interval),
            _command_loop(identity, args.backend_url, args.api_key, args.command_interval, args.simulate),
            _honeypot_loop(honeypot, identity, args.backend_url, args.api_key),
        )
    except asyncio.CancelledError:
        pass
    finally:
        await honeypot.stop()
        await _notify_disconnect(identity, args.backend_url, args.api_key)


if __name__ == "__main__":
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        log.info("Agent stopped by user (KeyboardInterrupt).")
        sys.exit(0)
