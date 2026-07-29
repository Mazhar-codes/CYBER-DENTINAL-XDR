"""
Endpoint Telemetry & SOAR Agent
Runs on each monitored Windows host. Collects system telemetry, ships it to
the XDR backend via POST /ingest, polls GET /commands to receive SOAR actions,
executes them, and acknowledges each command via POST /commands/<id>/ack.

Run standalone:
    python endpoint_agent.py --backend http://192.168.1.10:8000 --api-key <key>

Environment variable overrides:
    BACKEND_URL   — backend base URL  (default: http://localhost:8000)
    XDR_API_KEY   — API key header    (default: changeme-dev-key)
    COMPUTERNAME  — host identity     (default: socket.gethostname())
"""
import argparse
import json
import logging
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import psutil
import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# IP validation helper (module-level so it is importable without an instance)
# ---------------------------------------------------------------------------
_IP_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")


def _is_valid_ip(ip: str) -> bool:
    """Return True only for well-formed IPv4 addresses (no CIDR, no hostnames)."""
    m = _IP_RE.match(ip.strip())
    if not m:
        return False
    return all(0 <= int(m.group(i)) <= 255 for i in range(1, 5))


# ---------------------------------------------------------------------------
# EndpointAgent
# ---------------------------------------------------------------------------

class EndpointAgent:
    """
    Main agent that runs continuously on an endpoint host.

    Cycle (every `poll_interval` seconds):
      1. Collect system telemetry (CPU, memory, disk, network, processes, connections)
      2. POST telemetry to /ingest
      3. GET /commands?host=<hostname>
      4. For every pending command document, execute each action in cmd["actions"]
      5. ACK the command via POST /commands/<id>/ack
    """

    def __init__(
        self,
        host: str = None,
        backend_url: str = None,
        api_key: str = None,
        poll_interval: int = 10,
        # Legacy kwarg aliases kept for backwards-compat with argparse callers
        hostname: str = None,
    ):
        # Resolve host — accept both kwarg spellings
        self.host = (
            host
            or hostname
            or os.environ.get("COMPUTERNAME")
            or socket.gethostname()
        )
        self.backend_url = (
            (backend_url or os.environ.get("BACKEND_URL", "http://localhost:8000")).rstrip("/")
        )
        self.api_key = api_key if api_key is not None else os.environ.get(
            "XDR_API_KEY", "changeme-dev-key"
        )
        self.poll_interval = poll_interval
        self._running = False

        self._session = requests.Session()
        self._session.headers.update({
            "X-API-Key": self.api_key,
            "Content-Type": "application/json",
        })

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def run(self):
        """Blocking run loop — call this to start the agent."""
        self._running = True
        logger.info(
            "Endpoint agent started  host=%s  backend=%s  interval=%ds",
            self.host, self.backend_url, self.poll_interval,
        )
        while self._running:
            try:
                # --- telemetry ---
                telemetry = self.collect_telemetry()
                self._send_telemetry(telemetry)

                # --- command polling ---
                commands = self.poll_commands()
                for cmd in commands:
                    self._process_command(cmd)

            except KeyboardInterrupt:
                self.stop()
                break
            except Exception as exc:
                logger.error("Agent loop error: %s", exc, exc_info=True)

            time.sleep(self.poll_interval)

    def stop(self):
        self._running = False
        logger.info("Endpoint agent stopping.")

    # ------------------------------------------------------------------
    # Telemetry collection — flat summary dict (for /ingest)
    # ------------------------------------------------------------------

    def collect_telemetry(self) -> dict:
        """
        Return a telemetry payload with two layers:
          - top-level flat counters used by collect_telemetry() callers
          - nested "data" sub-tree matching the full XDR ingest schema
        """
        now = datetime.now(timezone.utc).isoformat()
        net = psutil.net_io_counters()
        vm = psutil.virtual_memory()

        return {
            # Flat counters (spec-required surface)
            "cpu_percent":    psutil.cpu_percent(),
            "mem_percent":    vm.percent,
            "disk_percent":   psutil.disk_usage("C:\\").percent,
            "num_processes":  len(psutil.pids()),
            "net_bytes_sent": net.bytes_sent,
            "net_bytes_recv": net.bytes_recv,
            # Ingest envelope
            "host":      self.host,
            "timestamp": now,
            "data": {
                "cpu":         self._collect_cpu(),
                "memory":      self._collect_memory(),
                "disk":        self._collect_disk(),
                "network":     self._collect_network(),
                "processes":   self._collect_processes(top_n=20),
                "connections": self._collect_connections(),
            },
        }

    def _collect_cpu(self) -> dict:
        freq = psutil.cpu_freq()
        return {
            "percent":        psutil.cpu_percent(interval=1),
            "count_logical":  psutil.cpu_count(logical=True),
            "count_physical": psutil.cpu_count(logical=False),
            "freq_mhz":       freq.current if freq else None,
        }

    def _collect_memory(self) -> dict:
        vm = psutil.virtual_memory()
        return {
            "total_mb":     round(vm.total     / 1_048_576),
            "used_mb":      round(vm.used      / 1_048_576),
            "available_mb": round(vm.available / 1_048_576),
            "percent":      vm.percent,
        }

    def _collect_disk(self) -> list:
        results = []
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
                results.append({
                    "device":     part.device,
                    "mountpoint": part.mountpoint,
                    "total_gb":   round(usage.total / 1_073_741_824, 2),
                    "used_gb":    round(usage.used  / 1_073_741_824, 2),
                    "percent":    usage.percent,
                })
            except PermissionError:
                pass
        return results

    def _collect_network(self) -> dict:
        c = psutil.net_io_counters()
        return {
            "bytes_sent":   c.bytes_sent,
            "bytes_recv":   c.bytes_recv,
            "packets_sent": c.packets_sent,
            "packets_recv": c.packets_recv,
            "errin":        c.errin,
            "errout":       c.errout,
        }

    def _collect_processes(self, top_n: int = 20) -> list:
        procs = []
        for proc in psutil.process_iter(
            ["pid", "name", "cpu_percent", "memory_percent", "status"]
        ):
            try:
                procs.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return sorted(procs, key=lambda p: p.get("cpu_percent") or 0, reverse=True)[:top_n]

    def _collect_connections(self) -> list:
        conns = []
        try:
            for c in psutil.net_connections(kind="inet"):
                try:
                    conns.append({
                        "laddr":  f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                        "raddr":  f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                        "status": c.status,
                        "pid":    c.pid,
                    })
                except Exception:
                    pass
        except Exception as exc:
            logger.warning("net_connections() error: %s", exc)
        return conns[:50]

    # ------------------------------------------------------------------
    # Backend communication
    # ------------------------------------------------------------------

    def _send_telemetry(self, telemetry: dict) -> bool:
        try:
            resp = self._session.post(
                f"{self.backend_url}/ingest",
                data=json.dumps(telemetry, default=str),
                timeout=10,
            )
            resp.raise_for_status()
            logger.debug("Telemetry sent OK (%d bytes)", len(resp.content))
            return True
        except requests.RequestException as exc:
            logger.error("Telemetry send failed: %s", exc)
            return False

    def poll_commands(self) -> list:
        """
        GET /commands?host=<self.host>
        Returns the list of pending command documents, or [] on error.
        On HTTP 403 the agent sleeps 60 s to avoid hammering with bad credentials.
        """
        try:
            resp = self._session.get(
                f"{self.backend_url}/commands",
                params={"host": self.host},
                timeout=10,
            )
            if resp.status_code == 403:
                logger.error(
                    "Invalid API key — received 403 from /commands. Sleeping 60 s."
                )
                time.sleep(60)
                return []
            resp.raise_for_status()
            return resp.json().get("commands", [])
        except requests.RequestException as exc:
            logger.error("Command poll failed: %s", exc)
            return []

    def _ack_command(self, command_id: Optional[str], status: str, result: str):
        """POST /commands/<id>/ack — always called after every command, success or fail."""
        if not command_id:
            logger.warning("_ack_command called with no command_id — skipping")
            return
        try:
            resp = self._session.post(
                f"{self.backend_url}/commands/{command_id}/ack",
                data=json.dumps({"status": status, "result": result}),
                timeout=5,
            )
            if resp.status_code == 403:
                logger.error("ACK rejected with 403 for command %s", command_id)
            else:
                resp.raise_for_status()
                logger.debug("ACK'd command %s → %s", command_id, status)
        except requests.RequestException as exc:
            logger.error("Command ack failed for %s: %s", command_id, exc)

    # ------------------------------------------------------------------
    # Command dispatch — handles both "action" (str) and "actions" (list)
    # ------------------------------------------------------------------

    def _process_command(self, command: dict):
        """
        Handle one command document from the backend.

        The backend schema uses "actions": [str, ...]  (list).
        A legacy "action": str  field is also accepted for compatibility.
        All actions are executed in order; failures do not abort subsequent actions.
        The command is ACK'd once after all actions finish.
        """
        command_id = command.get("_id")
        params = command.get("params", {})

        # Normalise to list
        raw = command.get("actions") or command.get("action") or []
        actions: list = raw if isinstance(raw, list) else [raw]

        if not actions:
            logger.warning("Command %s has no actions — ACK-ing as failed", command_id)
            self._ack_command(command_id, "failed", "no actions specified")
            return

        results = []
        overall_status = "done"

        for action in actions:
            logger.info("Executing action '%s' params=%s (cmd=%s)", action, params, command_id)
            try:
                result = self.execute_action(action, params)
                results.append(result)
                if result.get("status") not in ("executed", "done"):
                    overall_status = "failed"
            except Exception as exc:
                msg = f"Action '{action}' raised exception: {exc}"
                logger.error(msg, exc_info=True)
                results.append({"action": action, "status": "failed", "result": msg})
                overall_status = "failed"

        # Single ACK covering all actions
        combined_result = json.dumps(results, default=str)
        self._ack_command(command_id, overall_status, combined_result)

    # Public alias used by legacy callers
    def execute_command(self, command: dict):
        return self._process_command(command)

    # ------------------------------------------------------------------
    # SOAR action dispatcher
    # ------------------------------------------------------------------

    def execute_action(self, action: str, params: dict = None) -> dict:
        """
        Dispatch to an action handler and return a result dict.
        Always returns a dict with at least {"action": ..., "status": ...}.
        """
        if params is None:
            params = {}

        dispatch = {
            "isolate_host":       self._action_isolate_host,
            "unblock_host":       self._action_unblock_host,
            "block_ip":           self._action_block_ip,
            "unblock_ip":         self._action_unblock_ip,
            "kill_process":       self._action_kill_process,
            "quarantine_file":    self._action_quarantine_file,
            "collect_memory_dump": self._action_collect_memory_dump,
        }

        handler = dispatch.get(action)
        if handler is None:
            logger.warning("Unknown action received: '%s'", action)
            return {"action": action, "status": "unknown_action"}

        try:
            result_text = handler(**params)
            return {"action": action, "status": "executed", "result": result_text}
        except Exception as exc:
            msg = f"{exc}"
            logger.error("Action '%s' failed: %s", action, msg, exc_info=True)
            return {"action": action, "status": "failed", "result": msg}

    # ------------------------------------------------------------------
    # SOAR action implementations (Windows — shell=False throughout)
    # ------------------------------------------------------------------

    def _action_isolate_host(self, interface: str = "Ethernet") -> str:
        """Disable a network interface to isolate the host."""
        try:
            result = subprocess.run(
                ["netsh", "interface", "set", "interface", interface, "disable"],
                capture_output=True, text=True, timeout=15,
            )
            output = result.stdout.strip() or result.stderr.strip() or "interface disabled"
            logger.info("isolate_host: %s", output)
            return output
        except subprocess.TimeoutExpired:
            return "isolate_host timed out"

    def _action_unblock_host(self, interface: str = "Ethernet") -> str:
        """Re-enable a previously isolated network interface."""
        try:
            result = subprocess.run(
                ["netsh", "interface", "set", "interface", interface, "enable"],
                capture_output=True, text=True, timeout=15,
            )
            output = result.stdout.strip() or result.stderr.strip() or "interface enabled"
            logger.info("unblock_host: %s", output)
            return output
        except subprocess.TimeoutExpired:
            return "unblock_host timed out"

    def _action_block_ip(self, ip: str = "") -> str:
        """
        Add inbound + outbound Windows Firewall rules to block an IP.
        Rule names are XDR_BLOCK_<ip> for easy identification and cleanup.
        """
        if not _is_valid_ip(ip):
            raise ValueError(f"Invalid IP address: {ip!r}")
        rule_name = f"XDR_BLOCK_{ip}"
        try:
            for direction in ("in", "out"):
                subprocess.run(
                    [
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={rule_name}",
                        f"dir={direction}",
                        "action=block",
                        f"remoteip={ip}",
                    ],
                    capture_output=True, text=True, timeout=15,
                )
            logger.info("block_ip: blocked %s (rules: %s)", ip, rule_name)
            return f"blocked {ip}"
        except subprocess.TimeoutExpired:
            return f"block_ip {ip} timed out"

    def _action_unblock_ip(self, ip: str = "") -> str:
        """Remove the XDR firewall block rules for an IP."""
        if not _is_valid_ip(ip):
            raise ValueError(f"Invalid IP address: {ip!r}")
        rule_name = f"XDR_BLOCK_{ip}"
        try:
            subprocess.run(
                [
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={rule_name}",
                ],
                capture_output=True, text=True, timeout=15,
            )
            logger.info("unblock_ip: removed rule %s", rule_name)
            return f"unblocked {ip}"
        except subprocess.TimeoutExpired:
            return f"unblock_ip {ip} timed out"

    def _action_kill_process(self, pid=None, name: str = "") -> str:
        """
        Terminate a process by PID or image name.
        pid is cast to int() before use — never interpolated directly.
        """
        try:
            if pid is not None:
                safe_pid = int(pid)   # security: always cast, never interpolate raw
                result = subprocess.run(
                    ["taskkill", "/PID", str(safe_pid), "/F"],
                    capture_output=True, text=True, timeout=15,
                )
            elif name:
                result = subprocess.run(
                    ["taskkill", "/IM", name, "/F"],
                    capture_output=True, text=True, timeout=15,
                )
            else:
                return "kill_process: neither pid nor name supplied"
            output = result.stdout.strip() or result.stderr.strip() or "process killed"
            logger.info("kill_process: %s", output)
            return output
        except subprocess.TimeoutExpired:
            return "kill_process timed out"

    def _action_quarantine_file(self, file_path: str = "") -> str:
        """
        Move a file to C:\\XDR_Quarantine to prevent execution.
        The quarantine directory is created if it does not exist.
        """
        if not file_path:
            return "quarantine_file: no file_path supplied"
        src = Path(file_path)
        quarantine_dir = Path(r"C:\XDR_Quarantine")
        try:
            quarantine_dir.mkdir(parents=True, exist_ok=True)
            dest = quarantine_dir / src.name
            shutil.move(str(src), str(dest))
            logger.info("quarantine_file: moved %s → %s", src, dest)
            return f"quarantined {src} → {dest}"
        except FileNotFoundError:
            return f"quarantine_file: source not found: {file_path}"
        except Exception as exc:
            return f"quarantine_file error: {exc}"

    def _action_collect_memory_dump(
        self, pid: int = None, output_path: str = r"C:\XDR_Dumps"
    ) -> str:
        """Create a full mini-dump of a process using Sysinternals ProcDump."""
        if pid is None:
            return "collect_memory_dump: no pid supplied"
        procdump_bin = shutil.which("procdump") or shutil.which("procdump64")
        if not procdump_bin:
            return "procdump not found; install Sysinternals ProcDump and add it to PATH"
        try:
            result = subprocess.run(
                [procdump_bin, "-ma", str(int(pid)), output_path],
                capture_output=True, text=True, timeout=60,
            )
            return result.stdout.strip() or result.stderr.strip() or "dump complete"
        except subprocess.TimeoutExpired:
            return "collect_memory_dump timed out"


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stdout,
    )
    parser = argparse.ArgumentParser(description="Cyber Sentinel XDR — Endpoint Agent")
    parser.add_argument(
        "--backend",
        default=os.environ.get("BACKEND_URL", "http://localhost:8000"),
        help="Backend base URL (env: BACKEND_URL)",
    )
    parser.add_argument(
        "--api-key",
        default=os.environ.get("XDR_API_KEY", "changeme-dev-key"),
        help="XDR API key (env: XDR_API_KEY)",
    )
    parser.add_argument(
        "--host",
        default=None,
        help="Override hostname (default: COMPUTERNAME env var or socket.gethostname())",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=10,
        help="Poll interval in seconds (default: 10)",
    )
    args = parser.parse_args()

    agent = EndpointAgent(
        host=args.host,
        backend_url=args.backend,
        api_key=args.api_key,
        poll_interval=args.interval,
    )
    print(f"Endpoint Agent starting on host: {agent.host}")
    print(f"Polling {agent.backend_url} every {agent.poll_interval}s")
    agent.run()


if __name__ == "__main__":
    _main()
