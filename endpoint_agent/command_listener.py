"""
command_listener.py — SOAR command poll-and-execute layer for Cyber Sentinel XDR.

Polls GET /endpoint/commands/{endpoint_id} for pending response commands,
dispatches each to the appropriate action handler, and ACKs the result via
POST /endpoint/command/ack.

Security guarantees (mirrors Backend/agents/endpoint_agent.py):
  - All subprocess calls use list form (shell=False) — never shell=True.
  - IP addresses are validated with a strict regex before being passed to netsh.
  - PIDs are always cast to int() before use — never interpolated as strings.
  - Firewall rules are named XDR_BLOCK_<ip> for easy identification and cleanup.
  - Simulate mode logs every command but never touches the OS.
"""

import ctypes
import json
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable

import httpx
import psutil

try:
    from . import identity as _identity_mod          # package mode: -m endpoint_agent.agent
except ImportError:                                   # script mode: python agent.py
    import identity as _identity_mod

logger = logging.getLogger(__name__)

# Strict IPv4 validation — no shell injection possible through a validated address.
_IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

# Files written by the agent itself — persisted in the frozen-aware data dir so
# quarantine/ and the isolation flag survive across restarts of a packaged .exe
# (see identity.data_dir()).
_AGENT_DIR = _identity_mod.data_dir()
QUARANTINE_DIR = _AGENT_DIR / "quarantine"
_ISOLATION_FLAG = _AGENT_DIR / "isolation_flag.txt"

# Timeout for every subprocess call (seconds)
_SUBPROCESS_TIMEOUT = 15

# ---------------------------------------------------------------------------
# Full paths to Windows system executables.
# Using full paths ensures commands succeed even when PATH is restricted
# (e.g., when the agent runs as a Windows Service or under a minimal account).
# ---------------------------------------------------------------------------
_NETSH  = r"C:\Windows\System32\netsh.exe"
_NET    = r"C:\Windows\System32\net.exe"
_SCHTASKS = r"C:\Windows\System32\schtasks.exe"
_SHUTDOWN = r"C:\Windows\System32\shutdown.exe"
_RUNDLL32 = r"C:\Windows\System32\rundll32.exe"
_POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

# Grace period (seconds) shown to the user before a power action takes effect.
_POWER_GRACE_SECONDS = 30

# Suppress console windows on all subprocess calls — required so that no
# UAC or CMD popups appear when the agent executes SOAR actions silently.
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)


def _is_admin() -> bool:
    """Return True when the current process has Administrator privileges."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def check_and_warn_admin() -> None:
    """
    Log a CRITICAL warning at agent startup if not running as Administrator.
    SOAR actions that call netsh or net.exe will fail silently without elevation.
    Call this once from the agent's main entry point.

    NSSM note: if the agent is installed as a Windows Service via NSSM, open
    the service properties (nssm edit CyberSentinelAgent), go to the Log On tab,
    and select "Local System account" — OR add the service account to the local
    Administrators group.  Verify the current service configuration with:
        sc qc CyberSentinelAgent
    """
    if platform.system() != "Windows":
        return
    if not _is_admin():
        logger.critical(
            "SOAR AGENT WARNING: Not running as Administrator. "
            "SOAR actions requiring elevation WILL FAIL: "
            "block_ip, unblock_ip, isolate_host, unisolate_host, lock_account, unlock_account. "
            "If running as NSSM service: ensure service Log On tab uses LocalSystem account "
            "or an account in the local Administrators group. "
            "Verify with: sc qc CyberSentinelAgent"
        )
    else:
        logger.info("SOAR AGENT: Running as Administrator — all SOAR actions available.")

# ---------------------------------------------------------------------------
# Centralized execution wrapper
# ---------------------------------------------------------------------------


def safe_execute_command(
    action_name: str,
    handler_fn: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    """
    Centralized execution wrapper for all SOAR action handlers.

    Guarantees:
    - Structured return dict always has 'success' and 'message' keys.
    - Execution duration measured in milliseconds and added to result.
    - ALL exceptions are caught and returned as a failure dict — never raises
      to the caller.
    - Start and end are logged at INFO level so operators have a full audit
      trail even when the action handler itself does not log.
    """
    start = time.monotonic()
    try:
        logger.info("[SOAR] Starting action=%r", action_name)
        result = handler_fn()
        duration_ms = int((time.monotonic() - start) * 1000)
        success = result.get("success", False)
        logger.info(
            "[SOAR] Completed action=%r success=%s duration=%dms message=%r",
            action_name, success, duration_ms,
            str(result.get("message", ""))[:120],
        )
        result["duration_ms"] = duration_ms
        return result
    except Exception as exc:
        duration_ms = int((time.monotonic() - start) * 1000)
        logger.error(
            "[SOAR] Action=%r raised exception after %dms: %s",
            action_name, duration_ms, exc, exc_info=True,
        )
        return {
            "success": False,
            "message": f"Unhandled exception in {action_name}: {exc}",
            "duration_ms": duration_ms,
        }


# ---------------------------------------------------------------------------
# Post-action verification helpers
# ---------------------------------------------------------------------------


def _verify_ip_blocked(ip: str) -> bool:
    """
    Verify that the XDR_BLOCK_<ip> firewall rule exists after block_ip runs.

    Queries netsh for the named rule; returns True only when netsh exits 0 AND
    the rule name appears in stdout (both directions share one name).
    Returns False on any exception so callers degrade gracefully.
    """
    if not _validate_ip(ip):
        return False
    rule_name = f"XDR_BLOCK_{ip}"
    try:
        result = subprocess.run(
            [_NETSH, "advfirewall", "firewall", "show", "rule", f"name={rule_name}"],
            capture_output=True,
            text=True,
            timeout=10,
            shell=False,
            creationflags=_NO_WINDOW,
        )
        return result.returncode == 0 and rule_name in result.stdout
    except Exception:
        return False


def _verify_host_isolated() -> bool:
    """
    Verify that the isolation flag was written and contains the expected sentinel.

    The flag is written by _action_isolate_host() before the netsh call so it
    survives even a failed NIC disable.  This function simply confirms the file
    exists and its content equals "ISOLATED".
    """
    try:
        return _ISOLATION_FLAG.exists() and _ISOLATION_FLAG.read_text(encoding="utf-8").strip() == "ISOLATED"
    except Exception:
        return False


def _verify_account_locked(username: str) -> bool:
    """
    Verify that a Windows local account is disabled after lock_account runs.

    Runs ``net user <username>`` and looks for the "Account active ... No" line
    that Windows prints when the account is disabled.  Returns False on any
    exception so callers degrade gracefully.
    """
    try:
        result = subprocess.run(
            [_NET, "user", username],
            capture_output=True,
            text=True,
            timeout=10,
            shell=False,
            creationflags=_NO_WINDOW,
        )
        if result.returncode != 0:
            return False
        # "Account active               No" indicates a disabled account.
        # Split on the label and inspect the remainder of that line only.
        if "Account active" not in result.stdout:
            return False
        after_label = result.stdout.split("Account active")[-1].split("\n")[0]
        return "No" in after_label
    except Exception:
        return False


def _verify_file_quarantined(basename: str) -> bool:
    """
    Verify that a file is present in the quarantine directory after quarantine_file runs.

    Uses the original filename (basename) because _action_quarantine_file
    preserves it when moving the file.
    """
    return (QUARANTINE_DIR / basename).exists()


# ---------------------------------------------------------------------------
# Filesystem scan constants
# ---------------------------------------------------------------------------

# Fixed root paths inspected by _action_scan_filesystem
WATCH_PATHS = [
    r"C:\Users",
    r"C:\Temp",
    r"C:\Windows\Temp",
    r"C:\ProgramData",
]

# Extensions considered suspicious when recently modified
SUSPICIOUS_EXTENSIONS = {".exe", ".dll", ".ps1", ".bat", ".vbs", ".scr"}

# Timeout for HTTP calls (seconds)
_HTTP_TIMEOUT = 10.0


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_network_interface() -> str:
    """
    Return the network interface name to use for host isolation/unisolation.

    Reads from the persisted endpoint_config.json (set at startup by identity.py).
    Falls back to psutil auto-detection, then to "Wi-Fi" if everything fails.
    """
    try:
        iface = _identity_mod.get_identity().get("network_interface", "")
        if iface:
            return iface
    except Exception as exc:
        logger.debug("Could not read network_interface from identity: %s", exc)
    # Identity not yet loaded or missing key — detect directly
    return _identity_mod.detect_network_interface()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def poll_commands(endpoint_id: str, backend_url: str, api_key: str) -> list[dict]:
    """
    Poll the backend for pending commands addressed to this endpoint.

    GET /endpoint/commands/{endpoint_id}

    Returns an empty list on any error so the caller loop continues safely.
    """
    url = f"{backend_url.rstrip('/')}/endpoint/commands/{endpoint_id}"
    headers = {"X-API-Key": api_key}
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            return data.get("commands", []) if isinstance(data, dict) else []
    except httpx.HTTPStatusError as exc:
        logger.warning(
            "Command poll HTTP %d: %s",
            exc.response.status_code,
            exc.response.text[:200],
        )
    except Exception as exc:
        logger.debug("Command poll error: %s", exc)
    return []


async def execute_command(cmd: dict[str, Any], simulate: bool = False) -> dict[str, Any]:
    """
    Dispatch a command document to the matching action handler.

    Supported actions
    -----------------
    kill_process        target = PID (str) or process name
    block_ip            target = IPv4 address
    unblock_ip          target = IPv4 address
    isolate_host        target = (ignored) — disables primary NIC via netsh
    unisolate_host      target = (ignored) — re-enables primary NIC via netsh
    quarantine_file          target = absolute file path
    restore_quarantine_file  target = original absolute path to restore to
    lock_account             target = Windows local username to disable
    scan_filesystem     target = (ignored) — scans WATCH_PATHS for recently
                        modified suspicious files (last 60 min)
    monitor_persistence target = (ignored) — checks HKCU Run keys, startup
                        folder, and scheduled tasks count

    Returns a result dict with at minimum:
        {"success": bool, "message": str}

    The "command_id" key from the incoming document is preserved so the
    caller can attach it to the ACK payload.
    """
    action = cmd.get("action", "")
    target = cmd.get("target", "")
    command_id = cmd.get("command_id", "")

    logger.info(
        "Executing command — action=%r target=%r command_id=%s simulate=%s",
        action, target, command_id, simulate,
    )

    # Advisory-only actions: no OS-level change is performed.
    # The server already filters these out before sending to the endpoint agent,
    # but if one arrives (e.g. via a direct API call) we acknowledge it gracefully.
    _advisory_actions = frozenset({
        "alert_admin", "update_software", "patch_openssl",
        "rotate_certificates", "check_exposed_secrets",
        "force_logout", "review_account", "review_logs",
        "invalidate_sessions", "log_event", "log_user_session",
        "restrict_access", "rate_limit_traffic",
    })
    if action in _advisory_actions:
        msg = f"Advisory action acknowledged: {action}"
        logger.info("[SOAR] %s", msg)
        return {
            "command_id": command_id,
            "action": action,
            "success": True,
            "message": msg,
        }

    # Dispatch table — keeps the match expression flat and extensible
    dispatch: dict[str, Any] = {
        "kill_process":        lambda: _action_kill_process(target, simulate),
        "block_ip":            lambda: _action_block_ip(target, simulate),
        "unblock_ip":          lambda: _action_unblock_ip(target, simulate),
        "isolate_host":        lambda: _action_isolate_host(simulate),
        "unisolate_host":      lambda: _action_unisolate_host(simulate),
        "quarantine_file":          lambda: _action_quarantine_file(target, simulate),
        "restore_quarantine_file": lambda: _action_restore_quarantine_file(target, simulate),
        "lock_account":             lambda: _action_lock_account(target, simulate),
        "unlock_account":      lambda: _action_unlock_account(target, simulate),
        "scan_filesystem":     lambda: _action_scan_filesystem(target, simulate),
        "monitor_persistence": lambda: _action_monitor_persistence(target, simulate),
        "shutdown_host":       lambda: _action_shutdown_host(simulate),
        "sleep_host":          lambda: _action_sleep_host(simulate),
    }

    handler = dispatch.get(action)
    if handler is None:
        msg = f"Unknown action: {action!r}"
        logger.warning(msg)
        return {"command_id": command_id, "success": False, "message": msg}

    # safe_execute_command() wraps the handler: measures duration, catches all
    # exceptions, and guarantees the result always has 'success' + 'message'.
    result = safe_execute_command(action, handler)
    result["command_id"] = command_id
    result["action"] = action
    return result


async def acknowledge_command(result: dict[str, Any], backend_url: str, api_key: str) -> None:
    """
    POST the action result back to the backend.

    POST /endpoint/command/ack

    Failures are logged but never propagated so the command loop keeps running.
    """
    url = f"{backend_url.rstrip('/')}/endpoint/command/ack"
    headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            response = await client.post(url, json=result, headers=headers)
            if response.status_code not in (200, 201, 202, 204):
                logger.warning(
                    "ACK returned HTTP %d: %s",
                    response.status_code,
                    response.text[:200],
                )
            else:
                logger.debug(
                    "ACK sent for command_id=%s", result.get("command_id", "?")
                )
    except Exception as exc:
        logger.warning("ACK POST failed: %s", exc)


# ---------------------------------------------------------------------------
# Action handlers (synchronous — called from async via lambda in dispatch)
# ---------------------------------------------------------------------------


def _action_kill_process(target: str, simulate: bool) -> dict[str, Any]:
    """
    Terminate a process by PID (digits only) or by name.

    PID is always cast to int() before use — never interpolated as a string
    into a command.
    """
    # Reject absurdly long strings before any processing — Windows process names
    # are capped at 260 chars by MAX_PATH; anything longer is almost certainly
    # garbage input or an injection attempt.
    if len(target) > 260:
        return {"success": False, "message": "Target too long (max 260 characters)"}

    if simulate:
        return {"success": True, "message": f"[SIM] Would kill process: {target!r}"}

    killed: list[str] = []
    errors: list[str] = []

    _TASKKILL_EXE = r"C:\Windows\System32\taskkill.exe"

    if target.isdigit():
        # Kill by PID — cast guarantees no injection
        pid = int(target)
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            killed.append(str(pid))
            logger.info("Terminated PID %d (%s)", pid, proc.name())
        except psutil.NoSuchProcess:
            return {"success": False, "message": f"No process with PID {pid}"}
        except psutil.AccessDenied:
            # Fallback: taskkill /F /PID
            logger.warning("kill_process psutil AccessDenied PID=%d, trying taskkill", pid)
            try:
                _tk = subprocess.run(
                    [_TASKKILL_EXE, "/F", "/PID", str(pid)],
                    capture_output=True, text=True, timeout=_SUBPROCESS_TIMEOUT,
                    shell=False, creationflags=_NO_WINDOW,
                )
                if _tk.returncode == 0:
                    killed.append(f"{pid} (via taskkill)")
                else:
                    return {"success": False, "message": f"Access denied + taskkill failed: {(_tk.stderr or _tk.stdout).strip()}"}
            except Exception as _tke:
                return {"success": False, "message": f"Access denied terminating PID {pid}; taskkill also failed: {_tke}"}
        except Exception as exc:
            return {"success": False, "message": str(exc)}
    else:
        # Kill by name — match case-insensitively
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                if (proc.info.get("name") or "").lower() == target.lower():
                    pid = int(proc.info["pid"])   # explicit int cast
                    proc.terminate()
                    killed.append(str(pid))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                errors.append(f"PID {proc.info.get('pid', '?')}")
            except Exception as exc:
                errors.append(str(exc))
        # If psutil couldn't kill any (all access denied), fall back to taskkill /F /IM
        if not killed and errors:
            logger.warning("kill_process psutil denied all matches for %r; trying taskkill /F /IM", target)
            try:
                _tk_im = subprocess.run(
                    [_TASKKILL_EXE, "/F", "/IM", target],
                    capture_output=True, text=True, timeout=_SUBPROCESS_TIMEOUT,
                    shell=False, creationflags=_NO_WINDOW,
                )
                if _tk_im.returncode == 0:
                    killed.append(f"{target} (via taskkill /IM)")
                    errors.clear()
                else:
                    errors.append(f"taskkill /IM: {(_tk_im.stderr or _tk_im.stdout).strip()}")
            except Exception as _tke:
                errors.append(f"taskkill /IM exception: {_tke}")

    if killed:
        return {"success": True, "message": f"Killed PIDs: {', '.join(killed)}"}
    suffix = f" (errors: {'; '.join(errors)})" if errors else ""
    return {"success": False, "message": f"No process found matching {target!r}{suffix}"}


def _validate_ip(ip: str) -> bool:
    """Return True if ip is a valid IPv4 address (strict regex)."""
    return bool(_IP_RE.match(ip.strip()))


def _action_block_ip(ip: str, simulate: bool) -> dict[str, Any]:
    """
    Add inbound + outbound firewall deny rules for the given IPv4 address.

    Rule names follow the XDR_BLOCK_<ip> convention for easy cleanup.
    IP is validated before any subprocess call — shell=False throughout.
    """
    if not _validate_ip(ip):
        return {"success": False, "message": f"Invalid IP address: {ip!r}"}

    if simulate:
        return {"success": True, "message": f"[SIM] Would block IP: {ip}"}

    rule_name = f"XDR_BLOCK_{ip}"
    errors: list[str] = []
    directions_added: list[str] = []

    for direction in ("in", "out"):
        cmd = [
            _NETSH, "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            f"dir={direction}",
            "action=block",
            f"remoteip={ip}",
            "protocol=any",
            "enable=yes",
        ]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=_SUBPROCESS_TIMEOUT,
                shell=False,                  # security requirement — never shell=True
                creationflags=_NO_WINDOW,     # suppress console popup
            )
            if result.returncode != 0:
                err = (result.stderr or result.stdout).strip()
                errors.append(f"{direction}: rc={result.returncode} {err}")
                logger.warning(
                    "netsh block_ip %s dir=%s failed rc=%d: %s",
                    ip, direction, result.returncode, err,
                )
            else:
                directions_added.append(direction)
                logger.debug("netsh block_ip %s dir=%s OK", ip, direction)
        except Exception as exc:
            errors.append(f"{direction}: {exc}")
            logger.error("netsh block_ip %s dir=%s exception: %s", ip, direction, exc)

    if errors:
        # Partial state: at least one direction was added but the other failed.
        # Roll back by deleting the named rule (removes both directions at once)
        # so the host is never left with an asymmetric block that provides false
        # security assurance.
        if directions_added:
            logger.warning(
                "block_ip %s partial failure — rolling back %d direction(s) added",
                ip, len(directions_added),
            )
            _action_unblock_ip(ip, simulate=False)
        # Fallback: try PowerShell New-NetFirewallRule
        logger.warning("block_ip netsh failed; trying PowerShell fallback for %s", ip)
        _PS_ERRORS: list[str] = []
        _PS_ADDED: list[str] = []
        for _ps_dir in ("Inbound", "Outbound"):
            _ps_rule = f"{rule_name}_{_ps_dir}"
            try:
                _ps_result = subprocess.run(
                    [
                        "powershell", "-NonInteractive", "-Command",
                        (
                            f"New-NetFirewallRule -DisplayName '{_ps_rule}' "
                            f"-Direction {_ps_dir} -Action Block "
                            f"-RemoteAddress {ip} -Protocol Any -Enabled True"
                        ),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=_SUBPROCESS_TIMEOUT,
                    shell=False,
                    creationflags=_NO_WINDOW,
                )
                if _ps_result.returncode == 0:
                    _PS_ADDED.append(_ps_dir)
                else:
                    _PS_ERRORS.append(f"{_ps_dir}: {(_ps_result.stderr or _ps_result.stdout).strip()}")
            except Exception as _pse:
                _PS_ERRORS.append(f"{_ps_dir}: {_pse}")
        if not _PS_ERRORS and len(_PS_ADDED) == 2:
            logger.info("block_ip %s via PowerShell fallback (both directions)", ip)
            return {"success": True, "message": f"Blocked IP: {ip} (in + out via PowerShell)", "verified": True}
        return {
            "success": False,
            "message": (
                f"Partial block failure (rolled back) — netsh: {'; '.join(errors)}"
                + (f"; PS: {'; '.join(_PS_ERRORS)}" if _PS_ERRORS else "")
            ),
            "verified": False,
        }

    # Both rules were accepted by netsh — confirm they actually exist in the
    # Windows firewall policy before declaring success.
    logger.info("Blocked IP %s (both directions)", ip)
    verified = _verify_ip_blocked(ip)
    if not verified:
        logger.warning(
            "[SOAR] block_ip verification FAILED for %s — rule may not be active", ip
        )
    return {
        "success": True,
        "message": f"Blocked IP: {ip} (in + out)",
        "verified": verified,
    }


def _action_unblock_ip(ip: str, simulate: bool) -> dict[str, Any]:
    """
    Delete the XDR_BLOCK_<ip> firewall rules created by block_ip.

    IP is validated before any subprocess call — shell=False throughout.
    """
    if not _validate_ip(ip):
        return {"success": False, "message": f"Invalid IP address: {ip!r}"}

    if simulate:
        return {"success": True, "message": f"[SIM] Would unblock IP: {ip}"}

    rule_name = f"XDR_BLOCK_{ip}"
    cmd = [
        _NETSH, "advfirewall", "firewall", "delete", "rule",
        f"name={rule_name}",
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_SUBPROCESS_TIMEOUT,
            shell=False,                  # security requirement
            creationflags=_NO_WINDOW,     # suppress console popup
        )
        if result.returncode == 0:
            logger.info("Unblocked IP %s", ip)
            return {"success": True, "message": f"Unblocked IP: {ip}"}
        out = (result.stderr or result.stdout).strip()
        logger.warning("netsh unblock_ip %s failed rc=%d: %s", ip, result.returncode, out)
        return {
            "success": False,
            "message": out or f"netsh exited {result.returncode}",
        }
    except Exception as exc:
        logger.error("netsh unblock_ip %s exception: %s", ip, exc)
        return {"success": False, "message": str(exc)}


def _action_isolate_host(simulate: bool) -> dict[str, Any]:
    """
    Disable the primary network interface to isolate this endpoint.

    The interface name is read from endpoint_config.json (set by identity.py
    at startup via detect_network_interface()).  This avoids hard-coding "Wi-Fi"
    which fails on hosts whose adapter is named "Ethernet", "Wi-Fi 2", etc.

    Behaviour guarantees:
      - isolation_flag.txt is ALWAYS written, even when the netsh command fails,
        so the agent and backend know isolation was instructed.
      - shell=False is used for the netsh call (security requirement).
      - Non-zero netsh exit is logged with stderr but does NOT suppress flag write.
    """
    # Resolve interface name from persisted identity — never hard-coded
    interface = _get_network_interface()

    # Write isolation flag — always, even in simulate mode or on netsh failure
    try:
        _ISOLATION_FLAG.write_text("ISOLATED", encoding="utf-8")
        logger.debug("Isolation flag written to %s", _ISOLATION_FLAG)
    except OSError as exc:
        logger.warning("Could not write isolation flag: %s", exc)

    if simulate:
        return {
            "success": True,
            "message": (
                f"[SIM] Host isolation requested — interface {interface!r} "
                "not disabled (simulate mode)"
            ),
        }

    system = platform.system()
    if system != "Windows":
        return {
            "success": False,
            "message": f"isolate_host not supported on {system} (Windows only)",
        }

    logger.warning("Isolating host: disabling interface %r", interface)
    cmd = [_NETSH, "interface", "set", "interface", interface, "disable"]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_SUBPROCESS_TIMEOUT,
            shell=False,                  # security requirement — never shell=True
            creationflags=_NO_WINDOW,     # suppress console popup
        )
        if result.returncode == 0:
            logger.warning("HOST ISOLATED — interface %r disabled", interface)
            # Confirm the isolation flag was written correctly.  The flag is
            # intentionally left in place even when netsh fails (written above)
            # so the agent and backend always know an isolation was instructed,
            # regardless of whether the NIC disable actually succeeded.
            verified = _verify_host_isolated()
            if not verified:
                logger.warning(
                    "[SOAR] isolate_host verification FAILED — flag file not found or corrupted"
                )
            return {
                "success": True,
                "message": f"Host isolated — interface {interface!r} disabled",
                "verified": verified,
            }
        out = (result.stderr or result.stdout).strip()
        # Flag is already written above — isolation is recorded even if NIC
        # disable failed.  This is intentional: we want the backend to know
        # isolation was attempted even when netsh returns a non-zero exit code
        # (e.g., the interface name is wrong, or a UAC prompt was suppressed).
        # Rollback is NOT performed here because the flag serves as a safety
        # marker — removing it would make the system believe the host is online.
        logger.error(
            "isolate_host netsh failed (rc=%d): %s — isolation flag still set",
            result.returncode, out,
        )
        return {
            "success": False,
            "message": (
                f"netsh exited {result.returncode}: {out or '(no output)'} "
                f"(isolation flag written, interface={interface!r})"
            ),
            "verified": _verify_host_isolated(),
        }
    except Exception as exc:
        logger.error("isolate_host exception: %s — isolation flag still set", exc)
        return {
            "success": False,
            "message": (
                f"{exc} (isolation flag written, interface={interface!r})"
            ),
            "verified": _verify_host_isolated(),
        }


def _action_unisolate_host(simulate: bool) -> dict[str, Any]:
    """
    Re-enable the primary network interface to lift a previous host isolation.

    The interface name is read from endpoint_config.json (same source as
    _action_isolate_host) so both operations always target the same adapter.

    Shell=False is used for the netsh call (security requirement).
    """
    # Resolve interface name from persisted identity
    interface = _get_network_interface()

    # Remove isolation flag so the agent loop knows it is no longer isolated
    try:
        if _ISOLATION_FLAG.exists():
            _ISOLATION_FLAG.unlink()
            logger.debug("Isolation flag removed from %s", _ISOLATION_FLAG)
    except OSError as exc:
        logger.warning("Could not remove isolation flag: %s", exc)

    if simulate:
        return {
            "success": True,
            "message": (
                f"[SIM] Host unisolation requested — interface {interface!r} "
                "not re-enabled (simulate mode)"
            ),
        }

    system = platform.system()
    if system != "Windows":
        return {
            "success": False,
            "message": f"unisolate_host not supported on {system} (Windows only)",
        }

    logger.info("Unisolating host: re-enabling interface %r", interface)
    cmd = [_NETSH, "interface", "set", "interface", interface, "enable"]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_SUBPROCESS_TIMEOUT,
            shell=False,                  # security requirement — never shell=True
            creationflags=_NO_WINDOW,     # suppress console popup
        )
        if result.returncode == 0:
            logger.info("HOST UNISOLATED — interface %r re-enabled", interface)
            return {
                "success": True,
                "message": f"Host unisolated — interface {interface!r} re-enabled",
            }
        out = (result.stderr or result.stdout).strip()
        logger.error(
            "unisolate_host netsh failed (rc=%d): %s",
            result.returncode, out,
        )
        return {
            "success": False,
            "message": out or f"netsh exited {result.returncode}",
        }
    except Exception as exc:
        logger.error("unisolate_host exception: %s", exc)
        return {"success": False, "message": str(exc)}


def _action_quarantine_file(path: str, simulate: bool) -> dict[str, Any]:
    """
    Move a suspicious file into the agent's quarantine/ subdirectory.

    The source path must exist and must be an absolute path.  The destination
    filename is the original basename; an existing file in quarantine/ of the
    same name is overwritten.
    """
    # Null bytes in a path string can be used to trick open() into truncating
    # the path at the NUL character, potentially bypassing path checks.
    if '\x00' in path:
        return {"success": False, "message": "Invalid path: contains null byte"}

    src = Path(path)

    if not src.is_absolute():
        return {"success": False, "message": f"Path must be absolute: {path!r}"}

    if not src.exists():
        return {"success": False, "message": f"File not found: {path!r}"}

    if simulate:
        return {"success": True, "message": f"[SIM] Would quarantine: {path!r}"}

    basename = src.name
    try:
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        dest = QUARANTINE_DIR / basename
        shutil.move(str(src), str(dest))
        logger.warning("Quarantined file: %s -> %s", src, dest)
        verified = _verify_file_quarantined(basename)
        if not verified:
            logger.warning(
                "[SOAR] quarantine_file verification FAILED — %s not found in quarantine dir",
                basename,
            )
        return {
            "success": True,
            "message": f"Quarantined to: {dest}",
            "verified": verified,
        }
    except Exception as exc:
        logger.error("quarantine_file error: %s", exc)
        return {"success": False, "message": str(exc)}


def _action_restore_quarantine_file(target: str, simulate: bool) -> dict[str, Any]:
    """
    Restore a previously quarantined file back to its original location.

    ``target`` is the original absolute path the file should be restored to.
    The quarantine source is derived as ``quarantine/<basename(target)>`` —
    the same naming convention used by ``_action_quarantine_file``.

    Behaviour:
      - Returns a clear error if the quarantine copy does not exist.
      - Creates any missing parent directories in the destination path.
      - Uses shutil.move so the file is removed from quarantine on success.
      - shell=False / no subprocess — pure Python file operation.
    """
    if not target or not target.strip():
        return {"success": False, "message": "Target (original file path) is required for restore_quarantine_file"}

    dest = Path(target.strip())

    if not dest.is_absolute():
        return {"success": False, "message": f"Target path must be absolute: {target!r}"}

    quarantine_file = QUARANTINE_DIR / dest.name

    if simulate:
        return {
            "success": True,
            "message": f"[SIM] Would restore {quarantine_file} -> {dest}",
        }

    if not quarantine_file.exists():
        return {
            "success": False,
            "message": (
                f"Quarantined file not found: {quarantine_file}. "
                f"(Expected basename: {dest.name!r})"
            ),
        }

    try:
        # Ensure destination parent directories exist
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(quarantine_file), str(dest))
        logger.info("Restored quarantined file: %s -> %s", quarantine_file, dest)
        return {"success": True, "message": f"File restored to: {dest}"}
    except Exception as exc:
        logger.error("restore_quarantine_file error: %s", exc)
        return {"success": False, "message": str(exc)}


def _action_lock_account(target: str, simulate: bool) -> dict[str, Any]:
    """
    Disable a Windows local user account so they cannot log in.

    Uses ``net user <username> /active:no`` — shell=False, no interpolation.
    The username is validated against a strict allow-list regex (alphanumeric,
    underscore, hyphen, dot, space; 1–20 chars) before being passed to net.exe,
    preventing any command-injection attempt.
    """
    if not target or not target.strip():
        return {"success": False, "message": "Target username is required for lock_account"}

    username = target.strip()

    if simulate:
        return {"success": True, "message": f"[SIM] Would lock account: {username!r}"}

    # Validate username — strict allowlist prevents command injection
    import re as _re
    if not _re.match(r'^[\w\-\. ]{1,20}$', username):
        return {"success": False, "message": f"Invalid username format: {username!r}"}

    system = platform.system()
    if system != "Windows":
        return {"success": False, "message": f"lock_account not supported on {system}"}

    cmd = [_NET, "user", username, "/active:no"]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_SUBPROCESS_TIMEOUT,
            shell=False,                  # security requirement — never shell=True
            creationflags=_NO_WINDOW,     # suppress console popup
        )
        if result.returncode == 0:
            logger.warning("Locked account: %r", username)
            verified = _verify_account_locked(username)
            if not verified:
                logger.warning(
                    "[SOAR] lock_account verification FAILED for %r — account may still be active",
                    username,
                )
            return {
                "success": True,
                "message": f"Account locked: {username}",
                "verified": verified,
            }
        out = (result.stderr or result.stdout).strip()
        logger.warning(
            "lock_account failed for %r rc=%d: %s", username, result.returncode, out
        )
        return {
            "success": False,
            "message": out or f"net user exited {result.returncode}",
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "message": "lock_account timed out"}
    except Exception as exc:
        return {"success": False, "message": str(exc)}


def _action_unlock_account(target: str, simulate: bool) -> dict[str, Any]:
    """
    Re-enable a Windows local user account that was previously disabled.

    Uses ``net user <username> /active:yes`` — shell=False, no interpolation.
    The username is validated against the same strict allow-list regex as
    lock_account (alphanumeric, underscore, hyphen, dot, space; 1–20 chars)
    before being passed to net.exe, preventing any command-injection attempt.
    """
    if not target or not target.strip():
        return {"success": False, "message": "Target username is required for unlock_account"}

    username = target.strip()

    if simulate:
        return {"success": True, "message": f"[SIM] Would unlock account: {username!r}"}

    # Validate username — strict allowlist prevents command injection
    import re as _re
    if not _re.match(r'^[\w\-\. ]{1,20}$', username):
        return {"success": False, "message": f"Invalid username format: {username!r}"}

    if sys.platform != "win32":
        return {"success": False, "message": "unlock_account requires Windows"}

    cmd = [_NET, "user", username, "/active:yes"]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_SUBPROCESS_TIMEOUT,
            shell=False,                  # security requirement — never shell=True
            creationflags=_NO_WINDOW,     # suppress console popup
        )
        if result.returncode == 0:
            logger.info("Unlocked account: %r", username)
            return {"success": True, "message": f"Account '{username}' unlocked (re-enabled)."}
        out = (result.stderr or result.stdout).strip()
        logger.warning(
            "unlock_account failed for %r rc=%d: %s", username, result.returncode, out
        )
        return {
            "success": False,
            "message": out or f"net user exited {result.returncode}",
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "message": "unlock_account timed out"}
    except Exception as exc:
        return {"success": False, "message": str(exc)}


def _action_scan_filesystem(target: str, simulate: bool) -> dict[str, Any]:
    """
    Walk WATCH_PATHS and collect executables/scripts modified in the last hour.

    ``target`` is accepted for API consistency but is intentionally ignored —
    the scan always covers the fixed WATCH_PATHS list.  Known noise directories
    (AppData, node_modules, .git, venv, __pycache__) are skipped to keep the
    walk fast.  Returns the top-10 most recently modified files plus the total
    count.
    """
    if simulate:
        return {"success": True, "message": "[SIM] Would scan filesystem for suspicious files"}

    cutoff = time.time() - 3600  # files modified in the last hour
    found: list[tuple[float, str]] = []

    for root_path in WATCH_PATHS:
        try:
            for dirpath, dirnames, filenames in os.walk(root_path):
                # Skip known-noisy subdirectories to bound scan time
                dirnames[:] = [
                    d for d in dirnames
                    if d not in {"AppData", "node_modules", ".git", "venv", "__pycache__"}
                ]
                for fname in filenames:
                    if Path(fname).suffix.lower() in SUSPICIOUS_EXTENSIONS:
                        try:
                            fpath = os.path.join(dirpath, fname)
                            mtime = os.path.getmtime(fpath)
                            if mtime >= cutoff:
                                found.append((mtime, fpath))
                        except Exception:
                            continue
        except Exception:
            continue

    found.sort(reverse=True)
    top10 = [fp for _, fp in found[:10]]
    msg = f"Found {len(found)} recently modified suspicious files; top: {top10}"
    logger.info("scan_filesystem: %d suspicious files found", len(found))
    return {"success": True, "message": msg, "count": len(found), "files": top10}


def _action_monitor_persistence(target: str, simulate: bool) -> dict[str, Any]:
    """
    Enumerate three common Windows persistence mechanisms and return findings.

    Checks performed (all read-only — no system changes):
      1. HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run registry key values
      2. Files in the per-user Startup folder
         (%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup)
      3. Total count of scheduled tasks via ``schtasks /query``

    ``target`` is accepted for API consistency but ignored.
    The ``message`` field contains a JSON-serialised findings dict so callers
    can parse it; the same keys are also promoted to the top-level result dict.
    shell=False is used for the schtasks call (security requirement).
    """
    if simulate:
        return {"success": True, "message": "[SIM] Would check persistence mechanisms"}

    findings: dict[str, Any] = {
        "registry_run_keys": [],
        "startup_files": [],
        "scheduled_tasks": 0,
    }

    # 1. Run registry keys — HKCU (always readable) + HKLM (requires elevation)
    try:
        import winreg
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        for hive, hive_name in [
            (winreg.HKEY_CURRENT_USER,  "HKCU"),
            (winreg.HKEY_LOCAL_MACHINE, "HKLM"),
        ]:
            try:
                with winreg.OpenKey(hive, key_path) as key:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            findings["registry_run_keys"].append(
                                f"{hive_name}\\Run: {name}={value}"
                            )
                            i += 1
                        except OSError:
                            break
            except PermissionError:
                # HKLM requires Administrator — degrade gracefully with a note
                findings["registry_run_keys"].append(
                    f"{hive_name}\\Run: Access denied (requires elevation)"
                )
            except OSError:
                pass  # key does not exist on this system
    except ImportError:
        findings["registry_run_keys"] = ["winreg not available (non-Windows)"]
    except Exception as exc:
        findings["registry_run_keys"].append(f"read error: {exc}")

    # 2. Startup folder contents
    try:
        startup = os.path.expandvars(
            r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
        )
        if os.path.isdir(startup):
            findings["startup_files"] = [
                f for f in os.listdir(startup)
                if not f.startswith("desktop.ini")
            ]
    except Exception as exc:
        findings["startup_files"] = [f"read error: {exc}"]

    # 3. Scheduled tasks count — shell=False required
    try:
        result = subprocess.run(
            [_SCHTASKS, "/query", "/fo", "CSV"],
            capture_output=True,
            text=True,
            timeout=_SUBPROCESS_TIMEOUT,
            shell=False,                  # security requirement — never shell=True
            creationflags=_NO_WINDOW,     # suppress console popup
        )
        if result.returncode == 0:
            lines = [
                line for line in result.stdout.splitlines()
                if line.strip() and not line.startswith('"TaskName"')
            ]
            findings["scheduled_tasks"] = len(lines)
    except Exception:
        findings["scheduled_tasks"] = -1

    logger.info(
        "monitor_persistence: %d run keys, %d startup files, %d tasks",
        len(findings["registry_run_keys"]),
        len(findings["startup_files"]),
        findings["scheduled_tasks"],
    )
    return {"success": True, "message": json.dumps(findings), **findings}


def _action_shutdown_host(simulate: bool) -> dict[str, Any]:
    """
    Schedule a full shutdown of this endpoint after a grace period.

    Uses ``shutdown /s /t <grace> /c "<message>"`` which shows the user Windows'
    own countdown warning dialog before powering off.  The action is reversible
    ONLY within the grace window via ``shutdown /a`` (abort) — once the machine
    powers off it can only be restarted by physically powering it back on.

    shutdown.exe returns immediately after scheduling (the OS handles the timer),
    so this handler does not block the agent's command loop.
    """
    grace = _POWER_GRACE_SECONDS
    warn_msg = (
        "Security Operations Center: this machine has been flagged and will "
        f"SHUT DOWN in {grace} seconds. Save your work now."
    )

    if simulate:
        return {"success": True, "message": f"[SIM] Would shut down host in {grace}s"}

    system = platform.system()
    if system != "Windows":
        return {"success": False, "message": f"shutdown_host not supported on {system} (Windows only)"}

    # /s = shutdown, /t = grace seconds, /c = message shown to the user, /f = force-close apps
    cmd = [_SHUTDOWN, "/s", "/t", str(grace), "/c", warn_msg, "/f"]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_SUBPROCESS_TIMEOUT,
            shell=False,                  # security requirement — never shell=True
            creationflags=_NO_WINDOW,     # suppress console popup
        )
        if result.returncode == 0:
            logger.warning("SHUTDOWN SCHEDULED — host powers off in %ds", grace)
            return {
                "success": True,
                "message": (
                    f"Shutdown scheduled — host powers off in {grace}s "
                    "(abortable on the host with 'shutdown /a')"
                ),
            }
        out = (result.stderr or result.stdout).strip()
        logger.error("shutdown_host failed rc=%d: %s", result.returncode, out)
        return {"success": False, "message": out or f"shutdown exited {result.returncode}"}
    except subprocess.TimeoutExpired:
        return {"success": False, "message": "shutdown_host timed out"}
    except Exception as exc:
        logger.error("shutdown_host exception: %s", exc)
        return {"success": False, "message": str(exc)}


def _action_sleep_host(simulate: bool) -> dict[str, Any]:
    """
    Put this endpoint to sleep after a grace period.

    Windows' shutdown.exe has no native sleep verb, so this handler:
      1. Best-effort notifies the interactive user with a msg popup.
      2. Launches a detached PowerShell that waits <grace> seconds and then calls
         SetSuspendState, so the agent's command loop is never blocked.

    Note: SetSuspendState(0,...) requests SLEEP, but Windows will HIBERNATE
    instead if hibernation is enabled on the host (run 'powercfg /hibernate off'
    to guarantee sleep).  Sleep is fully reversible — any key/power press wakes
    the machine and the agent resumes.
    """
    grace = _POWER_GRACE_SECONDS

    if simulate:
        return {"success": True, "message": f"[SIM] Would sleep host in {grace}s"}

    system = platform.system()
    if system != "Windows":
        return {"success": False, "message": f"sleep_host not supported on {system} (Windows only)"}

    # 1. Best-effort on-screen warning to every interactive session (msg.exe may be
    #    absent on Home editions — never let its failure abort the sleep).
    try:
        subprocess.run(
            [r"C:\Windows\System32\msg.exe", "*",
             f"Security Operations Center: this machine will SLEEP in {grace} seconds."],
            capture_output=True, text=True, timeout=10,
            shell=False, creationflags=_NO_WINDOW,
        )
    except Exception as _msg_exc:
        logger.debug("sleep_host user notification skipped: %s", _msg_exc)

    # 2. Detached delayed-sleep worker — Popen (fire-and-forget) so we return now.
    ps_command = (
        f"Start-Sleep -Seconds {grace}; "
        f"Start-Process -WindowStyle Hidden -FilePath '{_RUNDLL32}' "
        "-ArgumentList 'powrprof.dll,SetSuspendState 0,1,0'"
    )
    try:
        subprocess.Popen(
            [_POWERSHELL, "-NonInteractive", "-NoProfile",
             "-WindowStyle", "Hidden", "-Command", ps_command],
            shell=False,
            creationflags=_NO_WINDOW,
        )
        logger.warning("SLEEP SCHEDULED — host suspends in %ds", grace)
        return {
            "success": True,
            "message": f"Sleep scheduled — host suspends in {grace}s (any keypress wakes it)",
        }
    except Exception as exc:
        logger.error("sleep_host exception: %s", exc)
        return {"success": False, "message": str(exc)}
