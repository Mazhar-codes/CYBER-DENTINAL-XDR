"""
Winlogbeat lifecycle manager — Cyber Sentinel XDR.

Starts and stops Winlogbeat automatically alongside the XDR monitoring loop.
When the user clicks "Start Monitoring" in the SOC dashboard, Winlogbeat is
started if it is installed but not already running.  When monitoring stops
(or the server shuts down), Winlogbeat is stopped.

Gracefully skips all operations if Winlogbeat is not installed — the system
falls back to the PowerShell Get-WinEvent path for user behavior scoring.

NOTE: This module provides auto-start/stop tied to the monitoring lifecycle.
      For first-time installation and service registration, run the separate
      winlogbeat_setup.ps1 script (only needed once).
      NOTE: Winlogbeat is also auto-started when you click 'Start Monitoring'
      in the SOC dashboard. winlogbeat_setup.ps1 is only needed for first-time
      configuration.
"""
from __future__ import annotations

import asyncio
import logging
import os
import platform
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Install-path probe order — checked in sequence; first match wins.
# ---------------------------------------------------------------------------
_BASE_DIR = Path(__file__).parent  # Backend/

# Bundled copy shipped with Cyber Sentinel XDR (unpacked alongside User Behavior/)
_BUNDLED_WB = _BASE_DIR.parent / "User Behavior" / "winlogbeat-9.3.3-windows-x86_64" / "winlogbeat.exe"

_WINLOGBEAT_PATHS: list[str] = [
    str(_BUNDLED_WB),
    r"C:\Program Files\Elastic\Beats\winlogbeat\winlogbeat.exe",
    r"C:\winlogbeat\winlogbeat.exe",
    r"C:\tools\winlogbeat\winlogbeat.exe",
    r"C:\Program Files\Winlogbeat\winlogbeat.exe",
    r"D:\winlogbeat\winlogbeat.exe",
]

# XDR-optimised config written to Backend/ so it never conflicts with the
# bundled winlogbeat.yml in the User Behavior directory.
_XDR_CONFIG_PATH: Path = _BASE_DIR / "winlogbeat_xdr.yml"
_WINLOGBEAT_LOG_DIR: str = r"C:\XDR_Logs"

# Windows service name (used when Winlogbeat was installed as a service)
_SERVICE_NAME: str = "winlogbeat"

# PID file — records the PID of a winlogbeat subprocess started by this module
_PID_FILE: Path = _BASE_DIR / ".winlogbeat_pid"


# ---------------------------------------------------------------------------
# Public helpers (also imported by backend.py for the /health endpoint)
# ---------------------------------------------------------------------------

def find_winlogbeat() -> Path | None:
    """Return the path to winlogbeat.exe if it is installed, else None.

    Checks the bundled copy first, then common system-wide install paths,
    then falls back to PATH lookup.
    """
    for p in _WINLOGBEAT_PATHS:
        path = Path(p)
        if path.exists():
            return path
    found = shutil.which("winlogbeat")
    return Path(found) if found else None


def winlogbeat_is_running() -> bool:
    """Return True if a winlogbeat process is currently alive.

    Checks two sources:
    1. The PID file written by this module (subprocess started directly).
    2. A Windows service query (``sc query winlogbeat``).

    Falls back gracefully if psutil or sc are unavailable.
    """
    # --- Check stored PID (subprocess path) ---
    pid = _load_pid()
    if pid is not None:
        try:
            import psutil as _psutil  # noqa: PLC0415
            proc = _psutil.Process(pid)
            if proc.is_running() and "winlogbeat" in (proc.name() or "").lower():
                return True
        except Exception:
            pass  # process gone or psutil unavailable

    # --- Check Windows service status ---
    if platform.system() == "Windows":
        try:
            result = subprocess.run(
                ["sc", "query", _SERVICE_NAME],
                capture_output=True,
                timeout=5,
            )
            if result.returncode == 0 and b"RUNNING" in result.stdout:
                return True
        except Exception:
            pass

    # --- psutil scan fallback (catches winlogbeat started by other means) ---
    try:
        import psutil as _psutil  # noqa: PLC0415
        for proc in _psutil.process_iter(["name"]):
            try:
                if "winlogbeat" in (proc.info.get("name") or "").lower():
                    return True
            except (_psutil.NoSuchProcess, _psutil.AccessDenied):
                continue
    except Exception:
        pass

    return False


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _write_xdr_config(log_dir: str = _WINLOGBEAT_LOG_DIR) -> Path:
    """Write a minimal XDR-optimised winlogbeat.yml next to this module.

    The file captures only the Windows Security events needed by the user
    behavior model and outputs NDJSON to log_dir.
    """
    os.makedirs(log_dir, exist_ok=True)
    # Use forward slashes inside the YAML string — avoids YAML escape issues
    log_dir_yaml = log_dir.replace("\\", "/")
    config = (
        "# Cyber Sentinel XDR — auto-generated Winlogbeat config\n"
        "# Generated by winlogbeat_manager.py — do not edit manually.\n"
        "# Re-generated each time 'Start Monitoring' is clicked.\n"
        "\n"
        "winlogbeat.event_logs:\n"
        "  - name: Security\n"
        "    event_id: 4624, 4625, 4634, 4647, 4648, 4663, 4670, 4672,"
        " 4688, 4697, 4698, 4699, 4700, 4719, 4720, 4726, 4732, 4776\n"
        "    ignore_older: 4h\n"
        "\n"
        "output.file:\n"
        f'  path: "{log_dir_yaml}"\n'
        "  filename: xdr_events.ndjson\n"
        "  rotate_every_kb: 102400\n"
        "  number_of_files: 3\n"
        "\n"
        "logging.level: warning\n"
        "logging.to_files: true\n"
        "logging.files:\n"
        f'  path: "{log_dir_yaml}"\n'
        "  name: winlogbeat.log\n"
        "  keepfiles: 3\n"
    )
    _XDR_CONFIG_PATH.write_text(config, encoding="utf-8")
    logger.debug("Winlogbeat XDR config written to %s", _XDR_CONFIG_PATH)
    return _XDR_CONFIG_PATH


def _pid_file() -> Path:
    return _PID_FILE


def _store_pid(pid: int) -> None:
    try:
        _pid_file().write_text(str(pid), encoding="utf-8")
    except Exception as exc:
        logger.debug("Could not write winlogbeat PID file: %s", exc)


def _load_pid() -> int | None:
    try:
        text = _pid_file().read_text(encoding="utf-8").strip()
        return int(text) if text else None
    except Exception:
        return None


def _clear_pid() -> None:
    try:
        _pid_file().unlink(missing_ok=True)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Public async API
# ---------------------------------------------------------------------------

async def start_winlogbeat() -> bool:
    """Start Winlogbeat for XDR data collection.

    Strategy (tried in order):
    1. If Winlogbeat is already running — return True immediately (idempotent).
    2. If the Windows service exists — start it via ``net start winlogbeat``.
    3. Otherwise — launch winlogbeat.exe directly as a subprocess.

    Returns:
        True  — Winlogbeat is now running (or was already running).
        False — Winlogbeat is not installed; system will use Get-WinEvent.

    Never raises — all exceptions are caught and logged at WARNING level.
    """
    if platform.system() != "Windows":
        logger.debug("Winlogbeat auto-start skipped — not running on Windows")
        return False

    wb_exe = find_winlogbeat()
    if not wb_exe:
        logger.info(
            "Winlogbeat not found in any known install path — "
            "user behavior will use Get-WinEvent (no action needed)"
        )
        return False

    # Idempotency: skip if already alive
    if winlogbeat_is_running():
        logger.info("Winlogbeat already running — skipping start")
        return True

    logger.info("Winlogbeat found at %s — attempting to start for XDR monitoring", wb_exe)

    # --- Attempt 1: Windows service (preferred — survives machine restarts) ---
    try:
        svc_result = await asyncio.to_thread(
            subprocess.run,
            ["sc", "query", _SERVICE_NAME],
            capture_output=True,
            timeout=5,
        )
        if svc_result.returncode == 0:
            # Service exists — start it
            start_proc = await asyncio.create_subprocess_exec(
                "net", "start", _SERVICE_NAME,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(start_proc.wait(), timeout=15)
            if winlogbeat_is_running():
                logger.info("Winlogbeat Windows service started")
                return True
            logger.warning(
                "Winlogbeat service start returned but process not detected — "
                "falling back to subprocess mode"
            )
    except asyncio.TimeoutError:
        logger.warning("Winlogbeat service start timed out — falling back to subprocess")
    except Exception as exc:
        logger.debug("Winlogbeat service start attempt failed: %s — trying subprocess", exc)

    # --- Attempt 2: Direct subprocess ---
    try:
        config_path = await asyncio.to_thread(_write_xdr_config)
        # Log stderr to a file in the same directory as the exe
        log_file = wb_exe.parent / "logs" / "winlogbeat_stderr.log"
        await asyncio.to_thread(log_file.parent.mkdir, parents=True, exist_ok=True)

        stderr_fh = open(str(log_file), "a", encoding="utf-8")  # noqa: WPS515
        proc = await asyncio.create_subprocess_exec(
            str(wb_exe),
            "-c", str(config_path),
            "-e",          # log to stderr (captured to file above)
            stdout=asyncio.subprocess.DEVNULL,
            stderr=stderr_fh,
            cwd=str(wb_exe.parent),
        )
        _store_pid(proc.pid)
        logger.info(
            "Winlogbeat started as subprocess (PID %d, config: %s)",
            proc.pid,
            config_path,
        )
        return True
    except Exception as exc:
        logger.warning("Winlogbeat subprocess start failed: %s", exc)
        return False


async def stop_winlogbeat() -> None:
    """Stop Winlogbeat if it was started by XDR monitoring.

    Strategy (tried in order):
    1. Stop the Windows service if it exists.
    2. Terminate the subprocess tracked by the PID file.

    Never raises — all exceptions are caught and logged at WARNING level.
    """
    if platform.system() != "Windows":
        return

    wb_exe = find_winlogbeat()
    if not wb_exe:
        return  # not installed — nothing to stop

    # --- Attempt 1: Windows service ---
    try:
        svc_result = await asyncio.to_thread(
            subprocess.run,
            ["sc", "query", _SERVICE_NAME],
            capture_output=True,
            timeout=5,
        )
        if svc_result.returncode == 0 and b"RUNNING" in svc_result.stdout:
            stop_proc = await asyncio.create_subprocess_exec(
                "net", "stop", _SERVICE_NAME,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                await asyncio.wait_for(stop_proc.wait(), timeout=15)
                logger.info("Winlogbeat Windows service stopped")
            except asyncio.TimeoutError:
                logger.warning("Winlogbeat service stop timed out")
            return
    except Exception as exc:
        logger.debug("Winlogbeat service stop attempt: %s", exc)

    # --- Attempt 2: PID file (subprocess path) ---
    pid = _load_pid()
    if pid is not None:
        try:
            import psutil as _psutil  # noqa: PLC0415
            _psutil.Process(pid).terminate()
            logger.info("Winlogbeat subprocess terminated (PID %d)", pid)
        except Exception as exc:
            logger.debug("Could not terminate winlogbeat PID %d: %s", pid, exc)
        finally:
            _clear_pid()
