"""
sysmon_winevent_reader.py — Cyber Sentinel XDR
===============================================
File-based Sysmon event reader that tails a Winlogbeat NDJSON output file.

The previous Windows Event Log API approach (win32evtlog, PowerShell subprocess)
has been abandoned entirely due to persistent winerror 6 failures on the
ETW-backed Sysmon channel.  This module now reads the same JSON file that
Winlogbeat produces — no Windows API calls, no subprocess, no pywin32.

Default source file:
    C:\\winlogbeat\\logs\\sysmon_events.json

Configure Winlogbeat to write Sysmon events there:
    output.file:
      path: C:\\winlogbeat\\logs
      filename: sysmon_events.json

Emitted event dict schema (FLAT — no nested winlog):
    {
        "event_id":  int,       # e.g. 1
        "timestamp": str,       # ISO-8601, e.g. "2024-01-01T12:00:00Z"
        "process":   str,       # process image path or name
        "file":      str,       # file path (EventID 11) or ""
        "dest_ip":   str,       # destination IP (EventID 3) or ""
        "dest_port": str,       # destination port as string or ""
        "pid":       str,       # process ID as string
        "cmdline":   str,       # command line or ""
    }

Supported EventIDs:
    1  ProcessCreate         3  NetworkConnect        7  ImageLoad
    8  CreateRemoteThread   10  ProcessAccess         11  FileCreate
   12  RegistryObjectAddedOrDeleted                   13  RegistryValueSet
   22  DNSQuery             25  ProcessTampering

Usage (standalone test):
    python sysmon_winevent_reader.py

Usage (from agent):
    from sysmon_winevent_reader import SysmonFileReader
    reader = SysmonFileReader()
    for event in reader.tail():   # blocks; yields flat dicts
        process(event)
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Generator

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# EventIDs we care about (as integers)
# ---------------------------------------------------------------------------

_INTERESTING_EVENT_IDS: frozenset[int] = frozenset({
    1, 3, 7, 8, 10, 11, 12, 13, 22, 25,
})

# ---------------------------------------------------------------------------
# SysmonFileReader
# ---------------------------------------------------------------------------

class SysmonFileReader:
    """
    Tail a Winlogbeat NDJSON output file and yield parsed Sysmon event dicts.

    Supports both ECS format (Winlogbeat 7+) and legacy format transparently.

    Parameters
    ----------
    log_path : str
        Path to the Winlogbeat NDJSON file.
        Default: C:\\winlogbeat\\logs\\sysmon_events.json
    poll_interval : float
        Seconds to sleep between readline() calls when no data is available.
        Default: 1.0
    """

    _DEFAULT_PATH = r"C:\winlogbeat\logs\sysmon_events.json"

    def __init__(
        self,
        log_path: str = _DEFAULT_PATH,
        poll_interval: float = 1.0,
    ) -> None:
        self.log_path = log_path
        self.poll_interval = poll_interval

    # ------------------------------------------------------------------
    # Internal: parse one JSON line into the flat output schema
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_line(raw: dict) -> dict | None:
        """
        Parse a single Winlogbeat JSON record into the flat event schema.

        Handles both ECS format (Winlogbeat 7+) and legacy format.
        Returns None if the event_id is not in the interesting set or if
        the line cannot be meaningfully parsed.
        """
        # ------------------------------------------------------------------
        # Determine event_id
        # ------------------------------------------------------------------
        event_id: int | None = None

        # ECS format: event.code
        ecs_event = raw.get("event", {})
        if isinstance(ecs_event, dict):
            code = ecs_event.get("code")
            if code is not None:
                try:
                    event_id = int(code)
                except (ValueError, TypeError):
                    pass

        # Legacy format: winlog.event_id
        if event_id is None:
            winlog = raw.get("winlog", {})
            if isinstance(winlog, dict):
                weid = winlog.get("event_id")
                if weid is not None:
                    try:
                        event_id = int(weid)
                    except (ValueError, TypeError):
                        pass

        if event_id is None or event_id not in _INTERESTING_EVENT_IDS:
            return None

        # ------------------------------------------------------------------
        # Timestamp
        # ------------------------------------------------------------------
        timestamp: str = raw.get("@timestamp", "")

        # ------------------------------------------------------------------
        # Field extraction — ECS format first, then legacy
        # ------------------------------------------------------------------

        # ECS format (Winlogbeat 7+)
        ecs_process = raw.get("process", {})
        ecs_file    = raw.get("file", {})
        ecs_network = raw.get("network", {})
        ecs_dest    = ecs_network.get("destination", {}) if isinstance(ecs_network, dict) else {}

        if isinstance(ecs_process, dict) and (
            ecs_process.get("name") or ecs_process.get("executable")
        ):
            # ECS path
            process  = ecs_process.get("executable") or ecs_process.get("name") or ""
            pid      = str(ecs_process.get("pid", ""))
            cmdline  = ecs_process.get("command_line") or ""
            file_val = ecs_file.get("path", "") if isinstance(ecs_file, dict) else ""
            dest_ip  = ecs_dest.get("ip", "") if isinstance(ecs_dest, dict) else ""
            dest_port = str(ecs_dest.get("port", "")) if isinstance(ecs_dest, dict) and ecs_dest.get("port") is not None else ""
        else:
            # Legacy format: winlog.event_data
            winlog    = raw.get("winlog", {})
            data      = winlog.get("event_data", {}) if isinstance(winlog, dict) else {}
            if not isinstance(data, dict):
                data = {}
            process   = data.get("Image", "")
            pid       = str(data.get("ProcessId", data.get("SourceProcessId", "")))
            cmdline   = data.get("CommandLine", "")
            file_val  = data.get("TargetFilename", "")
            dest_ip   = data.get("DestinationIp", "")
            dest_port = str(data.get("DestinationPort", "")) if data.get("DestinationPort") is not None else ""

        return {
            "event_id":  event_id,
            "timestamp": timestamp,
            "process":   process   or "",
            "file":      file_val  or "",
            "dest_ip":   dest_ip   or "",
            "dest_port": dest_port or "",
            "pid":       pid       or "",
            "cmdline":   cmdline   or "",
        }

    # ------------------------------------------------------------------
    # Public: tail() generator
    # ------------------------------------------------------------------

    def tail(self) -> Generator[dict, None, None]:
        """
        Infinite generator that tails the Winlogbeat NDJSON file and yields
        flat Sysmon event dicts for every EventID in the interesting set.

        Behaviour:
        - Opens the file once and seeks to EOF (tail mode — no historical replay).
        - Reads new lines as they arrive; sleeps poll_interval when no data.
        - If the file does not exist, prints a warning every 5 seconds and retries.
        - Skips blank lines and invalid JSON silently.
        - Never raises; runs until the process is killed or the caller breaks.
        """
        _warned_missing = False
        _last_warn_t = 0.0

        while True:
            path = Path(self.log_path)
            if not path.exists():
                now = time.monotonic()
                if now - _last_warn_t >= 5.0:
                    print(
                        f"[SysmonFileReader] WARNING: log file not found: {self.log_path} "
                        f"— ensure Winlogbeat is running and writing to that path. "
                        f"Retrying every 5s..."
                    )
                    _last_warn_t = now
                time.sleep(5.0)
                continue

            _warned_missing = False
            logger.debug(f"SysmonFileReader: opening {self.log_path}")

            try:
                with open(self.log_path, "r", encoding="utf-8", errors="ignore") as fh:
                    # Seek to end — tail mode only, no historical replay
                    fh.seek(0, 2)

                    while True:
                        line = fh.readline()

                        if not line:
                            # No new data — poll
                            time.sleep(self.poll_interval)
                            continue

                        line = line.strip()
                        if not line:
                            continue

                        # Parse JSON — skip invalid lines silently
                        try:
                            raw = json.loads(line)
                        except json.JSONDecodeError:
                            continue

                        if not isinstance(raw, dict):
                            continue

                        event = self._parse_line(raw)
                        if event is None:
                            continue

                        logger.debug("[SYSMON JSON] EventID=%s", event["event_id"])
                        yield event

            except OSError as exc:
                logger.warning(
                    f"SysmonFileReader: file read error ({exc}) — reopening in 5s"
                )
                time.sleep(5.0)


# ---------------------------------------------------------------------------
# Legacy compatibility exports
# ---------------------------------------------------------------------------

_WIN32_AVAILABLE = False   # legacy compat — always False now
SysmonWinEventReader = SysmonFileReader  # backwards-compat alias


# ---------------------------------------------------------------------------
# Standalone test — run as: python sysmon_winevent_reader.py
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stdout,
    )

    print("SysmonFileReader — tailing Winlogbeat NDJSON output")
    print(f"Source: {SysmonFileReader._DEFAULT_PATH}")
    print("Press Ctrl-C to stop.\n")

    reader = SysmonFileReader()
    count = 0
    try:
        for ev in reader.tail():
            print(
                f"  EventID={ev['event_id']:>2}  "
                f"pid={ev['pid']:>6}  "
                f"process={ev['process']}  "
                f"dest_ip={ev['dest_ip']}:{ev['dest_port']}  "
                f"file={ev['file']}"
            )
            count += 1
    except KeyboardInterrupt:
        print(f"\nStopped after {count} events.")
