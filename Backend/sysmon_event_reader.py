"""
sysmon_event_reader.py — Cyber Sentinel XDR
Reads Sysmon events from Windows Event Log (Microsoft-Windows-Sysmon/Operational)
and writes them as NDJSON to C:/winlogbeat/logs/sysmon_events.json.

Replaces Winlogbeat — uses Get-WinEvent via PowerShell subprocess.

Usage:
    python sysmon_event_reader.py              # runs forever, tails new events
    python sysmon_event_reader.py --flush      # dump all existing events and exit
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

OUTPUT_PATH = r"C:\winlogbeat\logs\sysmon_events.json"
CHANNEL     = "Microsoft-Windows-Sysmon/Operational"
POLL_SECS   = 3.0
BATCH_SIZE  = 500

SYSMON_EVENT_IDS = {1, 2, 3, 5, 6, 7, 8, 10, 11, 12, 13, 15, 17, 22, 23, 25, 26}
SYSMON_NAMES = {
    1:  "ProcessCreate",        2:  "FileCreationTimeChanged",
    3:  "NetworkConnect",       5:  "ProcessTerminate",
    6:  "DriverLoad",           7:  "ImageLoad",
    8:  "CreateRemoteThread",   10: "ProcessAccess",
    11: "FileCreate",           12: "RegistryObjectAddedOrDeleted",
    13: "RegistryValueSet",     15: "FileCreateStreamHash",
    17: "PipeCreated",          22: "DNSQuery",
    23: "FileDelete",           25: "ProcessTampering",
    26: "FileDeleteDetected",
}


def _query_events(max_events: int, start_time: str | None = None) -> list[dict]:
    """Fetch Sysmon events via a PowerShell temp script."""
    if start_time:
        time_filter = f"StartTime = [datetime]::Parse('{start_time}');"
    else:
        time_filter = ""

    ps_script = f"""
$ErrorActionPreference = 'SilentlyContinue'
$filter = @{{ LogName = 'Microsoft-Windows-Sysmon/Operational'; {time_filter} }}
try {{
    $events = Get-WinEvent -FilterHashtable $filter -MaxEvents {max_events} -ErrorAction Stop
}} catch {{
    Write-Output '[]'
    exit 0
}}
if (-not $events) {{ Write-Output '[]'; exit 0 }}
$out = [System.Collections.Generic.List[object]]::new()
foreach ($e in $events) {{
    try {{
        $xml = [xml]$e.ToXml()
        $data = @{{}}
        foreach ($d in $xml.Event.EventData.Data) {{
            if ($d.Name) {{ $data[$d.Name] = $d.'#text' }}
        }}
        $out.Add(@{{
            event_id   = [int]$e.Id
            time       = $e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
            event_data = $data
        }})
    }} catch {{ }}
}}
$out | ConvertTo-Json -Depth 5 -Compress
"""

    # Write to a temp .ps1 file — avoids quoting issues with -Command
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".ps1", delete=False, encoding="utf-8"
        ) as f:
            f.write(ps_script)
            tmp = f.name

        result = subprocess.run(
            ["powershell.exe", "-NonInteractive", "-NoProfile",
             "-ExecutionPolicy", "Bypass", "-File", tmp],
            capture_output=True, text=True, timeout=30,
        )
        raw = result.stdout.strip()
        if not raw or raw == "[]":
            return []
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            parsed = [parsed]
        return parsed or []
    except Exception as exc:
        log.debug(f"PS query error: {exc}")
        return []
    finally:
        if tmp and os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except Exception:
                pass


def _to_ndjson(evt: dict) -> dict | None:
    eid = int(evt.get("event_id", 0))
    if eid not in SYSMON_EVENT_IDS:
        return None
    return {
        "@timestamp": evt.get("time", datetime.now(timezone.utc).isoformat()),
        "winlog": {
            "event_id":   eid,
            "channel":    CHANNEL,
            "event_data": evt.get("event_data", {}),
        },
        "event": {
            "code":     str(eid),
            "action":   SYSMON_NAMES.get(eid, "Unknown"),
            "provider": "Microsoft-Windows-Sysmon",
        },
    }


def tail_sysmon(output_path: str, flush_only: bool = False):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    bookmark_path = output_path + ".bookmark"
    last_ts: str | None = None

    if os.path.exists(bookmark_path):
        try:
            with open(bookmark_path) as f:
                val = f.read().strip()
            # Only use bookmark if it looks like an ISO timestamp
            if val and val.startswith("20"):
                last_ts = val
                log.info(f"Resuming from {last_ts}")
        except Exception:
            pass

    log.info(f"Sysmon event reader started")
    log.info(f"Output : {output_path}")
    log.info(f"Mode   : {'flush-then-exit' if flush_only else 'tail (Ctrl+C to stop)'}")

    written_total = 0

    with open(output_path, "a", encoding="utf-8") as fh:
        while True:
            events = _query_events(BATCH_SIZE, start_time=last_ts)

            # Sort oldest-first
            events.sort(key=lambda e: e.get("time", ""))

            new_ts = last_ts
            batch_written = 0
            for evt in events:
                evt_ts = evt.get("time", "")
                if last_ts and evt_ts <= last_ts:
                    continue
                record = _to_ndjson(evt)
                if record is None:
                    continue
                fh.write(json.dumps(record) + "\n")
                batch_written += 1
                if evt_ts > (new_ts or ""):
                    new_ts = evt_ts

            if batch_written:
                fh.flush()
                written_total += batch_written
                log.info(f"Wrote {batch_written} events (total: {written_total})")

            if new_ts and new_ts != last_ts:
                last_ts = new_ts
                try:
                    with open(bookmark_path, "w") as bf:
                        bf.write(last_ts)
                except Exception:
                    pass

            if flush_only:
                log.info(f"Flush complete — {written_total} total events -> {output_path}")
                break

            time.sleep(POLL_SECS)


def main():
    ap = argparse.ArgumentParser(description="Sysmon -> NDJSON (Winlogbeat replacement)")
    ap.add_argument("--output",  default=OUTPUT_PATH)
    ap.add_argument("--flush",   action="store_true", help="Dump existing events then exit")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    tail_sysmon(args.output, flush_only=args.flush)


if __name__ == "__main__":
    main()
