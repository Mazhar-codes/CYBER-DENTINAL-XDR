"""
simulate_attack.py
------------------
Simulates an insider-threat attack pattern that triggers user behavior anomaly
detection in xdr_runtime.py and shows ANOMALY on the SOC dashboard.

Attack pattern:
  - 600 file creates  (Sysmon event 11) on D:/User Anomaly/
  - 200 file reads    (Sysmon event 15) across 50 unique directories on D:/
  - 8 after-hours events
  - 3 failed logon attempts (event 4625)

All events are injected as Winlogbeat-format ndjson records into the LOG_DIR
watched by xdr_runtime.py. The inference cycle (every 60s) will pick them up
and emit ANOMALY + score=1.0 to the dashboard via Socket.IO.
"""

import json
import os
import pathlib
import random
import time
from datetime import datetime, timezone, timedelta

# ── Config ──────────────────────────────────────────────────────────────────
HERE = pathlib.Path(__file__).parent
LOG_DIR = pathlib.Path(
    os.getenv(
        "USER_LOG_DIR",
        str(HERE / "User Behavior" / "final_model_backend_only" / "logs"),
    )
)
TARGET_USER = os.getenv("USERNAME", "DELL")
HOST_NAME   = os.environ.get("COMPUTERNAME", "DELL-PC")
OUT_FILE    = LOG_DIR / "sim_attack.ndjson"

ATTACK_ROOT   = "D:\\User Anomaly"
N_FILE_CREATE = 600   # triggers fast-path (>= 300)
N_FILE_READ   = 200
N_UNIQUE_DIRS = 55    # triggers dir-scan fast-path (>= 50)
N_FAILED_LOGON = 3


def _ts(offset_minutes: int = 0) -> str:
    t = datetime.now(timezone.utc) - timedelta(minutes=offset_minutes)
    return t.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def make_event(event_id: str, provider: str, target_filename: str = "",
               message: str = "", offset_min: int = 0, user: str = TARGET_USER) -> dict:
    return {
        "@timestamp": _ts(offset_min),
        "winlog": {
            "event_id": event_id,
            "provider_name": provider,
            "event_data": {"TargetFilename": target_filename},
            "user_data": {"TargetUserName": user},
        },
        "user":    {"name": user},
        "host":    {"name": HOST_NAME},
        "message": message or target_filename,
    }


def build_events() -> list:
    events = []
    now_hour = datetime.now().hour
    after_hours = now_hour < 9 or now_hour >= 18

    # 1. File creates (Sysmon 11) — 600 files in D:\User Anomaly\
    print(f"  Generating {N_FILE_CREATE} FileCreate events (Sysmon 11) ...")
    for i in range(1, N_FILE_CREATE + 1):
        path = f"{ATTACK_ROOT}\\file{i:04d}.txt"
        events.append(make_event(
            event_id="11",
            provider="Microsoft-Windows-Sysmon",
            target_filename=path,
            message=f"File created: {path}",
            offset_min=random.randint(0, 15),
        ))

    # 2. File reads (Sysmon 15) across N_UNIQUE_DIRS directories
    print(f"  Generating {N_FILE_READ} FileRead events across {N_UNIQUE_DIRS} dirs ...")
    dirs = [f"D:\\SimDirs\\dir{d:03d}" for d in range(1, N_UNIQUE_DIRS + 1)]
    for i in range(N_FILE_READ):
        d = dirs[i % len(dirs)]
        path = f"{d}\\scan_{i:04d}.dat"
        events.append(make_event(
            event_id="15",
            provider="Microsoft-Windows-Sysmon",
            target_filename=path,
            message=f"File stream: {path}",
            offset_min=random.randint(0, 20),
        ))

    # 3. Failed logon events (4625)
    print(f"  Generating {N_FAILED_LOGON} failed logon events (4625) ...")
    for _ in range(N_FAILED_LOGON):
        events.append({
            "@timestamp": _ts(random.randint(0, 10)),
            "winlog": {
                "event_id": "4625",
                "provider_name": "Microsoft-Windows-Security-Auditing",
                "event_data": {},
                "user_data": {"TargetUserName": TARGET_USER},
            },
            "user":    {"name": TARGET_USER},
            "host":    {"name": HOST_NAME},
            "message": f"An account failed to log on. User: {TARGET_USER}",
        })

    # 4. After-hours logon (4624)
    print("  Generating after-hours logon event ...")
    events.append({
        "@timestamp": _ts(5),
        "winlog": {
            "event_id": "4624",
            "provider_name": "Microsoft-Windows-Security-Auditing",
            "event_data": {},
            "user_data": {"TargetUserName": TARGET_USER},
        },
        "user":    {"name": TARGET_USER},
        "host":    {"name": HOST_NAME},
        "message": f"An account was successfully logged on. User: {TARGET_USER}",
    })

    random.shuffle(events)
    return events


def main():
    print("=" * 60)
    print("  CYBER SENTINEL XDR — Attack Simulation")
    print("=" * 60)
    print(f"  Target user : {TARGET_USER}")
    print(f"  Attack root : {ATTACK_ROOT}")
    print(f"  Log dir     : {LOG_DIR}")
    print()

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    events = build_events()
    print(f"\n  Total events injected: {len(events)}")

    with OUT_FILE.open("w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")

    print(f"  Written to  : {OUT_FILE}")
    print()
    print("  Attack injected. Waiting for inference cycle (up to 60s) ...")
    print("  Watch the dashboard — ANOMALY alert should appear shortly.")
    print()

    # Countdown so user can watch
    for i in range(60, 0, -5):
        print(f"  Inference fires in ~{i}s ...", end="\r", flush=True)
        time.sleep(5)

    print("\n  Done. Check the dashboard User Behavior panel now.")
    print("=" * 60)


if __name__ == "__main__":
    main()
