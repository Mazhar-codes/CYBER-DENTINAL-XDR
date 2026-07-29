import json, pathlib, random, os
from datetime import datetime, timezone, timedelta

LOG_DIR = pathlib.Path("C:/XDR_Logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)
OUT = LOG_DIR / "sim_attack.ndjson"

USER = os.environ.get("USERNAME", "DELL")
HOST = os.environ.get("COMPUTERNAME", "DELL-PC")

def ts(offset=0):
    t = datetime.now(timezone.utc) - timedelta(minutes=offset)
    return t.strftime("%Y-%m-%dT%H:%M:%S.000Z")

def file_event(eid, fname, offset=0):
    return {
        "@timestamp": ts(offset),
        "winlog": {
            "event_id": str(eid),
            "provider_name": "Microsoft-Windows-Sysmon",
            "event_data": {"TargetFilename": fname},
            "user_data": {"TargetUserName": USER},
        },
        "user": {"name": USER},
        "host": {"name": HOST},
        "message": fname,
    }

def logon_event(eid, offset=0):
    return {
        "@timestamp": ts(offset),
        "winlog": {
            "event_id": str(eid),
            "provider_name": "Microsoft-Windows-Security-Auditing",
            "event_data": {},
            "user_data": {"TargetUserName": USER},
        },
        "user": {"name": USER},
        "host": {"name": HOST},
        "message": f"Logon event {eid} for {USER}",
    }

events = []

# 600 FileCreate events (Sysmon 11) — D:\User Anomaly\
for i in range(1, 601):
    path = "D:/User Anomaly/file{:04d}.txt".format(i)
    events.append(file_event(11, path, random.randint(0, 15)))

# 200 FileRead events (Sysmon 15) across 55 unique directories
dirs = ["D:/SimDirs/dir{:03d}".format(d) for d in range(1, 56)]
for i in range(200):
    path = "{}/scan_{:04d}.dat".format(dirs[i % 55], i)
    events.append(file_event(15, path, random.randint(0, 20)))

# 3 failed logon attempts
for _ in range(3):
    events.append(logon_event(4625, random.randint(0, 10)))

# 1 successful logon
events.append(logon_event(4624, 5))

random.shuffle(events)

with OUT.open("w", encoding="utf-8") as f:
    for e in events:
        f.write(json.dumps(e) + "\n")

print("Attack injected: {} events -> {}".format(len(events), OUT))
print("USER={}, file_ops={}".format(USER, 800))
print("Fast-path fires at >=300. Score will be 1.0 (ANOMALY).")
print("Next inference cycle (within 60s) will emit to dashboard.")
