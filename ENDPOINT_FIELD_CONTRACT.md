# Endpoint Field Contract — Cyber Sentinel XDR
> Last updated: 2026-05-04 (finalized — Suricata, Sysmon, Winlogbeat, EMBER)
> This document is the single source of truth for every field the endpoint agent
> must send, the exact format and data type each field must be in, and which
> backend model or pipeline consumes it.
> All seven telemetry sections are sent together in one HTTP POST every 5 seconds.

---

## 1. HTTP Transport

| Property | Value |
|---|---|
| Method | `POST` |
| URL | `http://<backend-host>:8000/endpoint/ingest` |
| Header | `X-API-Key: <your-key>` |
| Content-Type | `application/json` |
| Interval | every **5 seconds** (`XDR_COLLECT_INTERVAL` env var overrides) |
| Max payload size | ~1 MB per request (Suricata + Winlogbeat events are batched, see limits below) |

The response is always `{"status": "ok", "endpoint_id": "..."}`.
Real output is delivered via **Socket.IO** events to the SOC dashboard.

---

## 2. Top-Level Payload Structure

```json
{
  "endpoint":          { ... },
  "timestamp":         "2026-05-04T10:23:45.123456+00:00",
  "network":           { ... },
  "system":            { ... },
  "user":              { ... },
  "malware":           { ... },
  "suricata":          { ... },
  "sysmon_events":     { ... },
  "winlogbeat_events": { ... }
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `endpoint` | object | **YES** | Identity block — never changes except `agent_version` |
| `timestamp` | ISO 8601 string | No | Auto-filled by backend (`datetime.utcnow()`) if omitted |
| `network` | object | No | psutil connection snapshot — empty `{}` is safe |
| `system` | object | No | psutil resource metrics — empty `{}` is safe |
| `user` | object | No | psutil session snapshot — empty `{}` is safe |
| `malware` | object | No | Local process heuristic scan — empty `{}` is safe |
| `suricata` | object | **YES (when Suricata is installed)** | Recent Suricata events from local `eve.json` |
| `sysmon_events` | object | **YES (when Sysmon + Winlogbeat are installed)** | Recent Sysmon behavioral events for SysmonBehaviorAgent |
| `winlogbeat_events` | object | **YES (when Winlogbeat is installed)** | Recent Windows security/logon events for the OC-SVM user model |

The backend `EndpointTelemetry` Pydantic model currently only parses `network`, `system`, `user`, `malware`.
The new `suricata`, `sysmon_events`, `winlogbeat_events` blocks require the Pydantic model to be extended
(or accepted as passthrough `dict` fields — either approach works).

---

## 3. `endpoint` — Identity Block

Generated once on first run, persisted in `endpoint_config.json`. Sent on every request.

```json
{
  "endpoint_id":    "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "hostname":       "DESKTOP-BTH57BG",
  "ip_address":     "192.168.1.42",
  "os":             "Windows",
  "os_version":     "10.0.26200",
  "username":       "anna",
  "agent_version":  "1.0.0"
}
```

| Field | Type | Required | Description | Used by |
|---|---|---|---|---|
| `endpoint_id` | UUID v4 string | **YES** | Stable unique ID — never changes per host | All layers; MongoDB registry key |
| `hostname` | string | **YES** | `socket.gethostname()` | All layers; display; Sysmon event enrichment |
| `ip_address` | string (IPv4) | **YES** | Primary NIC IP (`socket.gethostbyname(hostname)`) | Registry; NetworkDetection; display |
| `os` | string | **YES** | `platform.system()` → `"Windows"` | Registry; SOAR command selection |
| `os_version` | string | No | `platform.version()` | Registry; display |
| `username` | string | **YES** | `os.getlogin()` with env-var fallback | UserBehavior; display; `endpoint_update` event |
| `agent_version` | string | No | Hardcoded `"1.0.0"` | Registry |

---

## 4. `network` — psutil Network Telemetry

**Consumed by:** `NetworkDetectionAgent.detect_from_endpoint_network()` → Gate 1 IsolationForest + Gate 2 RandomForest → `network_score`  
**Displayed in:** Network flows table (attack-classified connections), EndpointDetailView connections stat card

```json
{
  "connections": [
    {
      "laddr":  "192.168.1.42:52341",
      "raddr":  "8.8.8.8:443",
      "status": "ESTABLISHED",
      "pid":    1234
    }
  ],
  "bytes_sent":      15728640,
  "bytes_recv":      31457280,
  "packets_sent":    102400,
  "packets_recv":    204800,
  "suspicious_ports": [4444]
}
```

| Field | Type | Required | Description | Notes |
|---|---|---|---|---|
| `connections` | array of objects | **YES** | Active TCP/UDP connections. Listening sockets (no `raddr`) must be excluded. Max 50. | ML classifier builds synthetic flow dicts from these |
| `connections[].laddr` | string | **YES** | Local address as `"IP:PORT"`, e.g. `"192.168.1.42:52341"`. IPv6: `"[::1]:8080"` | Used as flow source IP |
| `connections[].raddr` | string | **YES** | Remote address as `"IP:PORT"`. Entries with empty raddr must be excluded before sending | ML pipeline filters empty raddr silently |
| `connections[].status` | string | **YES** | TCP state: `ESTABLISHED`, `SYN_SENT`, `CLOSE_WAIT`, `TIME_WAIT`, `FIN_WAIT1`, `FIN_WAIT2` | Used to synthesize TCP flag bits (syn_flag, ack_flag, fin_flag) |
| `connections[].pid` | int | No | Process ID owning the socket | Informational only — not used by ML |
| `bytes_sent` | int | **YES** | Aggregate bytes sent since last boot from `psutil.net_io_counters().bytes_sent` | Distributed evenly across flows for CIC ML feature vector |
| `bytes_recv` | int | **YES** | Aggregate bytes received since last boot | Distributed evenly across flows |
| `packets_sent` | int | **YES** | Aggregate packets sent since last boot — `psutil.net_io_counters().packets_sent` | ⚠ **MISSING in current `network_collector.py`** — defaults to 0, degrades ML accuracy |
| `packets_recv` | int | **YES** | Aggregate packets received since last boot — `psutil.net_io_counters().packets_recv` | ⚠ **MISSING in current `network_collector.py`** |
| `suspicious_ports` | array of int | No | Remote ports in the watchlist: 22, 23, 135, 139, 445, 1433, 3389, 4444, 5900, 6666, 8080, 8443, 31337 | Logged; triggers `endpoint_alert` event |

### Fix required in `network_collector.py`
```python
# Add after bytes_sent/bytes_recv collection:
io = psutil.net_io_counters()
return {
    "connections":      connections,
    "bytes_sent":       io.bytes_sent,
    "bytes_recv":       io.bytes_recv,
    "packets_sent":     io.packets_sent,   # ← ADD THIS
    "packets_recv":     io.packets_recv,   # ← ADD THIS
    "suspicious_ports": sorted(suspicious_ports_seen),
}
```

---

## 5. `system` — System Resource Telemetry

**Consumed by:** `SystemMonitorAgent.predict_from_metrics()` → resource-aware heuristic severity → `system_score`  
**Displayed in:** EndpointDetailView CPU/Memory stat cards, system anomaly alerts, threat timeline

```json
{
  "cpu_percent":    45.2,
  "memory_percent": 67.1,
  "memory_used_mb": 10824.5,
  "disk_percent":   42.0,
  "process_count":  213,
  "processes": [
    { "pid": 4552, "name": "chrome.exe",  "cpu_percent": 12.3, "memory_mb": 512.4 },
    { "pid": 1234, "name": "python.exe",  "cpu_percent": 8.1,  "memory_mb": 128.0 }
  ]
}
```

| Field | Type | Required | Description | ML feature |
|---|---|---|---|---|
| `cpu_percent` | float (0–100) | **YES** | `psutil.cpu_percent(interval=0.5)` | `cpu_percent` |
| `memory_percent` | float (0–100) | **YES** | `psutil.virtual_memory().percent` | `mem_percent` |
| `memory_used_mb` | float | No | `vm.used / 1_048_576` | Informational |
| `disk_percent` | float (0–100) | No | `psutil.disk_usage("C:\\").percent` | Informational |
| `process_count` | int | **YES** | `len(psutil.pids())` | `num_processes` |
| `processes` | array of objects | **YES** | Top 10 by CPU — used by both System and Malware layers | Also feeds `assess_process_metadata()` |
| `processes[].pid` | int | **YES** | Process ID | |
| `processes[].name` | string | **YES** | Executable name, e.g. `"chrome.exe"` | IOC match in malware heuristic |
| `processes[].cpu_percent` | float | No | Per-process CPU % | Informational |
| `processes[].memory_mb` | float | No | RSS in MB | Informational |

### Optional fields that improve LSTM Autoencoder accuracy
If added to the collector, these map directly to LSTM feature vector slots (currently filled with 0):

```json
{
  "swap_percent":  12.5,
  "num_threads":   2048,
  "cpu_freq_mhz":  3600.0
}
```

---

## 6. `user` — psutil Session Telemetry

**Consumed by:** `UserBehaviorAgent.score_session_telemetry()` → multi-factor session heuristic → `user_score`  
**Displayed in:** User Behavior view (ENDPOINT badge rows), EndpointDetailView

```json
{
  "current_user": "anna",
  "sessions": [
    {
      "user":     "anna",
      "terminal": "Console",
      "host":     "",
      "started":  "2026-05-04 08:30:00"
    },
    {
      "user":     "anna",
      "terminal": "pts/0",
      "host":     "192.168.1.10",
      "started":  "2026-05-04 01:15:00"
    }
  ],
  "session_count": 2
}
```

| Field | Type | Required | Description | Notes |
|---|---|---|---|---|
| `current_user` | string | **YES** | Currently logged-in OS user | Anomaly if SYSTEM / NT AUTHORITY\SYSTEM / LOCAL SERVICE / NETWORK SERVICE |
| `sessions` | array of objects | **YES** | All active interactive sessions from `psutil.users()` | ⚠ **Key MUST be `"sessions"` not `"active_sessions"`** |
| `sessions[].user` | string | **YES** | Username for this session | |
| `sessions[].terminal` | string | No | Terminal name (Console, pts/0) | Informational |
| `sessions[].host` | string | **YES** | Remote client IP if RDP/SSH; empty string for local console | Empty or `"localhost"` → local session (score 0); dotted-decimal IP → remote session (may score) |
| `sessions[].started` | string | **YES** | Session start as `"YYYY-MM-DD HH:MM:SS"` 24-hour local time | ⚠ **Must be string, NOT a Unix float** |
| `session_count` | int | No | `len(sessions)` — informational counter | Informational |

### ⚠ CRITICAL Bugs in Current `user_collector.py`

**Bug 1 — Wrong key name (sessions always empty → user_score always 0):**
```python
# CURRENT (broken):
return {
    "current_user": current_user,
    "active_sessions": active_sessions,   # ← wrong key
    "session_count": len(active_sessions),
}

# FIXED:
return {
    "current_user": current_user,
    "sessions": active_sessions,          # ← rename to "sessions"
    "session_count": len(active_sessions),
}
```

**Bug 2 — Wrong `started` format (unusual-hours detection never fires):**
```python
# CURRENT (broken):
active_sessions.append({
    "user":     user_entry.name or "",
    "terminal": user_entry.terminal or "",
    "host":     user_entry.host or "",
    "started":  user_entry.started,       # ← Unix float, e.g. 1714819800.0
})

# FIXED — convert to datetime string:
from datetime import datetime
active_sessions.append({
    "user":     user_entry.name or "",
    "terminal": user_entry.terminal or "",
    "host":     user_entry.host or "",
    "started":  datetime.fromtimestamp(user_entry.started).strftime("%Y-%m-%d %H:%M:%S"),
})
```

### Session Anomaly Scoring Reference

| Condition | Score added | Triggers anomaly? |
|---|---|---|
| `current_user` is SYSTEM / NT AUTHORITY\SYSTEM / LOCAL SERVICE / NETWORK SERVICE | +0.60 | Alone: No (borderline). With any second factor: **YES** |
| 4+ concurrent sessions | +0.30 | No — needs second factor |
| 3 sessions | +0.15 | No |
| 2+ remote sessions AND session started before 05:00 or ≥ 23:00 | +0.50 | **YES** (0.50 alone brings total ≥ 0.70 if any other factor present) |
| 1 remote session AND session started before 05:00 or ≥ 23:00 | +0.30 | No — needs second factor |
| 3+ remote sessions during business hours | +0.30 | No |
| 1 remote session during business hours | +0.00 | **NO** — normal admin/RDP |
| **Anomaly threshold** | **0.70** | Score ≥ 0.70 → `anomaly: true` |

---

## 7. `malware` — Process Indicator Telemetry

**Consumed by:** `MalwareAnalysisAgent.assess_process_metadata()` → IOC substring match → `malware_score`  
**Displayed in:** Malware Behavior view (process-level detections)

```json
{
  "scanned_count": 213,
  "suspicious": [
    {
      "pid":    4444,
      "name":   "mimikatz.exe",
      "path":   "C:\\Users\\anna\\AppData\\Local\\Temp\\mimikatz.exe",
      "reason": "known suspicious process name: 'mimikatz.exe'; executable in temp directory"
    }
  ],
  "processes": [
    { "name": "chrome.exe",  "pid": 4552 },
    { "name": "python.exe",  "pid": 1234 },
    { "name": "svchost.exe", "pid": 800  }
  ]
}
```

| Field | Type | Required | Description | Notes |
|---|---|---|---|---|
| `scanned_count` | int | No | Total processes scanned — informational | |
| `suspicious` | array of objects | **YES** | Processes flagged by local heuristics | Backend re-checks these against 22 known-malicious name substrings |
| `suspicious[].pid` | int | No | Process ID | |
| `suspicious[].name` | string | **YES** | Executable name — checked against IOC list | |
| `suspicious[].path` | string | No | Full executable path — checked against 5 temp-path tokens | |
| `suspicious[].reason` | string | No | Human-readable heuristic description | |
| `processes` | array of objects | **YES (Recommended)** | **All running processes** for wider IOC coverage | ⚠ **Currently missing** from `malware_collector.py` |
| `processes[].name` | string | **YES** | Executable name | |
| `processes[].pid` | int | **YES** | Process ID | |

### Fix required in `malware_collector.py`
```python
# At the end of collect_malware(), before return, add:
import psutil as _psutil
all_processes = []
try:
    for p in _psutil.process_iter(["name", "pid"]):
        try:
            all_processes.append({"name": p.info.get("name") or "", "pid": p.info.get("pid") or 0})
        except (_psutil.NoSuchProcess, _psutil.AccessDenied):
            continue
except Exception:
    pass

return {
    "scanned_count": scanned,
    "suspicious":    suspicious,
    "processes":     all_processes,   # ← ADD THIS
}
```

### Known-Malicious IOC Substrings (case-insensitive)
Backend checks if any of these appear as a **substring** in any process name:
`mimikatz`, `meterpreter`, `cobaltstrike`, `cobalt_strike`, `bloodhound`, `sharphound`,
`rubeus`, `certify`, `powersploit`, `invoke-mimikatz`, `empire`, `ncat`, `netcat`, `nc.exe`,
`psexec`, `wmiexec`, `smbexec`, `xmrig`, `monero`, `cryptonight`, `beacon.exe`, `metasploit`

### Score-to-Label Thresholds
| Score | Label | Prediction |
|---|---|---|
| < 0.30 | `benign` | `BENIGN` |
| 0.30 – 0.69 | `suspicious` | `SUSPICIOUS` |
| ≥ 0.70 | `malicious` | `MALICIOUS` |

---

## 8. `suricata` — Local Suricata Alert Events

**Consumed by:** `NetworkDetectionAgent` RuleDetector + HybridDetector → enriched `network_score`  
**Displayed in:** Network flows table (attack-classified flows), Alerts table

Suricata runs locally on the endpoint and writes to `C:\SuricataLogs\eve.json`.
The endpoint agent must read the **last N minutes** (suggested: last 30 seconds = 6 tick windows)
of Suricata events from that file and include them here.

```json
{
  "suricata": {
    "eve_path": "C:\\SuricataLogs\\eve.json",
    "last_read_offset": 204800,
    "alert_events": [
      {
        "timestamp":  "2026-05-04T10:23:44.123456+0000",
        "event_type": "alert",
        "src_ip":     "192.168.1.42",
        "src_port":   52341,
        "dest_ip":    "185.220.101.1",
        "dest_port":  4444,
        "proto":      "TCP",
        "alert": {
          "signature":    "ET TROJAN Metasploit Default Certificate",
          "signature_id": 2003068,
          "category":     "A Network Trojan was detected",
          "severity":     1,
          "action":       "allowed"
        }
      }
    ],
    "flow_events": [
      {
        "timestamp":  "2026-05-04T10:23:40.000000+0000",
        "event_type": "flow",
        "src_ip":     "192.168.1.42",
        "src_port":   52341,
        "dest_ip":    "8.8.8.8",
        "dest_port":  443,
        "proto":      "TCP",
        "flow": {
          "pkts_toserver":   42,
          "pkts_toclient":   38,
          "bytes_toserver":  5200,
          "bytes_toclient":  9100,
          "start":           "2026-05-04T10:23:35.000000+0000",
          "end":             "2026-05-04T10:23:40.000000+0000",
          "age":             5,
          "state":           "established",
          "reason":          "timeout"
        }
      }
    ]
  }
}
```

### Alert Event Fields

| Field | Type | Required | Description | Used by |
|---|---|---|---|---|
| `eve_path` | string | No | Path to the eve.json file on the endpoint | Informational; for agent config validation |
| `last_read_offset` | int | No | Byte offset of the last read — agent should persist this to avoid re-sending old events | Bookmark for incremental reads |
| `alert_events` | array | **YES** | IDS alert events from Suricata (`event_type: "alert"`) from the last 30 seconds. Max 100 per payload. | RuleDetector + HybridDetector |
| `alert_events[].timestamp` | ISO 8601 string | **YES** | Suricata event timestamp with timezone offset | |
| `alert_events[].event_type` | string | **YES** | Must be `"alert"` | |
| `alert_events[].src_ip` | string | **YES** | Source IP | |
| `alert_events[].src_port` | int | **YES** | Source port | |
| `alert_events[].dest_ip` | string | **YES** | Destination IP | |
| `alert_events[].dest_port` | int | **YES** | Destination port | |
| `alert_events[].proto` | string | **YES** | Protocol: `"TCP"` \| `"UDP"` \| `"ICMP"` | |
| `alert_events[].alert.signature` | string | **YES** | Suricata rule name | |
| `alert_events[].alert.signature_id` | int | No | Suricata rule SID | |
| `alert_events[].alert.category` | string | No | Suricata alert category | |
| `alert_events[].alert.severity` | int | No | Suricata severity 1 (high) to 4 (low) | |
| `alert_events[].alert.action` | string | No | `"allowed"` or `"blocked"` | |
| `flow_events` | array | **YES** | Completed flow records (`event_type: "flow"`) from the last 30 seconds. Max 200 per payload. | HybridDetector CIC feature extraction |
| `flow_events[].timestamp` | ISO 8601 string | **YES** | | |
| `flow_events[].event_type` | string | **YES** | Must be `"flow"` | |
| `flow_events[].src_ip` | string | **YES** | | |
| `flow_events[].src_port` | int | **YES** | | |
| `flow_events[].dest_ip` | string | **YES** | | |
| `flow_events[].dest_port` | int | **YES** | | |
| `flow_events[].proto` | string | **YES** | | |
| `flow_events[].flow.pkts_toserver` | int | **YES** | Packets sent from client → server | CIC "Total Fwd Packets" |
| `flow_events[].flow.pkts_toclient` | int | **YES** | Packets sent from server → client | CIC "Total Backward Packets" |
| `flow_events[].flow.bytes_toserver` | int | **YES** | Bytes sent from client → server | CIC "Total Length of Fwd Packets" |
| `flow_events[].flow.bytes_toclient` | int | **YES** | Bytes sent from server → client | CIC "Total Length of Bwd Packets" |
| `flow_events[].flow.start` | ISO 8601 string | **YES** | Flow start timestamp | |
| `flow_events[].flow.end` | ISO 8601 string | **YES** | Flow end timestamp | |
| `flow_events[].flow.age` | int | No | Flow duration in seconds | CIC "Flow Duration" |
| `flow_events[].flow.state` | string | No | `"established"` \| `"closed"` \| `"new"` | |
| `flow_events[].flow.reason` | string | No | Flow end reason: `"timeout"` \| `"rst"` \| `"fin"` | |

### Collector to Add: `suricata_collector.py`
```python
import json
from pathlib import Path
from datetime import datetime, timezone, timedelta

EVE_PATH = Path(r"C:\SuricataLogs\eve.json")
_OFFSET_FILE = Path(__file__).parent / ".suricata_offset"

async def collect_suricata(lookback_seconds: int = 30) -> dict:
    offset = 0
    if _OFFSET_FILE.exists():
        try:
            offset = int(_OFFSET_FILE.read_text().strip())
        except Exception:
            offset = 0

    alert_events, flow_events = [], []
    new_offset = offset
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=lookback_seconds)

    try:
        with EVE_PATH.open("r", encoding="utf-8", errors="ignore") as f:
            f.seek(offset)
            for line in f:
                new_offset += len(line.encode("utf-8"))
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                    ts = datetime.fromisoformat(ev.get("timestamp", "").replace("+0000", "+00:00"))
                    if ts < cutoff:
                        continue
                    if ev.get("event_type") == "alert":
                        alert_events.append(ev)
                    elif ev.get("event_type") == "flow":
                        flow_events.append(ev)
                except Exception:
                    continue
        _OFFSET_FILE.write_text(str(new_offset))
    except FileNotFoundError:
        pass

    return {
        "eve_path":          str(EVE_PATH),
        "last_read_offset":  new_offset,
        "alert_events":      alert_events[-100:],
        "flow_events":       flow_events[-200:],
    }
```

---

## 9. `sysmon_events` — Sysmon Behavioral Events

**Consumed by:** `SysmonBehaviorAgent._handle_event()` → TF-IDF token window → IsolationForest → `anomaly_score`  
**Displayed in:** Sysmon Behavior view (Live Process Events panel)

Sysmon writes behavioral events to the Windows Event Log (Sysmon/Operational channel).
Winlogbeat reads these and writes them to `C:\winlogbeat\logs\sysmon_events.json` as NDJSON.
The endpoint agent must read the last N events from that file and include them here.

### Supported Sysmon Event IDs

| EventID | Name | What it captures |
|---|---|---|
| 1 | ProcessCreate | New process: image path, command line, parent, user |
| 3 | NetworkConnect | Outbound TCP/UDP connection from a process |
| 5 | ProcessTerminate | Process exit |
| 7 | ImageLoad | DLL loaded into a process |
| 8 | CreateRemoteThread | **HIGH RISK** — process injecting a thread into another |
| 10 | ProcessAccess | Process opened with access rights (credential theft pattern) |
| 11 | FileCreate | New file created |
| 12 | RegistryObjectAddedOrDeleted | Registry key/value created or deleted |
| 13 | RegistryValueSet | Registry value modified |
| 15 | FileCreateStreamHash | Alternate data stream created |
| 22 | DNSQuery | DNS lookup from a process |
| 23 | FileDelete | File deleted |
| 25 | ProcessTampering | **HIGH RISK** — process image tampering / hollowing |

### Two Accepted Formats

**Format A — Flat (preferred, lighter):**
```json
{
  "sysmon_events": {
    "source_file": "C:\\winlogbeat\\logs\\sysmon_events.json",
    "events": [
      {
        "event_id":  1,
        "ts":        "2026-05-04T10:23:44.123456+00:00",
        "process":   "C:\\Windows\\System32\\powershell.exe",
        "pid":       4552,
        "cmdline":   "powershell.exe -NoP -W Hidden -Exec Bypass -Enc SGVsbG8=",
        "parent":    "C:\\Windows\\explorer.exe",
        "user":      "anna",
        "dest_ip":   "",
        "dest_port": 0,
        "file":      ""
      },
      {
        "event_id":  3,
        "ts":        "2026-05-04T10:23:45.001234+00:00",
        "process":   "C:\\Windows\\System32\\powershell.exe",
        "pid":       4552,
        "cmdline":   "",
        "parent":    "",
        "user":      "anna",
        "dest_ip":   "185.220.101.1",
        "dest_port": 4444,
        "file":      ""
      }
    ]
  }
}
```

**Format B — Winlogbeat NDJSON (passthrough from file, also accepted):**
The SysmonBehaviorAgent handles both formats via `_sysmon_event_to_token()`.
```json
{
  "sysmon_events": {
    "source_file": "C:\\winlogbeat\\logs\\sysmon_events.json",
    "events": [
      {
        "@timestamp": "2026-05-04T10:23:44.123456+00:00",
        "winlog": {
          "event_id": "1",
          "provider_name": "Microsoft-Windows-Sysmon",
          "event_data": {
            "Image":            "C:\\Windows\\System32\\powershell.exe",
            "CommandLine":      "powershell.exe -NoP -W Hidden -Exec Bypass -Enc SGVsbG8=",
            "ParentImage":      "C:\\Windows\\explorer.exe",
            "ProcessId":        "4552",
            "User":             "DESKTOP-BTH57BG\\anna"
          }
        }
      }
    ]
  }
}
```

### Flat Format Field Reference

| Field | Type | Required | Description |
|---|---|---|---|
| `event_id` | int | **YES** | Sysmon event ID (1, 3, 7, 8, 10, 11, 12, 13, 22, 23, 25) |
| `ts` | ISO 8601 string | **YES** | Event timestamp with timezone |
| `process` | string | **YES** | Full path of process image, e.g. `"C:\\Windows\\System32\\powershell.exe"` |
| `pid` | int | **YES** | Process ID |
| `cmdline` | string | No | Command line of the process (EventID 1 only) |
| `parent` | string | No | Full path of parent process image (EventID 1 only) |
| `user` | string | No | User account running the process |
| `dest_ip` | string | No | Destination IP for network events (EventID 3 only) |
| `dest_port` | int | No | Destination port for network events (EventID 3 only) |
| `file` | string | No | Target file path for file events (EventID 11, 23, 15 only) |
| `target_image` | string | No | Target process image for injection events (EventID 8, 10 only) |
| `registry_key` | string | No | Registry key path for registry events (EventID 12, 13 only) |
| `dns_query` | string | No | DNS hostname queried (EventID 22 only) |
| `image_loaded` | string | No | DLL path for image load events (EventID 7 only) |

### Collector to Add: Sysmon reader in `sysmon_collector.py`
```python
import json
from pathlib import Path

SYSMON_LOG = Path(r"C:\winlogbeat\logs\sysmon_events.json")
_SYSMON_OFFSET_FILE = Path(__file__).parent / ".sysmon_offset"
MAX_EVENTS_PER_TICK = 50

async def collect_sysmon() -> dict:
    offset = 0
    if _SYSMON_OFFSET_FILE.exists():
        try:
            offset = int(_SYSMON_OFFSET_FILE.read_text().strip())
        except Exception:
            offset = 0

    events = []
    new_offset = offset
    try:
        with SYSMON_LOG.open("r", encoding="utf-8", errors="ignore") as f:
            f.seek(offset)
            for line in f:
                new_offset += len(line.encode("utf-8"))
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        _SYSMON_OFFSET_FILE.write_text(str(new_offset))
    except FileNotFoundError:
        pass

    return {
        "source_file": str(SYSMON_LOG),
        "events": events[-MAX_EVENTS_PER_TICK:],
    }
```

---

## 10. `winlogbeat_events` — Windows Security Event Log

**Consumed by:** `xdr_runtime.normalize_events_to_features()` → One-Class SVM → detailed user anomaly score  
**Also consumed by:** `SysmonBehaviorAgent` for USB and logon enrichment  
**Displayed in:** User Behavior view (After-Hours Logins, USB Events, Files Accessed, Total Logins)

Winlogbeat reads Windows Security and System event logs and writes NDJSON to `C:\XDR_Logs\`.
The endpoint agent must read the last `lookback_minutes` (suggest: 10 minutes) of events and include them.

```json
{
  "winlogbeat_events": {
    "source_dir": "C:\\XDR_Logs",
    "lookback_minutes": 10,
    "events": [
      {
        "@timestamp": "2026-05-04T10:23:44.123456+00:00",
        "winlog": {
          "event_id": "4624",
          "provider_name": "Microsoft-Windows-Security-Auditing",
          "event_data": {
            "TargetUserName":   "anna",
            "LogonType":        "2",
            "IpAddress":        "127.0.0.1"
          },
          "user_data": {
            "TargetUserName":   "anna"
          }
        },
        "user": {
          "name": "anna"
        },
        "host": {
          "name": "DESKTOP-BTH57BG"
        },
        "message": "An account was successfully logged on."
      },
      {
        "@timestamp": "2026-05-04T10:15:22.000000+00:00",
        "winlog": {
          "event_id": "11",
          "provider_name": "Microsoft-Windows-Sysmon",
          "event_data": {
            "TargetFilename": "C:\\Users\\anna\\AppData\\Roaming\\suspicious_file.exe",
            "ProcessId":      "4552"
          }
        },
        "user": { "name": "anna" },
        "host": { "name": "DESKTOP-BTH57BG" },
        "message": "File created"
      }
    ]
  }
}
```

### Required Event IDs and What They Feed

| EventID | Provider | OC-SVM feature | Description |
|---|---|---|---|
| `4624` | Security-Auditing | `logon_count` | Successful logon |
| `4625` | Security-Auditing | `failed_logon_count` | Failed logon attempt |
| `4634` | Security-Auditing | `logoff_count` | Account logoff |
| `4647` | Security-Auditing | `logoff_count` | User-initiated logoff |
| `11` | Microsoft-Windows-Sysmon | `file_ops_count`, `file_write_count` | File created |
| `23` | Microsoft-Windows-Sysmon | `file_ops_count`, `file_write_count` | File deleted |
| `15` | Microsoft-Windows-Sysmon | `file_ops_count`, `file_read_count` | File stream hash created |
| USB events | Any provider | `device_connects`, `device_disconnects`, `device_events` | Any event with "usb", "usbstor", or "removable" in message |
| Email events | Any provider | `emails_sent` | Any event with "smtp", "outlook", or "email" in message |

### Key Fields Required per Event

| Field | Type | Required | Notes |
|---|---|---|---|
| `@timestamp` | ISO 8601 string | **YES** | Used for lookback filtering and after-hours calculation (events outside 09:00–18:00 increment `after_hours_activity`) |
| `winlog.event_id` | string | **YES** | Must be string, e.g. `"4624"` (not int) |
| `winlog.provider_name` | string | No | Used to filter Sysmon vs Security events |
| `winlog.event_data.TargetUserName` | string | No | Username — merged with `user.name` |
| `winlog.event_data.TargetFilename` | string | No | File path — used for unique file count |
| `winlog.user_data.TargetUserName` | string | No | Alternate user name path |
| `user.name` | string | **YES** | Primary username extraction |
| `host.name` | string | No | Hostname of the originating machine |
| `message` | string | No | Full event message — scanned for USB/email keywords |

### OCEAN Features (currently 0.0 — hardcoded)
The OC-SVM feature vector includes 5 OCEAN psychometric dimensions (O, C, E, A, N).
These currently default to `0.0` because there is no live data source.
If the endpoint implements `POST /users/ocean`, these can be populated from a `user_profiles` MongoDB document.

### Collector to Add: Winlogbeat reader in `winlogbeat_collector.py`
```python
import json
from pathlib import Path
from datetime import datetime, timezone, timedelta

WINLOGBEAT_DIR = Path(r"C:\XDR_Logs")
_WB_OFFSET_FILE = Path(__file__).parent / ".winlogbeat_offset"
MAX_EVENTS_PER_TICK = 100
LOOKBACK_MINUTES = 10

async def collect_winlogbeat() -> dict:
    offset = 0
    if _WB_OFFSET_FILE.exists():
        try:
            offset = int(_WB_OFFSET_FILE.read_text().strip())
        except Exception:
            offset = 0

    cutoff = datetime.now(timezone.utc) - timedelta(minutes=LOOKBACK_MINUTES)
    events = []
    new_offset = offset

    try:
        import pandas as pd  # for timestamp parsing
        candidates = sorted(
            p for p in WINLOGBEAT_DIR.iterdir()
            if p.is_file() and (p.name.startswith("winlogbeat") or p.suffix == ".ndjson")
        )
        for path in candidates:
            with path.open("r", encoding="utf-8", errors="ignore") as f:
                f.seek(offset)
                for line in f:
                    new_offset += len(line.encode("utf-8"))
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ev = json.loads(line)
                        ts = pd.to_datetime(ev.get("@timestamp"), errors="coerce", utc=True)
                        if pd.notna(ts) and ts >= pd.Timestamp(cutoff):
                            events.append(ev)
                    except Exception:
                        continue
        _WB_OFFSET_FILE.write_text(str(new_offset))
    except Exception:
        pass

    return {
        "source_dir":       str(WINLOGBEAT_DIR),
        "lookback_minutes": LOOKBACK_MINUTES,
        "events":           events[-MAX_EVENTS_PER_TICK:],
    }
```

---

## 11. PE File Scanning — EMBER Malware Model

**Consumed by:** `MalwareAnalysisAgent.predict_from_features()` → LightGBM 280-dim EMBER classifier → `malware_score`  
**Displayed in:** Malware Behavior view (file-level MALICIOUS/SUSPICIOUS/BENIGN labels)

The EMBER-based LightGBM model requires a **280-dimensional feature vector** extracted from the PE binary.
For remote endpoints, the backend cannot read endpoint files directly — the agent must either:
- **Option A (Recommended):** Extract the 280-dim feature vector locally and send it via `POST /predict/malware`
- **Option B (Simple fallback):** Send base64-encoded file bytes to a new `POST /endpoint/scan_file` endpoint (not yet implemented)

### Option A — Pre-extracted Feature Vector (Requires `pefile` on endpoint)

Install on endpoint: `pip install pefile`

The endpoint agent detects suspicious files, extracts the feature vector, and POSTs it directly:

```http
POST /predict/malware
X-API-Key: <key>
Content-Type: application/json

{
  "features": [0.0, 0.003, 0.0, ..., 0.52, 0.14],
  "file_path": "C:\\Users\\anna\\AppData\\Local\\Temp\\suspicious.exe",
  "file_size": 45056,
  "sha256":    "a1b2c3d4e5f6..."
}
```

This is a **separate HTTP call** from the main telemetry POST — it goes to `/predict/malware` not `/endpoint/ingest`.

### Feature Vector Layout (280 dimensions — EXACT ORDER IS CONTRACT)

| Index | Feature | Extraction |
|---|---|---|
| 0–255 | Byte histogram (normalized) | 256-element byte frequency / total bytes |
| 256 | Mean byte entropy | Shannon entropy / 8.0 (normalized to [0,1]) |
| 257 | file_size | `len(file_bytes)` as float |
| 258 | virtual_size | PE `OPTIONAL_HEADER.SizeOfImage` |
| 259 | has_debug | 1 if `DIRECTORY_ENTRY_DEBUG` exists else 0 |
| 260 | num_exports | Count of exported symbols |
| 261 | num_imports | Count of imported DLLs |
| 262 | has_resources | 1 if `DIRECTORY_ENTRY_RESOURCE` exists else 0 |
| 263 | has_signature | 1 if `DIRECTORY_ENTRY_SECURITY` exists else 0 |
| 264 | has_tls | 1 if `DIRECTORY_ENTRY_TLS` exists else 0 |
| 265 | num_symbols | `FILE_HEADER.NumberOfSymbols` |
| 266 | is_64bit | 1 if machine type = 0x8664 (AMD64) else 0 |
| 267 | coff_timestamp_norm | `FILE_HEADER.TimeDateStamp / 2^32` |
| 268 | num_sections | Number of PE sections |
| 269 | subsystem | `OPTIONAL_HEADER.Subsystem` integer |
| 270 | max_section_entropy | Max Shannon entropy across all sections |
| 271 | avg_section_entropy | Mean section entropy |
| 272 | avg_section_size_norm | Mean `SizeOfRawData` / 1,000,000 |
| 273 | num_rx_sections | Sections with both EXECUTE + READ flags |
| 274 | num_rw_sections | Sections with both READ + WRITE flags |
| 275 | num_imported_libs | Total imported DLL count |
| 276 | num_imported_funcs_norm | Total imported function count / 100.0 |
| 277 | num_exported_funcs_norm | Total exported function count / 100.0 |
| 278 | strings_entropy | Printable string entropy / 8.0 |
| 279 | strings_count_norm | Count of printable runs (≥5 chars) / 1000.0 |

### Score Trust Caps Applied Server-Side

| Condition | Cap |
|---|---|
| File path matches `site-packages`, `\Python3`, `C:\Windows\System32`, `C:\Program Files\` | Score capped at **0.40**, `trusted=True`, `trust_reason="known_safe_path"` |
| Feature[263] (has_signature) == 1 AND score < 0.85 | Score capped at **0.50**, `trusted=True`, `trust_reason="signed_binary"` |

### Files to Trigger Scanning
The endpoint should initiate a `/predict/malware` call whenever:
- `malware_collector.py` detects a process running from a temp directory
- Winlogbeat reports Sysmon EventID 11 (file created) with `.exe`, `.dll`, `.sys`, `.scr`, `.bat`, `.ps1`, `.vbs` extension
- File write detected in `C:\Users\<user>\AppData\Local\Temp\`, `C:\Windows\Temp\`, or `C:\ProgramData\`

---

## 12. Complete Example Payload

```json
{
  "endpoint": {
    "endpoint_id":   "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "hostname":      "DESKTOP-BTH57BG",
    "ip_address":    "192.168.1.42",
    "os":            "Windows",
    "os_version":    "10.0.26200",
    "username":      "anna",
    "agent_version": "1.0.0"
  },
  "timestamp": "2026-05-04T10:23:45.123456+00:00",
  "network": {
    "connections": [
      { "laddr": "192.168.1.42:52341", "raddr": "8.8.8.8:443",     "status": "ESTABLISHED", "pid": 4552 },
      { "laddr": "192.168.1.42:49812", "raddr": "20.54.36.14:443", "status": "ESTABLISHED", "pid": 1234 }
    ],
    "bytes_sent":       15728640,
    "bytes_recv":       31457280,
    "packets_sent":     102400,
    "packets_recv":     204800,
    "suspicious_ports": []
  },
  "system": {
    "cpu_percent":    45.2,
    "memory_percent": 67.1,
    "memory_used_mb": 10824.5,
    "disk_percent":   42.0,
    "process_count":  213,
    "processes": [
      { "pid": 4552, "name": "chrome.exe",  "cpu_percent": 12.3, "memory_mb": 512.4 },
      { "pid": 1234, "name": "python.exe",  "cpu_percent":  8.1, "memory_mb": 128.0 },
      { "pid":  800, "name": "svchost.exe", "cpu_percent":  2.1, "memory_mb":  64.0 }
    ]
  },
  "user": {
    "current_user": "anna",
    "sessions": [
      { "user": "anna", "terminal": "Console", "host": "",             "started": "2026-05-04 08:30:00" },
      { "user": "anna", "terminal": "pts/0",   "host": "192.168.1.10", "started": "2026-05-04 01:15:00" }
    ],
    "session_count": 2
  },
  "malware": {
    "scanned_count": 213,
    "suspicious": [],
    "processes": [
      { "name": "chrome.exe",  "pid": 4552 },
      { "name": "python.exe",  "pid": 1234 },
      { "name": "svchost.exe", "pid":  800 }
    ]
  },
  "suricata": {
    "eve_path":          "C:\\SuricataLogs\\eve.json",
    "last_read_offset":  204800,
    "alert_events":      [],
    "flow_events": [
      {
        "timestamp":  "2026-05-04T10:23:40.000000+0000",
        "event_type": "flow",
        "src_ip":     "192.168.1.42",
        "src_port":   52341,
        "dest_ip":    "8.8.8.8",
        "dest_port":  443,
        "proto":      "TCP",
        "flow": {
          "pkts_toserver": 42, "pkts_toclient": 38,
          "bytes_toserver": 5200, "bytes_toclient": 9100,
          "start": "2026-05-04T10:23:35.000000+0000",
          "end":   "2026-05-04T10:23:40.000000+0000",
          "age": 5, "state": "established", "reason": "timeout"
        }
      }
    ]
  },
  "sysmon_events": {
    "source_file": "C:\\winlogbeat\\logs\\sysmon_events.json",
    "events": [
      {
        "event_id": 1,
        "ts":       "2026-05-04T10:23:44.123456+00:00",
        "process":  "C:\\Windows\\System32\\powershell.exe",
        "pid":      4552,
        "cmdline":  "powershell.exe -Command Get-Process",
        "parent":   "C:\\Windows\\explorer.exe",
        "user":     "anna",
        "dest_ip":  "", "dest_port": 0, "file": ""
      }
    ]
  },
  "winlogbeat_events": {
    "source_dir":       "C:\\XDR_Logs",
    "lookback_minutes": 10,
    "events": [
      {
        "@timestamp": "2026-05-04T10:23:44.123456+00:00",
        "winlog": {
          "event_id": "4624",
          "provider_name": "Microsoft-Windows-Security-Auditing",
          "event_data": { "TargetUserName": "anna", "LogonType": "2" }
        },
        "user": { "name": "anna" },
        "host": { "name": "DESKTOP-BTH57BG" },
        "message": "An account was successfully logged on."
      }
    ]
  }
}
```

---

## 13. Backend Response

```json
{ "status": "ok", "endpoint_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479" }
```

---

## 14. Socket.IO Events Emitted After Each Ingest

| Event | Triggered when | Key payload fields |
|---|---|---|
| `endpoint_update` | Every ingest | `endpoint_id`, `hostname`, `ip_address`, `os`, `username`, `status`, `cpu`, `memory`, `last_seen` |
| `endpoint_alert` | `cpu > 85%` OR `mem > 90%` OR suspicious ports detected | `endpoint_id`, `severity`, `reason` |
| `user_anomaly` | Every ingest (all sessions, always) | `user`, `anomaly_score`, `prediction_label` ("NORMAL"/"ANOMALY"), `session_count`, `unusual_hours`, `remote_sessions`, `flags` |
| `system_anomaly` | `is_genuinely_anomalous = True` (cpu > 85 OR mem > 95) | `cpu_percent`, `memory_percent`, `severity`, `is_genuinely_anomalous` |
| `network_anomaly` | Any connection scored as ATTACK by RandomForest | `attack_type`, `confidence`, `src_ip`, `dest_ip` |
| `malware_alert` | `malware_score ≥ 0.30` (suspicious or malicious) | `label`, `prediction`, `malware_score`, `suspicious_indicators` |
| `sysmon_alert` | SysmonBehaviorAgent scores a window above threshold | `process_name`, `pid`, `anomaly_score`, `severity`, `label`, `high_risk` |
| `fusion_alert` | Fused severity is HIGH or CRITICAL | `threat_score`, `severity`, `attack_type`, `shap`, `endpoint_id`, `contributing_signals` |
| `response_required` | `fusion_alert` fired AND cooldown (120 s per endpoint) passed | `endpoint_id`, `severity`, `attack_type`, `plan_id` |
| `endpoint_fusion_alert` | Every ingest (backward compat) | `endpoint_id`, `threat_score`, `severity` |

---

## 15. Fields Shown on the Frontend by Section

### Endpoints Grid (`EndpointView.tsx`)
| Display | Source |
|---|---|
| Hostname | `endpoint.hostname` |
| IP Address | `endpoint.ip_address` |
| OS | `endpoint.os` (from `endpoint_update` socket event) |
| Username | `endpoint.username` (from `endpoint_update` socket event) |
| Online/Offline dot | `last_seen` > 30 s = offline |
| CPU bar | `endpoint_update.cpu` |
| Memory bar | `endpoint_update.memory` |
| Last Seen | `endpoint.last_seen` |

### Endpoint Detail View (`EndpointDetailView.tsx`)
| Display | Priority order |
|---|---|
| CPU % stat card | 1. `endpoint_update.cpu` (live socket), 2. `timeline[last].cpu` |
| Memory % stat card | 1. `endpoint_update.memory` (live socket), 2. `timeline[last].memory` |
| Connections count | `timeline[last].connections` (count of `network.connections` in last payload) |
| Threat Score % | `timeline[last].threat_score × 100` + `%` suffix |
| Severity badge | `timeline[last].severity` |
| OS | `endpoint_update.os` |
| User | `endpoint_update.username` |
| Threat sparkline | `endpoint_timelines` MongoDB collection |

### User Behavior (`UserBehaviorView.tsx`)
| Column | Source | Available from endpoint? |
|---|---|---|
| User name | `user.current_user` | ✅ Yes |
| ENDPOINT badge | `source === "endpoint"` | ✅ Yes |
| Risk Score bar | `user_score` (heuristic 0–1) | ✅ Yes |
| NORMAL/ANOMALY | `prediction_label` (threshold 0.70) | ✅ Yes |
| Session Count | `user.session_count` | ✅ Yes |
| After-Hours Logins | `winlogbeat_events` — count of events outside 09:00–18:00 | ✅ **Once `winlogbeat_events` collector added** |
| USB Events | `winlogbeat_events` — messages containing "usb"/"usbstor" | ✅ **Once `winlogbeat_events` collector added** |
| Files Accessed | `winlogbeat_events` — EventID 11/23 count | ✅ **Once `winlogbeat_events` collector added** |
| Emails Sent | `winlogbeat_events` — messages containing "smtp"/"outlook" | ✅ **Once `winlogbeat_events` collector added** |
| Total Logins | `winlogbeat_events` — EventID 4624 count | ✅ **Once `winlogbeat_events` collector added** |

### Network Behavior
| Display | Source |
|---|---|
| psutil attack flows | `network_anomaly` (RandomForest on psutil connections) |
| Suricata attack flows | `network_anomaly` (RuleDetector + HybridDetector on Suricata `flow_events`) |
| Suricata IDS alerts | `endpoint_alert` with Suricata signature in reason |
| Attack Type | RandomForest classifier output (DoS, DDoS, PortScan, BruteForce, Botnet, C2 Beaconing, etc.) |

### Sysmon Behavior
| Display | Source |
|---|---|
| Live Process Events | `sysmon_alert` events (from `sysmon_events` block → SysmonBehaviorAgent) |
| System Telemetry Logs | `system_anomaly` events (from `system` block → SystemMonitorAgent) |

### Malware Behavior
| Display | Source |
|---|---|
| Process-level heuristic | `malware_alert` (from `malware` block → `assess_process_metadata()`) |
| File-level EMBER score | `malware_alert` (from separate `POST /predict/malware` call with 280-dim feature vector) |
| Label (BENIGN/SUSPICIOUS/MALICIOUS) | Computed server-side from score thresholds (0.30 / 0.70) |
| Trusted badge | Trusted-path and signed-binary caps applied |

---

## 16. MongoDB Collections Written per Ingest

### `endpoint_registry` (one doc per endpoint, upserted)
```json
{
  "endpoint_id":   "...", "hostname": "DESKTOP-BTH57BG",
  "ip_address":    "192.168.1.42", "os": "Windows",
  "os_version":    "10.0.26200", "username": "anna",
  "agent_version": "1.0.0", "last_seen": "2026-05-04T10:23:45.123456",
  "status":        "online"
}
```

### `endpoint_logs` (one doc per ingest, capped 10,000)
Full payload blob: `{ endpoint_id, hostname, ip_address, timestamp, network, system, user, malware }`
(Suricata/Sysmon/Winlogbeat blocks are logged when backend model is extended to accept them.)

### `endpoint_timelines` (one doc per ingest, capped 50,000)
Time-series for sparkline chart:
```json
{
  "endpoint_id": "...", "timestamp": "...",
  "cpu": 45.2, "memory": 67.1, "connections": 2,
  "threat_score": 0.09, "severity": "LOW"
}
```

### `fused_alerts` (capped 1,000)
```json
{
  "endpoint_id": "...", "hostname": "...", "source": "endpoint_telemetry",
  "threat_score": 0.72, "severity": "HIGH", "attack_type": "Network Attack", "ts": "..."
}
```

### `endpoint_commands` (capped 2,000)
SOAR commands for the agent to execute:
```json
{
  "endpoint_id": "...", "action": "kill_process",
  "target": "mimikatz.exe", "status": "pending", "created_at": "..."
}
```
Agent polls `GET /endpoint/commands/{endpoint_id}` every 3 seconds.

---

## 17. Required Fixes — Summary Table

### A. Critical Bugs in Current Collectors (must fix before production)

| File | Bug | Impact if unfixed | Fix |
|---|---|---|---|
| `user_collector.py` | Returns `"active_sessions"` but backend reads `"sessions"` | `user_score` always 0, session anomaly detection completely broken | Rename key to `"sessions"` |
| `user_collector.py` | `started` is a Unix float; backend calls `datetime.strptime(..., "%Y-%m-%d %H:%M:%S")` | `unusual_hours_detected` always False (ValueError silently caught) | `datetime.fromtimestamp(user_entry.started).strftime("%Y-%m-%d %H:%M:%S")` |
| `network_collector.py` | Missing `packets_sent` and `packets_recv` | Both default to 0 → CIC features `Total Fwd Packets`, `Total Backward Packets` degraded | Add from `psutil.net_io_counters().packets_sent` / `.packets_recv` |
| `malware_collector.py` | Missing `processes` key | Backend only scores the heuristic-flagged list — full running process list never checked against IOCs | Add `"processes": [{"name": p.name, "pid": p.pid} for p in psutil.process_iter(["name","pid"])]` |

### B. New Collectors to Add (for Suricata + Sysmon + Winlogbeat)

| New file | Data source | Feeds backend model |
|---|---|---|
| `collectors/suricata_collector.py` | `C:\SuricataLogs\eve.json` | RuleDetector + HybridDetector (richer network flow data than psutil alone) |
| `collectors/sysmon_collector.py` | `C:\winlogbeat\logs\sysmon_events.json` | SysmonBehaviorAgent (process behavior anomaly scoring) |
| `collectors/winlogbeat_collector.py` | `C:\XDR_Logs\winlogbeat*.ndjson` | xdr_runtime OC-SVM (full user behavior model — logons, file ops, USB events) |

### C. Backend Pydantic Model Extension Required

```python
# backend.py — EndpointTelemetry model must be extended to accept new blocks:
class EndpointTelemetry(BaseModel):
    endpoint:          EndpointIdentity
    timestamp:         Optional[datetime] = None
    network:           dict = {}
    system:            dict = {}
    user:              dict = {}
    malware:           dict = {}
    suricata:          dict = {}          # ← ADD
    sysmon_events:     dict = {}          # ← ADD
    winlogbeat_events: dict = {}          # ← ADD
```

### D. Backend Processing to Add for New Blocks

| New block | Backend handler to add |
|---|---|
| `suricata.flow_events` | Convert to `FlowSummary` and route through `NetworkDetectionAgent.detect_from_flows()` |
| `suricata.alert_events` | Log to `suricata_alerts` MongoDB collection; emit `network_anomaly` for severity 1–2 |
| `sysmon_events.events` | Route each event to `_sysmon_agent._handle_event()` asynchronously |
| `winlogbeat_events.events` | Pass to `xdr_runtime.run_inference()` via a new `run_inference_from_events(events)` function |

---

## 18. Deployment Checklist

Before the endpoint agent goes live, verify:

- [ ] `XDR_API_KEY` set to a non-default value on both agent and backend
- [ ] `XDR_BACKEND_URL` points to the correct backend host
- [ ] Suricata running, writing to `C:\SuricataLogs\eve.json`
- [ ] Sysmon installed and running (verify with `Get-Service -Name Sysmon64`)
- [ ] Winlogbeat running, writing sysmon events to `C:\winlogbeat\logs\sysmon_events.json`
- [ ] Winlogbeat running, writing security events to `C:\XDR_Logs\`
- [ ] Bug fix 1 applied: `user_collector.py` — `"active_sessions"` → `"sessions"`
- [ ] Bug fix 2 applied: `user_collector.py` — `started` converted from float to string
- [ ] Bug fix 3 applied: `network_collector.py` — `packets_sent` / `packets_recv` added
- [ ] Bug fix 4 applied: `malware_collector.py` — `processes` key added
- [ ] New collector: `suricata_collector.py` added and imported in `collectors/__init__.py`
- [ ] New collector: `sysmon_collector.py` added and imported
- [ ] New collector: `winlogbeat_collector.py` added and imported
- [ ] Backend `EndpointTelemetry` Pydantic model extended with `suricata`, `sysmon_events`, `winlogbeat_events` fields
- [ ] `pefile` installed on endpoint (`pip install pefile`) for EMBER pre-extraction (optional but recommended)
