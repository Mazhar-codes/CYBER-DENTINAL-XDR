# Cyber Sentinel XDR — Integration Session Report
**Date:** 2026-04-20 (Session 2)  
**Scope:** Suricata + Winlogbeat auto-start, dashboard normal traffic visibility, Winlogbeat crash root-cause resolution

---

## Summary of Changes

### 1. Suricata + Winlogbeat Auto-Start

**Goal:** Eliminate the need for a separate terminal to start capture processes; tie their lifecycle to the SOC dashboard.

| Component | Change |
|-----------|--------|
| `backend.py` — module state | Added `_suricata_proc` and `_winlogbeat_proc` module-level variables to hold `subprocess.Popen` handles |
| `backend.py` — command lists | Added `_SURICATA_CMD` and `_WINLOGBEAT_CMD` as raw-string Python lists (Windows paths with spaces quoted correctly) |
| `backend.py` — `_start_capture_processes()` | Launches both processes via `subprocess.Popen` with `CREATE_NEW_PROCESS_GROUP` flag; stderr redirected to per-tool log files |
| `backend.py` — `_stop_capture_processes()` | Sends SIGTERM to each process; waits up to 5 s; falls back to `kill()` if process does not exit |
| `backend.py` — `/start-monitoring` | Now calls `_start_capture_processes()` before starting the monitoring loop; response body includes capture process status |
| `backend.py` — `/stop-monitoring` | Now calls `_stop_capture_processes()` before halting the monitoring loop |
| `backend.py` — `_shutdown()` | FastAPI lifespan shutdown hook also calls `_stop_capture_processes()` so processes are not orphaned on server exit |
| `start_capture.ps1` | New file at `D:\Cyber Sentinal\start_capture.ps1` — manual fallback script to start Suricata and Winlogbeat independently if the dashboard cannot reach them |
| `Network Behavior/COMMANDS.md` | Startup order simplified: MongoDB → backend (single terminal) → dashboard; Suricata and Winlogbeat no longer require their own terminals |

---

### 2. Normal Traffic Visibility on Dashboard

**Problem:** The SOC dashboard showed no data during normal operation because both the network and user behavior pipelines silently dropped non-anomalous results before emitting to the frontend.

| Component | Root Cause | Fix |
|-----------|-----------|-----|
| `backend.py` — `_process_network_result()` | Only emitted `ml_result` to Socket.IO when `prediction == "ATTACK"`; all NORMAL flows were silently discarded | Emit ALL `ml_result` objects via `sio.emit("network", ...)` regardless of prediction label; MongoDB write still gated on ATTACK only |
| `backend.py` — `_handle_user_result()` | Only emitted a user row to Socket.IO when `anomaly == True`; normal user sessions were never sent to the frontend | Emit ALL user rows via Socket.IO; MongoDB write still gated on `anomaly == True` only |

**Result:** The dashboard now shows a live stream of both NORMAL and ATTACK network flows, and all user sessions appear in the User Behavior Panel. MongoDB storage on Atlas M0 is preserved because only confirmed anomalies and attacks are persisted.

---

### 3. Winlogbeat Crash Resolution

Winlogbeat was crashing on every launch. Six independent root causes were identified and resolved in sequence.

| Root Cause | Symptom | Fix |
|-----------|---------|-----|
| `permissions: 0600` in `winlogbeat.yml` | Config validation failure on Windows (Linux-only directive) | Removed the `permissions` key entirely |
| Two separate `- name: Security` event log entries in `winlogbeat.yml` | Winlogbeat 9.x metrics registry panic: `received_events_count already used` | Merged into a single `- name: Security` entry with a combined `event_id` filter list |
| `setup.kibana: enabled: false` in `winlogbeat.yml` | YAML parse error (invalid key for this block) | Removed the invalid directive |
| `Microsoft-Windows-Sysmon/Operational` event log source listed | Sysmon is not installed; Winlogbeat failed to open the provider | Removed the Sysmon source from `winlogbeat.yml` |
| `subprocess.Popen` launched without `cwd` set | Winlogbeat resolved `modules.d/`, `data/`, and internal paths relative to the Python process cwd, not its own directory | Added `cwd=str(_WINLOGBEAT_DIR)` to the `Popen` call |
| Stale `data/` directory from the old two-Security config | Metrics registry state from the previous broken config caused a continued panic on restart | Deleted the stale `data/` directory so Winlogbeat rebuilt clean state |

**Additional hardening applied:**
- Added unique `id` fields to each event log source entry (required by Winlogbeat 9.x schema validation)
- Winlogbeat stderr redirected to `winlogbeat-9.3.3-windows-x86_64/logs/winlogbeat_stderr.log` for persistent diagnostics

**`xdr_runtime.py` — log file glob fix:**
- `read_ndjson_logs()` was globbing `*.ndjson` but Winlogbeat 9.x writes files named `winlogbeat`, `winlogbeat.1`, etc. (no extension)
- Changed glob pattern to match both `winlogbeat*` and `*.ndjson` so the user behavior inference engine picks up real log files

---

## Current System Status

| Component | Status |
|-----------|--------|
| Suricata | Running and capturing live traffic (auto-started by `/start-monitoring`) |
| Winlogbeat | Running and writing to `C:\XDR_Logs\winlogbeat` — no more panic |
| Network flows — dashboard | All flows (NORMAL + ATTACK) stream to the SOC dashboard in real time |
| User behavior — dashboard | All user sessions (NORMAL + ANOMALY) emitted to the User Behavior Panel |
| MongoDB Atlas | Only anomalies and attacks persisted; storage headroom preserved |

---

## Outstanding Work

1. **Sysmon** — not installed; installing it would enrich the `Microsoft-Windows-Sysmon/Operational` event log with per-process network and file telemetry (optional but recommended)
2. **Train `network_classifier.pkl`** — run `train_classifier.py` against the CIC-IDS2017 dataset in `Network Behavior/CICDS_dataset/`
3. **Train `personal_baseline_model.pkl`** — run `collect_baseline.py` (30-60 min capture) then `train_personal_model.py`
4. **OCEAN personality features** — hardcoded to 0.0; no data source connected
5. **SHAP explainability** — `shap_agent.py` exists but `TreeExplainer` not wired to `network_classifier.pkl`
6. **System LSTM Autoencoder** — not implemented
7. **Malware RF (EMBER)** — not implemented
8. **SOAR endpoint polling loop** — command documents written to MongoDB `commands` collection but no endpoint agent executes them yet

---

*Next Analysis Recommended: After `network_classifier.pkl` is trained and first real attack classification result flows through the fusion engine.*
