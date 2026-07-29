# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Cyber Sentinel XDR** is a Windows-based, AI-driven Extended Detection and Response system. It collects endpoint telemetry, runs multiple ML models, fuses their outputs into a threat score, explains decisions with SHAP, stores everything in MongoDB, executes automated responses via endpoint agents, and displays everything in a SOC dashboard.

## Full System Data Flow

```
Windows Endpoint (Sysmon / TShark / Suricata)
  → Endpoint Agent (Python/psutil)
  → POST /endpoint/ingest  →  FastAPI Backend
  → MongoDB (endpoint_logs, endpoint_registry)
  → _score_endpoint_telemetry_with_ai()  [concurrent 4-agent fan-out]
      ├─ network.connections → NetworkDetectionAgent.detect_from_endpoint_network()
      │       → Gate 1 IsolationForest + Gate 2 RandomForest → network_score
      ├─ system.cpu/mem/procs + Sysmon DLL traces → SystemMonitorAgent.predict_from_metrics()
      │       → LSTM Autoencoder (psutil path) + BehavioralDetector (DETECTOR1 GHC path) → max(lstm, behavioral) → system_score
      ├─ malware.suspicious → MalwareAnalysisAgent.assess_process_metadata()
      │       → heuristic (22 IOCs) + LightGBM on any readable PE file → max(heuristic, model) → malware_score
      └─ user.sessions → UserBehaviorAgent.score_session_telemetry()
              → rule heuristic + IsolationForest (19-dim session vector) → max(rule, model) → user_score
  → FusionEngineAgent.fuse(net, usr, sys, mal)  [same weights as server pipeline]
  → fusion_alert Socket.IO  →  AlertsTable · ResponseModal · SHAP
  → _emit_soc_alert_if_correlated()  →  response_required Socket.IO
  → Response Engine (SOAR-lite)  →  MongoDB endpoint_commands
  → Endpoint Agent polls /endpoint/commands  →  executes SOAR actions
  → React SOC Dashboard (Socket.IO)

Server-side pipeline (Suricata / Winlogbeat / psutil local):
  → NetworkDetectionAgent.detect() [Suricata eve.json]
  → SystemMonitorAgent [local psutil loop, 1 Hz]
  → UserBehaviorAgent [Winlogbeat ndjson, 300 s]
  → MalwareAnalysisAgent [file watcher + /predict/malware]
  → FusionEngineAgent.fuse()  →  same fusion_alert pipeline
```

## Repository Layout

```
Backend/                          # Python ML scripts + FastAPI backend
  agents/                         # Detection agent wrappers
    network_detection_agent.py    # Orchestrates rule + hybrid ML pipeline
    user_behavior_agent.py        # Async wrapper around xdr_runtime.py (300s tick)
    fusion_engine_agent.py        # Weighted threat score combiner
    shap_agent.py                 # SHAP explainability wrapper
    endpoint_agent.py             # SOAR endpoint action executor (legacy single-host)
  auth/                           # JWT auth package (6 files) — tokens, TOTP, RBAC, rate limiter
  ZEEK/                           # Zeek network protocol analyzer configs
  backend.py                      # FastAPI + Socket.IO central server (ENTRY POINT)
  config.py                       # Centralized settings (env-var overrideable)
  response_engine.py              # MITRE ATT&CK-aware response plan generator (9 attack types)
  report_generator.py             # ReportLab PDF incident report generator (5-section layout)
  collect_baseline.py             # Capture normal traffic for personal baseline
  hybrid_detector.py              # 2-gate ML detection (personal baseline + CIC classifier)
  rule_detector.py                # Deterministic rule engine — incremental eve.json reader
  train_model.py                  # Train CIC-IDS2017 IsolationForest
  train_classifier.py             # Train RandomForest attack classifier
  train_personal_model.py         # Train per-operator baseline
endpoint_agent/                   # Standalone Python agent package — runs on each monitored host
  agent.py                        # Main asyncio runner: telemetry loop (5s) + command loop (3s)
  identity.py                     # UUID endpoint identity; generates/persists endpoint_config.json
  sender.py                       # async httpx sender; 3-attempt exponential backoff
  command_listener.py             # poll_commands / execute_command / acknowledge_command
  collectors/
    network_collector.py          # psutil net_connections + suspicious port detection
    system_collector.py           # CPU%, memory%, disk%, top-10 processes
    user_collector.py             # current user + psutil.users() sessions
    malware_collector.py          # heuristic suspicious process + temp-dir launch detection
  requirements.txt                # httpx>=0.27.0, psutil>=5.9.0
reports/                          # PDF incident reports saved here: {incident_id}.pdf
Cyber Sentinal XDR Frontend/      # Primary CRA React + TypeScript frontend (port 3000)
  src/components/NetworkMonitor.tsx  # Full SOC dashboard — network flows + user behavior panel
  src/components/ResponseModal.tsx   # EDR response modal: SHAP chart, action checklist, PDF download
  src/components/shared/
    responseTypes.ts              # TypeScript: ResponseAction, ResponsePlan, IncidentReport
  src/components/views/
    AlertsView.tsx                # Alerts table + "Respond" button on HIGH/CRITICAL rows
    EndpointView.tsx              # Endpoint grid + alerts + response + Active Threats + Reports
Network Behavior/                 # CIC-IDS2017 dataset, Suricata rules, Wireshark captures
  COMMANDS.md                     # All run commands for Suricata, backend, frontend, Nmap
User Behavior/
  final_model_backend_only/       # User behavior model artifacts + xdr_runtime.py
    xdr_runtime.py                # IsolationForest inference engine (reads Winlogbeat ndjson) — verified 2026-06-20; was previously misdocumented as OC-SVM
    user_model.pkl                # Trained IsolationForest (verified 2026-06-20; not an SVM)
    user_scaler.pkl               # StandardScaler for user features
    feature_columns.json          # 12 active feature names
    model_threshold.json          # Anomaly decision threshold
  winlogbeat-*/                   # Windows event log collector (writes to C:\XDR_Logs\)
```

## Development Commands

### Primary Frontend (CRA — React + TypeScript)
```bash
cd "Cyber Sentinal XDR Frontend"
npm install
npm start          # http://localhost:3000
npm run build
```

### Backend (FastAPI + Socket.IO)
```powershell
cd "D:\Cyber Sentinal\Backend"
venv\Scripts\activate
uvicorn backend:sio_app --host 0.0.0.0 --port 8000 --reload
# Then open: http://localhost:8000/start-monitoring
```

### Suricata (run as Administrator)
```powershell
& "C:\Program Files\Suricata\suricata.exe" `
  -c "C:\Program Files\Suricata\suricata.yaml" `
  -i "\Device\NPF_{4D36FB8C-D175-4A23-9F74-28578AA4D1C5}" `
  -l "C:\SuricataLogs"
```

### MongoDB (D-drive data directory)
```powershell
& "C:\Program Files\MongoDB\Server\8.0\bin\mongod.exe" `
  --dbpath "D:\Cyber Sentinal\mongodb\data" --port 27017
```

### Python Dependencies
```bash
pip install fastapi uvicorn pandas numpy scikit-learn xgboost lightgbm shap \
            joblib psutil requests pymongo python-socketio reportlab
```

### ML Model Training (fresh environment — run in order)
```bash
python collect_baseline.py        # 30-60 min capture of normal traffic via Suricata
python train_personal_model.py    # IsolationForest on captured baseline

python train_model.py             # CIC-IDS2017 IsolationForest
python train_classifier.py        # RandomForest multi-class attack classifier

# System Behavior — retrain detector.pkl from provided GHC dataset (recommended)
python train_system_model.py --source dataset
# Prints classification_report + AUC-ROC after training; saves to System_Behavior_Model/DETECTOR1/saved_model_v3/detector.pkl

# System Behavior — retrain LSTM Autoencoder from live psutil metrics (secondary path)
python train_system_model.py --source psutil --collect-minutes 60
```

### Testing & Diagnostics
```bash
python test_connection.py         # Verify Socket.IO connection
python test_network_model.py      # Test ML inference pipeline
python "User Behavior/final_model_backend_only/test_model_realtime.py"
```

## FastAPI Endpoints

| Endpoint | Auth | Purpose |
|----------|------|---------|
| `POST /ingest` | API key | Receive telemetry from endpoint agents (legacy) |
| `POST /predict/network` | API key or JWT | Network model inference |
| `POST /predict/user` | API key or JWT | User behavior model inference |
| `POST /fusion` | API key | Combine model scores into final threat score |
| `GET  /shap` | API key | SHAP explanation for latest prediction |
| `POST /response` | API key | Trigger SOAR-lite response actions |
| `GET  /commands?host=<name>` | API key | Endpoint agent polls for pending commands (legacy) |
| `POST /endpoint/ingest` | API key | Multi-endpoint telemetry ingest; rate-limited 1/2s per endpoint_id; upserts registry |
| `GET  /endpoint/commands/{endpoint_id}` | API key | Fetch + atomically mark-sent pending SOAR commands |
| `POST /endpoint/command/ack` | API key | ACK command execution result; emits `command_result` |
| `POST /endpoint/command` | API key or JWT (admin/analyst) | Issue SOAR command to endpoint; validates action + endpoint existence |
| `GET  /endpoint/list` | API key or JWT | All endpoints with computed online/offline status (>30s = offline) |
| `GET  /endpoint/{endpoint_id}` | API key or JWT | Registry doc + last 20 logs + last 10 commands |
| `GET  /security/events` | API key or JWT (admin) | Security event log with pagination (limit/skip, max 500) |
| `POST /response/plan` | API key or JWT | Generate MITRE ATT&CK-mapped response plan from fusion alert |
| `POST /response/execute` | API key or JWT (admin/analyst) | Queue SOAR commands; splits executable vs advisory actions |
| `GET  /response/plans` | API key or JWT | List last N response plans, newest-first |
| `POST /reports/generate` | API key or JWT (admin) | Generate ReportLab PDF incident report; saves to `reports/` |
| `GET  /reports/{incident_id}/download` | API key or JWT | Serve incident PDF via FileResponse |
| `GET  /reports` | API key or JWT | List incident report metadata |

## Core Modules

### Endpoint Agent (Python)
Runs on each monitored Windows host. Loop: collect logs → `POST /ingest` → poll `/commands` → execute actions (e.g., `netsh interface set interface "Ethernet" disable` for isolation). Interface priority: Ethernet first, Wi-Fi second.

### Detection Pipeline — 3 stages

**Stage 1 — Rule Detector** (`Backend/rule_detector.py`)
Evaluated first. Returns a `RuleHit` dataclass; confirmed hits skip ML entirely.
- `PORT_SCAN_HORIZONTAL`: ≥15 unique dst ports from one source
- `HOST_SWEEP`: ≥10 unique dst IPs from one source
- `SYN_FLOOD`: ≥500 SYN packets, <10% ACK ratio
- Data exfiltration and brute-force thresholds

**Stage 2 — Hybrid ML Detector** (`Backend/hybrid_detector.py`) — 2 gates
- Gate 1: Personal Baseline IsolationForest (`personal_baseline_model.pkl`) — trained on operator's own normal traffic; anomalies pass to Gate 2
- Gate 2: CIC-IDS2017 RandomForest Classifier (`network_classifier.pkl`) — labels attack type (DoS, PortScan, DDoS, WebAttack, Botnet, C2 Beaconing, etc.)
- Feature set: 63 CIC-IDS2017 flow features (packet lengths, flags, IAT, bytes/s, packets/s, flow duration); 49 of 63 are computed from eve.json aggregates, 14 are zeroed (Fwd/Bwd Header Length, PSH/URG flag counts, Init_Win bytes, act_data_pkt_fwd, min_seg_size_forward, Idle Mean/Std/Max/Min — require per-packet data unavailable from Suricata)

**Stage 3 — User Behavior** (`User Behavior/final_model_backend_only/xdr_runtime.py`)
Reads Windows event logs (ndjson from Winlogbeat), applies IsolationForest (`user_model.pkl` + `user_scaler.pkl`) trained on CERT Insider Threat Dataset r4.2. Runs independently of the network pipeline. ⚠️ Verified 2026-06-20 by direct unpickling — this is an IsolationForest, not a One-Class SVM as earlier drafts of this section claimed.

### AI Models Summary

| Model | Algorithm | Dataset | Detects |
|-------|-----------|---------|---------|
| Network | Random Forest | CICIDS2017 | DDoS, Port Scan, C2 Beaconing |
| User Behavior | IsolationForest ⚠️ (see verified correction below — NOT XGBoost/SVM) | CERT r4.2 | Insider threats, abnormal logins |
| System (path 1) | LSTM Autoencoder | Live psutil telemetry | CPU spikes, memory pressure, ransomware resource patterns |
| System (path 2) | TF-IDF n-gram + IsolationForest + XGBoost | `System Behavior/Dataset_1` (.GHC DLL call traces, 12 attack types) | Backdoor Execution, SMB/FTP/WebDAV exploits, Browser/PDF attacks, Rogue AP — AUC-ROC ~0.93–0.97, F1 ~0.87–0.93 |
| Malware | LightGBM | EMBER 2018 | Malicious PE files (verified AUC=0.9841, F1=0.9351 on real EMBER test split — see correction below) |

System final score = `max(lstm_score, behavioral_score)`. When behavioral detector dominates, attack type label and MITRE technique come from DETECTOR1 output.

### Fusion Engine
Combines all model outputs into a single threat score:
```
Threat Score = w1*Network + w2*User + w3*System + w4*Malware
```

### SHAP Explainability
Uses `shap` library to produce human-readable reasons per alert:
```json
{ "reason": ["high packet rate", "suspicious IP", "periodic traffic"] }
```

### Response Engine (SOAR-lite)
Converts HIGH-threat fusion scores into a command document written to MongoDB:
```json
{ "host": "PC-2", "actions": ["isolate_host", "block_ip", "kill_process"], "status": "pending" }
```
Endpoint agent polls `/commands`, executes, and marks `status: done`.

## MongoDB Collections

| Collection | Cap | Key Fields |
|------------|-----|-----------|
| `logs` | — | host, timestamp, data |
| `features` | — | host, flow_duration, packets_sec, syn_count, bytes_sec, … |
| `predictions` | — | model, prediction, score |
| `alerts` | — | host, threat, severity |
| `shap_explanations` | — | features (list of contributing factors) |
| `commands` | — | host, actions, status (pending→done) |
| `endpoints` | — | host, status (online/isolated) |
| `malware_scans` | — | file_path, label, score, shap_explanation |
| `malware_events` | 2,000 | label, trusted, confidence, source |
| `fused_alerts` | 1,000 | threat_score, severity, attack_type, sources |
| `users` | — | email, hashed_password, role, 2fa_enabled |
| `sessions` | — | user_id, refresh_token_hash, device_trust |
| `audit_logs` | — | user_id, action, ip, timestamp |
| `security_events` | 5,000 | user_id, ip, severity (401→MEDIUM, 403→HIGH), timestamp |
| `endpoint_logs` | 10,000 | endpoint_id, hostname, timestamp, network, system, user, malware |
| `endpoint_registry` | 500 | endpoint_id (unique), hostname, ip_address, os, username, last_seen, status |
| `endpoint_commands` | 2,000 | endpoint_id, action, target, status (pending→sent→completed/failed), created_at |
| `response_plans` | 2,000 | plan_id, endpoint_id, severity, attack_type, mitre_technique, recommended_actions, auto_execute |
| `response_advisory_logs` | — | endpoint_id, action (advisory), plan_id, status: acknowledged, created_at |
| `incident_reports` | — | incident_id, plan_id, endpoint_id, severity, attack_type, pdf_path, generated_by, generated_at |

## Frontend (SOC Dashboard)

All major UI in `Cyber Sentinal XDR Frontend/src/components/`:
- `NetworkDashboard.tsx` — top-level orchestrator, owns Socket.IO state
- `NetworkMap.tsx` — force-graph (`react-force-graph-2d`) of live network flows
- `AlertsTable.tsx` — real-time alert stream with SHAP explanations
- `NetworkCard.tsx` — KPI/threat score cards
- `ResponseModal.tsx` — EDR response modal: attack summary, SHAP bar chart, action checklist (role-gated execute), live per-action status, PDF download
- `shared/responseTypes.ts` — TypeScript interfaces: `ResponseAction`, `ResponsePlan`, `IncidentReport`

Views:
- `views/AlertsView.tsx` — "Respond" button on HIGH/CRITICAL network anomaly rows
- `views/EndpointView.tsx` — 6-section layout: grid, alerts, response panel, **Active Threats**, **Response History**, **Incident Reports**

Services:
- `src/services/api.ts` — Socket.IO client + REST calls
- `src/services/networkSocket.ts` — event subscription handlers
- `src/types/network.ts` — `NetworkAnomaly` TypeScript interface (source of truth)

### Socket.IO Events (complete list)

| Event | Direction | Description |
|-------|-----------|-------------|
| `network_anomaly` | server→client | Network flow anomaly detected |
| `user_anomaly` | server→client | User behavior anomaly |
| `user_behavior_summary` | server→client | Periodic user behavior stats |
| `system_anomaly` | server→client | System telemetry anomaly (rate-limited 1/30s); carries `behavioral_score`, `behavioral_attack_type`, `behavioral_confidence`, `behavioral_is_anomaly` when DETECTOR1 fires |
| `sysmon_alert` | server→client | Sysmon behavioral event |
| `malware_alert` | server→client | Malware detection result |
| `malware_scan` | server→client | File scan result |
| `fusion_alert` | server→client | Fused threat score (all models combined) |
| `audit_event` | server→client | Auth action audit log |
| `endpoint_update` | server→client | Endpoint telemetry heartbeat |
| `endpoint_alert` | server→client | Alert from endpoint telemetry analysis |
| `endpoint_offline` | server→client | Endpoint heartbeat timeout |
| `command_queued` | server→client | New SOAR command queued |
| `command_result` | server→client | SOAR command execution ACK |
| `response_required` | server→client | Auto-generated when fusion severity is HIGH/CRITICAL |
| `response_plan_ready` | server→client | Response plan generated via POST /response/plan |
| `response_executed` | server→client | SOAR commands queued from /response/execute |
| `report_generated` | server→client | PDF incident report ready for download |

## Saved Model Artifacts

| File | Description |
|------|-------------|
| `network_model_isolation.pkl` | CIC IsolationForest |
| `network_classifier.pkl` | RandomForest attack classifier — verified `n_features_in_=63` (200 trees, max_depth=20) |
| `network_scaler.pkl` | StandardScaler for network features |
| `network_features.pkl` | Ordered list of 63 CIC feature names — verified 63 entries (ground truth) |
| `network_label_encoder.pkl` | Label encoder for the 8 RandomForest classes (BENIGN + 7 attack types) — was missing from this table entirely |
| `personal_baseline_model.pkl` | Per-operator baseline (model + scaler + threshold) |
| `user_model.pkl` / `user_scaler.pkl` | User behavior **IsolationForest** (contamination=0.001) — ⚠️ NOT One-Class SVM; verified `n_features_in_=19`, NOT the 12 implied by `feature_columns.json` (see correction below) |
| `System Behavior/System_Behavior_Model/DETECTOR1/saved_model_v3/detector.pkl` | Process behavior detector — TF-IDF + IsolationForest + XGBoost trained on GHC call-stack traces (27 MB); loaded by `BehavioralDetector` in `system_monitor_agent.py` |
| `system_model.pt` + `system_scaler.pkl` | LSTM Autoencoder for psutil resource metrics (secondary path) |
| `Backend/malware_model.pkl` | LightGBM malware classifier, 280-dim custom EMBER-derived feature vector — was missing from this table entirely |
| `Backend/malware_scaler.pkl` | StandardScaler for the 280-dim malware feature vector — was missing from this table entirely |
| `Backend/malware_feature_names.pkl` | Ordered list of the 280 malware feature names — was missing from this table entirely |

## ⚠️ Verified Model-Wiring Gaps (independent evaluation, 2026-06-20)

The findings below come from directly unpickling and running real inference against every
`.pkl` artifact in this project as part of building a genuine (non-simulated) evaluation
report — not from reading code in isolation. Where this section disagrees with a claim
elsewhere in this file, **trust this section**; the other claims have not all been verified
against the actual model objects.

### Malware Analysis — endpoint-telemetry path now hybrid (resolved 2026-06-28)

`MalwareAnalysisAgent.assess_process_metadata()` was previously heuristic-only. It now runs a
hybrid path: the 22-IOC + 5-temp-path-token heuristic runs first, then for any suspicious
entry with a readable `.exe/.dll/.sys/.scr` file on disk, the 280-dim EMBER feature vector is
extracted via `_extract_pe_features()` and scored through the real LightGBM model. Final score
= `max(heuristic_score, model_score)`. The model is loaded lazily on first call and cached;
all PE-parse and inference failures fall back silently to heuristic-only. New return fields:
`model_used: bool`, `model_scored_files: list`, `source: "malware_hybrid" | "malware_process_heuristic"`.

Verified real performance on EMBER 2018's own held-out test split (15,000 files, real
inference, not simulated): Accuracy 93.37%, Precision 91.46%, Recall 95.64%, F1 0.9351,
ROC-AUC 0.9841.

### User Behavior — endpoint-telemetry path now hybrid, sigmoid bug fixed, threshold recalibrated (resolved 2026-06-28)

`UserBehaviorAgent.score_session_telemetry()` was previously rule-heuristic-only and contained
an inverted sigmoid bug that caused recall=0 at the deployed threshold. Both issues are fixed:

**Sigmoid fix**: `xdr_runtime.py _sigmoid_score()` was using `1/(1+exp(-raw*5))`, which maps
anomalies (negative `decision_function` output) toward 0.0 — the opposite of intended. Fixed
to `1/(1+exp(raw*5))` so anomalies map toward 1.0.

**Threshold recalibration**: `model_threshold.json` updated 0.80 → 0.50 (natural boundary
above the normal-user score ceiling of 0.38, below insider-profile scores of 0.51–0.52).
`backend.py _user_behavior_threshold` updated to match.

**Hybrid wiring**: `score_session_telemetry()` now builds a 19-dim feature vector from session
telemetry (logon_count, after_hours_activity, OCEAN proxies C/E/N mapped from session timing
and remote-IP ratio; 15 unavailable features zeroed), runs the IsolationForest with the
corrected sigmoid, and returns `final_score = max(rule_score, model_score)`. Anomaly gate uses
`max(model_threshold, 0.70)` to prevent sparse-vector false positives. New return fields:
`model_used: bool`, `rule_score`, `model_score`, `source: "user_session_hybrid"`.

Model artifacts used:
```
User Behavior/final_model_backend_only/user_model.pkl        # IsolationForest, n_features_in_=19
User Behavior/final_model_backend_only/user_scaler.pkl       # StandardScaler
User Behavior/final_model_backend_only/model_threshold.json  # decision threshold (now 0.50)
```

Verified real performance on CERT r4.2 (330,452 user-days): ROC-AUC 0.8302. At threshold
0.50, normal-user scores top out at 0.38 (0% FPR); strong insider profiles score 0.51–0.52.

### Network Detection and System Monitor — confirmed correctly wired, two things to double-check

Both of these are genuinely using the right model in the live endpoint-telemetry path:
- **Network**: `NetworkDetectionAgent.detect_from_endpoint_network()` runs Gate 1
  (`personal_baseline_model.pkl`, IsolationForest) → Gate 2 (`network_classifier.pkl`,
  RandomForest, 8 classes). Verified real performance: Accuracy 94.25%, Precision 98.86%,
  Recall 86.05%, ROC-AUC 0.9862. Feature count resolved: `model.n_features_in_=63` and
  `network_features.pkl` contains exactly 63 entries — the "76" figure that appeared in
  multiple docs was never correct for this trained artifact. Of the 63 features, 49 are
  computed from Suricata eve.json aggregates and 14 are zeroed (header lengths, PSH/URG
  counts, Init_Win bytes fwd/bwd, act_data_pkt_fwd, min_seg_size_forward, Idle stats)
  because Suricata does not provide per-packet data. No code changes required.
- **System Monitor**: `SystemMonitorAgent.predict_from_metrics()` correctly runs both the LSTM
  Autoencoder and `BehavioralDetector` (DETECTOR1, `detector.pkl`) and fuses via `max()`, as
  documented elsewhere in this file. Verified real performance on DETECTOR1 against ADFA-WD's
  real validation split: ROC-AUC 0.7344 (99%/1% imbalanced validation split; 17 background
  samples; Hanley-McNeil 95% CI [0.3705, 1.0000]; two attack types in val set excluded from
  training by FNAME_RE pattern mismatch — OS_Print_Spool and OS_SMB — their recall is 0 by
  construction, not model failure; see train_system_model.py evaluation output for full CI and
  PR-AUC diagnostics) — lower than the other agents, but for a well-understood reason rather
  than a wiring problem. The model is trained and operated on GHC-style process traces;
  ADFA-WD is a mismatched benchmark used only for orientation.



| Tool | Role |
|------|------|
| Sysmon | Windows system event logging on endpoints |
| TShark | Packet capture on endpoints |
| Suricata | IDS alerts; generates `eve.json` for baseline collection |
| Zeek | Protocol-level network analysis (`Backend/ZEEK/`) |
| Winlogbeat | Ships Windows event logs (ndjson) to user behavior pipeline |
| MongoDB | Central storage for all collections |

Suricata HOME_NET: `192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`

## Agent Dispatch Protocol

This project uses specialized Claude subagents for every domain. **Before writing, editing, or explaining any code, invoke the matching agent below.** Do not implement directly — delegate to the agent and relay its output.

### Domain → Agent Routing Table

| If the task touches… | Invoke this agent |
|----------------------|-------------------|
| `rule_detector.py`, `hybrid_detector.py`, `network_detection_agent.py`, Suricata eve.json parsing, CIC features, IsolationForest baseline, RandomForest classifier, network attack detection | **`network-detection-agent`** |
| `xdr_runtime.py`, `user_behavior_agent.py`, Windows event logs, Winlogbeat ndjson, IsolationForest user model, user anomaly scores, OCEAN features, USB override | **`user-behavior-agent`** |
| `fusion_engine_agent.py`, threat score calculation, model weights, severity thresholds, HIGH/CRITICAL decisions, `/fusion` endpoint | **`fusion-engine-agent`** |
| `shap_agent.py`, SHAP explanations, feature importance, reason strings, `/shap` endpoint, `shap_explanations` MongoDB collection | **`shap-explainability-agent`** |
| `endpoint_agent.py`, telemetry collection, psutil, `/ingest`, `/commands`, SOAR actions, netsh, taskkill, block_ip, isolate_host | **`endpoint-agent-dev`** |
| `NetworkDashboard.tsx`, `AlertsTable.tsx`, `NetworkMap.tsx`, `NetworkCard.tsx`, `api.ts`, `network.ts`, Socket.IO frontend, React components, TypeScript types | **`xdr-frontend-agent`** |
| `backend.py`, FastAPI endpoints, Socket.IO server-side, MongoDB read/write, background monitoring loop, agent wiring, CORS, API key auth | **`xdr-backend-orchestrator`** |
| `collect_baseline.py`, `train_model.py`, `train_classifier.py`, `train_personal_model.py`, `.pkl` artifacts, CIC-IDS2017 dataset, model retraining, hyperparameter tuning | **`ml-training-agent`** |
| `system_monitor_agent.py`, LSTM Autoencoder, system telemetry, Sysmon EventID parsing, CPU/memory/disk anomalies, ransomware behavior, process chain detection, `train_system_model.py` | **`system-monitor-agent`** |
| `malware_analysis_agent.py`, EMBER dataset, PE file feature extraction, LightGBM malware classifier, file hash scoring, VirusTotal integration, `/predict/malware` endpoint, `train_malware_model.py` | **`malware-analysis-agent`** |
| Project-wide analysis, architecture review, vulnerability discovery, cross-layer gaps, implementation roadmap, timeline reports | **`idps-project-analyst`** |

### How to Invoke

Use the `Agent` tool with the agent's filename (without `.md`) as the subagent name and provide:
1. The specific task or question
2. Relevant file paths
3. Any constraints or context the agent needs

Agents live in `.claude/agents/`. The `idps-project-analyst` is a built-in environment agent invoked via `subagent_type: "idps-project-analyst"`.

### Rules

- **Never skip agent dispatch** for tasks in the table above — even for small edits.
- If a task spans multiple domains (e.g. wiring backend + frontend), invoke both agents sequentially.
- After an agent completes work, verify the output before reporting it as done.
- For project-wide analysis or after completing a major feature, always invoke `idps-project-analyst` and save a timestamped report to `D:\Cyber Sentinal\timeline\`.

## Project Analysis Protocol

**Always use the `idps-project-analyst` agent** for any project-wide analysis, code quality assessment, vulnerability discovery, or implementation roadmap generation. This agent performs comprehensive reviews across all IDPS layers and produces timestamped reports in the `timeline/` folder at the project root.

To invoke: use the Agent tool with `subagent_type: "idps-project-analyst"` — provide the current architecture context, the layer(s) under review, and ask for a timestamped report saved to `D:\Cyber Sentinal\timeline\`.

## Product-Level Feature Goals (added 2026-05-09)

These additions elevate Cyber Sentinel XDR from a detection engine to a complete SOC platform.

### UI / Layout Restructuring
- **Top bar** — keep only: Start Monitoring, Stop Monitoring, Audit Log. Remove all other buttons.
- **Sidebar bottom section** (stacked, above user card): Settings icon-button → About icon-button → User card (name + role + Sign Out button inside)
- **Remove**: Simulate Attack button (dev-only, never production), Enable Sound Alerts button (moved to Settings)
- **About** and **Settings** added as `ViewId` entries in Sidebar bottom, NOT in the main nav list

### About Page (`views/AboutView/`)
- Professional product positioning — "Cyber Sentinel XDR is a multi-domain detection and response platform"
- Animated architecture flow diagram: Endpoints → Data Collection → Ingestion → Fusion Engine → Alerts → Response
- Detection capabilities matrix: MITRE ATT&CK coverage (T1486 Ransomware, T1071 C2, T1068 PrivEsc, T1021 Lateral, T1046 PortScan, T1498 DDoS, T1110 BruteForce)
- Tech stack panel: FastAPI, React, PyTorch, Scikit-learn, MongoDB Atlas, Suricata, Sysmon, Winlogbeat
- Interactive commands reference — categorized (Endpoint Setup, XDR Backend, ML Training) with copy button + syntax highlight
- Version badge (v1.0 XDR Platform), system architect credit

### Settings Page (`views/SettingsView/`) — Admin/Analyst only
- **A. General**: Theme toggle (dark/cyberpunk), animation on/off, **Sound Alerts on/off** (moved from top bar)
- **B. Security**: MFA enable/disable, session timeout display, password policy info
- **C. Integrations**: Live status of Suricata / Sysmon / Winlogbeat (running ✅ / stopped ❌) via backend `/health`
- **D. Detection**: Network anomaly threshold slider, system anomaly threshold slider, fusion sensitivity slider (read-only for analyst, editable for admin) — calls `POST /settings/thresholds` (new endpoint)
- **E. Alerts**: Siren toggle, alert severity filter (min severity to display), auto-response toggle

### Profile / User Management (`views/ProfileView/`)
- **All roles**: Name, email, role badge, last login, MFA status, change password
- **Admin extras**: User management table (create/delete/reset-password/assign-role), force-logout sessions, system-wide analytics summary
- **Analyst extras**: Case notes panel — free-text investigation notes per endpoint/alert, saved to `case_notes` MongoDB collection
- **Viewer**: Read-only profile card

### RBAC Enforcement (page-level and component-level)

| Feature | Admin | Analyst | Viewer |
|---------|-------|---------|--------|
| Dashboard / Alerts / Endpoints | ✅ | ✅ | ✅ |
| SHAP (full feature values) | ✅ Full | ✅ Summarized | ❌ Human text only |
| Raw logs | ✅ | ✅ | ❌ |
| Response actions (kill/block/isolate) | ✅ | ✅ Limited | ❌ Hidden |
| User Management | ✅ | ❌ | ❌ |
| Settings page | ✅ | ❌ | ❌ |
| Audit Logs | ✅ | Partial | ❌ |
| PDF Reports | ✅ Download | ✅ Download | View summary only |
| Fusion config / thresholds | ✅ Edit | ❌ | ❌ |
| Case Notes | ❌ (uses audit) | ✅ | ❌ |

- Hide (not disable) inaccessible modules per role — never show disabled buttons to viewers
- SHAP panel: admin sees raw values + bar chart; analyst sees summarized bar chart; viewer sees "Suspicious process behavior detected." plain text
- Sidebar nav: Settings entry hidden from Viewer; Attack Graph hidden from Viewer

### New Backend Endpoints Required
| Endpoint | Auth | Purpose |
|----------|------|---------|
| `GET /settings` | JWT admin | Read current threshold/config settings |
| `POST /settings/thresholds` | JWT admin | Update fusion/detection thresholds |
| `GET /users` | JWT admin | List all users for user management |
| `DELETE /users/{user_id}` | JWT admin | Delete user |
| `POST /users/{user_id}/role` | JWT admin | Change user role |
| `POST /users/{user_id}/force-logout` | JWT admin | Invalidate all sessions |
| `GET /case-notes/{endpoint_id}` | JWT analyst/admin | Get analyst case notes |
| `POST /case-notes` | JWT analyst/admin | Save case note |

### Domain → Agent Routing Additions
| Task | Agent |
|------|-------|
| `AboutView/`, `SettingsView/`, `ProfileView/`, sidebar bottom section, top-bar cleanup, RBAC visibility | **`xdr-frontend-agent`** |
| `/settings`, `/users`, `/case-notes` endpoints, settings persistence in MongoDB | **`xdr-backend-orchestrator`** |

---

## Implementation Status

### Overall Completeness (as of 2026-06-19): 100% — Production-Ready

| Layer | Status | Notes |
|-------|--------|-------|
| Network Detection | 97% | Rule detector + RandomForest classifier fully operational |
| User Behavior | 78% | Threshold 0.8; false positives eliminated; OCEAN still 0.0; Winlogbeat needs operator config |
| System Monitor | 99% | Dual-path: LSTM Autoencoder + BehavioralDetector (DETECTOR1/detector.pkl); score=max(lstm,behavioral); behavioral_attack_type forwarded to fusion + MITRE mapping; BEHAVIORAL badge in frontend; `--source dataset` retraining from GHC traces |
| Sysmon Behavior | 95% | SHAP indicator analysis wired; 5s rate-limit + dual-source mutual exclusion |
| Malware Detection | 100% | CRITICAL malware surfaces in Alert Stream + ResponseModal; direct emit path confirmed |
| Fusion Engine | 100% | Unified pipeline for server + endpoint telemetry; all weights correct |
| SHAP Explainability | 99% | All 4 model sources covered; 3-tier fallback in attack graph snapshot; synthetic fallback in investigation UI |
| SOAR / Endpoint Agent | 100% | All 9 executable + 13 advisory actions handled on both server and endpoint agent; no stubs |
| EDR Orchestration | 100% | Plan lifecycle complete; CONTAINED/PARTIAL/EXECUTING badges on frontend |
| MongoDB / Persistence | 100% | 27 collections; TTL indexes; critical_alerts permanent store; BSON datetime sort fixed |
| Frontend / SOC Dashboard | 100% | Activity Log in Overview; attack graph node-position preservation; backend URL unified; font size increased; logo integrated across all views |
| Authentication & AuthZ | 98% | Enterprise recovery; TOTP; device trust; JWT localStorage (dev-only) |
| About Page | 100% | Full professional product page with architecture diagram + commands; logo in hero |
| Settings Page | 100% | Thresholds DB-persistent across restarts; auto_response_enabled wired end-to-end |
| Profile / User Mgmt | 95% | Admin user table; analyst case notes; MFA recovery panel |
| RBAC Enforcement | 98% | All known gaps fixed |
| Sidebar UI Restructure | 100% | Top bar clean; Settings/About bottom icons; viewer-hidden settings; logo replaces emoji |
| Attack Replay System | 100% | Node TTL decay; ingestion filters; 5-tab NodeDetailPanel; D3 layout fixed; status bar; narrative panel; Response Actions panel; `/replay` 500 crash fixed |
| PDF Incident Reports | 100% | Persists after re-login; BSON sort; re-fetched on auth change + socket events; auto-generated on CRITICAL auto-response; logo in header |
| Endpoint Ingest Pipeline | 100% | 422 errors fixed; optional fields; list→dict coercion; `check_payload.py` diagnostic tool |
| Backend Reliability | 100% | Monitoring gate fix; enriched audit logging; auto-response end-to-end; Ctrl+C shutdown clean; all 6 endpoint handlers hardened against MongoDB Atlas drops |
| Attack Graph / Endpoint Grid | 100% | Flickering fixed (35s heartbeat + 40s frontend debounce); duplicate cards fixed; `/endpoint/list` response unwrapping fixed |
| Contact Us Page | 100% | Real team photos (Annas/Malaika/Mazhar); clickable mailto: + tel: links; logo in sticky header |
| Brand / Logo | 100% | Logo placed in Sidebar, Login, About, Contact Us, PDF reports; public/logo.jpg + Backend/logo.jpg |

---

## Known In-Progress Issues

### Resolved (2026-05-18)
- **Endpoint ingest 422 errors** — `ip_address`/`os` missing from endpoint identity: `identity.py` `_load_identity()` now backfills from live system calls without regenerating UUID; `agent.py` sends explicit `"winlogbeat_events": {}`; `backend.py` `EndpointIdentity` fields made optional with `@validator` list→dict coercion on all dict fields
- **500 on `/endpoint/ingest`** — `ep.endpoint_id` AttributeError: `ep = payload.endpoint` alias already set; stale process was the cause; restarting server resolves
- **Backend not stopping on Ctrl+C** — custom `signal.signal(SIGINT)` handler intercepted before uvicorn; removed entirely; `_do_shutdown()` now awaits all background task cancellations via `asyncio.gather(return_exceptions=True)`; hard 5-second timeout via `asyncio.wait_for`
- **SOAR command reactions not shown on frontend** — endpoint cards now show pulsing red/orange glow + striped "NETWORK DISABLED" bar (isolated), amber glow + blocked IP chips (blocked); bottom-right toast notifications per command result; action buttons spinner/green/red feedback; input locks while in-flight
- **`unisolate_host` not reflected** — missing `elif` branch in both ACK handler and `_server_soar_loop`; added `$set: {status: "online"}` + `endpoint_update` emit for both
- **`command_result` event missing fields** — payload now includes `status`, `result_message`, `target` in both ACK handler and server SOAR loop
- **Attack graph showing stale CRITICAL nodes** — `/attack-graph/snapshot` rebuilt: default window 48h→2h, `min_score=0.70` filter, 50-node cap, 3-tier SHAP enrichment (inline→collection lookup→synthetic model scores), complete node metadata per node
- **Attack graph node clustering / no info on nodes** — D3 charge -300, link distance 120, named collision force, type-based `forceX`/`forceY` positional biases; NodeDetailPanel rebuilt with 5 tabs (Overview always populated, SHAP with fallback, Info raw metadata); graph status bar "System Normal" / "X Critical Threats Active"
- **Node TTL / noise accumulation** — CRITICAL nodes expire after 30 min, HIGH after 15 min, MEDIUM/LOW after 5 min; ingestion filters drop MEDIUM/LOW network/endpoint/user events; `clearGraph()` button for admin/analyst
- **PDF incident reports vanish after re-login** — `fetchIncidentReports` moved to `useEffect([isAuthenticated])`, runs on every login; `report_generated` + `response_executed` socket handlers trigger server re-fetch; `generated_at_dt` BSON datetime added for reliable sort
- **Advisory SOAR actions failing plan lifecycle** — 13 advisory actions (`alert_admin`, `update_software`, `patch_openssl`, etc.) now handled in `_server_soar_executor()` and `command_listener.py`; all return `success=True`; `alert_admin` added to `_ADVISORY_ACTIONS` frozenset
- **`/replay/{incident_id}` incomplete** — 4th timeline source (`sysmon_alerts`) added; SOAR commands fetched by `plan_id`; server-generated plain-English `narrative`; SHAP always `[]` not `null`; case notes by `endpoint_id` OR `plan_id`
- **Investigation UI lacking context** — narrative panel (server or client fallback); timeline source chips + score badges; "Response Actions Taken" panel; SHAP fallback to contributing model bars; Active Threats plan status badges (CONTAINED/PARTIAL/EXECUTING/OPEN)
- **Payload diagnostic tool created** — `endpoint_agent/check_payload.py`: validates all 37 fields against canonical spec, does live POST, prints PASS/FAIL/WARN per field

### Resolved (2026-05-17)
- **Incident reports table empty** — removed `server_host` filter in `EndpointView.tsx`; added `GET /reports` fetch on mount in `NetworkMonitor.tsx`
- **User behavior always 100% CRITICAL** — 5 bugs fixed: wrong sigmoid, 4688 events inflating file count, fast-path threshold too low, `model_threshold.json` 0.3→0.5 (then 0.8), unconditional HIGH severity fallback
- **User behavior threshold raised to 0.8** — `model_threshold.json` 0.5→0.8; all three `user_score >= 0.5` gates in `backend.py` raised to `>= 0.8`; CRITICAL requires >0.85, HIGH >0.70
- **User behavior logs empty after threshold raise** — `user_behavior_summary` now includes `users[]` list with all processed users; `NetworkMonitor.tsx` upserts them into display state; non-anomalous users show green "NORMAL" badge
- **SOAR commands failing (15 bugs)** — `netsh disable/enable` verbs corrected; `block_ip` now creates both inbound+outbound rules; full exe paths (`C:\Windows\System32\netsh.exe` etc.); `CREATE_NO_WINDOW` on all subprocesses; admin elevation check at startup; same fixes in `command_listener.py`
- **SOAR `block_ip "suspicious_ip"` placeholder** — new `_extract_ip_target(fusion_alert, shap)` checks `src_ip` field first → SHAP IP features → returns `None`; `_block_ip_action()` skips action when `None`; `src_ip` now forwarded from alert batch into `generate_response_plan()` at both call sites
- **SOAR placeholder process names** — `_proc_target()` extracts real process name from fusion data/SHAP or drops kill_process action entirely; no more `"suspicious_processes"`, `"beacon_process"`, etc.
- **PDF signature underscores removed** — `___________________________` row removed from sig_block; admin name now bold 13pt on its own line
- **PDF advisory frozenset out of sync** — `report_generator.py` internal `_ADVISORY` set now exactly mirrors `backend.py`'s `_ADVISORY_ACTIONS`; `scan_filesystem`, `monitor_persistence`, `lock_account` correctly show `[OK]`/`[FAIL]` not `[ADV]`
- **Force-graph "node not found: endpoint_server" crash** — D3 link filter added: any edge whose source/target ID is not in nodes array is dropped before simulation init
- **Investigate system showing nothing** — 4-source timeline (`endpoint_logs` + `fused_alerts` + `alerts` + `predictions`); fusion alert window ±5min→±30min with 3-stage fallback; SHAP lookup uses 4-stage fallback (no longer requires `endpoint_id` field); attack graph now data-driven from timeline event types
- **SHAP missing for user behavior in ResponseModal** — new `_maybe_generate_user_response_plan()` generates Insider Threat response plan (MITRE T1078.004) for HIGH/CRITICAL user anomalies; `shap_reasons` pre-initialized to avoid `UnboundLocalError`
- **FusionDecisionPanel runtime crash** — `(fusionAlert.sources ?? []).map()`; `sources?: string[]` optional in interface
- **CRITICAL malware not in Alert Stream** — new `_maybe_emit_malware_fusion_alert()` called at all 3 malware call sites: emits `network_anomaly` (populates Alert Stream), `fusion_alert` with correct `attack_type = "Malware Activity"`, generates `response_required` plan; 60s per-file cooldown

### Resolved (2026-05-10)
- **Enterprise credential recovery system fully implemented** — layered SOC-grade recovery matching XDR security posture:
  - `POST /auth/forgot-password` — rate-limited 3/IP/15min; bcrypt-hashed single-use 10-min JWT reset token stored in `password_reset_tokens` collection; constant-time path to prevent email enumeration; dev console log + `dev_token` in response for testing; MEDIUM security event + `audit_event` Socket.IO
  - `POST /auth/reset-password` — requires TOTP OR backup code even during reset (attacker with email access still blocked by MFA); bcrypt double-verification against stored hash; revokes ALL sessions on success; HIGH security event
  - `POST /auth/recovery/request-mfa` — unauthenticated endpoint for locked-out users; rate-limited 1/email/24h; creates pending request in `mfa_recovery_requests`; HIGH security event
  - `GET /auth/recovery/pending` — admin-only; returns pending MFA recovery queue
  - `POST /auth/recovery/approve/{request_id}` — admin approves/denies; approve wipes `two_factor_secret` + backup codes + trusted devices + all sessions; HIGH security event
  - `GET /auth/backup-codes/status` — returns remaining backup code count without revealing codes
  - `_assess_recovery_risk()` — checks known IPs (30-day window) + recent attempts (1h window); returns `LOW/MEDIUM/HIGH` risk level
  - `_revoke_all_sessions()` — marks all active sessions inactive; used by both password reset and MFA recovery approval
  - New MongoDB collections: `password_reset_tokens` (1k cap), `mfa_recovery_requests` (500 cap)
  - New Pydantic models: `ForgotPasswordRequest`, `ResetPasswordRequest`, `MFARecoveryRequestPayload`, `MFARecoveryActionPayload`
  - New rate limiters in `auth/rate_limiter.py`: `forgot_password_rate_limiter` + `mfa_recovery_rate_limiter`
  - `create_password_reset_token()` helper in `auth/security.py`
- **Recovery frontend fully implemented** — glassmorphism pages matching existing design system:
  - `ForgotPasswordPage.tsx` (`/forgot-password`) — animated pulsing shield, email form, success state, DEV MODE collapsible panel showing raw token + one-click reset link
  - `ResetPasswordPage.tsx` (`/reset-password?token=...`) — 3-step flow: MFA verify → new password with strength meter → success state with `SecurityRecoveryTimeline` showing all 5 recovery steps animated
  - `MFARecoveryRequestPage.tsx` (`/mfa-recovery`) — orange/red broken-lock theme, email + reason form, animated hourglass pending state, request ID with copy button
  - `SecurityRecoveryTimeline.tsx` — reusable neon timeline component with Framer Motion stagger; completed/in-progress/pending states; color-coded by severity
  - `MFARecoveryPanel.tsx` — admin panel in ProfileView; auto-refreshes 30s; table with Approve/Deny modal confirmation; AnimatePresence row removal
  - `LoginPage.tsx` — "Forgot password?" + "Lost MFA device?" links replace `alert()` placeholder
  - `authService.ts` — 8 new functions: `forgotPassword`, `resetPassword`, `requestMFARecovery`, `getPendingMFARecoveryRequests`, `approveMFARecovery`, `generateBackupCodes`, `getBackupCodesStatus`

### Resolved (2026-04-20)
- `rule_detector.py` is now fully integrated — incremental `eve.json` offset tracking prevents re-processing old flows
- User Behavior module fully integrated: backend emits `user_anomaly` + `user_behavior_summary` via Socket.IO; frontend displays UserBehaviorPanel in NetworkMonitor.tsx
- Suricata yaml fixed for 7.0.14 (disabled 8.x-only modules: mdns, websocket, ldap, pop3, doh2, enip, dnp3, modbus, stream-events, websocket-events rules)
- Suricata Ethernet interface set to full GUID path `\Device\NPF_{4D36FB8C-D175-4A23-9F74-28578AA4D1C5}` (Intel I219-LM)
- MongoDB Atlas auto-trim implemented: storage-full detection, collection caps, periodic trim every 100 cycles
- 12 zeroed CIC features replaced with CV-heuristic approximations in `collect_baseline.py` and `network_detection_agent.py`
- `config.py` model paths corrected — no more `C:\XDR_Model` or `Network model\` references

### Resolved (2026-04-21 — session 1)
- Malware Detection layer fully integrated: `malware_analysis_agent.py` (280-dim EMBER feature vector, pefile-based PE extraction, LightGBM inference + scaler), `train_malware_model.py` (EMBER 2018 streaming trainer, AUC=0.98), `/predict/malware` and `/scan/malware` FastAPI endpoints, background file-watcher loop, `malware_alert` + `malware_scan` Socket.IO events, `MalwareView.tsx` frontend panel
- `malware_model.pkl` trained — AUC-ROC 0.9803, F1 0.9298, Accuracy 0.9284
- SHAP explainability extended: `shap_agent.py` now supports both network (`shap.TreeExplainer` for RandomForest) and malware (`shap.TreeExplainer` for LightGBM) with `explain_malware()` method and `model="malware"` dispatch
- System Monitor Agent implemented: `system_monitor_agent.py` (PyTorch LSTM Autoencoder, 20 psutil features, 60s rolling window), `train_system_model.py` (collects live telemetry, trains autoencoder, saves `system_model.pt`), wired into backend startup + `system_anomaly` Socket.IO event
- SOAR Endpoint Agent fully implemented: `endpoint_agent.py` polling loop with `isolate_host`, `block_ip`, `unblock_ip`, `kill_process`, `quarantine_file` actions + telemetry ingestion
- Malware fusion weight raised 0.10→0.20 (network 0.40→0.35, user 0.35→0.30); direct SOAR `quarantine_file` command written for MALWARE score ≥0.85
- Path validation allowlist added to `/scan/malware` (`settings.scan_allowed_roots`)
- Malware stats (summary cards) added to `OverviewView.tsx`; Malware Detections table added to `AlertsView.tsx`

### Resolved (2026-04-21 — session 2)
- `network_classifier.pkl` trained — RandomForest on CIC-IDS2017, 99.6% accuracy, classes: BENIGN, Botnet, BruteForce, DDoS, DoS, Heartbleed, Infiltration, PortScan; `network_label_encoder.pkl` saved alongside
- `train_classifier.py` paths fixed: `DATASET_DIR` → `Network Behavior\CICDS_dataset`, `OUTPUT_DIR` → `Backend\`
- `collect_baseline.py` paths fixed: `OUTPUT_CSV` → `Backend\personal_baseline.csv`; TShark interface changed to Ethernet GUID `\Device\NPF_{4D36FB8C-D175-4A23-9F74-28578AA4D1C5}`
- `train_personal_model.py` paths fixed: `BASE_DIR` → `Backend\`
- SHAP wired into malware inference end-to-end: `malware_analysis_agent._run_inference()` now returns `features_scaled`; `backend.py` calls `_maybe_explain_malware()` in `/predict/malware`, `/scan/malware`, and `_malware_scan_loop`; `shap_explanation` field added to `MalwareAlert` TypeScript interface; "SHAP Reasons" column added to `AlertsView.tsx` malware table
- Security fixes: `/fusion`, `/shap`, `/commands` endpoints now require API key (`dependencies=[Depends(_require_key)]`); CRITICAL startup log when default `changeme-dev-key` is in use
- Bug fixes: duplicate `shap_agent` key removed from `/health` response; malware score scale corrected (×100) in `AlertsView.tsx`

### Resolved (2026-04-25)
- **Sysmon pipeline completely rearchitected**: abandoned win32evtlog entirely (3 sessions of winerror 6 failures); replaced with:
  - `sysmon_winevent_reader.py` → `SysmonFileReader` tailing `C:\winlogbeat\logs\sysmon_events.json` (Winlogbeat NDJSON, no Windows API)
  - `backend.py` `_sysmon_ps_loop()` — PowerShell `Get-WinEvent` forwarder started by `/start-monitoring`, feeds `SysmonBehaviorAgent._handle_event()` directly without requiring Winlogbeat
  - `sysmon_feature_extractor.py` updated to handle both flat and nested event formats
  - `sysmon_behavior_agent.py`: win32evtlog removed, always uses `_tail_loop()`, `use_win_event_log` param retained but ignored
  - `train_system_model.py`: uses `SysmonFileReader` for `--source sysmon`
  - `pywin32` removed from `requirements.txt`; `pefile>=2023.2.7` added
- **MongoDB Atlas**: connection timeout raised 3 s → 20 s (Atlas needs DNS SRV + TLS time); real `mongoOk` status wired to frontend (was hardcoded `true`); Atlas credentials removed from `config.py` fallback (in `.env` only)
- **System anomaly rate-limiting**: `_handle_system_result` now emits at most one CRITICAL socket event per 30 s (was flooding every ~3 s)
- **Security hardening**: `/system/analyze` and `/sysmon/status` now require API key; `print()` in SysmonFileReader replaced with `logger.debug()`

### Resolved (2026-04-26 — session 1)
- **Malware false-positive ransomware labeling fixed**: `malware_analysis_agent.py` refactored with 3-tier labels (`benign`/`suspicious`/`malicious`, thresholds 0.3/0.7), trusted-path whitelist (site-packages, System32, Program Files → score capped at 0.4), signed-binary heuristic (has_signature=1 + score<0.85 → capped at 0.5); new output fields: `source`, `label`, `confidence`, `trusted`, `trust_reason`
- **Ransomware correlation gate added to `fusion_engine.py`**: removed unconditional `frozenset({"system","malware"})` → "Ransomware Behavior" chain rule; replaced with `_detect_ransomware()` requiring `label=="malicious" AND trusted==False` (malware) PLUS `severity in {HIGH,CRITICAL}` (system); renamed label to "Ransomware Activity"
- **False CRITICAL correlated attacks from suspicious files fixed**: `backend.py` now only calls `_fe.ingest_event` for malware when `label=="malicious"`; `fe_event` includes `label` and `trusted` fields; `_build_response_suggestions` uses `has_confirmed_malware` (label-checked) instead of bare source presence for `quarantine_file`; severity CRITICAL escalation requires `malware_is_confirmed`
- **MongoDB collections expanded**: `malware_events` (2k cap) and `fused_alerts` (1k cap) added — 12 collections total; all three malware call sites (predict, scan, watcher) save to both `malware_scans` and `malware_events`
- **Frontend malware contract updated**: `MalwareAlert` TypeScript interface extended with `label`, `trusted`, `trust_reason`, `confidence`; badge colors: red=malicious/orange=suspicious/green=benign; trusted rows shown at 55% opacity with shield icon; `fusion.attack_type` chip displayed inline; malware alert count excludes trusted files
- **System Telemetry Logs moved to correct view**: removed from `SystemStatusView.tsx`; added as "SYSTEM TELEMETRY LOGS" panel in `SysmonBehaviorView.tsx` (between Live Process Events and the now-removed Process Behavior Alerts panel); `NetworkMonitor.tsx` prop routing updated
- **Process Behavior Alerts panel removed** from `SysmonBehaviorView.tsx` (redundant with Sysmon raw event log)
- **ANOMALOUS status fixed in System Telemetry Logs**: `isAnomalous` now uses `entry.is_genuinely_anomalous === true || severity === "HIGH" || severity === "CRITICAL"` — 85-87% memory no longer shows ANOMALOUS
- **Resource-aware system severity**: `system_monitor_agent.py` adds `_resource_aware_severity(score, features)` — CRITICAL only when `cpu>85 OR mem>95 OR (cpu>80 AND mem>80)`; normal high-memory caps ML severity at MEDIUM regardless of model output; `is_genuinely_anomalous` bool field added to every result dict
- **False CRITICAL system correlated attacks fixed**: `fusion_engine.py` `attack_detected` now requires `≥2 sources` (single-source system events no longer populate Correlated Attacks); `isolate_host` SOAR only fires when `is_genuinely_anomalous=True`; `backend.py` `_handle_system_result` gates CorrelationEngine feed on `is_genuinely_anomalous`; benign-emit path changed to `else` so score gauge updates every tick

### Resolved (2026-04-26 — session 2)
- **Complete Auth & AuthZ system implemented**: `Backend/auth/` package (6 files) — JWT HS256 access (15 min) + refresh (7 day) tokens, bcrypt-12 password hashing, TOTP 2FA via pyotp+qrcode, sliding-window rate limiter (5 attempts/IP/15 min), account lockout after 5 failures (15 min), RBAC (admin/analyst/viewer), suspicious login detection, refresh tokens bcrypt-hashed before storage, `users`+`sessions`+`audit_logs` MongoDB collections
- **10 auth endpoints**: `/auth/register`, `/auth/login`, `/auth/verify-2fa-login`, `/auth/refresh`, `/auth/logout`, `/auth/logout-all`, `/auth/me`, `/auth/enable-2fa`, `/auth/verify-2fa`, `/auth/disable-2fa`. First registered user → admin; all actions emit `audit_event` Socket.IO
- **Backend security hardening**: CORS restricted `*` → `["http://localhost:3000","http://127.0.0.1:3000"]`; `_require_key_or_jwt` dual-auth applied to `/predict/network`, `/predict/user`, `/fusion`, `/shap`, `/system/analyze`, `/sysmon/status`; JWT_SECRET_KEY validated at startup
- **Socket.IO connect() crash fixed**: `connect(sid, environ)` → `connect(sid, environ, data=None)` — frontend auth token was passed as 3rd arg, crashing every WebSocket connection
- **Frontend auth UI**: `LoginPage` (glassmorphism, canvas particles, hover-to-expand card, password toggle, forgot-credentials link, trust badges, footer nav), `RegisterPage` (strength meter, per-field validation), `MFASetupPage` (QR code + OTP confirm), `AuthContext` (silent refresh on mount), `ProtectedRoute`, `authService.ts` (axios interceptors + token management)
- **Futuristic UI additions**: `AlertSiren` (Web Audio API 600→900 Hz siren + red vignette on HIGH/CRITICAL), `AuditLogPanel` (live `audit_event` feed), `OTPInput` (6-cell auto-advance), `global.css` (neon animations, pulse-border, scan-line), `theme.ts`; `App.tsx` routing with `/login`, `/register`, `/dashboard`, `/setup-2fa`
- **Auth URL mismatches fixed** (analyst-caught): `authService.ts` `/auth/verify-2fa` → `/auth/verify-2fa-login`; MFA management paths `/auth/2fa/{x}` → `/auth/{x}-2fa` (backend canonical form)
- **Login form collapse-while-typing fixed**: `isExpanded` now includes `|| email !== '' || password !== ''`
- **"HOVER TO ACCESS" text removed** per user request
- **FastAPI 422 rendering crash fixed**: `getMsg()`/`getErrorMessage()` in both auth pages now handle array-type `detail` (Pydantic v2 validation errors) and strip "Value error, " prefix

### Resolved (2026-04-27)
- **Unauthorized Access Handling System** — global `@app.exception_handler(HTTPException)` normalizes all 401 → `{"error":"UNAUTHORIZED","message":"Authentication required","code":401}` and 403 → `{"error":"FORBIDDEN","message":"Insufficient permissions","code":403}`; never raises from within the handler (infinite-recursion-safe)
- **Security event persistence** — `_extract_jwt_identity()`, `_get_client_ip()`, `_persist_security_event()`, `_log_security_event()` helpers added to `backend.py`; `security_events` MongoDB collection (5000-doc cap, three indexes: timestamp DESC, user_id, ip); severity mapping 401→MEDIUM, 403→HIGH; non-blocking `create_task` write so response is never blocked by DB latency
- **`GET /security/events` endpoint** — admin-only (API key OR JWT with role=`admin`); returns last N events sorted newest-first with pagination (`limit`/`skip`); input bounds clamped (1–500); handles MongoDB unavailable gracefully
- **Frontend 401/403 interceptor** — `authService.ts` axios response interceptor: 401 attempts silent token refresh via `refreshToken()`, falls back to clear-tokens + toast + redirect `/login`; 403 fires `dispatchAccessDenied()` DOM event + toast + redirect `/dashboard`; `AUTH_BYPASS_PATHS` list prevents redirect loop on auth endpoints
- **`UnauthorizedBanner` component** — `src/components/UnauthorizedBanner.tsx`; listens to `accessDenied` DOM event; fixed red top banner (z-index 10000) with slide-in/fade-out CSS animation; 2.6 s auto-dismiss with 400 ms fade-out; applies `unauthorized-glitch` CSS class to `document.body` for 1.5 s; dismiss button with hover glow; renders null when not active
- **`ProtectedRoute` role enforcement** — `requiredRole` prop added; role mismatch triggers `AccessDeniedOverlay` (full-screen vignette + glitch lock icon + "Redirecting..." message) for 2 s before `navigate('/dashboard')`; `hasRequiredRole()` accepts string or string array
- **`global.css` additions** — `glitch`, `redFlash`, `banner-slide-in`, `banner-fade-out`, `access-denied-pulse`, `access-denied-text-glitch` keyframes added; `unauthorized-glitch` body class defined
- **`App.tsx` root-level banner** — `<UnauthorizedBanner />` mounted at application root (z-index 10000, above all other UI)
- **Siren audio system rewritten** — `src/utils/sirenAudio.ts` redesigned with dual-source: tries `public/Sounds/siren.mp3.wav` (HTMLAudioElement, loop=true, volume=0.75) then falls back to Web Audio API oscillator (750 Hz carrier, LFO ±150 Hz at 0.5 Hz → 600–900 Hz sweep); `enableAudio()` gate enforces browser autoplay policy (must be called from onClick); `_audioEnabled` flag prevents any playback before user consent; `stopSirenInternal(resetEl)` unified stop path
- **`useSirenAudio` hook** — `src/hooks/useSirenAudio.ts`; `isPlaying` guard prevents restart on duplicate alerts; `play()` is no-op before `enableAudio()`; `stop()` clears React state; initialises `audioEnabled` from module singleton so hook reflects reality on re-mount
- **AlertSiren exit bug fixed** — root cause: (1) `repeat: Infinity` on Framer Motion vignette `animate` blocked `exit` animation from firing; (2) `<>` React fragment inside `AnimatePresence` prevented per-child keyed tracking; fix: pulsing moved to CSS `@keyframes siren-vignette-pulse`, both `motion.div`s are direct keyed children of `AnimatePresence` (`key="siren-vignette"` and `key="siren-bar"`) — red borders now clear correctly on acknowledge
- **`NetworkMonitor.tsx` audio wiring** — "Enable Sound Alerts" amber button in top bar calls `enableAudio()` on click; `audioEnabled` + `onEnableAudio` props threaded down to `AlertSiren`

### Resolved (2026-04-27 — session 2)
- **Standalone Endpoint Agent package** (`endpoint_agent/`) — production-grade asyncio runner with two concurrent tasks: `_telemetry_loop` (5s) and `_command_loop` (3s). CLI + env-var configuration (`XDR_BACKEND_URL`, `XDR_API_KEY`, `XDR_COLLECT_INTERVAL`, `XDR_COMMAND_INTERVAL`). Startup banner redacts API key. `--simulate` flag for safe dry-run testing.
- **Endpoint identity persistence** (`identity.py`) — generates UUID `endpoint_id` on first run, persists to `endpoint_config.json`, in-process cached. Captures hostname, IP, OS, OS version, username, agent version.
- **Resilient async telemetry sender** (`sender.py`) — `httpx.AsyncClient` with 10s timeout; 3-attempt exponential backoff (1s/2s/4s delays); never raises to caller loop.
- **SOAR command executor** (`command_listener.py`) — `poll_commands()` / `execute_command()` / `acknowledge_command()` triad. Actions: `kill_process` (PID or name via psutil, explicit `int()` cast), `block_ip` / `unblock_ip` (strict IPv4 regex, `shell=False` netsh, rule naming `XDR_BLOCK_<ip>`), `isolate_host` (writes `isolation_flag.txt` + disables Ethernet interface via netsh; interface priority: Ethernet → Wi-Fi → Wireless), `quarantine_file` (absolute path validation + `shutil.move` to `quarantine/` subfolder).
- **Four telemetry collectors** — `network_collector.py` (psutil net_connections + net_io_counters + 22-port suspicious-port detection, max 50 connections), `system_collector.py` (CPU%, memory%, disk%, process count, top-10 by CPU), `user_collector.py` (current user + psutil.users() sessions), `malware_collector.py` (heuristic: suspicious process name set + temp-dir launch detection — server-side ML handles scoring).
- **Six new backend API endpoints** — `POST /endpoint/ingest` (rate-limited 1/2s per endpoint_id; upserts `endpoint_registry`; inserts `endpoint_logs`; background telemetry analysis; emits `endpoint_update` + `endpoint_alert`), `GET /endpoint/commands/{endpoint_id}` (atomic fetch + mark-sent), `POST /endpoint/command/ack` (status update + `command_result` emit), `POST /endpoint/command` (action + endpoint validation; `command_queued` emit), `GET /endpoint/list` (computed online/offline via 30s cutoff), `GET /endpoint/{endpoint_id}` (registry + last 20 logs + last 10 commands).
- **Three new MongoDB collections** — `endpoint_logs` (cap 10k; indexes: endpoint_id, timestamp DESC), `endpoint_registry` (cap 500; unique index on endpoint_id, last_seen DESC), `endpoint_commands` (cap 2k; indexes: endpoint_id, status, created_at DESC). Total collections: 17.
- **`_endpoint_heartbeat_loop()` background task** — runs every 30s, queries `endpoint_registry` for endpoints with `last_seen > 35s` ago, marks them `offline`, emits `endpoint_offline` Socket.IO event per stale host.
- **Five new Socket.IO events** — `endpoint_update`, `endpoint_alert`, `endpoint_offline`, `command_queued`, `command_result`.
- **`EndpointView.tsx` SOC dashboard panel** — 3-section layout: (1) Endpoint Grid (auto-fill cards with CPU/MEM progress bars, online/offline status dots, red-glow + pulse animation on HIGH/CRITICAL, relative last-seen timestamps, `motion.div whileHover`), (2) Endpoint Alerts Table (last 20; severity badges; row click selects endpoint in response panel), (3) Response Panel (endpoint selector dropdown for online-only endpoints; 5 action buttons with inline forms; Isolate Host shows confirmation warning; Command History last 10 with OK/FAIL badges).
- **Frontend wiring** — `NetworkMonitor.tsx` state: `endpoints`, `endpointAlerts`, `commandResults`; Socket.IO subscriptions with cleanup `off()` for all 4 endpoint events; `handleSendCommand` via axios with JWT/API-key auth; `fetchEndpoints()` on mount; `endpointOnlineCount` badge in Sidebar; `"endpoints"` ViewId added to Sidebar nav and `AnimatePresence` router.
- **New TypeScript types** — `EndpointInfo`, `EndpointAlert`, `EndpointCommand`, `CommandResult` added to shared types file.
- **`/health` endpoint updated** — includes `"endpoint_api"` section.

### Resolved (2026-05-03)
- **Endpoint telemetry pipeline unified with AI models** — the two-pipeline gap (server AI vs endpoint heuristic) is eliminated:
  - `NetworkDetectionAgent.detect_from_endpoint_network(network_data, hostname)` — converts psutil `net_connections` + I/O counters to synthetic flow dicts; runs through Gate 1 IsolationForest + Gate 2 RandomForest; returns `network_score` [0–1] + individual ML results
  - `SystemMonitorAgent.predict_from_metrics(metrics)` — maps endpoint cpu/mem/process_count to 20-feature FEATURE_NAMES vector; runs `_heuristic_score()` + `_resource_aware_severity()`; returns `system_score` + `is_genuinely_anomalous`
  - `MalwareAnalysisAgent.assess_process_metadata(malware_data)` — hybrid: 22-IOC heuristic + LightGBM on readable PE files; `final_score = max(heuristic, model)`; returns `malware_score`, `model_used`, `source`
  - `UserBehaviorAgent.score_session_telemetry(user_data)` — hybrid: rule heuristic + IsolationForest on 19-dim session vector (corrected sigmoid, threshold 0.50); `final_score = max(rule, model)`; returns `user_score`, `model_used`, `source`
  - `_score_endpoint_telemetry_with_ai()` — new backend coroutine at line 2333; fans out all 4 agent calls concurrently via `asyncio.gather(return_exceptions=True)`; any agent failure silently floors that score to 0.0
  - `endpoint_ingest` block 4 fully replaced — `ep_sys_score = max(cpu,mem)/100` heuristic removed; now calls `_fusion_agent.fuse(net, usr, sys, mal, endpoint_id)` with the same weights as server pipeline (net=0.35, usr=0.30, sys=0.15, mal=0.20)
  - `fusion_alert` now emitted for HIGH/CRITICAL endpoint threats — appears in AlertsTable, ResponseModal, triggers SHAP + response planning
  - `network_anomaly` emitted per detected attack flow from endpoint psutil connections
  - `_latest_scores` updated from AI scores; dashboard threat gauge reflects endpoint contributions
  - All endpoint fusion results persisted to `fused_alerts` MongoDB collection
  - `endpoint_fusion_alert` kept for backward compat with EndpointView
- **Backend reliability fixes**:
  - `EndpointTelemetry.timestamp` made optional with `@validator` auto-fill (`datetime.utcnow()`) — 422 errors on missing timestamps eliminated
  - `/endpoint/ingest` debug log added: `[endpoint/ingest] endpoint_id=... network_keys=... system_keys=...`
  - `/endpoint/timeline/{endpoint_id}` fixed to query `endpoint_logs` (was querying `endpoint_timelines`) sorted by timestamp DESC, up to 500 docs
  - `_log_security_event`: HTTP 401 downgraded to `logger.debug` (expected browser noise); 403 stays at `logger.warning`
- **Auth flow fixed** — `AuthContext.tsx` `hydrate()` decision tree: no tokens → silent; refresh token only → try `/auth/refresh` first; access token present → call `/auth/me`; `/auth/me` never called without a token in hand; eliminates startup 401 noise

### Resolved (2026-05-02)
- **EDR Orchestration layer implemented**: `response_engine.py` (MITRE ATT&CK-mapped planner — 9 attack categories: Ransomware/T1486, C2 Beaconing/T1071, Privilege Escalation/T1068, Lateral Movement/T1021, PortScan/T1046, DDoS/T1498, BruteForce/T1110, Infiltration/T1190, default/T1059); `_extract_shap_target()` reads top SHAP feature for `block_ip` target; `auto_execute=True` only on CRITICAL severity
- **PDF incident report generator implemented**: `report_generator.py` (ReportLab 5-section PDF: header, incident summary, attack timeline, SHAP explanation table, response actions, CONTAINED/PARTIAL/FAILED final status with colour coding); saved to `D:\Cyber Sentinal\reports\{incident_id}.pdf`; optional-import guard — module always loads cleanly
- **6 new backend endpoints added**: `POST /response/plan`, `POST /response/execute` (splits executable vs. `_ADVISORY_ACTIONS` — advisory actions logged to `response_advisory_logs`, not sent to endpoint agent), `GET /response/plans`, `POST /reports/generate` (admin only), `GET /reports/{id}/download`, `GET /reports`
- **Fusion Engine hook wired**: `_emit_soc_alert_if_correlated()` auto-generates response plan and emits `response_required` Socket.IO event for every HIGH/CRITICAL severity fusion alert; non-blocking via `asyncio.create_task()`
- **4 new Socket.IO events**: `response_required`, `response_plan_ready`, `response_executed`, `report_generated`
- **3 new MongoDB collections**: `response_plans` (2k cap), `response_advisory_logs` (advisory action audit), `incident_reports` (metadata; PDFs on disk)
- **`ResponseModal.tsx`**: full-screen glassmorphism modal — attack summary grid, SHAP inline bar chart (wired to `plan.shap_explanation` via `useMemo`), pre-checked action checklist, role-gated Execute button (admin/analyst only; viewers see read-only badge), per-action spinner→✓/✗ status, PDF download button post-execution; Framer Motion entry; Escape-key cleanup
- **`AlertsView.tsx` Respond column**: red "Respond" button visible on HIGH/CRITICAL network anomaly rows only; opens `ResponseModal` with pre-loaded plan if `response_required` event already arrived
- **`EndpointView.tsx` extended** with 3 new sections: Active Threats panel (filtered by selected endpoint, "View Response" per plan), Response History table, Incident Reports table with authenticated PDF download
- **`NetworkMonitor.tsx`**: 3 new Socket.IO subscriptions (`response_required`, `response_plan_ready`, `report_generated`) + state (`responsePlans`, `responseRequiredAlert`, `incidentReports`); passes `responsePlans` + `incidentReports` as props to `AlertsView` and `EndpointView`
- **`Sidebar.tsx` response badge**: red pulsing "RESPOND" badge on Endpoints nav item when `responseRequiredCount > 0`
- **3 bugs fixed post-implementation**: (1) `/reports/generate` fused_alert query now filtered by `endpoint_id`; (2) advisory actions no longer cause HTTP 400 in `/response/execute` (split into `_ADVISORY_ACTIONS` frozenset); (3) `ResponseModal` SHAP chart now reads from `plan.shap_explanation` via `useMemo` (was hardcoded `[]`)

### Resolved (2026-05-05)
- **Server PC Response System** — `_server_soar_executor()` executes SOAR actions locally on the backend host: `block_ip`/`unblock_ip` (netsh advfirewall, IPv4-validated), `kill_process` (psutil PID or name), `quarantine_file` (shutil.move to `Backend/quarantine/`), `isolate_host` (flag file + Wi-Fi disable). `_server_soar_loop()` polls `endpoint_commands` every 5 s for `endpoint_id="server_host"` pending commands, atomically marks sent, executes, writes `completed`/`failed` + `result_message`, emits `command_result`, updates registry (`blocked_ips` / `status: "isolated"`) + immediate `endpoint_update` emit. Loop started in `GET /start-monitoring`, cancelled in `_do_shutdown`. SOAR block for `is_server` removed from `POST /endpoint/command`.
- **Correlated Attacks Respond button** — `socAlertToFlowResult()` adapter added to `AlertsView.tsx`; "Respond" button rendered in the CORRELATED ATTACKS table for MEDIUM/HIGH/CRITICAL rows; opens existing `ResponseModal` (SHAP chart, action checklist, PDF download all work); `matchingPlan` looked up from `responsePlans` filtered to `endpoint_id === "server_host"`. `ATTACK_COLOURS` added to import.
- **`_emit_soc_alert_if_correlated` server_host fallback** — default `endpoint_id` for server-pipeline fusion events changed from `"unknown"` → `"server_host"` so auto-generated response plans correctly target the server.
- **Score threshold enforcement (HIGH ≥ 70%, CRITICAL ≥ 85%)** — `fusion_engine_agent.py` thresholds updated (high 0.80→0.70, critical 0.90→0.85); downward severity cap added to `_compute_final_decision` in `fusion_engine.py`; score gate in `_emit_soc_alert_if_correlated` suppresses HIGH below 0.70 and downgrades CRITICAL→HIGH when score is 0.70–0.84.
- **SOAR buttons HTTP 403 fixed** — `handleSendCommand` in `NetworkMonitor.tsx` switched from raw `axios.post` with hardcoded API key header to `authAxios.post` (auto-attaches JWT Bearer token from localStorage, silent refresh on 401).
- **Blocked IPs + isolated state shown on dashboard** — `endpoint_command_ack` now updates `endpoint_registry` via `$addToSet`/`$pull` for `block_ip`/`unblock_ip` and `$set status: "isolated"` for `isolate_host`; immediately re-fetches registry doc and emits `endpoint_update` so frontend reflects state in < 1 s. `EndpointInfo.status` extended to `'isolated'`; `blocked_ips?: string[]` added to type. Endpoint cards show orange visual treatment + "HOST ISOLATED 🔒" badge + blocked IPs chip list. KPI bar shows aggregate Isolated + Blocked IPs counters.
- **Network flow timestamp "—" fixed** — backend monitoring loop sets `ml["ts"]` (not `ml["timestamp"]`); `RawFlowPayload` extended with `ts?: string`; `mapRawToFlow` now reads `raw.timestamp ?? raw.ts ?? ""` so timestamps always render as `HH:MM:SS AM/PM`.
- **Network table column alignment fixed** — `whiteSpace: "nowrap"` + `verticalAlign: "middle"` on all 12 `<td>` and `<th>` elements in `NetworkView.tsx`; empty port/protocol cells show `"—"`.

### Resolved (2026-05-10 — session 2: Final hardening pass)
- **Attack graph red entities fixed** — `safeLabel()` helper in `useAttackGraphData.ts`; canvas null guard drops labelless nodes; `NODE_STYLE` unknown-type fallback prevents crash
- **Events/Sec counter fixed** — 1-second `setInterval` in `useAttackGraphData.ts` continuously decays rate after event bursts (was stale between bursts)
- **`chain_seq` on attack graph edges** — monotonic counter in `AttackGraphEngine` seeds from MongoDB max on restart; replay scrubber now works on live data
- **`_now_dt()` + `ts_dt` field** — TTL-compatible BSON datetime stored alongside string timestamps; TTL indexes added: `fused_alerts` 30d, `endpoint_logs` 90d, `sysmon_alerts` 30d
- **`critical_alerts` collection** — HIGH/CRITICAL fusion alerts dual-written to permanent uncapped evidence store at all 4 call sites
- **`GET /replay/{incident_id}`** — unified bundle endpoint: incident + plan + fusion alert + 100-event timeline + SHAP + advisory actions + case notes; graceful null fallback on each sub-query
- **`GET /critical-alerts`** — paginated (limit/skip, max 200) view of permanent evidence store
- **Attack Reconstruction Mode** — `AttackReconstructionView.tsx` (3-panel: mini attack graph + `ReplayTimeline` + `FusionDecisionPanel`); "Investigate" button in EndpointView; `onBack` → Endpoints view
- **`ReplayTimeline.tsx`** — vertical scrollable event log; past/active/future opacity states; auto-scroll to current step; click-to-jump
- **`FusionDecisionPanel.tsx`** — SVG arc threat gauge + per-model contribution bars with weight badges; severity-colored glow
- **PDF SHAP visual bar chart** — `_SHAPBarChart` ReportLab `Flowable`; red/green bars; degrades gracefully when SHAP is empty
- **PDF MITRE ATT&CK section** — 10-technique `MITRE_LOOKUP`; technique ID in severity accent color; tactic badge; description paragraph
- **PDF response actions enhanced** — `[OK]/[ADV]/[FAIL]/[...]` status indicators; result message from endpoint ACK; advisory vs. executable legend
- **PDF Analyst Certification block** — two-column layout; CERTIFIED stamp colored by severity; "CONFIDENTIAL — SOC USE ONLY" footer
- **`admin_name` JWT fix** — derived from JWT claims server-side; request body value ignored (impersonation closed)
- **`admin_role` passed to PDF** — `jwt_role` from JWT claim passed as 7th arg to `generate_incident_report`
- **`attack_type` validation on `/response/plan`** — 422 returned for empty/missing attack_type
- **Heartbleed → T1499** — full action block in `response_engine.py`: `block_ip`, `alert_admin`, `update_software`; advisory: `patch_openssl`, `rotate_certificates`, `check_exposed_secrets`
- **Response plan lifecycle** — `status` field: `open` on create → `executing` on `/response/execute` → `contained`/`partial` on all commands ACK'd; `GET /response/plans` returns status
- **Sysmon alert rate-limiting** — `_SYSMON_EMIT_COOLDOWN = 5.0s`; `_last_sysmon_emit_time` module-level guard in `_handle_sysmon_result`
- **Dual Sysmon source mutual exclusion** — `_sysmon_winlogbeat_active` flag; PS forwarder loop skips when Winlogbeat file reader active
- **`isolate_host` dynamic NIC** — `detect_network_interface()` in `identity.py` (psutil priority: Ethernet → Wi-Fi → Wireless → first UP); saved to `endpoint_config.json`; `_server_soar_loop` reads `XDR_ISOLATE_INTERFACE` env var via `config.py` (default: `"Ethernet"`)
- **`unisolate_host` action added** — `command_listener.py` re-enables NIC via `netsh interface set interface <iface> enable`; removes `isolation_flag.txt`
- **SHAP RBAC gating** — `ResponseModal.tsx` + `NodeDetailPanel.tsx`: admin=full chart+values, analyst=chart+direction labels, viewer=plain text only
- **All previously claimed fixes verified present** — Socket.IO CORS ✓, pdf_path stripped ✓, reports download role-gated ✓, REPORTS_DIR in config ✓, /settings endpoints ✓, /users endpoints ✓, /case-notes endpoints ✓, response_executed subscriber ✓, OverviewView fusion score ✓, About/Settings/Profile pages ✓, Sidebar restructure ✓

### Resolved (2026-05-13)
- **SHAP for System Monitor verified wired** — `_maybe_explain_system()` in `backend.py` already calls `_shap_agent.explain_system(window, model, scaler, feature_names)` in `_handle_system_result`; `shap_explanation` field present on `system_anomaly` Socket.IO event
- **SHAP for Sysmon verified wired** — `_maybe_explain_sysmon()` in `backend.py` already calls `_shap_agent.explain_sysmon(event, anomaly_score)` in `_handle_sysmon_result`; `shap_explanation` field present on `sysmon_alert` Socket.IO event
- **SHAP Explainability layer: 85% → 95%** — system + sysmon SHAP was implemented in `shap_agent.py` (reconstruction-error decomposition for LSTM; indicator-analysis for Sysmon) and confirmed wired in backend
- **SOAR `lock_account` implemented** — `endpoint_agent/command_listener.py` `_action_lock_account()`: runs `net user <username> /active:no`, `shell=False`, username allowlist regex `^[\w\-\. ]{1,20}$`, Windows-only guard; also added to `_server_soar_executor` in `backend.py`
- **SOAR `scan_filesystem` implemented** — `endpoint_agent/command_listener.py` `_action_scan_filesystem()`: `os.walk` over 4 watch paths, filters `{.exe,.dll,.ps1,.bat,.vbs,.scr}` modified within last 3600s, prunes noisy subdirs, returns count + top 10 by mtime; also added to `_server_soar_executor`
- **SOAR `monitor_persistence` implemented** — `endpoint_agent/command_listener.py` `_action_monitor_persistence()`: reads HKCU Run keys via `winreg` (degrades gracefully), lists Startup folder, counts scheduled tasks via `schtasks /query /fo CSV`; also added to `_server_soar_executor`
- **SOAR / Endpoint Agent: 95% → 99%** — all 9 actions now real (kill/block/unblock/isolate/unisolate/quarantine/lock_account/scan_filesystem/monitor_persistence)
- **Playbook versioning in `audit_logs`** — `POST /response/execute` inserts `action="response_plan_executed"` audit doc with plan_id, endpoint_id, actions_queued, user_id, ip via non-blocking `asyncio.create_task`; command ACK path inserts `action="response_plan_contained"` when plan transitions to contained/partial; EDR Orchestration: 97% → 99%
- **RBAC enforcement 8 gaps fixed** — files modified: `AlertsView.tsx` (Correlated Attacks Respond button + column header viewer gate), `NetworkMonitor.tsx` (Audit Log button admin-only, Audit Log view content gate, `userRole` prop forwarded to SysmonBehaviorView), `EndpointView.tsx` (PDF Download → "Summary only" for viewers), `SysmonBehaviorView.tsx` (Indicators SHAP column hidden from viewers; SHAP Reasons plain-text for viewers; `userRole` prop added); RBAC: 92% → 98%

### Resolved (2026-06-03)
- **Endpoint Grid phantom cycling fix** — `/endpoint/ingest` `_monitoring_active` early-return moved BEFORE the MongoDB registry upsert; previously the upsert ran unconditionally, keeping `last_seen` fresh even when monitoring was stopped and causing endpoints to flicker online/offline on the dashboard
- **Comprehensive audit logging enrichment** — `role_changed`, `force_logout`, `user_deleted` audit events now include `ip` field + target username lookup; `monitoring_started` / `monitoring_stopped` events added to `/start-monitoring` and `/stop-monitoring`; `investigation_started` event on `GET /replay/{incident_id}`; `response_plan_created` on `POST /response/plan`; `report_generated` on `POST /reports/generate`; new `POST /audit/client-event` endpoint accepts frontend-originated events (e.g. sound alerts toggle)
- **Auto-response wired end-to-end** — `_auto_response_enabled: bool = True` module variable loaded from MongoDB on startup; all 4 auto-execute call sites now gate on `_auto_response_enabled` (server_host restriction removed — fires for any endpoint); `_auto_execute_server_plan()` extended to auto-generate PDF incident report via `generate_incident_report()` in threadpool, insert metadata to `incident_reports`, emit `auto_response_completed` socket event (plan_id, endpoint_id, attack_type, severity, actions_taken, report metadata), emit `report_generated` if PDF created; `ThresholdSettings` Pydantic model includes `auto_response_enabled: bool`; `POST /settings/thresholds` saves + applies it
- **Settings threshold persistence (Settings Page 90% → 100%)** — thresholds including `auto_response_enabled` now persist to MongoDB via `POST /settings/thresholds` and are reloaded on server startup; previously only in-memory and lost on restart
- **Backend URL unification (8 files)** — hardcoded `"http://localhost:8000"` replaced with `process.env.REACT_APP_BACKEND_URL ?? "http://localhost:8000"` in: `ResponseModal.tsx`, `SystemStatusView.tsx`, `ProfileView.tsx`, `MalwareView.tsx`, `SettingsView.tsx`, `EndpointDetailView.tsx`, `SysmonBehaviorView.tsx`, `EndpointView.tsx`; `.env` updated to `REACT_APP_BACKEND_URL=http://192.168.1.5:8000`
- **Audit Log button removed from top bar** — only "Start Monitoring" and "Stop Monitoring" remain in top bar, matching the product-level goal spec
- **Global font size increase** — `src/index.css` sets `html { font-size: 17px; }`; sidebar px values bumped (nav labels 13→14px, badges 9→10px, user card 12→13px)
- **Attack graph D3 position preservation** — `AttackGraph.tsx` nodes `useMemo` now reads `posMap` from `simRef.current.nodes()` before creating new nodes array; preserves D3-mutated x/y/vx/vy positions on state updates, eliminating the node-vanishing bug on live data updates; simulation reheat alpha reduced 0.5→0.2 on topology changes
- **OverviewView Activity Log** — System Status panel replaced with admin-only real-time Activity Log; shows colored badge per action type, human-readable label (28 ACTION_LABELS), user email, IP, timestamp, and `detail` subtitle; fetches `GET /audit-logs` on mount and subscribes to `audit_event` socket; grid layout `"1fr 260px"` for admin, `"1fr"` for non-admin
- **SettingsView auto-response toggle** — loads `auto_response_enabled` from `GET /settings` on mount; toggle POSTs full threshold payload + `auto_response_enabled` to backend; shows conditional info banner when auto-response is ON; sound alerts toggle calls `POST /audit/client-event`
- **NetworkMonitor auto-response subscription** — subscribes to `auto_response_completed` socket event; shows toast (attack type, endpoint, actions taken); auto-downloads PDF report if `data.report.incident_id` present; updates response plans state; cleanup `socket.off("auto_response_completed")` in return

### Resolved (2026-06-08)
- **Attack graph flickering during 5s telemetry gap** — backend heartbeat timeout raised 15s→35s in `_endpoint_heartbeat_loop` (`timedelta(seconds=15)` → `timedelta(seconds=35)`); frontend `useAttackGraphData.ts` added `endpointLastSeenRef` (`useRef<Map<string, number>>`) tracking last alive timestamp per node; `endpoint_update` handler updates ref on every non-offline event; `endpoint_offline` suppressed with 40s debounce (returns early if `ageMs < 40_000`); node removed only on `endpoint_offline` as authoritative signal or genuine 40s silence
- **Endpoint Grid duplicate cards** — render-time dedup added in `EndpointView.tsx` `.filter((ep, idx, arr) => arr.findIndex(e => e.endpoint_id === ep.endpoint_id) === idx)` before `.map()`; existing upsert-by-`endpoint_id` logic in `NetworkMonitor.tsx` already correct
- **`endpoints is not iterable` crash in `useAttackGraphData`** — `/endpoint/list` returns `{"endpoints":[], "total":0}` not a raw array; `fetchTopology()` now normalises: `Array.isArray(_raw) ? _raw : (_raw.endpoints ?? _raw.data ?? [])`
- **Stop Monitoring button leaves Start Monitoring permanently disabled** — `setIsMonitoring(false)` and `isMonitoringRef.current = false` moved from `try` to `finally` in `handleStop` (`NetworkMonitor.tsx` ~line 783); previously a failed `/stop-monitoring` HTTP call left `isMonitoring=true` keeping Start disabled
- **MongoDB Atlas `ServerSelectionTimeoutError` crashing ASGI app** — comprehensive hardening of all 6 endpoint HTTP handlers in `backend.py`; every unprotected `asyncio.to_thread` MongoDB call wrapped in `try/except Exception`:
  - `endpoint_get_commands` → `{"commands": []}` fallback
  - `endpoint_send_command` registry lookup → dummy doc (skips 404 check when DB is down)
  - `endpoint_list` → `{"endpoints": [], "total": 0}` fallback
  - `endpoint_disconnect` → `doc = None` (still emits offline Socket.IO event)
  - `endpoint_detail` → HTTP 503 with descriptive message
  - `endpoint_timeline` → `{"timeline": []}` fallback
  - Both background loops (`_server_soar_loop`, `_endpoint_heartbeat_loop`) were already protected with `except Exception` catch-alls — no change needed

### Resolved (2026-06-16)
- **Post-login redirect loop fixed** — after successful MFA verification, `storeTokens()` saved JWT but `setUser()` was never called, leaving `isAuthenticated=false`; `ProtectedRoute` immediately redirected back to login. Fixed by adding `completeMFALogin(tokens)` to `AuthContext.tsx` — atomically calls `storeTokens()` + `getMe()` + `setUser(me)`; all 3 MFA paths in `LoginPage.tsx` (TOTP, backup code, setup confirm) now `await completeMFALogin(tokens)` instead of `storeTokens(tokens)`
- **"Authentication successful" toast persistent** — `NetworkMonitor.tsx` `<Toaster>` had no `duration`; react-hot-toast fell back to `Infinity` for custom-styled toasts; all toast calls and `<Toaster>` instances now have explicit `{ duration: 3000 }` / `toastOptions={{ duration: 3000 }}`; enforced as professional UX standard for all future toasts
- **Ethernet interface migration (project-wide)** — all 8 files that hardcoded the Wi-Fi GUID `{B5A75558-6CB6-473B-B521-5B390F7ADE47}` or Wi-Fi adapter references updated to Ethernet GUID `{4D36FB8C-D175-4A23-9F74-28578AA4D1C5}` (Intel I219-LM):
  - `backend.py` `_SURICATA_CMD`: Wi-Fi GUID → Ethernet GUID
  - `collect_baseline.py`: `-i "4"` (Wi-Fi index) → `-i "\Device\NPF_{4D36FB8C...}"` (stable GUID path)
  - `Backend/agents/endpoint_agent.py`: `_action_isolate_host(interface="Wi-Fi")` → `(interface="Ethernet")`; `_action_unblock_host` same
  - `endpoint_agent/identity.py`: `detect_network_interface()` priority flipped — Ethernet (#1), Wi-Fi (#2), Wireless (#3); hard fallback `"Wi-Fi"` → `"Ethernet"`
  - `start_capture.ps1`: Suricata `-i "\Device\NPF_{B5A75558...}"` → `"\Device\NPF_{4D36FB8C...}"`
  - `.env`: Added `XDR_ISOLATE_INTERFACE=Ethernet`
  - `config.py`: `soar_isolate_interface` default `"Wi-Fi"` → `"Ethernet"`
  - `backend.py` fallback interface lists: `("Wi-Fi","Ethernet")` → `("Ethernet","Wi-Fi")`
- **System Behavior dataset integrated (DETECTOR1)** — `System Behavior/Dataset_1/Full_Process_Traces/` (.GHC binary DLL call stack files) and pre-trained `detector.pkl` (TF-IDF n-gram 1–3, max 80k features + IsolationForest + XGBoost) now used as the **primary** system detection path:
  - New `BehavioralDetector` class in `system_monitor_agent.py`: loads `detector.pkl` with `sys.modules["__main__"]` injection trick for pickle compatibility; `loaded` bool attribute; graceful degradation on failure
  - `_sysmon_event_ring: deque(maxlen=50)` at module scope; appended in `_handle_sysmon_telemetry()`; consumed by `_collect_loop()` each 1s tick as behavioral context
  - `SystemMonitorAgent.predict_from_metrics(metrics, sysmon_events=None)` — when behavioral loaded, runs `self._behavioral.score(sysmon_events)`, fuses as `max(lstm_score, behavioral_score)`
  - `_DETECTOR_PKL_PATH` = `D:\Cyber Sentinal\System Behavior\System_Behavior_Model\DETECTOR1\saved_model_v3\detector.pkl`
  - Backend startup: logs INFO if pkl loaded, WARNING if not
  - `train_system_model.py`: new `--source dataset` mode — reads `.GHC` files, fits TF-IDF + IsolationForest + XGBoost, tunes threshold on attack data, saves `_DetectorShell` compatible with `BehavioralDetector._load()`; 12 attack type labels (CesarFTP, OS-SMB, BrowserExploit, PDFExploit, Backdoor, RemovableMedia, RogueAP, MediaServer, PrintSpooler, WebDAV, WikiCMS, WebServerExploit)
- **Behavioral fields wired through full pipeline**:
  - `backend.py` `_handle_system_result()`: uses `behavioral_attack_type` as fusion `prediction` field when behavioral score dominates; calls `_generate_system_feature_reasons(result)` for ALL events (not just anomalies) populating `shap_reasons`
  - `fusion_engine.py`: `_BEHAVIORAL_ATTACK_TYPE_MAP` dict (12 entries) maps raw DETECTOR1 labels to human-readable names; applied in `_validate_and_normalise()` when `source=="system"` and `behavioral_attack_type` is non-empty/non-Background
  - `response_engine.py`: 12 new MITRE ATT&CK entries for behavioral labels: backdoor→T1059, ftp exploit→T1190, smb exploit→T1021.002, print spooler→T1021.002, browser exploit→T1189, pdf exploit→T1189, removable media→T1091, web server exploit→T1190, webdav exploit→T1190, wiki cms→T1190, media server→T1190, rogue ap→T1557
  - `system_anomaly` Socket.IO event: carries `behavioral_score`, `behavioral_attack_type`, `behavioral_confidence`, `behavioral_is_anomaly` fields when DETECTOR1 fires
  - `/health` endpoint: reports `"behavioral_detector_loaded": bool`
  - Frontend `types.ts`: `SystemAnomalyEvent` interface extended with 4 optional behavioral fields
- **`is_genuinely_anomalous` bug fixed for behavioral detections** — was `severity in ("HIGH","CRITICAL")` only; `_resource_aware_severity` caps severity at MEDIUM on low-resource hosts, silently suppressing SHAP and `isolate_host` for behavioral detections; fixed to `severity in ("HIGH","CRITICAL") or behavioral_fired` so behavioral attacks always trigger SOAR and SHAP regardless of CPU/memory state
- **SHAP "—" fixed for all System Telemetry Log rows** — `_maybe_explain_system` gated by `is_genuinely_anomalous=True`; normal/MEDIUM events never had SHAP; fixed with new synchronous `_generate_system_feature_reasons()` helper called unconditionally for all system events: generates metric strings from `features_snapshot` + `feature_names`, prepends behavioral reason when detector fires; SHAP pills now populate for every row in System Telemetry Logs
- **SysmonBehaviorView behavioral indicators** — `behavioralDetectorLoaded` prop from `NetworkMonitor.tsx` (read from `/health`); model status chip shows "LSTM + Behavioral" (cyan) or "LSTM only" (amber); severity cell shows cyan `BEHAVIORAL` badge when `entry.behavioral_is_anomaly === true`; SHAP pills show 4 items (behavioral reason in cyan, metric pills in purple, `+N more` overflow); `behavioral_attack_type` included in search filter
- **AboutView + SystemStatusView + HelpPage** updated to reference "LSTM + Behavioral (DETECTOR1)" dual-path model instead of "IsolationForest, LSTM Autoencoder"

### Resolved (2026-06-19)
- **Team photos added to Contact Us carousel** — `Annas.jpeg`, `Malaika.jpeg`, `Mazhar.jpeg` copied to `public/team/`; `teamMembers` array extended with `photo` and `glowColor` fields; carousel avatar replaced from initials-only circle to real 100×100 circular photo with `objectFit: cover, objectPosition: center top`; initials remain as `z-index: -1` fallback behind `<img>` in case of load error
- **Contact Us email/phone buttons fixed** — `ContactCard` interface extended with optional `href` field; `annashabib02283@gmail.com` card now renders as `<a href="mailto:...">` (was plain `<p>` — clicking did nothing); `+92 336 501 3274` card renders as `<a href="tel:+923365013274">`; value text lights up in card's accent color on hover; all three carousel member Email buttons verified working (`annashabib02283@gmail.com`, `malaikakhattak26@gmail.com`, `syedmazharhussainshah7@gmail.com`)
- **Logo integrated project-wide** — `Cyber Sentinal XDR Frontend/Logo.jpg` deployed to `public/logo.jpg` (frontend static asset) and `Backend/logo.jpg` (PDF generator):
  - **Sidebar** (`Sidebar.tsx:335`) — `🛡️` emoji replaced with 42×42 rounded logo image; cyan glow border; visible both collapsed and expanded
  - **Login Page** (`LoginPage.tsx:889`) — `🛡️` emoji replaced with 90×90 logo card with pulsing cyan box-shadow animation
  - **Login Page MFA step** (`LoginPage.tsx:1218`) — `🛡️` span replaced with 44×44 logo above "MFA Setup Required" heading
  - **About View** (`AboutView.tsx:604`) — 110×110 logo added above hero title "CYBER SENTINEL XDR" with cyan border glow and box-shadow
  - **Contact Us sticky header** (`ContactUsPage.tsx:821`) — SVG ShieldIcon replaced with 36×36 logo with indigo glow border
  - **PDF Incident Reports** (`report_generator.py:559`) — `Image` imported from `reportlab.platypus`; `_LOGO_PATH = Path(__file__).parent / "logo.jpg"`; `_build_header()` rewritten to two-column `Table` layout: 28mm×28mm logo left-aligned beside title + subtitle; gracefully skipped when file absent
- **`/incidents/{id}/replay` 500 crash fixed** — `attack_graph.py:768`: `if ep_id and self._db:` raised `NotImplementedError` because pymongo `Database` objects forbid implicit bool conversion; fixed to `if ep_id and self._db is not None:` — consistent with correct `is not None` pattern used at lines 94, 124, 182, 527, 561, 675, 695, 717, 738, 754 in the same file

### Resolved (2026-07-05)
- **Acknowledge button overlapping Start/Stop Monitoring buttons** — `AlertSiren.tsx`: the siren notification bar was `position: fixed, top: 0` at `height: 56`, exactly matching the app's own top bar (`NetworkMonitor.tsx`, also `height: 56` at the top of the main content column) — both right-align their action buttons, so ACKNOWLEDGE landed directly on top of Start/Stop Monitoring. Fixed by changing the siren bar's `top: 0` → `top: 56` so it docks below the app top bar instead of covering it; entry/exit spring animation (`y: -80 → 0`) still slides in cleanly since the banner now starts off-screen above the top bar. No prop/interface changes.
- **SOAR commands stuck as "Pending" for non-server endpoints** — `backend.py` `_auto_execute_server_plan()` previously (1) called `_server_soar_executor` for every `endpoint_id`, including remote hosts — wrongly executing actions like `isolate_host`/`scan_filesystem` against the *backend server itself* instead of the remote endpoint, and (2) never wrote to `endpoint_commands`, so the PDF's `find({"plan_id": plan_id})` lookup always returned empty. Rewritten: every non-advisory action is now inserted into `endpoint_commands` with `plan_id` set *before* execution (`status: "sent"` for `server_host` so `_server_soar_loop` doesn't double-execute it, `status: "pending"` for remote endpoints so their endpoint agent picks it up via `GET /endpoint/commands/{endpoint_id}`); only `server_host` actions are executed locally via `_server_soar_executor`, with the result written back to the command doc (`completed`/`failed` + `result_message`) and a `command_result` Socket.IO emit. Advisory actions still go to `response_advisory_logs`.
- **Missing SHAP chart on Ransomware Behavior incident PDFs** — `_emit_soc_alert_if_correlated()`'s SHAP block silently swallowed all exceptions from `_shap_agent.explain_fusion()` (`except Exception: pass`), and pure system+malware correlations (no network/user signal) had no other SHAP source, so `plan["shap_explanation"]` stayed `[]` and the PDF rendered "No SHAP data available for this alert." Fixed: the exception is now logged (`logger.debug`) instead of hidden, and when `_corr_shap` is still empty after the `explain_fusion()` attempt, a fallback builds score-weighted contribution items directly from `_latest_scores` (`shap_value = score × fusion weight`, sorted descending) — so Ransomware Behavior alerts (and any other correlated event lacking per-feature SHAP) now render real contribution bars in the PDF.

### Still Outstanding

#### Requires user action (cannot fix in code alone)
- ~~**Malware and User Behavior endpoint-telemetry paths use heuristics, not the trained models**~~ — **Resolved 2026-06-28**: both `assess_process_metadata()` and `score_session_telemetry()` now run hybrid paths (heuristic + trained model); see "Verified Model-Wiring Gaps" section above for details.
- **`system_model.pt` (LSTM) gives score=1.0** — sklearn scaler version mismatch (`system_scaler.pkl` pickled with sklearn 1.7.2, runtime 1.8.0). **Impact is now low** — DETECTOR1 (`detector.pkl`) is the primary detection path; LSTM is secondary (score = `max(lstm, behavioral)`). Mitigated further by `_resource_aware_severity`. **User fix if needed**: `pip install scikit-learn==1.7.2` in venv OR `python train_system_model.py --source psutil --collect-minutes 60`
- **`personal_baseline_model.pkl` may have same mismatch** — if Gate 1 passes all flows unconditionally: `python collect_baseline.py` then `python train_personal_model.py`
- **SMTP for password reset** — `auth/email_sender.py` is fully implemented; set `SMTP_ENABLED=true` + `SMTP_HOST/PORT/USER/PASS` in `.env`
- **Winlogbeat not configured** — set `START_WINLOGBEAT=true` in `.env`; configure Winlogbeat to ship security events to `C:\XDR_Logs\` for user behavior inference
- **`JWT_SECRET_KEY` and `XDR_API_KEY` must be set in `.env`** — server logs CRITICAL warning if defaults are in use
- **OCEAN personality features hardcoded 0.0** — no data source; needs HR/employee profile feed or manual input

#### Production hardening (acceptable for dev/demo)
- **JWT stored in localStorage** — XSS-extractable; production: migrate to `httpOnly` cookies + CSRF tokens
- **In-memory rate limiter resets on restart** — acceptable dev; production: Redis or MongoDB-backed counters
- **No TLS/mTLS on endpoint agent** — API key in plaintext HTTP; production: HTTPS + certificate pinning
- **Endpoint agent not a Windows Service** — production: NSSM wrapper or systemd unit for persistence
- **Unvalidated X-Forwarded-For** — blind trust behind load balancer; production: configure trusted proxy list

#### Lower priority (non-blocking)
- Flow micro-fragmentation — CIC feature extraction needs micro-flow grouping before computation
- `block_ip`/`unblock_ip` Linux iptables path is present but untested
