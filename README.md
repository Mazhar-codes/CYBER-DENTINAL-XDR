# Cyber Sentinel XDR

A Windows-based, AI-driven Extended Detection and Response (XDR) platform. It collects
endpoint telemetry, runs four independent ML detection models, fuses their outputs into a
single threat score, explains every decision with SHAP, stores everything in MongoDB,
executes automated SOAR responses on endpoints, and displays it all in a real-time React SOC
dashboard.

This document is the entry point for anyone pulling this repository fresh: what's in it,
how the pieces fit together, how to install and run every component, and where things live
on disk. For AI-assisted development conventions (which subagent owns which file, coding
rules), see [`CLAUDE.md`](CLAUDE.md) instead — this README is for humans standing the system up.

---

## Table of contents

1. [Architecture at a glance](#architecture-at-a-glance)
2. [What's in this repo (and what isn't)](#whats-in-this-repo-and-what-isnt)
3. [Repository layout / path conventions](#repository-layout--path-conventions)
4. [Prerequisites](#prerequisites)
5. [Getting the code](#getting-the-code)
6. [Environment configuration (.env)](#environment-configuration-env)
7. [Running the system](#running-the-system)
8. [First-run checklist](#first-run-checklist)
9. [ML model training (optional)](#ml-model-training-optional)
10. [API reference](#api-reference)
11. [MongoDB collections](#mongodb-collections)
12. [Socket.IO events](#socketio-events)
13. [Testing & diagnostics](#testing--diagnostics)
14. [Troubleshooting](#troubleshooting)
15. [Known limitations](#known-limitations)

---

## Architecture at a glance

```
Windows Endpoint (Sysmon / TShark / Suricata)
  → Endpoint Agent (Python/psutil)
  → POST /endpoint/ingest  →  FastAPI Backend
  → MongoDB (endpoint_logs, endpoint_registry)
  → _score_endpoint_telemetry_with_ai()  [concurrent 4-agent fan-out]
      ├─ network.connections → NetworkDetectionAgent  → Gate1 IsolationForest + Gate2 RandomForest → network_score
      ├─ system.cpu/mem/procs → SystemMonitorAgent    → LSTM Autoencoder + BehavioralDetector      → system_score
      ├─ malware.suspicious   → MalwareAnalysisAgent   → 22-IOC heuristic + LightGBM               → malware_score
      └─ user.sessions        → UserBehaviorAgent      → rule heuristic + IsolationForest          → user_score
  → FusionEngineAgent.fuse(net, usr, sys, mal)
  → fusion_alert Socket.IO  →  React SOC Dashboard (Alerts, SHAP, ResponseModal)
  → Response Engine (SOAR-lite)  →  MongoDB endpoint_commands
  → Endpoint Agent polls /endpoint/commands  →  executes SOAR actions (isolate host, block IP, kill process, ...)
```

There is a second, parallel server-side pipeline that runs directly off Suricata/psutil/
Winlogbeat on the machine hosting the backend (no endpoint agent required for that host) and
feeds the same fusion + alerting pipeline. Both pipelines converge on the same
`FusionEngineAgent`, the same MongoDB collections, and the same Socket.IO events.

Four independently trained models do the actual detection work:

| Domain | Algorithm | Trained on |
|---|---|---|
| Network | RandomForest (+ IsolationForest baseline gate) | CIC-IDS2017 |
| User Behavior | IsolationForest | CERT r4.2 insider-threat dataset |
| System | LSTM Autoencoder + IsolationForest/XGBoost (DETECTOR1) | live psutil telemetry + GHC DLL call-trace dataset |
| Malware | LightGBM | EMBER 2018 |

## What's in this repo (and what isn't)

This is a **monorepo**: the FastAPI backend, the standalone endpoint agent, and the React
frontend all live under one GitHub repo, each in its own top-level folder.

**Included:**
- All application source code (`Backend/`, `endpoint_agent/`, `Cyber Sentinal XDR Frontend/`)
- Small trained model artifacts actually loaded at runtime (`.pkl`/`.pt` files under ~30MB
  each — `network_classifier.pkl`, `malware_model.pkl`, `user_model.pkl`, `detector.pkl`,
  etc.) so the backend runs immediately after a clone, without retraining anything.
- Documentation, timeline reports, evaluation scripts, thesis/poster assets.

**Excluded** (via `.gitignore` — kept local-only, never pushed, ~50GB total):
- `Network Behavior/CICDS_dataset/`, `Network Behavior/Wire shark/` — raw CIC-IDS2017 flows + pcaps
- `User Behavior/final_model_backend_only/r4.2/` and `.../Dataset/` — raw CERT r4.2 dataset
- `User Behavior/winlogbeat-9.3.3-windows-x86_64/` — vendored Winlogbeat binary (112MB `.exe`, over GitHub's 100MB limit anyway — download it yourself, see [Winlogbeat](#4-winlogbeat-user-behavior-optional))
- `System Behavior/Dataset_1/` — raw GHC DLL call-trace dataset
- `Malware Behavior/` — raw EMBER 2018 dataset
- `ml_training_env/` — a Python virtualenv that shouldn't have been in the repo tree to begin with
- `venv/`, `node_modules/`, `__pycache__/`, `build/`, `.env`, `reports/`, `mongodb/`, `quarantine/`, `*.log`

Practical effect: **you can run the whole detection + response + dashboard pipeline right
after cloning**, using the models as already trained. You only need the raw datasets back if
you intend to *retrain* a model (see [ML model training](#ml-model-training-optional)).

## Repository layout / path conventions

```
Cyber Sentinal XDR/                      ← repo root (this file lives here)
├── README.md                            ← you are here
├── CLAUDE.md                            ← AI-assistant dev conventions, full change history
├── .env.example                         ← copy to .env and fill in (see below)
├── .gitignore
│
├── Backend/                             ← FastAPI + Socket.IO server (Python) — ENTRY POINT: backend.py
│   ├── backend.py                       ← FastAPI app, all HTTP + Socket.IO wiring, background loops
│   ├── config.py                        ← centralized settings, all paths relative to Backend/ or env-overrideable
│   ├── response_engine.py               ← MITRE ATT&CK response-plan generator
│   ├── fusion_engine.py                 ← threat-score fusion + correlation
│   ├── report_generator.py              ← ReportLab PDF incident reports → ../reports/
│   ├── rule_detector.py, hybrid_detector.py   ← network detection stages 1–2
│   ├── attack_graph.py                  ← attack-graph / replay backend
│   ├── train_*.py                       ← model retraining scripts (need raw datasets, see below)
│   ├── collect_baseline.py              ← captures your own "normal" traffic baseline via Suricata
│   ├── agents/                          ← one wrapper class per detection domain
│   │   ├── network_detection_agent.py
│   │   ├── system_monitor_agent.py
│   │   ├── malware_analysis_agent.py
│   │   ├── user_behavior_agent.py
│   │   ├── fusion_engine_agent.py
│   │   ├── shap_agent.py
│   │   └── endpoint_agent.py            ← legacy single-host SOAR executor (server-side)
│   ├── auth/                            ← JWT auth: tokens, TOTP 2FA, RBAC, rate limiting
│   ├── ZEEK/                            ← Zeek protocol analyzer configs
│   ├── *.pkl / *.pt                     ← trained model artifacts (included in git, see table below)
│   ├── network_dataset.xlsx, personal_baseline.csv  ← small reference/sample data
│   └── requirements.txt
│
├── endpoint_agent/                      ← standalone agent — runs on EVERY monitored Windows host
│   ├── agent.py                         ← ENTRY POINT: asyncio loop (5s telemetry, 3s commands)
│   ├── identity.py                      ← persists a UUID endpoint identity to endpoint_config.json
│   ├── sender.py                        ← async telemetry POST with retry/backoff
│   ├── command_listener.py              ← executes SOAR actions received from the backend
│   ├── collectors/                      ← network/system/user/malware telemetry collectors (psutil-based)
│   └── requirements.txt
│
├── Cyber Sentinal XDR Frontend/         ← React + TypeScript SOC dashboard (CRA), port 3000
│   ├── src/components/                 ← dashboard views, tables, modals, shared UI
│   ├── src/services/                   ← api.ts (REST), networkSocket.ts (Socket.IO client)
│   ├── src/types/                      ← TypeScript interfaces (source of truth for event shapes)
│   ├── public/
│   └── .env.example                    ← copy to .env, set REACT_APP_BACKEND_URL
│
├── Network Behavior/                    ← Suricata rules, capture commands, (gitignored) raw CIC dataset
│   ├── COMMANDS.md                      ← every Suricata/Nmap/capture command used in this project
│   └── rules.txt
├── User Behavior/final_model_backend_only/   ← user-behavior model + inference runtime
│   ├── xdr_runtime.py                   ← IsolationForest inference engine (reads Winlogbeat ndjson)
│   ├── user_model.pkl, user_scaler.pkl  ← trained model + scaler (included in git)
│   ├── feature_columns.json, model_threshold.json
│   └── train_user_model.py, calibrate_threshold.py
├── System Behavior/
│   ├── Sysmon/                          ← Sysmon binaries + config (small, included)
│   └── System_Behavior_Model/DETECTOR1/saved_model_v3/detector.pkl   ← included in git
├── Malware Behavior/                    ← (gitignored) raw EMBER dataset only; the trained
│                                            malware_model.pkl itself lives in Backend/
│
├── evaluation/                          ← independent model-performance evaluation scripts + reports
├── timeline/                            ← timestamped project-analysis reports (audit trail)
├── reports/                             ← generated incident-report PDFs (gitignored, created at runtime)
├── mongodb/                             ← local MongoDB data directory if you run Mongo yourself (gitignored)
│
├── attack_*.py, inject_attack.py, simulate_attack.py, run_demo.py   ← attack-simulation / demo scripts
├── config.py                            ← shared config for the demo/attack scripts above
├── start_capture.ps1, start_xdr.bat, update_ip.py
└── ATTACK_CATALOG.md, ATTACK_COVERAGE.md, ENDPOINT_FIELD_CONTRACT.md   ← reference docs
```

**Path convention:** almost everything resolves paths relative to the file's own location
(`Path(__file__).parent` in Python, e.g. `Backend/config.py`), or via environment variables
with sensible defaults — **not** hardcoded to a specific drive letter. You can clone this
repo to any path on any drive and it will work. The few genuinely-absolute defaults
(`C:\SuricataLogs\eve.json`, `C:\winlogbeat\logs\sysmon_events.json`, `C:\XDR_Logs`) point at
where those *external tools* (Suricata, Winlogbeat) write their own logs — those are
independent of where you cloned this repo, and are all overrideable via `.env` (see
`Backend/config.py`).

## Prerequisites

| Tool | Version used | Required for |
|---|---|---|
| Python | 3.11–3.13 | Backend, endpoint agent, training scripts |
| Node.js | 18+ (tested on 22) | Frontend |
| MongoDB | 7.x/8.x (Atlas or local) | All persistence |
| Suricata | 7.0.14 | Network IDS / `eve.json` (backend host or any monitored host) |
| Sysmon | included in `System Behavior/Sysmon/` | Process/DLL-load telemetry |
| Winlogbeat | 9.3.3 (download separately, not in repo — see below) | Ships Windows event logs for user-behavior inference |
| Git | any recent version | Cloning |

You do **not** need Suricata/Sysmon/Winlogbeat installed to get the backend, frontend, and
Mongo running end-to-end with simulated data (`run_demo.py` / `attack_*.py` / `inject_attack.py`)
— those are only required for live telemetry from a real Windows host.

## Getting the code

```bash
git clone https://github.com/lucifer-1589/cyber-sentinal-xdr.git
cd cyber-sentinal-xdr
```

That's it — no submodules, no LFS. The trained models you need to run the backend are
already in the tree (see [What's in this repo](#whats-in-this-repo-and-what-isnt)).

## Environment configuration (.env)

The backend and frontend each read their own `.env`, both git-ignored.

**1. Root `.env`** (read by `Backend/config.py` and the root-level demo scripts):

```bash
cp .env.example .env
```

Then edit `.env` and set at minimum:
- `MONGO_URI` — your MongoDB connection string (Atlas SRV string, or `mongodb://localhost:27017` for local)
- `MONGO_DB` — database name (any name; created automatically on first write)
- `XDR_API_KEY` — shared secret endpoint agents send as `X-API-Key`
- `JWT_SECRET_KEY` — 32+ random characters, used to sign dashboard login tokens
- `XDR_ISOLATE_INTERFACE` — your machine's network adapter name (`Ethernet`, `Wi-Fi`, etc. — check with `ipconfig`), used by the `isolate_host` SOAR action

Everything else in `.env.example` has a working default or is optional (SMTP for password-reset emails, custom reports directory).

**2. Frontend `.env`** (`Cyber Sentinal XDR Frontend/.env`):

```bash
cd "Cyber Sentinal XDR Frontend"
cp .env.example .env
```

Set `REACT_APP_BACKEND_URL` to wherever the backend is reachable — `http://localhost:8000`
if frontend and backend run on the same machine, or `http://<backend-host-ip>:8000` if the
dashboard is opened from a different machine on the network.

## Running the system

### 1. MongoDB

Use MongoDB Atlas (recommended — set `MONGO_URI` in `.env` to the Atlas SRV string), or run
locally:

```powershell
& "C:\Program Files\MongoDB\Server\8.0\bin\mongod.exe" `
  --dbpath "<repo-path>\mongodb\data" --port 27017
```

Create the `mongodb\data` folder first if running locally for the first time. With a local
Mongo, `MONGO_URI=mongodb://localhost:27017` in `.env`.

### 2. Backend (FastAPI + Socket.IO)

```powershell
cd Backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
uvicorn backend:sio_app --host 0.0.0.0 --port 8000 --reload
```

Then open `http://localhost:8000/start-monitoring` once to arm the background monitoring
loops (network/system/user/malware/heartbeat). `http://localhost:8000/health` reports the
status of every subsystem (Mongo connectivity, which models loaded, Suricata/Sysmon/Winlogbeat
process state).

The first registered user via `POST /auth/register` automatically becomes `admin`.

### 3. Frontend (React SOC dashboard)

```bash
cd "Cyber Sentinal XDR Frontend"
npm install
npm start
```

Open `http://localhost:3000`, register the first (admin) account, log in, and you should see
live data once the backend's monitoring loop is running and at least one data source
(endpoint agent, Suricata, or a demo/attack script) is feeding it.

### 4. Endpoint Agent (per monitored host)

Run this on the backend host itself and/or on any additional Windows machines you want
monitored:

```powershell
cd endpoint_agent
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python agent.py --backend-url http://<backend-ip>:8000 --api-key <XDR_API_KEY-from-.env>
```

Or via environment variables instead of flags: `XDR_BACKEND_URL`, `XDR_API_KEY`,
`XDR_COLLECT_INTERVAL` (default 5s), `XDR_COMMAND_INTERVAL` (default 3s). Add `--simulate`
for a dry run that doesn't execute real SOAR actions. On first run it writes
`endpoint_config.json` next to `agent.py` with a persistent UUID identity — don't delete this
between runs or the host will re-register as a "new" endpoint.

### 5. Suricata (network IDS — optional, for live network telemetry)

Run as Administrator. Find your interface GUID with `Get-NetAdapter` or `ipconfig /all`:

```powershell
& "C:\Program Files\Suricata\suricata.exe" `
  -c "C:\Program Files\Suricata\suricata.yaml" `
  -i "\Device\NPF_{YOUR-INTERFACE-GUID}" `
  -l "C:\SuricataLogs"
```

Set `SURICATA_EVE_PATH` in `.env` if you point `-l` somewhere other than `C:\SuricataLogs`.
Suricata's `HOME_NET` in this project is configured for `192.168.0.0/16`, `10.0.0.0/8`,
`172.16.0.0/12`. See `Network Behavior/COMMANDS.md` for the full command reference including
Nmap attack-simulation commands used to exercise the detectors.

### 6. Sysmon (process/DLL telemetry — optional)

Binaries and a starter config are in `System Behavior/Sysmon/`. Install and point Winlogbeat
(below) at its event channel — the backend reads Sysmon events via
`Backend/sysmon_winevent_reader.py` / a PowerShell `Get-WinEvent` forwarder started
automatically by `/start-monitoring`, so a separate manual Sysmon-reading step isn't needed
once Sysmon itself is installed and running.

### 7. Winlogbeat (user behavior — optional)

Not included in the repo (112MB binary, over GitHub's file-size limit — download the 9.3.3
Windows x86_64 build from elastic.co yourself). Configure it to ship Windows Security event
logs as NDJSON to `C:\XDR_Logs\` (or wherever `USER_LOG_DIR` in `.env` points). The user
behavior model (`xdr_runtime.py`) reads that NDJSON stream directly — no code changes needed,
just point Winlogbeat's output at the right file/path.

## First-run checklist

After starting Mongo + Backend + Frontend:

1. `http://localhost:8000/health` → `mongoOk: true`, model-loaded flags all `true`
2. Register the first dashboard user → becomes admin automatically
3. Log in at `http://localhost:3000`, hit **Start Monitoring** in the top bar
4. Run one of the attack simulation scripts to generate a real end-to-end alert without
   needing live Suricata/endpoint traffic:
   ```bash
   python attack_network.py     # or attack_system.py / attack_malware.py / attack_user.py / attack_fusion_max.py
   ```
5. Confirm an alert appears in the **Alerts** view with a SHAP explanation, and that a
   response plan / PDF report can be generated from **Respond**.

## ML model training (optional)

You only need this if you want to retrain a model against fresh or larger data. All training
scripts expect the corresponding raw dataset locally at the paths under `Network Behavior/`,
`User Behavior/`, `System Behavior/`, `Malware Behavior/` — those are git-ignored, so bring
your own copies (CIC-IDS2017, CERT r4.2, EMBER 2018, or the GHC trace dataset) or generate
your own baseline capture.

```bash
cd Backend

# Personal network baseline (30–60 min capture via Suricata, then train)
python collect_baseline.py
python train_personal_model.py

# CIC-IDS2017 network models
python train_model.py            # IsolationForest
python train_classifier.py       # RandomForest attack classifier

# System behavior — retrain detector.pkl from the GHC dataset (primary path)
python train_system_model.py --source dataset
# or retrain the LSTM Autoencoder from live psutil metrics (secondary path)
python train_system_model.py --source psutil --collect-minutes 60

# Malware (EMBER 2018)
python train_malware_model.py

# User behavior (CERT r4.2)
cd "../User Behavior/final_model_backend_only"
python train_user_model.py
```

Model performance figures achieved on the original training runs (real held-out test splits,
not simulated) are documented in `CLAUDE.md` under "Verified Model-Wiring Gaps".

## API reference

All protected endpoints accept either the `X-API-Key` header (for agents/scripts) or a JWT
`Authorization: Bearer` token (for the dashboard), unless noted otherwise.

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /endpoint/ingest` | API key | Endpoint agent telemetry ingest |
| `GET /endpoint/commands/{endpoint_id}` | API key | Endpoint agent polls for pending SOAR commands |
| `POST /endpoint/command/ack` | API key | Endpoint agent acknowledges command result |
| `POST /endpoint/command` | API key/JWT (admin/analyst) | Dashboard issues a SOAR command |
| `GET /endpoint/list`, `GET /endpoint/{id}` | API key/JWT | Endpoint registry + recent logs/commands |
| `POST /predict/network`, `/predict/user` | API key/JWT | Direct model inference |
| `POST /fusion` | API key | Combine model scores into a threat score |
| `GET /shap` | API key | SHAP explanation for the latest prediction |
| `POST /response/plan`, `POST /response/execute`, `GET /response/plans` | API key/JWT | EDR response plan lifecycle |
| `POST /reports/generate`, `GET /reports/{id}/download`, `GET /reports` | API key/JWT | PDF incident reports |
| `GET /security/events` | JWT (admin) | Auth/security event log |
| `GET /replay/{incident_id}` | API key/JWT | Full incident replay bundle |
| `GET /settings`, `POST /settings/thresholds` | JWT (admin) | Detection threshold config |
| `GET /users`, `DELETE /users/{id}`, `POST /users/{id}/role` | JWT (admin) | User management |
| `POST /case-notes`, `GET /case-notes/{endpoint_id}` | JWT (analyst/admin) | Analyst investigation notes |
| `GET /health` | none | Subsystem status (Mongo, models loaded, Suricata/Sysmon/Winlogbeat) |
| `POST /auth/register`, `/auth/login`, `/auth/verify-2fa-login`, `/auth/refresh`, `/auth/logout` | — | Dashboard auth |

This is the practical subset; `CLAUDE.md` has the exhaustive endpoint table including every
auth/recovery/RBAC endpoint.

## MongoDB collections

| Collection | Cap | Notes |
|---|---|---|
| `endpoint_logs` | 10,000 | Raw telemetry per endpoint |
| `endpoint_registry` | 500 | One doc per known endpoint |
| `endpoint_commands` | 2,000 | SOAR command queue + status |
| `fused_alerts` | 1,000 | Fusion engine output |
| `critical_alerts` | uncapped | Permanent HIGH/CRITICAL evidence store |
| `response_plans` | 2,000 | MITRE-mapped response plans |
| `incident_reports` | — | PDF report metadata |
| `malware_scans`, `malware_events` | 2,000 | Malware detection results |
| `users`, `sessions`, `audit_logs` | — | Auth |
| `security_events` | 5,000 | 401/403 and suspicious-login events |
| `shap_explanations`, `case_notes` | — | Explainability + analyst notes |

Full list (27 collections) is in `CLAUDE.md`.

## Socket.IO events

Backend → frontend, real-time: `network_anomaly`, `user_anomaly`, `system_anomaly`,
`sysmon_alert`, `malware_alert`, `fusion_alert`, `endpoint_update`, `endpoint_alert`,
`endpoint_offline`, `command_queued`, `command_result`, `response_required`,
`response_plan_ready`, `response_executed`, `report_generated`, `audit_event`,
`auto_response_completed`. Full event contract and payload shapes: `CLAUDE.md` and
`Cyber Sentinal XDR Frontend/src/types/network.ts`.

## Testing & diagnostics

```bash
cd Backend
python test_connection.py          # verify Socket.IO connectivity
python test_network_model.py       # exercise the network ML inference pipeline
python ../"User Behavior/final_model_backend_only/test_model_realtime.py"

cd ../endpoint_agent
python check_payload.py            # validates a live telemetry POST against the field contract
```

`evaluation/evaluate_all_models.py` (with `run_evaluation.sh` / `.bat`) runs the full,
non-simulated performance evaluation against each model's own held-out test split.

## Troubleshooting

- **`/health` shows `mongoOk: false`** — check `MONGO_URI` in `.env`; Atlas needs ~20s to
  establish the first TLS+SRV connection, this is expected on cold start.
- **Frontend can't reach the backend / CORS errors** — CORS is restricted to
  `http://localhost:3000` and `http://127.0.0.1:3000` by default; if you're opening the
  dashboard from another machine's browser, add that origin in `Backend/backend.py`.
- **Endpoint agent shows as offline immediately** — heartbeat timeout is 35s; check the agent
  process is actually running and `XDR_API_KEY` matches between agent and backend `.env`.
- **`isolate_host` SOAR action does nothing** — `XDR_ISOLATE_INTERFACE` in `.env` must match
  your actual adapter name exactly (`Get-NetAdapter | Select Name` to check).
- **System model score is always 1.0** — known sklearn scaler version mismatch on the LSTM
  path; low-impact since `detector.pkl` (DETECTOR1) is the primary system-detection path. See
  "Still Outstanding" in `CLAUDE.md` for the fix.

## Known limitations

Full, current status per layer (network/user/system/malware/fusion/SHAP/SOAR/frontend/auth)
and the complete "what's resolved vs. still outstanding" history is maintained in
[`CLAUDE.md`](CLAUDE.md) under **Implementation Status** and **Known In-Progress Issues** —
that file is kept up to date after every significant change and is the authoritative source,
not this README.

---

## Team

Built by Malaika Khattak and Syed Mazhar Hussain Shah. Contact details and
team photos are in the dashboard's Contact Us page (`ContactUsPage.tsx`).
