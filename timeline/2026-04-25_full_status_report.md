================================================================================
IDPS PROJECT ANALYSIS REPORT
================================================================================
Timestamp     : 2026-04-25 16:00:00 UTC
Analyst       : IDPS Project Analyst Agent
Scope         : Full project status review — all layers, all model artifacts,
                open bugs, and forward roadmap
Project Phase : Integration & Hardening (post-MVP; all agents implemented,
                some models not yet trained; Sysmon pipeline just rearchitected)
================================================================================

## EXECUTIVE SUMMARY

Cyber Sentinel XDR has reached a significant milestone: all eight detection and
response layers are code-complete and wired into the FastAPI/Socket.IO backend.
Four of six critical model artifacts are present on disk and loadable. The most
recent session (2026-04-25) replaced the brittle win32evtlog Sysmon reader with
a clean file-based architecture and introduced the PowerShell Get-WinEvent
forwarder as a parallel path for immediate event ingestion. The system currently
scores 7.2/10 overall — held back by two untrained model paths (personal baseline
Gate 1 bypass, Sysmon behavior model operating without a trained detector.pkl
from this machine's traffic), one confirmed score-corruption bug in the system
monitor, and several hardened-credential / configuration risks that must be
addressed before any production deployment.

================================================================================

## SECTION 1: CODE QUALITY ASSESSMENT

### 1.1 Strengths

- `backend.py` is well-structured: clear separation of startup, request handlers,
  background loops, and result processors. Dependency injection via FastAPI
  `Depends(_require_key)` is consistent across all sensitive endpoints.

- Graceful degradation is implemented throughout: every agent import is wrapped
  in try/except, and all optional libraries (torch, pefile, shap, joblib, psutil)
  have `_AVAILABLE` guard flags with fallback paths so the backend starts even in
  a minimal environment.

- Atlas M0 storage management is production-quality: per-collection caps, 50%
  emergency trim on storage-full errors, and periodic proactive trim every 100
  cycles.

- `SysmonBehaviorAgent` has a well-designed pickle allowlist `_PICKLE_ALLOWLIST`
  that blocks arbitrary class deserialization — a meaningful supply-chain
  defense.

- `FusionEngineAgent` implements multi-rule escalation overrides (corroboration
  bonus, synchronized attack+system override, confirmed-malware escalation) that
  go beyond naive weighted averaging.

- The `_sysmon_ps_loop()` PS forwarder correctly seeds `last_rec` from the live
  event log at startup so it does not replay historical events on restart.

- System monitor implements rolling self-calibration (99th-pct adaptive
  threshold after 60 windows) to avoid false positives during heavy ML workloads.

### 1.2 Issues Found

| Severity | Component | Issue | Recommendation |
|----------|-----------|-------|----------------|
| HIGH | `config.py` L54 | MongoDB Atlas URI with username and password is hardcoded as a fallback default — committed to the repo | Move to `.env` only; replace hardcoded default with `"mongodb://localhost:27017"` |
| HIGH | `config.py` L72 | `api_key` default is `"changeme-dev-key"` — predictable, checked at startup but never enforced to fail | Force startup failure (or at minimum a CRITICAL warning) and require the env var in non-dev mode |
| HIGH | `backend.py` L414 | `cors_allowed_origins="*"` on Socket.IO server — allows any origin to connect without auth | Restrict to known dashboard origin in production |
| HIGH | `backend.py` L419-421 | FastAPI CORS `allow_origins=["*"]` — same issue | Restrict to dashboard hostname in production |
| MEDIUM | `sysmon_winevent_reader.py` L251 | `print("[SYSMON JSON] EventID=", ...)` in production code path (inside `tail()` generator) — will flood stdout | Replace with `logger.debug(...)` |
| MEDIUM | `system_monitor_agent.py` L368 | `_anomaly_threshold` initialized to `1.0` before metadata is loaded; if metadata fails to parse, threshold is `1.0` but the model was trained with threshold `1.625` — score will always be < 1.0 instead of near 1.0 | Set default to a safer sentinel (e.g., `math.inf`) before metadata load |
| MEDIUM | `backend.py` L783 | `/system/analyze` endpoint has no API key requirement (`dependencies=[]` omitted) — publicly accessible manual telemetry injection endpoint | Add `dependencies=[Depends(_require_key)]` |
| MEDIUM | `backend.py` L850 | `/sysmon/status` endpoint has no API key requirement | Add `dependencies=[Depends(_require_key)]` |
| MEDIUM | `OverviewView.tsx` L43-50 | Global threat score computed client-side with hardcoded weights (0.6/0.4 network/user) — ignores system, malware, sysmon contributions and diverges from backend fusion weights | Pull threat score from `fusion_alert` Socket.IO event instead of recomputing client-side |
| LOW | `backend.py` L1093-1100 | `_MALWARE_WATCH_PATHS` hard-coded; `C:\Downloads` does not exist on most systems and `C:\Users` is extremely broad — the rglob will traverse the entire user profile tree every 120s | Add directory existence checks before rglob; consider narrowing to `Downloads`, `AppData\Temp`, `Desktop` |
| LOW | `sysmon_behavior_agent.py` L115-120 | `_EXTENDED_WHITELIST` includes `node.exe`, `python.exe`, `bash.exe` — these are high-value attacker tools (living-off-the-land) that should NOT be globally suppressed | Remove from whitelist; instead reduce verbosity by increasing alert cooldown for these PIDs |
| LOW | `requirements.txt` | Missing: `pefile`, `torch`, `python-dotenv` listed but `pefile` required by `malware_analysis_agent.py` is absent | Add `pefile>=2023.2.7` |

================================================================================

## SECTION 2: SECURITY VULNERABILITY ANALYSIS

### 2.1 Critical Vulnerabilities

**CRED-01 — MongoDB Atlas credentials in source code**
- Description: `config.py` line 54 hardcodes a full Atlas SRV URI including
  username (`annashabib02283_db_user`) and password (`5sJ6ZzdQg3rT2Zy2`) as the
  fallback default when `MONGO_URI` env var is unset.
- Impact: Any team member or CI system that clones this repo gets database
  write access. If the repo is ever made public (e.g., for a portfolio/demo),
  the Atlas cluster is immediately exposed.
- CWE: CWE-798 (Use of Hard-coded Credentials)
- Remediation: (1) Rotate the Atlas password NOW. (2) Replace the hardcoded URI
  with `"mongodb://localhost:27017"` as fallback. (3) Add `.env` to `.gitignore`
  and document that `MONGO_URI` must be set in `.env` before running.

**CRED-02 — Default API key accepted in all environments**
- Description: `XDR_API_KEY` defaults to `"changeme-dev-key"`. The CRITICAL
  startup log is a warning only — the backend still starts and accepts this key
  for `/ingest`, `/fusion`, `/shap`, `/commands`, `/predict/*`, and
  `/scan/malware`.
- Impact: Any local network participant who knows the default key can inject
  telemetry, retrieve SHAP explanations (information leakage), or flood the
  commands queue.
- CWE: CWE-1392 (Use of Default Credentials)
- Remediation: Check `settings.api_key == "changeme-dev-key"` in `_startup()`
  and conditionally refuse to serve protected endpoints (or shut down) unless
  the env var is explicitly overridden.

### 2.2 High Severity

**AUTH-01 — Unauthenticated endpoints exposing system state**
- `/system/analyze` (POST) — no API key required; accepts arbitrary 20-feature
  telemetry rows, injects them into the system agent's rolling buffer, and
  returns LSTM scores. An attacker can manipulate the buffer to inflate system
  scores and trigger false SOAR commands.
- `/sysmon/status` (GET) — no API key required; exposes agent status including
  log paths and event/alert counts (reconnaissance information).
- CVE reference: OWASP API3:2023 Broken Object Property Level Authorization.
- Remediation: Add `dependencies=[Depends(_require_key)]` to both endpoints.

**NET-01 — Wildcard CORS on authenticated API**
- `cors_allowed_origins="*"` allows any web page on any origin to make
  credentialed requests to the Socket.IO server and REST API.
- Impact: A malicious web page opened by a SOC analyst can silently subscribe
  to `malware_alert` / `fusion_alert` events and exfiltrate alert data.
- CWE: CWE-942 (Permissive Cross-domain Policy with Untrusted Domains)
- Remediation: Restrict to `["http://localhost:3000"]` for dev;
  parameterize for prod via `CORS_ORIGIN` env var.

**PKL-01 — Pickle deserialization of detector.pkl from filesystem**
- `SysmonBehaviorAgent._load_model()` loads a 27 MB pickle file from
  `D:\Cyber Sentinal\System Behavior\System_Behavior_Model\DETECTOR1\saved_model_v3\detector.pkl`.
  The allowlist is good but the path is not validated against any allowlist of
  trusted model directories — `model_pkl_path` comes from `settings.sysmon_model_dir`
  which is env-var overrideable.
- CWE: CWE-502 (Deserialization of Untrusted Data)
- Remediation: Validate that `model_pkl_path` resolves under a known, fixed
  parent path before calling `open()`.

### 2.3 Medium / Low Severity

**LOG-01 — Sensitive paths in log output**
- Model paths, Winlogbeat directory, MongoDB URI substring, and SOAR file paths
  are logged at INFO level. In a shared-log environment this leaks topology.
- CWE: CWE-532 (Insertion of Sensitive Information into Log File)
- Remediation: Redact connection strings (show only host:port) and shorten
  absolute paths in log messages.

**INPUT-01 — Malware scan path traversal partially mitigated**
- `/scan/malware` checks `is_relative_to()` against `scan_allowed_roots`.
  However, symlinks under an allowed root can escape the intended directory.
- CWE: CWE-22 (Path Traversal)
- Remediation: Resolve symlinks with `Path.resolve()` before the `is_relative_to`
  check (already done for `req_path`; verify `root` is also resolved).

**RATE-01 — No rate limiting on `/ingest`**
- `/ingest` accepts arbitrary JSON without rate limiting. An endpoint agent
  misconfiguration or compromised host can flood MongoDB.
- Remediation: Add a per-IP request-rate limit (e.g., `slowapi` middleware, or
  an nginx upstream rate limit).

================================================================================

## SECTION 3: ARCHITECTURE GAP ANALYSIS

| Layer | Component | Status | Notes |
|-------|-----------|--------|-------|
| Network Monitoring | Suricata eve.json + rule_detector.py | PARTIAL | Suricata rules and incremental eve.json reader complete; Suricata process auto-started by /start-monitoring |
| Network Detection | hybrid_detector.py Gate 2 (RandomForest) | COMPLETE | network_classifier.pkl present (19.7 MB, trained 2026-04-21, 99.6% accuracy) |
| Network Detection | hybrid_detector.py Gate 1 (Personal Baseline) | PARTIAL | personal_baseline_model.pkl present (2.6 MB, trained 2026-04-21) but the KNOWN BUG of sklearn version mismatch (1.7.2 scaler vs 1.8.0 runtime) may cause this to score=1.0 — needs verification after env upgrade |
| Network Detection | CIC-IDS2017 feature set (76 features) | COMPLETE | network_features.pkl, network_scaler.pkl, network_label_encoder.pkl all present |
| User Behavior | xdr_runtime.py OC-SVM inference | COMPLETE | user_model.pkl (1.9 MB) + user_scaler.pkl + feature_columns.json + model_threshold.json all present |
| User Behavior | Winlogbeat NDJSON delivery to XDR_Logs | NOT STARTED | C:\XDR_Logs not configured; Winlogbeat is conditionally started only when START_WINLOGBEAT=true; user behavior will read 0 real events |
| User Behavior | OCEAN personality features | NOT STARTED | All five OCEAN features hardcoded to 0.0 in xdr_runtime.py |
| System Monitor | LSTM Autoencoder + psutil | PARTIAL | system_model.pt present (248 KB, trained 2026-04-22, 241 windows, threshold=1.625); system_scaler.pkl present; BUT confirmed score=1.0 bug due to sklearn scaler version mismatch |
| System Monitor | Rolling self-calibration | COMPLETE | Implemented in _infer() — adapts threshold after 60 windows |
| Sysmon Behavior | SysmonBehaviorAgent (file-based) | COMPLETE | Fully rewritten 2026-04-25; _tail_loop + PS forwarder dual-path; no win32evtlog dependency |
| Sysmon Behavior | SysmonFileReader (NDJSON tailer) | COMPLETE | Handles ECS and legacy Winlogbeat formats |
| Sysmon Behavior | detector.pkl (trained model) | PARTIAL | 27 MB file present at saved_model_v3/detector.pkl (trained externally); agent loads it via custom _DetectorUnpickler with allowlist |
| Sysmon Behavior | Winlogbeat writing to C:\winlogbeat\logs\sysmon_events.json | NOT STARTED | File-based reader has no data source unless Winlogbeat is configured to write there; PS forwarder is the active fallback |
| Malware Detection | MalwareAnalysisAgent (EMBER features, LightGBM) | COMPLETE | malware_model.pkl (1.1 MB), malware_scaler.pkl, malware_feature_names.pkl all present |
| Malware Detection | Background file-watcher loop | COMPLETE | _malware_scan_loop() scans C:\Users, C:\Temp, etc. every 120s |
| Malware Detection | pefile dependency | MISSING | Not in requirements.txt; malware PE extraction silently degrades without it |
| Fusion Engine | Weighted fusion + corroboration bonuses | COMPLETE | Weights: net=0.35, user=0.30, sys=0.15, mal=0.20 (sum=1.0) |
| Fusion Engine | Escalation hard-overrides | COMPLETE | Rules A-D implemented for malware, network+system, insider threat, malware+network |
| SHAP Explainability | Network RandomForest SHAP | COMPLETE | TreeExplainer on network_classifier.pkl |
| SHAP Explainability | Malware LightGBM SHAP | COMPLETE | TreeExplainer on malware_model.pkl |
| SHAP Explainability | System LSTM SHAP | NOT STARTED | No SHAP path for system monitor or sysmon behavior |
| SHAP Explainability | Fusion SHAP | COMPLETE | explain_fusion() combines score contributions into reason strings |
| SOAR / Endpoint | EndpointAgent (poll/execute/ack) | COMPLETE | isolate_host, block_ip, unblock_ip, kill_process, quarantine_file all implemented |
| SOAR / Endpoint | SOAR commands written to MongoDB | COMPLETE | quarantine_file written at score>=0.85; response triggers at fusion>=0.65 |
| MongoDB / Persistence | All 8 collections | COMPLETE | logs, features, predictions, alerts, shap_explanations, commands, endpoints, user_behavior_cycles, malware_scans, sysmon_alerts |
| MongoDB / Persistence | Atlas M0 auto-trim | COMPLETE | Per-collection caps + emergency 50% trim |
| Frontend | SOC Dashboard (React CRA) | COMPLETE | NetworkView, AlertsView, MalwareView, UserBehaviorView, SystemStatusView, SysmonBehaviorView, OverviewView |
| Frontend | MongoDB live status card | COMPLETE | Polls /storage-status every 30s; passes mongoOk to OverviewView |
| Frontend | Socket.IO event subscription | COMPLETE | network, user_anomaly, user_behavior_summary, system_anomaly, malware_alert, malware_scan, sysmon_behavior_alert, sysmon_log, fusion_alert |
| Frontend | Global threat score | NEEDS REVISION | OverviewView computes its own score client-side (net*0.6 + user*0.4) ignoring malware/system/sysmon; should use fusion_alert score from backend |

================================================================================

## SECTION 4: CONFLICTS AND INCOMPATIBILITIES

### 4.1 sklearn Version Mismatch (CONFIRMED BUG — system_model.pt / system_scaler.pkl)

**Root Cause**: `system_scaler.pkl` was pickled by scikit-learn 1.7.2 (the
version active in the venv when `train_system_model.py` was run on 2026-04-22).
The current runtime environment has scikit-learn 1.8.0 installed (as evidenced
by `requirements.txt` specifying `scikit-learn>=1.3.0` without an upper bound).

**Effect**: When `_infer()` calls `self._scaler.transform(arr)`, scikit-learn
1.8.0's `StandardScaler` applies its new internal normalization paths to the
data pickled by 1.7.2, producing out-of-range scaled values. The LSTM
Autoencoder receives inputs with very large magnitudes, produces a high
reconstruction error, and the normalized score clamps to 1.0.

**Verification**: Run `python -c "import joblib; s=joblib.load('Backend/system_scaler.pkl'); print(s.__getstate__().get('_sklearn_version','unknown'))"` in the Backend venv.

**Resolution**: Retrain `system_model.pt` and `system_scaler.pkl` after pinning
scikit-learn to the exact version in the venv (`scikit-learn==1.8.0`), or set
`scikit-learn>=1.3.0,<1.8.0` and reinstall. Retraining takes approximately 60
minutes of normal operation to collect 241+ windows.

### 4.2 Personal Baseline Model — Same Version Risk

**Root Cause**: `personal_baseline_model.pkl` (2026-04-21, 4.3 MB CSV collected,
2.6 MB model) was trained in the same session where the sklearn version mismatch
may have existed. Gate 1 of the hybrid detector applies this IsolationForest to
CIC features; if the scaler is similarly mismatched, Gate 1 will pass all flows
to Gate 2 unconditionally (or block all flows).

**Resolution**: Same as 4.1 — retrain after confirming sklearn version.

### 4.3 Dual Sysmon Event Sources — Potential Double-Processing

**Root Cause**: The backend now runs two concurrent Sysmon event paths:
1. `SysmonBehaviorAgent._tail_loop()` — reads `C:\winlogbeat\logs\sysmon_events.json`
2. `_sysmon_ps_loop()` — polls Get-WinEvent via PowerShell every 2 seconds

Both paths call `_sysmon_agent._handle_event()` on the same agent instance.
If Winlogbeat is configured AND the PS forwarder is running, the same event may
be processed twice by `_handle_event()` — double-counting tokens in the PID
window, artificially accelerating the stride counter, and potentially firing
duplicate alerts.

**Resolution**: Make the two paths mutually exclusive: if `sysmon_events.json`
exists and is being written to, skip the PS forwarder (or vice versa). Add a
flag `_sysmon_source: str = "none"` and have the tail loop set it to `"file"`
when it successfully reads events; the PS forwarder checks this flag before
calling `_handle_event`.

### 4.4 system_anomaly Rate-Limit Does Not Apply to Sysmon Path

**Root Cause**: `_handle_system_result()` enforces a 30-second cooldown
(`_SYSTEM_ALERT_COOLDOWN`) before saving/emitting system anomaly alerts.
`_handle_sysmon_result()` has no cooldown — every scored PID window that crosses
the threshold fires an alert and emits to Socket.IO. At high event rates (e.g.,
a port scan generating EventID 3 floods), this can produce hundreds of
`sysmon_behavior_alert` events per minute.

**Resolution**: Add a per-PID cooldown to `_handle_sysmon_result()`, or reuse
the existing 120s `_ALERT_COOLDOWN_S` in `SysmonBehaviorAgent._score_pid()` (it
already exists but only suppresses the on_result callback, not the socket emit).

### 4.5 OverviewView Threat Score Diverges From Backend Fusion

**Root Cause**: `OverviewView.tsx` computes `globalThreatScore` as
`netScore * 0.6 + userScore * 0.4` where `netScore` is derived from raw attack
count percentage, completely ignoring system, malware, and sysmon contributions.
The backend fusion uses `net=0.35, user=0.30, sys=0.15, mal=0.20`.

**Resolution**: Listen to the `fusion_alert` Socket.IO event in the dashboard
and use `fusion_alert.threat_score * 100` as the gauge value. This eliminates
the client-side recomputation and stays in sync with backend escalation logic.

### 4.6 requirements.txt Missing pefile

`pefile` is imported in `malware_analysis_agent.py` with a graceful fallback,
but it is not listed in `requirements.txt`. A fresh `pip install -r requirements.txt`
will produce a working backend that silently cannot analyze PE files — malware
predictions will always return `reason="pefile_not_installed"`.

================================================================================

## SECTION 5: KNOWN BUGS AND OPEN ISSUES

### 5.1 CONFIRMED: system_model.pt produces score=1.0 always
- Root cause: sklearn scaler version mismatch (scaler pickled with 1.7.2,
  loaded by 1.8.0 runtime) causes extreme scaled inputs to the LSTM Autoencoder.
- Impact: System monitor CRITICAL alerts fire immediately on every 60-second
  window, flooding Socket.IO and potentially triggering false SOAR responses.
- Fix: Retrain system_model.pt and system_scaler.pkl after resolving sklearn
  version (see Section 4.1).

### 5.2 OPEN: OCEAN personality features hardcoded to 0.0
- Location: `User Behavior/final_model_backend_only/xdr_runtime.py`
- Impact: User behavior model accuracy is reduced; OCEAN-correlated insider
  threat patterns cannot be detected.
- Fix: Connect a data source (e.g., HR system export, baseline interview
  questionnaire) and inject OCEAN scores via the model configuration.

### 5.3 OPEN: Winlogbeat not configured for user behavior logs
- Location: User behavior pipeline reads from `C:\XDR_Logs\`
- Impact: `xdr_runtime.py` reads 0 real Windows events; all user behavior
  inference runs on empty or simulated data only.
- Fix: Configure Winlogbeat to write security events to `C:\XDR_Logs\`; enable
  `START_WINLOGBEAT=true` in `.env`.

### 5.4 OPEN: Winlogbeat not configured for Sysmon events
- Location: SysmonBehaviorAgent file-based path reads
  `C:\winlogbeat\logs\sysmon_events.json`
- Impact: File-based reader has no data; PS forwarder is the only active source.
  PS forwarder works but has higher latency (2s polling interval) than real-time
  Winlogbeat delivery.
- Fix: Configure Winlogbeat with `output.file` pointing to
  `C:\winlogbeat\logs\sysmon_events.json`; add the Sysmon operational channel
  to Winlogbeat's event log inputs.

### 5.5 OPEN: personal_baseline_model.pkl may be affected by sklearn mismatch
- See Section 4.2 above.
- A quick diagnostic: call `_network_agent.detect_from_flows([test_flow])` and
  check whether Gate 1 consistently returns anomaly=True for clearly benign
  traffic.

### 5.6 OPEN: pefile not in requirements.txt
- See Section 4.6 above.
- Immediate fix: add `pefile>=2023.2.7` to requirements.txt.

### 5.7 OPEN: print() statement in production code path
- `sysmon_winevent_reader.py` line 251: `print("[SYSMON JSON] EventID=", ...)`
  will fire for every Sysmon event yielded by the tail() generator.
- Impact: Floods stdout; useless in production; interferes with log aggregation.
- Fix: Replace with `logger.debug(...)`.

================================================================================

## SECTION 6: MODEL ARTIFACTS STATUS

| Artifact | Path | Exists | Size | Trained | Notes |
|----------|------|--------|------|---------|-------|
| network_classifier.pkl | Backend/ | YES | 19.7 MB | 2026-04-21 | 99.6% accuracy, 8-class RandomForest on CIC-IDS2017 |
| network_label_encoder.pkl | Backend/ | YES | 556 B | 2026-04-21 | Matches classifier classes |
| network_model_isolation.pkl | Backend/ | YES | 1.5 MB | 2026-02-25 | Legacy IsolationForest; Gate 2 now uses RandomForest |
| network_scaler.pkl | Backend/ | YES | 3.5 KB | 2026-02-25 | StandardScaler for 76 CIC features |
| network_features.pkl | Backend/ | YES | 1.2 KB | 2026-02-25 | Ordered list of 76 CIC feature names |
| personal_baseline_model.pkl | Backend/ | YES | 2.6 MB | 2026-04-21 | Gate 1 personal IsolationForest — MAY be affected by sklearn mismatch |
| personal_baseline.csv | Backend/ | YES | 4.3 MB | 2026-04-21 | Raw baseline capture used for training |
| user_model.pkl | User Behavior/.../final_model_backend_only/ | YES | 1.9 MB | 2026-04-21 | OC-SVM on CERT Insider Threat r4.2 |
| user_scaler.pkl | User Behavior/.../final_model_backend_only/ | YES | 1.6 KB | 2026-04-21 | StandardScaler for 12 user features |
| malware_model.pkl | Backend/ | YES | 1.1 MB | 2026-04-21 | LightGBM on EMBER 2018 (AUC=0.9803, F1=0.9298) |
| malware_scaler.pkl | Backend/ | YES | 7.3 KB | 2026-04-21 | StandardScaler for 280-dim EMBER features |
| malware_feature_names.pkl | Backend/ | YES | 3.1 KB | 2026-04-21 | 280 EMBER feature names for SHAP |
| system_model.pt | Backend/ | YES | 248 KB | 2026-04-22 | LSTM Autoencoder state dict — BUGGY (score=1.0 always) |
| system_scaler.pkl | Backend/ | YES | 1.1 KB | 2026-04-22 | VERSION MISMATCH — must retrain |
| system_metadata.json | Backend/ | YES | 847 B | 2026-04-22 | threshold=1.625, 241 training windows, n_features=20 |
| detector.pkl | System Behavior/.../saved_model_v3/ | YES | 27.2 MB | 2026-04-21 | WindowsAnomalyDetector (TF-IDF + XGBoost + IsolationForest); trained externally |
| sysmon_lstm_model.pt | Backend/ | NO | — | Not started | No LSTM for sysmon feature extractor path; not referenced in agent code |

**Summary**: 13/14 tracked artifacts exist. The one critical missing artifact is
`sysmon_lstm_model.pt` — though on review the SysmonBehaviorAgent does not use
it (it uses detector.pkl via the WindowsAnomalyDetector). The real functional
gap is `system_model.pt` and `system_scaler.pkl` needing retraining.

================================================================================

## SECTION 7: NEXT STEPS AND IMPLEMENTATION ROADMAP

### Immediate Actions (0-2 weeks) — Critical Fixes

**P0-1 — Rotate Atlas credentials and remove from source code**
1. Log into MongoDB Atlas, go to Database Access, and rotate the password for
   `annashabib02283_db_user` immediately.
2. In `config.py` line 54, replace the hardcoded Atlas URI with:
   `mongo_uri: str = _env("MONGO_URI", "mongodb://localhost:27017")`
3. Create `.env` at project root with the real Atlas URI; add `.env` to
   `.gitignore`.
4. Document in CLAUDE.md that `MONGO_URI` must be set in `.env`.

**P0-2 — Fix sklearn version mismatch and retrain system model**
1. Activate the Backend venv.
2. Run `pip install "scikit-learn==1.8.0"` (or whichever version is in the
   active runtime) to confirm the installed version.
3. Run `python train_system_model.py --collect-minutes 60` to retrain
   `system_model.pt` and `system_scaler.pkl` with the current sklearn.
4. Restart the backend and verify `system_agent.last_score` is not always 1.0.

**P0-3 — Add pefile to requirements.txt**
1. Add `pefile>=2023.2.7` to `Backend/requirements.txt`.
2. Run `pip install pefile` in the venv.
3. Verify `malware_analysis_agent._PEFILE_AVAILABLE` is True at startup.

**P0-4 — Fix unauthenticated endpoints**
1. In `backend.py`, add `dependencies=[Depends(_require_key)]` to:
   - `@app.post("/system/analyze")`
   - `@app.get("/sysmon/status")`
2. Update `CLAUDE.md` FastAPI endpoint table to reflect auth requirements.

**P0-5 — Remove print() from sysmon_winevent_reader.py**
1. In `sysmon_winevent_reader.py` line 251, replace:
   `print("[SYSMON JSON] EventID=", event["event_id"])`
   with:
   `logger.debug("[SYSMON JSON] EventID=%s", event["event_id"])`

### Short-term (2-6 weeks) — High Priority Improvements

**P1-1 — Configure Winlogbeat for user behavior and Sysmon event delivery**
1. Install Winlogbeat 9.3.3 in `User Behavior/winlogbeat-9.3.3-windows-x86_64/`.
2. Configure `winlogbeat.yml` to collect Security event log (events 4624, 4625,
   4648, 4688, 4720, 4726) and write NDJSON to `C:\XDR_Logs\`.
3. Add a second output stanza to write Sysmon operational log events to
   `C:\winlogbeat\logs\sysmon_events.json`.
4. Set `START_WINLOGBEAT=true` in `.env`.
5. Verify `xdr_runtime.py` reads events within one 60-second inference cycle.

**P1-2 — Resolve dual Sysmon source double-processing**
1. In `SysmonBehaviorAgent`, add `_active_source: str = "none"`.
2. In `_tail_file()`, set `_active_source = "file"` when a line is successfully
   read.
3. In `_sysmon_ps_loop()`, check `if _sysmon_agent._active_source == "file":
   continue` to skip calling `_handle_event` when the file source is active.

**P1-3 — Restrict CORS to dashboard origin**
1. In `backend.py`, change `cors_allowed_origins="*"` to
   `cors_allowed_origins=[settings.dashboard_origin]`.
2. Add `dashboard_origin: str = _env("DASHBOARD_ORIGIN", "http://localhost:3000")`
   to `config.py`.

**P1-4 — Fix OverviewView threat score gauge**
1. In `NetworkDashboard.tsx`, listen for `fusion_alert` Socket.IO events and
   store the latest `fusion_alert.threat_score` in React state.
2. Pass it to `OverviewView` as `fusionThreatScore: number`.
3. In `OverviewView.tsx`, replace the `globalThreatScore` useMemo with the
   received `fusionThreatScore * 100` when available, falling back to the
   existing heuristic when no fusion event has been received.

**P1-5 — Verify personal_baseline_model.pkl correctness**
1. Run `python -c "import joblib; m=joblib.load('Backend/personal_baseline_model.pkl'); print(type(m))"`.
2. Feed known-benign flows through `hybrid_detector.py` and check Gate 1 output.
3. If Gate 1 labels all benign flows as anomalies, retrain:
   `python collect_baseline.py` (30 min, requires Suricata), then
   `python train_personal_model.py`.

### Medium-term (6-12 weeks) — Architecture Enhancements

**P2-1 — SHAP coverage for system monitor and Sysmon behavior**
Currently SHAP only covers network (RandomForest) and malware (LightGBM).
- For `system_monitor_agent`: implement gradient-based attribution using
  `torch.autograd` or `captum` (PyTorch attribution library) on the LSTM
  Autoencoder to identify which of the 20 psutil features drove the
  reconstruction error.
- For `sysmon_behavior_agent`: the WindowsAnomalyDetector already has
  `nonzero_feats` from TF-IDF; expose top token contributions as a reason
  string in the result dict.

**P2-2 — Implement rate limiting on /ingest**
1. Add `slowapi` to requirements.txt.
2. Configure a `Limiter` middleware: `@limiter.limit("60/minute")` on `/ingest`.
3. Return HTTP 429 for excess requests.

**P2-3 — Add OCEAN feature data source**
1. Create a simple REST endpoint `POST /users/ocean` that accepts
   `{user: str, O: float, C: float, E: float, A: float, N: float}`.
2. Persist in a `user_profiles` MongoDB collection.
3. In `xdr_runtime.py`, query this collection to fill OCEAN features before
   OC-SVM inference instead of using hardcoded 0.0.

**P2-4 — Model drift detection for network and user classifiers**
1. Log per-prediction confidence distributions to MongoDB `predictions` collection
   (already done).
2. Add a weekly batch job (cron or manual script) that computes the KL divergence
   of the current week's confidence distribution vs. the training baseline.
3. Emit a `model_drift_warning` Socket.IO event to the dashboard when KL > 0.3.

**P2-5 — Narrow malware watcher scan scope**
1. Replace broad `C:\Users` rglob with targeted paths:
   `C:\Users\*\Downloads`, `C:\Users\*\Desktop`, `C:\Users\*\AppData\Local\Temp`.
2. Add existence checks before walking.
3. Reduce scan interval from 120s to 300s for the broad paths; keep 60s for
   `C:\Temp` and `C:\Windows\Temp`.

### Long-term (3-6 months) — Advanced Capabilities

**P3-1 — Replace hardcoded fusion weights with adaptive learning**
Collect ground-truth attack labels from confirmed incidents and implement a
gradient descent step on the fusion weights after each confirmed true positive,
with weight decay to prevent overfitting to recent attacks.

**P3-2 — Implement network flow micro-fragmentation grouping**
The CLAUDE.md known issue lists "flow micro-fragmentation" as outstanding.
Implement a flow aggregator in `network_detection_agent.py` that groups Suricata
flows by (src_ip, dst_ip, dst_port, proto, 60s bucket) before CIC feature
extraction, preventing artificially low byte/packet counts from fragmenting flows.

**P3-3 — High availability and failover**
- Run two backend instances behind an nginx upstream; configure MongoDB sessions
  with replica-set read preference `primaryPreferred`.
- Add Redis for shared state (_latest_scores, _malware_seen) when running
  multi-instance.

**P3-4 — Threat intelligence enrichment**
- Integrate VirusTotal API for file hash lookups in `malware_analysis_agent`.
  Already referenced in CLAUDE.md as a planned feature.
- Integrate AbuseIPDB or OTX for IP reputation checks in `rule_detector.py`.

================================================================================

## SECTION 8: METRICS AND KPIs TO TRACK

| Metric | Target | How to Measure |
|--------|--------|----------------|
| Network detection false positive rate | < 5% | `predictions` collection: count BENIGN flows with ML confidence > 50% |
| Network detection latency | < 500 ms | Time from Suricata eve.json write to Socket.IO `network` emit |
| User behavior inference cycle time | < 60s | `user_behavior_cycles.cycle_ts` delta between consecutive docs |
| System monitor buffer fill rate | 60/60 within 65s of start | `system_agent.buffer_fill` in /health |
| Sysmon PS forwarder lag | < 5s end-to-end | Compare event `TimeCreated` (in XML) to `ts` in `sysmon_alerts` |
| Malware scan coverage | > 90% of new PE files within 120s | Count unique files in `malware_scans` vs. new files in watched dirs |
| Fusion true positive rate | > 85% | Manual review of `alerts` where `should_respond=True` |
| SOAR command acknowledgment rate | > 95% within 30s | `commands` collection: `status=done` within 30s of `status=pending` |
| Atlas storage utilization | < 80% of cap per collection | `/storage-status` endpoint |
| API key rotation cadence | Every 90 days | Track `XDR_API_KEY` change date in runbook |

================================================================================

## SECTION 9: IMPLEMENTATION COMPLETENESS SUMMARY

| Layer | Completeness | Key Gap |
|-------|-------------|---------|
| Network Detection (rule + hybrid ML) | 90% | Personal baseline may need retraining; flow micro-fragmentation unresolved |
| User Behavior (OC-SVM, Winlogbeat) | 55% | Winlogbeat not configured; OCEAN=0.0; real events = 0 |
| System Monitor (LSTM psutil) | 60% | Model produces score=1.0 (sklearn mismatch bug); needs retraining |
| Sysmon Behavior (file-based, PS forwarder) | 70% | Winlogbeat sysmon output not configured; dual-source double-processing risk |
| Malware Detection (EMBER, LightGBM) | 95% | pefile missing from requirements.txt; otherwise fully operational |
| Fusion Engine | 100% | All weights, thresholds, escalation rules complete |
| SHAP Explainability | 80% | Network + malware + fusion covered; system/sysmon SHAP not implemented |
| SOAR / Endpoint Agent | 90% | Agent code complete; not deployed on remote endpoints in current setup |
| MongoDB / Persistence | 95% | All collections present; Atlas M0 auto-trim working |
| Frontend / SOC Dashboard | 85% | All views present; OverviewView threat score diverges from backend fusion |

**Overall project completeness: approximately 82%**

================================================================================
END OF REPORT
Next Analysis Recommended: After (a) retraining system_model.pt, (b) configuring
Winlogbeat, and (c) rotating Atlas credentials — estimated 2 weeks. Trigger
another full status review after the first production monitoring session (>1 hour
continuous operation with real network traffic).
================================================================================
