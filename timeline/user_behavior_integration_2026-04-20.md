================================================================================
IDPS PROJECT ANALYSIS REPORT
================================================================================
Timestamp     : 2026-04-20 00:00:00 UTC
Analyst       : IDPS Project Analyst Agent
Scope         : User Behavior Module — Backend Wiring & Frontend Integration
Project Phase : Integration (Backend functional; Frontend display absent)
================================================================================

## EXECUTIVE SUMMARY

The User Behavior module is in a split state: the backend plumbing is approximately
90% complete — the UserBehaviorAgent background loop fires every 300 seconds,
calls xdr_runtime.run_inference(), and the _handle_user_result callback is correctly
wired to emit Socket.IO events and persist anomalies to MongoDB. However, three
critical gaps block end-to-end operation: (1) the frontend (NetworkMonitor.tsx)
registers zero listeners for either "user_anomaly" or "user_behavior_summary",
so all emitted events are silently dropped at the browser; (2) the /predict/user
REST endpoint never invokes _handle_user_result, meaning on-demand calls produce
no Socket.IO emission and no MongoDB persistence; and (3) the anomaly_score
from the One-Class SVM decision_function can be negative — passing it raw into
the fusion engine produces mathematically invalid threat scores. A developer can
close all gaps in one focused sprint without touching model training artifacts.

Overall integration health score: 4/10


## SECTION 1: CODE QUALITY ASSESSMENT

### 1.1 Strengths

- UserBehaviorAgent (user_behavior_agent.py) follows clean async patterns:
  asyncio.to_thread() for blocking I/O, graceful CancelledError propagation,
  separate run_once() for on-demand calls vs. _tick() for the scheduled loop.
- _handle_user_result (backend.py lines 484-502) correctly filters only ANOMALY
  rows before emitting, avoiding alert flooding on normal cycles.
- xdr_runtime.py uses a layered fallback: decision_function -> predict_proba ->
  raw predict, making it resilient across sklearn estimator types.
- config.py externalizes all paths and thresholds via environment variables with
  sane defaults — no absolute paths are hardcoded in backend.py itself.
- The USB override threshold in run_inference() provides a rule-based escalation
  path independent of model confidence, which is sound defense-in-depth.

### 1.2 Issues Found

| Severity | Component | Issue | Recommendation |
|----------|-----------|-------|----------------|
| CRITICAL | backend.py:327-337 | /predict/user calls _user_agent.run_once() but never calls _handle_user_result(result); on-demand inferences do not emit Socket.IO events and are not persisted to MongoDB | After run_once(), call asyncio.create_task(_handle_user_result(result)) before returning |
| CRITICAL | NetworkMonitor.tsx:356-421 | Socket.IO useEffect registers handlers only for "network" and "monitoring_status"; "user_anomaly" and "user_behavior_summary" are never subscribed — events are dropped silently | Add socket.on("user_anomaly", ...) and socket.on("user_behavior_summary", ...) handlers |
| HIGH | xdr_runtime.py:224-226 | decision_function() returns raw SVM margin scores ranging roughly -1.0 to +1.0 (negative = normal for OC-SVM); these are stored as anomaly_score and passed as user_score to fusion.fuse() which expects [0.0, 1.0] — fusion math is incorrect for negative inputs | Normalize: normalized = (score - min_score) / (max_score - min_score) using calibrated bounds, or apply sigmoid: 1 / (1 + exp(-score)) before passing to fusion |
| HIGH | xdr_runtime.py:19 | LOG_DIR defaults to xdr_runtime.py's own parent directory / "logs" when USER_LOG_DIR env var is unset; config.py sets USER_LOG_DIR default to C:\XDR_Logs — but xdr_runtime.py is imported by user_behavior_agent.py which runs inside the backend process and reads its OWN env var, not config.py's setting. There is no code in user_behavior_agent.py or backend.py that sets os.environ["USER_LOG_DIR"] before importing xdr_runtime | In backend.py _startup(), before instantiating UserBehaviorAgent, set: os.environ["USER_MODEL_DIR"] = settings.user_model_dir and os.environ["USER_LOG_DIR"] = settings.user_log_dir |
| HIGH | xdr_runtime.py:289-300 | get_service_status() passes unsanitized service name directly into a PowerShell command string — classic command injection (CWE-78) | Use subprocess list form: ["powershell", "-NoProfile", "-Command", "Get-Service", "-Name", name] or validate name against an allowlist |
| MEDIUM | xdr_runtime.py:22-27 | load_pickle() uses pickle.load() as primary deserializer — arbitrary code execution if model file is tampered (CWE-502) | Use joblib.load() as primary (already available as fallback); alternatively verify a SHA-256 checksum of model artifacts at startup |
| MEDIUM | backend.py:327-337 | /predict/user endpoint has no rate limiting; a caller can trigger repeated full log scans of C:\XDR_Logs at arbitrary frequency, causing I/O exhaustion | Add a cooldown guard: track last_manual_run timestamp on _user_agent and enforce a minimum 60-second gap |
| MEDIUM | xdr_runtime.py:182-188 | OCEAN personality features (O, C, E, A, N) and business_unit are hardcoded to 0.0 in normalize_events_to_features(); the scaler was trained on the CERT r4.2 dataset where these features have real variance — hardcoding them biases every prediction toward the 0-value cluster | Either remove these features from feature_columns.json and retrain the scaler, or source them from a user profile lookup table |
| LOW | user_behavior_agent.py:106-109 | _loop() calls _tick() then sleeps — on first startup there is no immediate tick; the first inference runs only after interval_seconds (300s default) | Move the first _tick() call before the sleep in the loop, or call _tick() once immediately after start() |
| LOW | backend.py:484-502 | _handle_user_result does not persist the full result summary to a dedicated collection; only anomalous rows go to "alerts" | Consider writing summary to a "user_behavior_cycles" collection for SOC trend dashboards |


## SECTION 2: SECURITY VULNERABILITY ANALYSIS

### 2.1 Critical Vulnerabilities

None at the critical severity level for the integration scope specifically. The
PowerShell injection and pickle deserialization issues are pre-existing and flagged
in the High section below.

### 2.2 High Severity

**CWE-78 — OS Command Injection**
- Location: xdr_runtime.py, get_service_status(), line 296
- Description: The `name` parameter is interpolated directly into a PowerShell
  command string: f"(Get-Service {name}).Status". If name contains semicolons,
  pipes, or backticks, arbitrary PowerShell executes in the backend process context.
- Impact: Full system compromise on the host running the backend server.
- Remediation: Pass the service name as a separate argument:
  ["powershell", "-NoProfile", "-Command", "Get-Service", "-Name", name]
  and validate name matches r'^[A-Za-z0-9_\-\.]+$' before calling.

**CWE-502 — Deserialization of Untrusted Data**
- Location: xdr_runtime.py, load_pickle(), lines 22-27
- Description: pickle.load() is called on .pkl files. If an attacker can write
  to the model directory (C:\XDR_Logs or the model dir), they can achieve RCE
  via a crafted pickle payload.
- Impact: Remote code execution in the backend process.
- Remediation: Replace with joblib.load() throughout (already imported). Enforce
  filesystem ACLs on the model directory so only the service account can write.

**Unsigned Anomaly Score Passed to Fusion Engine**
- Location: xdr_runtime.py lines 224-226 -> _handle_user_result backend.py line 492
- Description: One-Class SVM decision_function() returns values in approximately
  [-1, +1] where negative means "inlier" (normal). A normal user with score -0.8
  passed as user_score=−0.8 to fusion.fuse() produces a negative contribution to
  the weighted threat score, which could suppress a legitimate threat from the
  network model below the HIGH threshold, creating a false negative.
- Impact: Fusion engine produces incorrect threat scores; HIGH-severity attacks
  may be downgraded to MEDIUM due to the negative user score.
- Remediation: Apply sigmoid normalization in _handle_user_result before passing
  to fuse(): import math; normalized = 1 / (1 + math.exp(-raw_score))

### 2.3 Medium/Low Severity

- **Hardcoded dev API key**: config.py line 68 defaults api_key to "changeme-dev-key".
  If the production .env is missing or misconfigured, the backend accepts this key.
  Remediation: Raise ValueError at startup if api_key equals the default string.

- **No TLS on Socket.IO**: CORS is set to "*" and Socket.IO runs plain HTTP.
  User anomaly data including usernames, login hours, and file access counts
  transmit unencrypted. Add nginx/caddy reverse proxy with TLS for production.

- **OCEAN features as zero**: All users appear at the same point in feature space
  for the personality dimensions, artificially compressing inter-user distance
  in the SVM kernel and increasing false negative rate for insider threats whose
  only distinguishing factor is behavioral pattern.


## SECTION 3: ARCHITECTURE GAP ANALYSIS

| Layer | Component | Status | Notes |
|-------|-----------|--------|-------|
| Data Source | Winlogbeat -> .ndjson | PARTIAL | Files must exist at USER_LOG_DIR (C:\XDR_Logs by default); logs/ subdir inside final_model_backend_only is EMPTY — no test data available |
| Data Source | USER_LOG_DIR env propagation | MISSING | backend.py does not set os.environ["USER_LOG_DIR"] before xdr_runtime imports; path resolution uses xdr_runtime's own _HERE which is the wrong directory |
| Inference | xdr_runtime.run_inference() | IMPLEMENTED | Correctly reads ndjson, aggregates by user, scores with OC-SVM, applies USB override |
| Inference | Model artifacts | IMPLEMENTED | user_model.pkl + user_scaler.pkl present in User Behavior/final_model_backend_only/ |
| Agent Wrapper | UserBehaviorAgent | IMPLEMENTED | Async background loop, on_result callback, run_once() for REST |
| Backend Startup | Agent instantiation | IMPLEMENTED | _startup() creates UserBehaviorAgent with on_result=_handle_user_result and calls await _user_agent.start() |
| Backend Callback | _handle_user_result | IMPLEMENTED | Filters anomalies, calls fusion, saves to alerts, emits "user_anomaly" and "user_behavior_summary" |
| REST Endpoint | POST /predict/user | PARTIAL | Calls run_once() and returns result but does NOT call _handle_user_result — no Socket.IO emission, no MongoDB write |
| Score Normalization | Anomaly score -> fusion input | MISSING | Raw SVM margin score passed to fusion without [0,1] normalization |
| Socket.IO Emission | "user_anomaly" event | IMPLEMENTED (backend) | Backend emits correctly; frontend does not listen |
| Socket.IO Emission | "user_behavior_summary" event | IMPLEMENTED (backend) | Backend emits correctly; frontend does not listen |
| Frontend Display | User anomaly panel | MISSING | No component exists; NetworkMonitor.tsx has zero user behavior state or handlers |
| Frontend Display | User behavior summary widget | MISSING | No StatCard, table, or chart for user behavior data |
| Fusion Input | user_score contribution | PARTIAL | Wired but score values are not normalized — see security section |
| MongoDB Persistence | alerts collection (user anomalies) | IMPLEMENTED | _handle_user_result calls _save("alerts", event) |
| MongoDB Persistence | user_behavior_cycles collection | MISSING | Summary statistics are not persisted, only emitted |
| SOAR Response | User-triggered response actions | MISSING | _handle_user_result does not generate SOAR commands even for CRITICAL fusion scores |


## SECTION 4: CONFLICTS AND INCOMPATIBILITIES

### Conflict 1: USER_LOG_DIR Resolution Race

**Root cause**: xdr_runtime.py resolves LOG_DIR at module import time (line 19):
  LOG_DIR = Path(os.getenv("USER_LOG_DIR", str(_HERE / "logs")))
When user_behavior_agent.py imports xdr_runtime at module load (line 19 of
user_behavior_agent.py), this happens before backend.py's _startup() could
set the environment variable. config.py's settings.user_log_dir is never written
to os.environ anywhere in the codebase.

**Effect**: The agent always reads logs from:
  D:\Cyber Sentinal\User Behavior\final_model_backend_only\logs\
instead of C:\XDR_Logs. This directory is empty, so every inference cycle
returns an empty result with zero users.

**Resolution**: In backend.py, before the import of user_behavior_agent, add:
  import os
  os.environ.setdefault("USER_MODEL_DIR", str(Path(__file__).parent.parent / "User Behavior" / "final_model_backend_only"))
  os.environ.setdefault("USER_LOG_DIR", r"C:\XDR_Logs")
Alternatively, modify UserBehaviorAgent.__init__() to accept log_dir and
model_dir as explicit parameters and pass them through to run_inference().

### Conflict 2: feature_columns.json vs. scaler.feature_names_in_

**Root cause**: feature_columns.json lists 12 features:
  ["total_logins", "avg_login_hour", "std_login_hour", "device_events",
   "files_accessed", "emails_sent", "emails_cc", "O", "C", "E", "A", "N"]

xdr_runtime.py line 202 uses scaler.feature_names_in_ if available, which may
differ from feature_columns.json if the scaler was trained on a different feature
set. The normalize_events_to_features() function produces 20 columns including
"after_hours_logins", "unique_pcs", "usb_connects", "usb_disconnects",
"unique_files", "unique_recipients", "business_unit", "user" — these are dropped
silently when X = df[scaler_features] is computed. The mismatch is tolerated but
means behavioral signals computed in normalize_events_to_features() (e.g.
after_hours_logins) are excluded from model input even though the model was
presumably trained to use them.

**Resolution**: Audit the original training script for the One-Class SVM to
confirm the exact feature list used during fit(). Regenerate feature_columns.json
to match. Consider adding "after_hours_logins", "unique_pcs", "unique_recipients"
to the feature set and retraining — these are high-signal insider threat indicators.

### Conflict 3: on-demand /predict/user vs. background loop divergence

**Root cause**: The background loop path:
  _tick() -> _run_inference() -> on_result() -> _handle_user_result() -> sio.emit() + _save()
The REST path:
  /predict/user -> run_once() -> return result (emit and save NEVER called)

**Effect**: A SOC analyst triggering /predict/user manually gets a JSON response
but no dashboard update and no MongoDB alert record. The two paths behave
differently with no indication to the caller.

**Resolution**: In predict_user() (backend.py line 327), after getting the result:
  asyncio.create_task(_handle_user_result(result))
  return result
This fires the handler asynchronously so the REST response is not delayed.


## SECTION 5: NEXT STEPS AND IMPLEMENTATION ROADMAP

### Immediate Actions (0-2 weeks) — Critical fixes

**Priority 1: Fix USER_LOG_DIR env propagation (30 min)**
File: D:\Cyber Sentinal\Backend\backend.py
Action: Before the line `from agents.user_behavior_agent import UserBehaviorAgent`
(currently line 26), insert:
  import os as _os
  _os.environ.setdefault("USER_LOG_DIR", r"C:\XDR_Logs")
  _os.environ.setdefault("USER_MODEL_DIR", str(Path(__file__).parent.parent / "User Behavior" / "final_model_backend_only"))
Verify by checking _user_agent.last_result after first tick — events_count
should be > 0 if Winlogbeat is running and writing to C:\XDR_Logs.

**Priority 2: Fix /predict/user to call _handle_user_result (15 min)**
File: D:\Cyber Sentinal\Backend\backend.py, function predict_user() (lines 327-337)
Replace:
  result = await _user_agent.run_once(...)
  return result
With:
  result = await _user_agent.run_once(...)
  asyncio.create_task(_handle_user_result(result))
  return result

**Priority 3: Add frontend user_anomaly listener (2-4 hours)**
File: D:\Cyber Sentinal\Cyber Sentinal XDR Frontend\src\components\NetworkMonitor.tsx
Inside the useEffect Socket.IO block (after line 409 socket.on("monitoring_status"...)),
add handlers and state:

Add state:
  const [userAnomalies, setUserAnomalies] = useState<UserAnomalyRow[]>([]);
  const [userSummary, setUserSummary] = useState<UserBehaviorSummary | null>(null);

Add types (before the component):
  interface UserAnomalyRow {
    user: string;
    prediction_label: string;
    anomaly_score: number;
    total_logins: number;
    avg_login_hour: number;
    after_hours_logins: number;
    device_events: number;
    usb_connects: number;
    files_accessed: number;
    emails_sent: number;
    time_anomaly: string;
    usb_burst: string;
    activity_spike: string;
    anomaly_reason: string;
    ts: string;
    fusion?: { threat_score: number; severity: string };
  }
  interface UserBehaviorSummary {
    total_users: number;
    normal: number;
    anomaly: number;
    ts: string;
  }

Add socket handlers inside useEffect:
  socket.on("user_anomaly", (data: UserAnomalyRow) => {
    setUserAnomalies(prev => [data, ...prev].slice(0, 50));
  });
  socket.on("user_behavior_summary", (data: UserBehaviorSummary) => {
    setUserSummary(data);
  });

**Priority 4: Add UserBehaviorPanel to the render output (4-6 hours)**
Add a new section below the flow table in NetworkMonitor.tsx render method.
Minimum viable panel contains:
  - A StatCard row: Total Users | Normal | Anomalies (from userSummary)
  - A table of userAnomalies rows with columns:
    User | Anomaly Score | After-Hours | USB Events | Files | Reason | Fusion Score | Time
  - Color-code rows: anomaly_score >= 0.9 -> red border, 0.7-0.9 -> orange

**Priority 5: Normalize anomaly_score before fusion (1 hour)**
File: D:\Cyber Sentinal\Backend\backend.py, function _handle_user_result() (line 492)
Replace:
  user_score = row.get("anomaly_score", 0.5)
  fusion = _fusion_agent.fuse(user_score=user_score) if _fusion_agent else None
With:
  import math
  raw = row.get("anomaly_score", 0.0)
  user_score = float(1 / (1 + math.exp(-raw)))   # sigmoid normalization to [0,1]
  fusion = _fusion_agent.fuse(user_score=user_score) if _fusion_agent else None

### Short-term (2-6 weeks) — High priority improvements

**Fix PowerShell injection in get_service_status()**
File: D:\Cyber Sentinal\User Behavior\final_model_backend_only\xdr_runtime.py
Lines 289-300: Use subprocess list form, add allowlist validation.

**Replace pickle.load() with joblib.load()**
File: xdr_runtime.py, load_pickle() function (lines 22-27)
Remove the try/except structure; call joblib_load(path) directly.
Add SHA-256 checksum verification at startup against stored hashes.

**Fix first-tick delay in UserBehaviorAgent**
File: D:\Cyber Sentinal\Backend\agents\user_behavior_agent.py
In _loop() (line 106), change:
  while self._running:
      await self._tick()
      await asyncio.sleep(self.interval_seconds)
This is already correct (tick before sleep). Confirm startup logs show first
inference within ~30s of server start.

**Create Winlogbeat configuration and log directory**
Action: Ensure Winlogbeat ships Windows event logs to C:\XDR_Logs\ as .ndjson files.
Required event IDs: 4624 (logon), 4625 (failed logon), 4663 (file access), 11/15/23 (Sysmon file create).
Winlogbeat output.file configuration:
  path: "C:/XDR_Logs"
  filename: winlogbeat
  rotate_every_kb: 10240

**Persist user behavior cycle summaries**
File: D:\Cyber Sentinal\Backend\backend.py, _handle_user_result() (lines 484-502)
After the anomalous_rows loop, before the summary emit, add:
  _save("user_behavior_cycles", {**result.get("summary", {}), "ts": ts, "threshold": result.get("threshold")})

**Harden default API key**
File: D:\Cyber Sentinal\Backend\config.py, line 68
Add after the settings class:
  if settings.api_key == "changeme-dev-key":
      import warnings
      warnings.warn("XDR_API_KEY is using the default insecure value. Set XDR_API_KEY in .env.", stacklevel=1)

### Medium-term (6-12 weeks) — Architecture enhancements

**OCEAN feature sourcing**
Create a user_profiles.json or MongoDB "user_profiles" collection mapping
usernames to OCEAN scores. Load in normalize_events_to_features() via a lookup
against the "user" field. Without this, insider threat recall will remain
artificially suppressed.

**Retrain One-Class SVM with extended feature set**
After OCEAN sourcing is in place, retrain with the full CERT r4.2 feature set
including after_hours_logins, unique_pcs, unique_recipients. Update
feature_columns.json to match the new scaler.feature_names_in_.

**Add /status/user endpoint**
Expose _user_agent.status() via a dedicated GET /status/user endpoint for
health check dashboards. Currently visible only via /health aggregate.

**UserBehaviorPanel as a separate component**
Refactor the user behavior section out of NetworkMonitor.tsx into:
  D:\Cyber Sentinal\Cyber Sentinal XDR Frontend\src\components\UserBehaviorPanel.tsx
This keeps NetworkMonitor.tsx focused on network flows and enables independent
routing if a tabbed dashboard is added later.

**Add rate limiting to /predict/user**
Implement a cooldown guard on UserBehaviorAgent using last_run_ts to prevent
I/O exhaustion from rapid manual calls.

### Long-term (3-6 months) — Advanced capabilities

**SOAR response for insider threat detections**
Extend _handle_user_result() to generate SOAR command documents for CRITICAL
fusion scores (e.g., disable USB device, lock account, isolate workstation).
Currently only the network pipeline generates commands.

**Streaming log ingestion via Winlogbeat -> Kafka -> backend**
Replace polling .ndjson files with a Kafka consumer in the backend to reduce
log ingestion latency from minutes (file-based) to seconds.

**Model drift detection for user behavior**
Implement a statistical drift monitor that compares the distribution of
anomaly_score values across cycles against a reference window. Alert if
mean score shifts significantly, indicating data distribution change or
attack campaign.

**System (LSTM Autoencoder) and Malware (EMBER) models**
Currently system_score and malware_score are always 0.0 in fusion, meaning
the fusion engine operates at 50% of its designed capacity (only network
and user scores contribute). Implement these to complete the architecture.


## SECTION 6: METRICS AND KPIs TO TRACK

| Metric | Target | How to Measure |
|--------|--------|----------------|
| User behavior inference success rate | >95% of ticks return events_count > 0 | Monitor UserBehaviorAgent.last_result.events_count per cycle |
| Log staleness | Latest ndjson file modified within 15 minutes | get_log_health().latest_modified_epoch delta from current time |
| Anomaly score distribution | Mean score near threshold (0.9); std > 0.1 | Track per-cycle score statistics in user_behavior_cycles collection |
| OCEAN feature coverage | 0% (currently hardcoded) -> 100% of active users | Count rows where O,C,E,A,N != 0.0 |
| User anomaly Socket.IO delivery rate | 100% of _handle_user_result calls should emit | Count sio.emit() calls vs. anomalous_rows count |
| Fusion score range validity | user_score always in [0.0, 1.0] | Assert after normalization; log violations |
| False positive rate | <5% of flagged users per cycle should be ANOMALY on review | Track weekly ratio; adjust threshold in model_threshold.json |
| Frontend event receipt | "user_anomaly" and "user_behavior_summary" listeners firing | Add console.debug in socket.on handlers; verify in browser devtools |


================================================================================
END OF REPORT
Files analyzed:
  D:\Cyber Sentinal\User Behavior\final_model_backend_only\xdr_runtime.py
  D:\Cyber Sentinal\Backend\agents\user_behavior_agent.py
  D:\Cyber Sentinal\Backend\backend.py
  D:\Cyber Sentinal\Cyber Sentinal XDR Frontend\src\components\NetworkMonitor.tsx
  D:\Cyber Sentinal\User Behavior\final_model_backend_only\feature_columns.json
  D:\Cyber Sentinal\User Behavior\final_model_backend_only\model_threshold.json
  D:\Cyber Sentinal\Backend\config.py
  D:\Cyber Sentinal\Cyber Sentinal XDR Frontend\src\App.tsx

Next Analysis Recommended: After completing Priority 1-5 fixes, or when the
System (LSTM) model implementation begins — whichever comes first.
================================================================================
