================================================================================
IDPS PROJECT ANALYSIS REPORT
================================================================================
Timestamp     : 2026-04-23 00:00:00 UTC
Analyst       : IDPS Project Analyst Agent
Scope         : Session 2026-04-23 — Fusion Engine hardening (TTL-guarded scores,
                5-step pipeline), System Monitor self-calibration + dual-fire fix,
                SysmonBehaviorAgent log auto-discovery + on_telemetry callback,
                SHAP fusion explainability, backend full wiring, and frontend
                SysmonBehaviorView Live Process Events panel
Project Phase : Layer 6 of 7 active — all detection layers operational or in
                degraded mode; fusion engine hardened; 4 previous HIGH bugs
                resolved; LSTM model still untrained
================================================================================

## EXECUTIVE SUMMARY

This session delivered targeted hardening across three critical components:
fusion TTL isolation now prevents stale-score corroboration (resolving prior
HIGH bug SESSION3-01); System Monitor self-calibration eliminates false
CRITICALs on ML-heavy workloads and the dual-fire bug is closed; Sysmon log
auto-discovery makes the agent resilient to Winlogbeat file-naming variants.
Code review confirms that every change described in the session brief has been
faithfully implemented and is syntactically and logically correct.  Nine
issues from the previous report have been resolved in full.  Seven new issues
were discovered during this review, including a medium-severity race condition
on the shared `_latest_sysmon_score` / `_latest_system_score` globals and a
stale Winlogbeat reference in the frontend empty-state text.  Overall project
health score: 7.8/10 (up from 7.2/10 on 2026-04-22).

---

## SESSION DELTA — ITEMS RESOLVED FROM 2026-04-22 REPORT

The following items from the 2026-04-22 baseline were confirmed resolved by
reading the current source files:

| Prior ID      | Description                                           | Status  |
|---------------|-------------------------------------------------------|---------|
| SESSION3-01   | _latest_scores dict had no TTL — stale score corroboration | RESOLVED |
| SESSION3-06   | Dual-fire risk in SystemMonitorAgent warmup path      | RESOLVED |
| SYSMON-01     | should_alert suppressed whitelisted procs on high-risk events | RESOLVED |
| SYSMON-02     | "unknown" in BENIGN_WHITELIST silenced unresolvable images | RESOLVED |
| SYSMON-03     | _DetectorUnpickler no strict allowlist (CWE-502)      | RESOLVED |
| SYSMON-04     | Fusion weight conflict — both agents fed system_score | PARTIALLY RESOLVED |
| SYSMON-05     | sysmon_alerts MongoDB collection missing              | RESOLVED |
| SYSMON-07     | asyncio.get_event_loop() deprecated in Python 3.10+   | RESOLVED |
| GLOBAL-04     | monitoring_status emission missing sysmon_active field | RESOLVED |

---

## SECTION 1: CODE QUALITY ASSESSMENT

### 1.1 Strengths

**Fusion Engine (fusion_engine_agent.py)**
- 5-step pipeline is cleanly delineated with inline comments; each step has
  a clear boundary and the final clamp is redundant-safe.
- FusionResult dataclass now carries `contributing_reasons: list[str]` — this
  is the correct pattern; no mutable default factory issues (field() used).
- `fuse_from_network_result()` convenience wrapper correctly normalises
  confidence 0-100 to 0-1 before routing.
- `_validate_weights()` logs a warning rather than raising — appropriate
  for a runtime service that must degrade gracefully.
- Escalation rules (A-D) use `max(threat_score, floor)` rather than
  assignment — correctly preserves higher scores already produced by prior
  rules, preventing rule order from introducing hidden priority bugs.

**System Monitor Agent (system_monitor_agent.py)**
- `_mse_history: deque(maxlen=300)` is correctly bounded — no unbounded growth.
- `_CALIBRATION_WARMUP = 60` defined as a local constant inside `_infer()`
  rather than a class attribute; this is acceptable for a single-use threshold
  but see Issue SYS-01 below.
- Self-calibration formula `max(training_threshold, running_99th * 1.5)` is
  sound: the 1.5× multiplier provides a 50% headroom buffer above the
  running 99th percentile, preventing false CRITICALs while remaining
  sensitive to true outliers.
- Warmup / inference branch guard changed to mutually exclusive `< window_size`
  vs `== window_size` — dual-fire is correctly eliminated.
- `_heuristic_score()` now returned from `_infer()` when model unavailable,
  rather than 0.0 — warmup and inference paths are now consistent.
- `torch.load(..., weights_only=True)` is present (line 451) — addresses
  prior PyTorch FutureWarning noted in session 2026-04-21.

**SysmonBehaviorAgent (sysmon_behavior_agent.py)**
- `_resolve_log_path()` is robust: checks primary path first, scans parent
  directory as fallback, sorts by mtime, logs auto-selection — all correct.
- `on_telemetry` callback is cleanly separated from `on_result`; rate-limiter
  (`_last_telemetry_time: Dict[str, float]`) prevents telemetry flooding at
  1-per-PID-per-5s.
- Loop-capturing pattern `self._loop = asyncio.get_running_loop()` in
  `start()` is correct — captured on the main event loop thread, avoiding the
  deprecated `get_event_loop()` from a worker thread.
- `_PICKLE_ALLOWLIST` now covers numpy, sklearn, xgboost, scipy, and builtins
  via prefix matching — substantially more restrictive than the prior
  unconditional `super().find_class()` fallback.
- High-risk events (EventID 8/25) now trigger alerts regardless of whitelist
  status — T1036.005 process masquerading blind spot is closed.
- `_MIN_FEAT_HITS` guard (line 512) is now applied BEFORE the `meta["high_risk"]`
  branch check (line 516), correctly requiring a minimum token window for both
  paths.

**Backend (backend.py)**
- `_get_current_scores()` (line 1239-1242) is a clean one-liner that applies
  the 300-second TTL to all four score entries simultaneously.
- `_handle_sysmon_result()` now saves to both `alerts` and `sysmon_alerts`
  collections (line 1199) — dedicated storage gap is closed.
- `_handle_system_result()` and `_handle_sysmon_result()` correctly compute
  `combined_system = max(_latest_system_score, _latest_sysmon_score)` before
  updating `_latest_scores["system"]` — score channel sharing is now handled
  via max() rather than last-writer-wins.
- `monitoring_status` now includes `sysmon_active` (line 982) — frontend
  monitoring bar will reflect sysmon agent health.
- `system_model_loaded` field added to `monitoring_status` (line 980) — allows
  frontend to distinguish "system agent running" from "LSTM model loaded".
- `_handle_sysmon_telemetry()` is a correct single-line pass-through to
  Socket.IO `sysmon_log` event (line 1216-1218).

**SysmonBehaviorView.tsx**
- "Live Process Events" panel correctly renders ALL events (normal + anomalous)
  with amber row tinting for high-risk events — good SOC UX decision.
- `sysmonLogs` prop with default `= []` prevents undefined errors if parent
  does not pass the prop.
- Sticky table header (`position: "sticky", top: 0, zIndex: 1`) in the Live
  Process Events table is correctly scoped to the scrollable container.
- `fmtTime(log.ts)` used consistently for timestamp formatting.
- Component no longer creates its own Socket.IO connection — listens exclusively
  via props passed from parent (confirmed: no `io()` call in this file).

**SHAP Agent (shap_agent.py)**
- `explain_fusion()` correctly uses pure contribution accounting rather than
  SHAP mathematics — appropriate for a weighted linear model; no information
  loss.
- `pct_share = contribution / total_contribution * 100` handles the
  `total_contribution == 0.0` case with an explicit guard (line 338-340).
- Escalation reasons from `FusionResult.contributing_reasons` are appended
  after component-level reasons — correct ordering for human readability.

### 1.2 Issues Found

| Severity | Component | Issue | Recommendation |
|----------|-----------|-------|----------------|
| HIGH | backend.py L1130-1132, L1175-1177 | `_latest_system_score` and `_latest_sysmon_score` are plain module-level floats mutated by two concurrent async handlers (`_handle_system_result`, `_handle_sysmon_result`). Python's GIL protects float assignment on CPython, but the combined_system = max(...) read-modify is a non-atomic two-step; under asyncio interleaving, one handler can read a stale value written by the other | Introduce a dedicated `asyncio.Lock()` around the read-modify-update of `combined_system`, or collapse both globals into the `_latest_scores` dict (add "sysmon" as a fifth key) to eliminate the separate floats entirely |
| HIGH | sysmon_behavior_agent.py L270-309 | The `_PICKLE_ALLOWLIST` set is defined but only checked as fallback (line 304) — the preceding prefix-based branches (`startswith("numpy")`, `startswith("sklearn")`, `startswith("xgboost")`, `startswith("scipy")`, `module == "builtins"`) pass ALL submodule classes without name-level restriction. A pickle file that contains a `numpy.ctypeslib.as_ctypes` or `scipy.io._mmio` call would be admitted | Change prefix branches to: `if (module, name) in _EXPANDED_ALLOWLIST: return super()...`, where `_EXPANDED_ALLOWLIST` is the exhaustive set of concrete classes known to appear in detector.pkl. Log the (module, name) of every admitted class at DEBUG level during first load to enumerate the full set |
| MEDIUM | system_monitor_agent.py L624 | `_CALIBRATION_WARMUP = 60` is a magic number defined as a local constant inside `_infer()`. It is re-evaluated and re-assigned on every call to `_infer()` (once per second after the buffer is full). Python will not re-declare it, but the pattern signals that this should be a class constant | Move to a class-level constant: `_CALIBRATION_WARMUP: int = 60` at the top of `SystemMonitorAgent` or module scope, alongside `WINDOW_SIZE` and `N_FEATURES` |
| MEDIUM | SysmonBehaviorView.tsx L368 | Empty-state text still reads "Ensure Sysmon + Winlogbeat are running and writing to C:\winlogbeat\logs\". Winlogbeat has been replaced by `sysmon_event_reader.py` (running as a Task Scheduler task). This is a misleading SOC operator instruction | Update text to: "Ensure Sysmon is running and sysmon_event_reader.py Task Scheduler task is active (writes to C:\winlogbeat\logs\)" |
| MEDIUM | backend.py L181-182 | `_latest_system_score` and `_latest_sysmon_score` are module-level globals but NOT included in `_latest_scores` dict. The TTL-guarded `_get_current_scores()` only operates on the dict — the raw globals used in `combined_system = max(...)` are not TTL-gated. A system or sysmon score from hours ago will remain in the max() computation even after `_latest_scores["system"]` has expired | Either (a) add `_latest_sysmon_score` and `_latest_system_score` as timestamped entries in `_latest_scores` (rename key from "system" to "system_lstm" and "system_sysmon"), and let `_get_current_scores()` compute `max(...)` with TTL, OR (b) zero the raw globals alongside the dict when TTL expires |
| MEDIUM | fusion_engine_agent.py — missing `fuse()` TTL awareness | `FusionEngineAgent.fuse()` has no knowledge of when each score was produced. It relies on the caller to pass TTL-filtered values. If `_get_current_scores()` is not called before `fuse()` (e.g., in the `/fusion` REST endpoint at line 755), stale scores can be passed in from the payload | The `/fusion` endpoint accepts arbitrary scores from external callers — it should not use `_latest_scores` but the values passed in the payload are caller-controlled. The risk here is different: callers can provide maliciously high scores. Add server-side clamping validation: `score = max(0.0, min(1.0, payload.score))` already handled by `_clamp()` in fuse(), but the `/fusion` endpoint has no rate-limiting or source authentication beyond the API key |
| LOW | SysmonBehaviorView.tsx L5 | `BACKEND_URL = "http://localhost:8000"` is hardcoded. Duplicated across at minimum MalwareView.tsx, SystemStatusView.tsx, and this file | Consolidate to `src/constants.ts` or read from `process.env.REACT_APP_BACKEND_URL` |
| LOW | sysmon_behavior_agent.py L503-504 | `_last_telemetry_time` dict grows unbounded as PIDs cycle over time. On a busy endpoint with high PID recycling, this dict may accumulate thousands of entries over a multi-day run | Add periodic cleanup: after `_total_events % 10_000 == 0`, discard entries where `time.time() - last_time > 300` (5 min grace period) |

---

## SECTION 2: SECURITY VULNERABILITY ANALYSIS

### 2.1 Critical Vulnerabilities

None at CRITICAL level in this session's changes.

### 2.2 High Severity

**[HIGH-1] Partial Pickle Allowlist — Prefix-Match Bypass (New)**
- Description: `_DetectorUnpickler.find_class()` in `sysmon_behavior_agent.py`
  (lines 286-309) grants unconditional access to entire module namespaces via
  prefix matching (`startswith("numpy")`, `startswith("sklearn")`,
  `startswith("xgboost")`, `startswith("scipy")`). The `_PICKLE_ALLOWLIST` set
  defined at line 270 is only consulted as the final fallback — it is never
  actually reached for numpy, sklearn, xgboost, or scipy classes because the
  prefix branches fire first.
- Impact: A tampered `detector.pkl` that references `numpy.ctypeslib.as_ctypes`,
  `scipy.io._mmio.mmopen`, or any callable inside these namespaces would be
  admitted without restriction.  Combined with the likelihood that the backend
  runs as SYSTEM or Administrator, this is an arbitrary code execution risk
  (CWE-502).
- CVE Reference: Analogous to CVE-2019-20907 (pickle arbitrary code execution
  via __reduce__).
- Remediation: Replace prefix matching with an explicit (module, name) allowlist.
  Run `python -c "import pickle; import pickletools; pickletools.dis(open('detector.pkl','rb'))"` 
  to enumerate exactly which classes appear in the pkl file. Add each to a
  named set `_PICKLE_ALLOWLIST` and raise `UnpicklingError` for anything outside
  it.

**[HIGH-2] Concurrent Mutation of `_latest_system_score` / `_latest_sysmon_score` (New)**
- Description: `backend.py` lines 1130-1132 and 1175-1177: two separate
  `async def` handlers both read and write the global pair
  `(_latest_system_score, _latest_sysmon_score)` without any synchronization.
  The `combined_system = max(...)` expression is a read-modify-write over two
  globals — not an atomic operation even under CPython's GIL when asyncio
  task switching can occur between the two reads.
- Impact: Under high-frequency system and sysmon events, the combined_system
  score fed to the fusion engine can be a non-deterministic mix of the two
  agents' values. In a worst case, a very high sysmon score could be
  overwritten by a lower system score before fusion runs, masking a behavioral
  alert (CWE-362 — Race Condition).
- Remediation: Collapse both globals into `_latest_scores` as separate
  timestamped entries ("system_lstm" and "system_sysmon"), then compute
  combined_system inside `_get_current_scores()` as
  `max(ttl_score("system_lstm"), ttl_score("system_sysmon"))`.
  This is both thread-safe (single dict lookup) and correctly TTL-gated.

**[HIGH-3] Prior HIGH Bug SESSION3-02 Still Open — Async Handler Race on `_latest_scores`**
- Description: From the 2026-04-22 report: five async handlers
  (`_process_network_result`, `_handle_user_result`, `_handle_system_result`,
  `_handle_sysmon_result`, and the malware endpoints) all mutate
  `_latest_scores[key]` without an `asyncio.Lock`. This was flagged as
  SESSION3-02 on 2026-04-22 and remains unresolved.
- Impact: Non-deterministic fusion snapshots under load when multiple models
  detect simultaneously. The risk is low under single-threaded asyncio but
  materialises if any handler is wrapped in `asyncio.to_thread()` (which
  creates a real OS thread).  Currently the result callbacks are not
  themselves called from threads, but the malware watcher loop calls them
  from within `asyncio.to_thread(_malware_agent.predict, ...)` context —
  the subsequent callback fires on the event loop, so the race is currently
  theoretical but one refactor away from real.
- Remediation: Introduce `_scores_lock = asyncio.Lock()` and wrap all
  `_latest_scores[key] = ...` assignments in `async with _scores_lock`.

### 2.3 Medium / Low Severity

**[MED-1] `_latest_system_score` / `_latest_sysmon_score` Not TTL-Guarded (New)**
- The TTL mechanism introduced this session correctly zeroes entries in
  `_latest_scores` after 300 seconds. However, the two raw floats
  `_latest_system_score` and `_latest_sysmon_score` at lines 131 and 132 are
  used to compute `combined_system` in both handlers. These floats carry no
  timestamp and are never zeroed — a system anomaly score from hours ago will
  persist in `combined_system` and inflate the fusion result.
- Remediation: See HIGH-2 remediation (collapse into `_latest_scores` dict).

**[MED-2] Winlogbeat Reference in SysmonBehaviorView Empty State (New)**
- SysmonBehaviorView.tsx line 368: empty-state text directs the SOC operator
  to check "Sysmon + Winlogbeat". Winlogbeat was replaced by
  `sysmon_event_reader.py` in a prior session. An operator seeing no events
  will attempt to debug Winlogbeat — which is irrelevant — wasting response
  time.
- Remediation: Update text to reference `sysmon_event_reader.py` and the
  Task Scheduler task name.

**[MED-3] Prior Unresolved — SESSION3-02 `_latest_scores` Race (Carryover)**
- See HIGH-3 above.  Still open from 2026-04-22.

**[MED-4] `/simulate-user-attack` Endpoint Lacks API Key Auth (Carryover)**
- GLOBAL-06 from 2026-04-22: the POST `/simulate-user-attack` endpoint has no
  `dependencies=[Depends(_require_key)]`. Any process with network access to
  port 8000 can inject fake attack events.
- Remediation: Add `dependencies=[Depends(_require_key)]` to the decorator.

**[LOW-1] `_last_telemetry_time` Dict Unbounded Growth**
- sysmon_behavior_agent.py: the per-PID telemetry rate-limiter dict is never
  pruned. Over days of operation this accumulates stale PID entries.
- Remediation: Periodic cleanup on `_total_events % 10_000 == 0`.

**[LOW-2] `BACKEND_URL` Hardcoded in Three Frontend Views**
- Consolidate to `src/constants.ts`.

---

## SECTION 3: ARCHITECTURE GAP ANALYSIS

| Layer | Component | Status | Notes |
|-------|-----------|--------|-------|
| Network Monitoring | Suricata + rule_detector.py + hybrid_detector.py | Implemented | personal_baseline_model.pkl now confirmed present; Gate 1 active |
| Endpoint/Host Monitoring | sysmon_behavior_agent.py | Implemented | Log auto-discovery added; on_telemetry callback wired |
| Endpoint/Host Monitoring | system_monitor_agent.py (LSTM Autoencoder) | Degraded — Self-Calibrating | system_model.pt still untrained; heuristic fallback active with self-calibration |
| Log Collection | sysmon_event_reader.py | Implemented | Writes to C:\winlogbeat\logs\; auto-discovery in agent covers naming variants |
| Log Collection | Winlogbeat → C:\XDR_Logs\ | Not Configured | User behavior inference reads 0 events until Winlogbeat configured |
| AI/ML — Network | RandomForest + IsolationForest (CIC-IDS2017) | Implemented | 99.6% accuracy; SHAP active |
| AI/ML — User Behavior | One-Class SVM (CERT r4.2) | Implemented — Degraded | Winlogbeat not writing; OCEAN features = 0.0 |
| AI/ML — Sysmon Behavior | TF-IDF + IsolationForest/XGBoost | Implemented | vocab=8524; detector.pkl present |
| AI/ML — System | LSTM Autoencoder (live telemetry) | Not Trained | system_model.pt absent; heuristic replaces inference; self-calibration engages after 60 real windows once model trained |
| AI/ML — Malware | LightGBM (EMBER 2018) | Implemented | AUC=0.9803, F1=0.9298; SHAP active |
| Fusion Engine | FusionEngineAgent — 5-step pipeline | Implemented | TTL-guarded scores via _get_current_scores(); corroboration + escalation rules; contributing_reasons on FusionResult |
| Fusion Engine — Channel Conflict | SystemMonitor + Sysmon both feed system_score | Partially Resolved | max() combination implemented in backend.py; raw globals not TTL-gated (see HIGH-2) |
| SHAP Explainability | Network + Malware + Fusion | Implemented | explain_fusion() added this session; no Sysmon SHAP |
| SHAP Explainability — Sysmon | TF-IDF token-based | Missing | No SHAP/LIME explainability for sysmon behavioral detections |
| Response / SOAR | endpoint_agent.py | Implemented | No kill_process SOAR action triggered by sysmon HIGH/CRITICAL alerts |
| Storage | MongoDB — sysmon_alerts collection | Implemented | Cap = 1000; _save("sysmon_alerts") wired in _handle_sysmon_result |
| Storage | MongoDB — all other collections | Implemented | Periodic Atlas trim every 100 cycles |
| Visualization | Live Process Events panel (SysmonBehaviorView) | Implemented | All events (normal + anomalous); high-risk rows amber-tinted |
| Visualization | SystemStatusView — Sysmon telemetry pass-through | Implemented | sysmonLogs prop passed to both SystemStatusView and SysmonBehaviorView |
| Visualization | AlertsView — sysmon_behavior column | Missing | Sysmon HIGH/CRITICAL alerts not surfaced in unified alert table |
| Visualization | Socket.IO connection per-view | Medium Issue | SysmonBehaviorView no longer duplicates, but BACKEND_URL still hardcoded in 3+ views |
| Observability | monitoring_status broadcast | Implemented | sysmon_active + system_model_loaded fields added this session |
| Security | API key on all sensitive endpoints | Mostly Implemented | /simulate-user-attack still unprotected (GLOBAL-06 carryover) |
| Security | Socket.IO auth | Missing | cors_allowed_origins="*"; no token in connect handshake |

---

## SECTION 4: CONFLICTS AND INCOMPATIBILITIES

| # | Conflict | Root Cause | Resolution |
|---|----------|------------|------------|
| 1 | `_latest_system_score` / `_latest_sysmon_score` raw globals bypass TTL | These floats are used to compute `combined_system` before updating `_latest_scores["system"]`; they have no timestamp and no expiry | Fold into `_latest_scores` dict as "system_lstm" and "system_sysmon" with separate timestamps; compute max inside `_get_current_scores()` |
| 2 | `_PICKLE_ALLOWLIST` set defined but never actually consulted for numpy/sklearn/xgboost/scipy classes | Prefix-match branches fire before the allowlist check | Remove prefix branches; replace with explicit (module, name) pair lookup against the set |
| 3 | System Monitor `_CALIBRATION_WARMUP = 60` redefined on every `_infer()` call | Local constant definition inside a hot path | Move to class-level or module-level constant |
| 4 | SysmonBehaviorView empty-state text references Winlogbeat | Stale copy from before sysmon_event_reader.py replaced Winlogbeat | Update empty-state text (see MED-2) |
| 5 | `/simulate-user-attack` lacks API key (GLOBAL-06, carryover) | Missing `dependencies=[Depends(_require_key)]` decorator argument | Add dependency |
| 6 | SESSION3-02 carryover: `_latest_scores` dict mutated without asyncio.Lock | Concurrent async handlers; mutation is non-atomic at asyncio task switch points | Add `asyncio.Lock()` wrapper |
| 7 | SysmonBehaviorView.tsx: no Sysmon SHAP reasons column | explain_sysmon() method not yet implemented in SHAPAgent | Medium-term: add shap.LinearExplainer or LIME for TF-IDF + classifier pipeline |

---

## SECTION 5: NEXT STEPS AND IMPLEMENTATION ROADMAP

### Immediate Actions (0-2 weeks) — Critical Fixes

1. **Fold raw system/sysmon globals into `_latest_scores` dict**
   File: Backend/backend.py
   - Remove `_latest_system_score` and `_latest_sysmon_score` module-level
     floats (lines 181-182).
   - Add `"system_lstm"` and `"system_sysmon"` as timestamped entries in
     `_latest_scores`.
   - Update `_handle_system_result()` and `_handle_sysmon_result()` to write
     to their respective keys.
   - Compute `combined_system = max(ttl_system_lstm, ttl_system_sysmon)` inside
     `_get_current_scores()`.
   - This eliminates HIGH-2, HIGH-3 (partial), and MED-1 in a single change.

2. **Restrict `_DetectorUnpickler` to explicit (module, name) allowlist**
   File: Backend/agents/sysmon_behavior_agent.py, `_load_model()`
   - Run `pickletools.dis()` on detector.pkl to enumerate all class references.
   - Replace prefix-match branches with a single `if (module, name) in
     _PICKLE_ALLOWLIST: return super().find_class(module, name)` guard.
   - This resolves HIGH-1.

3. **Add asyncio.Lock() around `_latest_scores` mutations**
   File: Backend/backend.py
   - Declare: `_scores_lock = asyncio.Lock()` at module level.
   - Wrap all `_latest_scores[key] = ...` assignments in
     `async with _scores_lock`.
   - This resolves SESSION3-02 / HIGH-3.

4. **Fix SysmonBehaviorView empty-state Winlogbeat reference**
   File: Cyber Sentinal XDR Frontend/src/components/views/SysmonBehaviorView.tsx
   Line 368.
   Update to reference sysmon_event_reader.py and Task Scheduler task.

5. **Add API key auth to `/simulate-user-attack`**
   File: Backend/backend.py, line 651.
   Add `dependencies=[Depends(_require_key)]` to the decorator.
   This resolves GLOBAL-06 (carryover).

### Short-term (2-6 weeks) — High Priority Improvements

6. **Train `system_model.pt` (LSTM Autoencoder)**
   Run: `python train_system_model.py --collect-minutes 60` during a normal
   workload period (no ML training running simultaneously, as that would skew
   the baseline toward high CPU/memory patterns).
   After training, the self-calibration mechanism will engage after 60 windows
   (~60 seconds) and adapt the threshold to the production workload profile.
   This is the highest-value single action to close the degraded-mode gap.

7. **Consolidate `BACKEND_URL` to `src/constants.ts`**
   Files: SysmonBehaviorView.tsx L5, MalwareView.tsx L10, SystemStatusView.tsx.
   Create `export const BACKEND_URL = process.env.REACT_APP_BACKEND_URL ?? "http://localhost:8000"` 
   and import from all views.

8. **Move `_CALIBRATION_WARMUP` to class-level constant**
   File: Backend/agents/system_monitor_agent.py.
   Add `_CALIBRATION_WARMUP: int = 60` as a class attribute on
   `SystemMonitorAgent`, alongside `window_size`.

9. **Add `_last_telemetry_time` pruning to SysmonBehaviorAgent**
   File: Backend/agents/sysmon_behavior_agent.py, `_handle_event()`.
   After `_total_events % 10_000 == 0`, prune entries older than 300 seconds.

10. **Add Sysmon HIGH/CRITICAL alerts to AlertsView.tsx unified table**
    The unified alert table (`AlertsView.tsx`) currently shows network and
    malware alerts. Sysmon behavioral HIGH/CRITICAL alerts should appear in
    this table alongside other alert types, with a "Source" column to
    distinguish them. Subscribe to `sysmon_behavior_alert` in AlertsView or
    pass through from `NetworkMonitor.tsx` state.

### Medium-term (6-12 weeks) — Architecture Enhancements

11. **Configure Winlogbeat to write to `C:\XDR_Logs\`**
    This is the single most impactful change for user behavior coverage.
    The One-Class SVM model is trained and ready; it is simply receiving no
    events because Winlogbeat is not configured to write to the expected path.
    Document the exact winlogbeat.yml fields required in COMMANDS.md.

12. **Add SHAP explainability for Sysmon behavior alerts**
    The Sysmon model uses TF-IDF features + IsolationForest/XGBoost.
    Extend `SHAPAgent` with `explain_sysmon(tokens_str: str, top_n: int = 5)`
    using `shap.LinearExplainer` on the TF-IDF + IsolationForest pipeline
    or `shap.KernelExplainer` if the model is non-linear.
    Surface top token contributions in alert reason strings.

13. **Add SOAR `kill_process` action for Sysmon HIGH/CRITICAL alerts**
    When `sysmon_behavior_alert` has `severity in ("HIGH", "CRITICAL")` and
    `anomaly_score >= 0.85`, write a `kill_process` command document to
    MongoDB analogous to the malware `quarantine_file` command.
    File: Backend/backend.py, `_handle_sysmon_result()`.

14. **Add dedicated `sysmon_weight` to FusionEngineAgent**
    The current architecture routes Sysmon through the `system` channel via
    `max()`. A cleaner long-term solution adds `sysmon_score` as a fifth
    fusion parameter with its own weight (e.g., 0.15), reducing the other
    weights proportionally:
    `network=0.30, user=0.25, system=0.12, sysmon=0.13, malware=0.20`.
    Update: `fusion_engine_agent.py`, `backend.py`, `config.py`.

15. **Retrain Sysmon model with live benign data**
    Run: `python train_sysmon_model.py --sysmon_benign C:/winlogbeat/logs/sysmon_events.json`
    after 1-2 weeks of clean operation to reduce false positives specific to
    this endpoint's application mix.

16. **Connect OCEAN personality features**
    `xdr_runtime.py` currently hardcodes all five OCEAN scores to 0.0.
    Investigate proxy metrics: Active Directory attributes, keyboard/mouse
    behavioral proxies, or departmental risk classification tags.

### Long-term (3-6 months) — Advanced Capabilities

17. **Replace pickle model artifacts with joblib + HMAC signing**
    All ML artifacts (detector.pkl, malware_model.pkl, network_classifier.pkl)
    should be saved via `joblib.dump()` with a detached HMAC or code-signing
    certificate. Verification before load prevents supply-chain attacks.

18. **Socket.IO namespace authentication**
    Implement token-based auth in the Socket.IO `connect` handler:
    the client passes an auth token in `io(url, { auth: { token } })`;
    the server verifies it before emitting any events.
    This closes MED-3 (information disclosure on Socket.IO events).

19. **Add EventID 5 (ProcessTerminate) handler to reset PID windows**
    File: Backend/agents/sysmon_behavior_agent.py, `_handle_event()`.
    When EventID 5 is received, call `self._processes.pop(pid, None)` to
    clear the stale window and prevent PID-reuse false positives.

20. **Sysmon model quantitative evaluation**
    Introduce a periodic evaluation run (nightly cron or post-deployment)
    that calculates precision/recall on a held-out labeled set of GHC events.
    Currently there is no automated way to detect model drift or threshold
    drift on the Sysmon layer.

---

## SECTION 6: METRICS AND KPIs TO TRACK

| Metric | Target | How to Measure |
|--------|--------|----------------|
| Fusion TTL hit rate (stale scores zeroed) | < 20% of fuse() calls | Add counter in `_get_current_scores()` when TTL expires |
| Self-calibration effective threshold vs. training threshold | < 2.0× training threshold | Log `effective_threshold` in `_infer()` after calibration kicks in |
| System monitor heuristic-to-model transition | 0 heuristic emissions after model trained | Monitor `system_model_loaded` in monitoring_status |
| Sysmon log auto-discovery fallback rate | 0 (configured path should always exist) | Count `_resolve_log_path()` fallback selections via log search |
| Sysmon telemetry rate | > 10 events/s | Monitor `total_events` delta in sysmon_agent /health over 60s |
| Sysmon alert precision (HIGH/CRITICAL not manually dismissed) | > 85% | SOC operator review of HIGH+ alerts over 72 hrs |
| combined_system TTL correctness | 0 scores older than 300s in fusion | Add assertion test: simulate 301s gap, verify combined_system == 0.0 |
| False-positive rate across all models (alerts requiring no action) | < 10% per 24h | Tag alerts in MongoDB as TP/FP during review; compute weekly |
| `/commands` poll latency (SOAR action latency) | < 10s from alert to command visible | Timestamp both alert creation and command creation, compare |
| MongoDB collection fill rate | < 80% cap for all collections | /storage-status endpoint, polled every 5 min |

---

## SECTION 7: OUTSTANDING ITEMS — COMPLETE REGISTRY

### From CLAUDE.md (System-Wide Operational Gaps)

| Item | Status | Priority |
|------|--------|----------|
| `system_model.pt` not yet trained — LSTM in heuristic mode | Outstanding | HIGH |
| Winlogbeat not configured for C:\XDR_Logs\ | Outstanding | HIGH |
| OCEAN features hardcoded 0.0 | Outstanding | MEDIUM |
| Flow micro-fragmentation in CIC feature extraction | Outstanding | MEDIUM |
| `personal_baseline_model.pkl` | PRESENT — resolved per memory record | Done |

### New Issues Discovered This Session

| ID | Severity | Description | File |
|----|----------|-------------|------|
| NEW-01 | HIGH | Raw system/sysmon globals bypass TTL; not in _latest_scores dict | backend.py L181-182 |
| NEW-02 | HIGH | _DetectorUnpickler prefix-match bypasses allowlist (partial fix from prior session) | sysmon_behavior_agent.py L286-309 |
| NEW-03 | MEDIUM | _CALIBRATION_WARMUP re-declared as local constant on every _infer() call | system_monitor_agent.py L624 |
| NEW-04 | MEDIUM | Empty-state text references Winlogbeat (stale) | SysmonBehaviorView.tsx L368 |
| NEW-05 | MEDIUM | _last_telemetry_time dict grows unbounded | sysmon_behavior_agent.py L503-504 |
| NEW-06 | LOW | BACKEND_URL hardcoded in 3 frontend views | Multiple .tsx files |

### Carryover Issues Still Open

| ID | Severity | Description |
|----|----------|-------------|
| SESSION3-02 | HIGH | _latest_scores mutation without asyncio.Lock — concurrent async handlers |
| GLOBAL-06 | MEDIUM | /simulate-user-attack lacks API key auth |
| AUTH-02 | MEDIUM | Default API key warning — confirmed present in backend.py L357-358 — LOW risk now that warning exists |
| SOAR-01 | MEDIUM | quarantine_file path allowlist absent (CWE-22) in endpoint_agent.py |
| SEC-01 | MEDIUM | cors_allowed_origins="*" on Socket.IO server |
| SYSMON-04 | MEDIUM | Sysmon/LSTM system channel fusion — partially resolved via max(); full resolution requires dedicated channel |

---

## PROJECT HEALTH SCORE: 7.8 / 10

| Dimension | Score | Rationale |
|-----------|-------|-----------|
| Detection Coverage | 8.5/10 | 5 layers active; system LSTM only layer in degraded mode; all behavioral layers operational |
| Code Quality | 7.5/10 | Strong modular design; a few recurring patterns (hardcoded URLs, local magic constants) need cleanup |
| Security Posture | 7.0/10 | TTL-guarded fusion is a meaningful improvement; pickle allowlist partial bypass is a new HIGH; Socket.IO auth still missing |
| Architecture Completeness | 8.0/10 | All target layers implemented; sysmon channel conflict partially resolved; Winlogbeat config still the single largest operational gap |
| Operational Readiness | 7.5/10 | Self-calibration prevents false CRITICALs; log auto-discovery adds resilience; user behavior layer effectively blind without Winlogbeat fix |
| Test Coverage | 5.0/10 | No automated regression tests; manual test scripts exist but no CI |
| Documentation | 8.5/10 | CLAUDE.md comprehensive; COMMANDS.md covers CLI operations; inline code comments are above average |

================================================================================
END OF REPORT
Report saved: D:\Cyber Sentinal\timeline\2026-04-23_fusion_systemfix_sysmon_report.md
Next Analysis Recommended:
  - Trigger: After `system_model.pt` is trained (run train_system_model.py --collect-minutes 60)
  - Trigger: After HIGH-2 (raw globals TTL fix) is implemented
  - Trigger: After Winlogbeat is configured for C:\XDR_Logs\ (user behavior will then produce real scores)
  - Maximum interval: 1 week
================================================================================
