================================================================================
IDPS PROJECT ANALYSIS REPORT
================================================================================
Timestamp     : 2026-04-25 14:47:24 UTC
Analyst       : IDPS Project Analyst Agent
Scope         : Fusion Engine Redesign — Pre/Post Analysis
                Files reviewed: fusion_engine_agent.py, backend.py, shap_agent.py,
                OverviewView.tsx, config.py; cross-referenced CLAUDE.md and all
                prior timeline reports.
Project Phase : Integration & Hardening (post-implementation, ~82% complete baseline)
================================================================================

## EXECUTIVE SUMMARY

The Cyber Sentinel XDR project carries a solid detection stack (5 agents, 4 ML
models, 6 deterministic rules) but the current Fusion Engine is a point-in-time
weighted linear scorer with no temporal memory, no cross-domain correlation, and
no MITRE ATT&CK mapping.  The proposed redesign — EventBuffer + CorrelationEngine
+ FusionDecisionEngine — closes these gaps and elevates the system from a score
aggregator to a genuine threat intelligence correlator.  This report documents
the pre-redesign weaknesses with precise evidence from the codebase, validates
the architectural intent of the new design, flags security and integration risks
to handle during implementation, and provides an updated production-readiness
roadmap.  Overall project health before redesign: 6.5/10.  Projected health
after full redesign and outstanding-bug remediation: 8.2/10.

================================================================================

## SECTION 1: CODE QUALITY ASSESSMENT

### 1.1 Strengths

- **FusionEngineAgent.fuse() is clean and well-documented** — five explicit
  steps (weighted base, corroboration bonus, escalation overrides, reason
  strings, final clamp) are numbered in comments, making the scoring pipeline
  fully auditable.  `FusionResult` is a proper `@dataclass` with `to_dict()`
  serialization — zero ad-hoc dict construction.

- **Weight validation guard** (`_validate_weights`) warns at startup when
  weights do not sum to 1.0 rather than silently producing a miscalibrated
  score.  This is good defensive programming for an operationally critical path.

- **Graceful degradation architecture** — every agent init in `backend.py` is
  wrapped in `try/except`; the system starts even if malware or SHAP agents
  fail to load.  `_get_current_scores()` applies a 300-second TTL so stale
  scores from offline sensors do not accumulate silently.

- **`fuse_from_network_result()` convenience wrapper** correctly maps rule-hit
  severity labels (LOW/MEDIUM/HIGH/CRITICAL) to numeric scores
  (0.55/0.70/0.85/0.95) and takes the max between rule score and ML confidence,
  preventing double-counting.

- **SHAPAgent.explain_fusion()** uses contribution accounting (weighted score
  breakdown) rather than approximate SHAP math for a linear model — this is
  methodologically correct and avoids the instability of approximating an
  already-linear function with SHAP.

### 1.2 Issues Found

| Severity | Component | Issue | Recommendation |
|----------|-----------|-------|----------------|
| HIGH | `backend.py` L192-197 | `_latest_system_score` and `_latest_sysmon_score` are raw module-level floats that bypass the 300s TTL enforced by `_latest_scores` dict. `_handle_system_result` (L1373) writes to `_latest_scores["system"]` via `combined_system = max(_latest_system_score, _latest_sysmon_score)` but both raw globals are never expired. A system anomaly at T=0 followed by 10 minutes of silence still contributes its original score to any subsequent fusion call. | Fold both into `_latest_scores` as `"system_lstm"` and `"system_sysmon"` with timestamps; compute `combined_system` from `_get_current_scores()` on both keys. |
| HIGH | `backend.py` L192 | `_latest_scores` dict is mutated by at minimum three concurrent async handlers (`_handle_user_result`, `_handle_system_result`, `_handle_sysmon_result`) without an `asyncio.Lock`. Under asyncio cooperative scheduling this is usually safe for simple assignments, but any await between read and write (even implicit) can interleave. | Add `_scores_lock = asyncio.Lock()` and wrap all `_latest_scores[k]` assignments with `async with _scores_lock`. |
| HIGH | `backend.py` L882 | `/simulate-user-attack` endpoint has no `dependencies=[Depends(_require_key)]`. Any unauthenticated client can inject arbitrary NDJSON into `C:\XDR_Logs\sim_attack.ndjson`, potentially poisoning the user behavior training baseline. | Add `dependencies=[Depends(_require_key)]` to the route decorator, consistent with all other write endpoints. |
| MEDIUM | `backend.py` L414 | `cors_allowed_origins="*"` on the Socket.IO server is separate from the FastAPI CORS middleware on L417. Socket.IO currently allows any browser origin to establish a real-time connection without authentication. | Restrict to dashboard origin (e.g., `["http://localhost:3000"]`) or require a bearer token in the Socket.IO `connect` handler before full deployment. |
| MEDIUM | `fusion_engine_agent.py` L57-59 | `fuse()` signature uses bare `float = 0.0` defaults. When called from `_process_network_result` (L1268-1273) fusion is only created for `is_attack == True`, which means benign-cycle fusion events never update the frontend's threat gauge. The gauge stays at its last non-zero value indefinitely during quiet periods. | Emit a `fusion_heartbeat` event on every monitoring cycle with the current scores (even if all zero) so the gauge decays gracefully. |
| MEDIUM | `OverviewView.tsx` L44 | `globalThreatScore = fusionScore ?? 0` — this prop is populated by the parent from `fusion_alert` Socket.IO events. However, `fusion_alert` is only emitted when `fusion.should_respond == True` (threshold ≥ 0.65). During low-threat periods the gauge reads 0 regardless of real model scores. | Wire to a dedicated `fusion_heartbeat` event (see above) that always carries the current weighted score, separate from the alert-threshold event. |
| MEDIUM | `shap_agent.py` L127-130 | `self.explainer.shap_values(X)` is called synchronously inside async request handlers via `asyncio.to_thread` in some paths but **directly** in others (e.g., via `_maybe_explain` in `_process_network_result` which is itself `async`). TreeExplainer for large RandomForests can block the event loop for >100ms on first call. | Always wrap SHAP calls in `await asyncio.to_thread(...)` from async context. |
| LOW | `fusion_engine_agent.py` L88 | Corroboration threshold is `> 0.30` — this is an inclusive-exclusive boundary that treats a score of exactly 0.30 as non-contributing. If a model is borderline anomalous (exactly 0.30), it is silently excluded from the multi-model bonus. Document this behavior explicitly or change to `>= 0.30`. |
| LOW | `backend.py` L77-87 | `_COLLECTION_CAP` does not include the three new collections that the redesign will add: `raw_events`, `correlated_alerts`, `high_severity_alerts`. These will grow without bound on Atlas M0 until manually trimmed. | Pre-register new collections in `_COLLECTION_CAP` before first write. |

---

## SECTION 2: SECURITY VULNERABILITY ANALYSIS

### 2.1 Critical Vulnerabilities

**None identified in the fusion engine module itself.**  The previous session
identified credential exposure in `config.py` (Atlas URI in fallback); that
was resolved by moving to `.env` only.

### 2.2 High Severity

**SEC-FUSION-01: Unauthenticated /simulate-user-attack (CWE-306)**
- Description: `POST /simulate-user-attack` at `backend.py` L882 lacks API
  key authentication. An attacker on the local network who can reach port 8000
  can inject any NDJSON payload into the user behavior pipeline's watched
  directory (`C:\XDR_Logs\`), manufacturing false anomaly signals or poisoning
  the training baseline.
- Impact: Data poisoning of user behavior model; false-positive SOAR triggers
  (e.g., isolate_host commands issued against legitimate users).
- CWE reference: CWE-306 (Missing Authentication for Critical Function),
  CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
- Remediation: Add `dependencies=[Depends(_require_key)]` immediately.

**SEC-FUSION-02: _latest_scores race condition (CWE-362)**
- Description: Three concurrent async handlers mutate the shared `_latest_scores`
  dict without synchronization. While Python's GIL prevents data structure
  corruption, the logical race (handler A reads a score, handler B updates it,
  handler A uses the stale value) can cause fusion to compute with mismatched
  domain scores from different time windows.
- Impact: Fusion threat score inconsistency; missed escalation or spurious
  CRITICAL alerts in high-event-rate scenarios.
- CWE reference: CWE-362 (Concurrent Execution Using Shared Resource With
  Improper Synchronization)
- Remediation: Introduce `_scores_lock = asyncio.Lock()` as a module-level
  singleton; acquire it in all `_handle_*` handlers before reading/writing
  `_latest_scores`.

**SEC-FUSION-03: System/Sysmon score TTL bypass (CWE-672)**
- Description: `_latest_system_score` and `_latest_sysmon_score` (L188-189)
  are bare floats that persist indefinitely after last assignment. They feed
  directly into `combined_system` in both `_handle_system_result` and
  `_handle_sysmon_result`, bypassing the 300-second TTL applied to
  `_latest_scores`. A CRITICAL system anomaly at T=0 will continue to
  influence fusion scores at T=600, T=1200, etc.
- Impact: Fusion score inflation; stale CRITICAL flags keeping SOAR responses
  active long after a transient event.
- CWE reference: CWE-672 (Operation on a Resource After Expiration or Release)
- Remediation: See Section 1.2, HIGH severity row.

### 2.3 Medium/Low Severity

**SEC-FUSION-04: CORS wildcard on Socket.IO (CWE-942) — Medium**
- Socket.IO server at L414: `cors_allowed_origins="*"` permits any web origin
  to establish a real-time subscription to all threat intelligence events
  (network anomalies, malware alerts, SOAR commands).
- Remediation: Before production, restrict to `["http://localhost:3000"]` or
  the deployed dashboard origin.

**SEC-FUSION-05: New MongoDB collections not pre-capped — Medium**
- `raw_events`, `correlated_alerts`, `high_severity_alerts` will be written
  by the redesign but are not in `_COLLECTION_CAP`. On Atlas M0 (512 MB),
  unbounded correlated alert storage is a storage exhaustion risk, especially
  if `raw_events` stores every ingest event.
- Remediation: Add entries to `_COLLECTION_CAP` before first write; suggest
  caps of raw_events=2000, correlated_alerts=500, high_severity_alerts=200.

**SEC-FUSION-06: Injection risk in CorrelationEngine MITRE mapping — Low**
- If the new `CorrelationEngine` stores MITRE technique IDs sourced from
  model output strings (e.g., parsed attack_type labels from the RandomForest
  classifier), and those strings are stored to MongoDB and later rendered in
  the frontend without sanitization, a model label containing `<script>` tags
  or MongoDB operators could result in XSS or NoSQL injection.
- Remediation: Validate MITRE technique IDs against an allowlist of known
  ATT&CK technique strings (T####.###) before persistence.

**SEC-FUSION-07: ingest_event() surface area — Low**
- The proposed `ingest_event()` method will be called from all four `_handle_*`
  handlers. If this method writes raw event dicts to MongoDB's `raw_events`
  collection without sanitizing keys, MongoDB operator injection (e.g., a key
  starting with `$`) is possible if any model output contains adversarial data.
- Remediation: Strip or reject keys starting with `$` before any `insert_one`
  call in the new fusion module.

---

## SECTION 3: ARCHITECTURE GAP ANALYSIS

### Pre-Redesign State

| IDPS Layer | Status | Notes |
|------------|--------|-------|
| Network Monitoring (Suricata/Zeek) | Partial | Suricata operational; Zeek configs present but not started by backend |
| Rule-Based Detection | Implemented | 6 rules in rule_detector.py; eve.json incremental read working |
| ML Network Detection | Implemented | RandomForest CIC-IDS2017 99.6% accuracy; IsolationForest Gate 1 active |
| User Behavior Detection | Partial | OC-SVM inference code complete; Winlogbeat not writing events |
| System Monitor (LSTM) | Degraded | system_model.pt MISSING; heuristic fallback active |
| Sysmon Behavioral | Functional | TF-IDF + IsolationForest; PS forwarder working |
| Malware Detection | Implemented | LightGBM EMBER AUC=0.9803; file watcher active |
| **Fusion Engine (BEFORE)** | **Partial** | **Single-cycle weighted score only; no temporal memory, no correlation** |
| SHAP Explainability | Partial | Network + malware covered; system/sysmon not yet implemented |
| SOAR / Response | Functional | 5 actions working; no path allowlist on quarantine_file |
| MongoDB Persistence | Functional | 9 capped collections; 3 new collections not yet registered |
| Frontend SOC Dashboard | Partial | 7 views; OverviewView threat gauge decoupled from fusion backend |

### Pre-Redesign Fusion Gaps (Task 1: Gap Analysis)

**Gap 1 — No temporal memory (highest impact)**
The current `FusionEngineAgent.fuse()` is a pure function — each call is
independent. It has no sliding time window. A port scan at T=0 followed by a
credential brute-force at T=120 followed by lateral movement at T=240 are each
scored in isolation. The correlating pattern — reconnaissance → exploitation →
lateral movement — is completely invisible to the current engine. The new
`EventBuffer` (5-minute sliding window) directly closes this gap.

**Gap 2 — No attack-chain detection**
The current engine applies only four scalar hard-override rules (malware >= 0.85,
network >= 0.80 + system >= 0.50, user >= 0.80, malware >= 0.60 + network >= 0.50).
These detect simultaneous multi-domain events but not sequential attack chains.
A multi-stage APT campaign that stays below individual domain thresholds at any
given moment will score LOW throughout despite representing a CRITICAL threat.

**Gap 3 — No MITRE ATT&CK mapping**
The current `FusionResult.contributing_reasons` are free-text strings like
"Synchronized network attack + system impact — HIGH escalation". There is no
structured mapping to MITRE ATT&CK technique IDs, making automated playbook
lookup, threat hunting, and compliance reporting impossible. The `CorrelationEngine`
MITRE mapping directly addresses this.

**Gap 4 — Single-domain false negative risk**
The current fusion only escalates when two or more models simultaneously exceed
0.30. A sophisticated attacker who keeps each domain's anomaly score just below
0.30 (by staying within training distribution per model) while operating across
all four domains simultaneously will produce a composite fusion score of
net=0.29 + user=0.29 + sys=0.29 + mal=0.29 = 0.35 × weights ≈ 0.35 total,
yielding severity MEDIUM and no SOAR response. The `EventBuffer` + correlation
layer adds a second decision path that triggers independent of individual score
magnitudes, based on pattern sequence alone.

**Gap 5 — No structured correlated alert schema**
The current engine emits `fusion_alert` events with a flat dict. There is no
structured schema for correlated multi-domain threats, no parent/child alert
relationship, and no deduplication. The new `correlated_alerts` MongoDB collection
and `soc_alert` Socket.IO event establish this missing schema.

**Gap 6 — OverviewView.tsx threat gauge decoupled from fusion backend**
As documented at L44 of `OverviewView.tsx`, the gauge reads from `fusionScore`
which is only updated when `fusion.should_respond == True` (threshold >= 0.65).
The client-side code at the parent component computes a separate approximation
(net×0.6 + user×0.4) that does not include system or malware weights and diverges
from the backend's true weighted score (net=0.35, user=0.30, sys=0.15, mal=0.20).
This is a display-layer false negative: operators see LOW when the backend is
accumulating a HIGH pattern across four domains.

### Post-Redesign Architecture Assessment

| Component | Pre-Redesign | Post-Redesign |
|-----------|-------------|---------------|
| Event correlation window | None | 5-minute EventBuffer (sliding) |
| Attack chain detection | None | CorrelationEngine pattern matching |
| MITRE ATT&CK mapping | None | Structured technique ID assignment |
| Correlated alert schema | Flat dict | Typed alert with parent events + MITRE |
| Frontend threat gauge | Decoupled/stale | Subscribed to fusion_alert + heartbeat |
| MongoDB correlated storage | None | raw_events, correlated_alerts, high_severity_alerts |
| soc_alert Socket.IO event | None | New multi-domain correlated event |
| Single-domain false negatives | High risk | Reduced via temporal pattern detection |

---

## SECTION 4: CONFLICTS AND INCOMPATIBILITIES

### Conflict 1 — Dual fusion invocation paths (High Risk for Redesign)
**Root cause**: The current backend calls `_fusion_agent.fuse()` in FIVE distinct
code locations:
  1. `_process_network_result()` — rule hits (L1243)
  2. `_process_network_result()` — ML results (L1268)
  3. `_handle_user_result()` — per anomaly row (L1313)
  4. `_handle_system_result()` — per cycle (L1380)
  5. `_handle_sysmon_result()` — per behavioral alert (L1430)
  6. `predict_malware` endpoint (L692)
  7. `scan_malware` endpoint (L755)
  8. `_malware_scan_loop()` — file watcher (L1156)

The redesign adds `ingest_event()` calls at all these sites. If both the old
`_fusion_agent.fuse()` and the new `FusionDecisionEngine.fuse()` are invoked in
parallel during the transition, they will produce independent `fusion_alert` and
`soc_alert` emissions that the frontend must distinguish. **Risk**: Double-alerting,
inconsistent threat scores displayed simultaneously.
**Resolution**: Gate the new `FusionDecisionEngine` behind a feature flag
(`USE_CORRELATION_ENGINE = True` in config.py); when enabled, suppress the
legacy `_fusion_agent.fuse()` calls and use only the new engine's output.

### Conflict 2 — _latest_scores TTL vs. EventBuffer TTL
**Root cause**: `_get_current_scores()` applies a 300-second TTL per domain.
The new `EventBuffer` has its own 5-minute (300-second) sliding window. If the
EventBuffer's window size differs from `_get_current_scores()`'s TTL, a score
that has expired from `_get_current_scores()` may still have its originating
event present in the EventBuffer (or vice versa).
**Resolution**: Set EventBuffer window to exactly 300 seconds (5 minutes) to
match. Document this coupling explicitly in both modules.

### Conflict 3 — `soc_alert` vs `fusion_alert` frontend routing
**Root cause**: The frontend `NetworkDashboard.tsx` already subscribes to
`fusion_alert`. The redesign adds `soc_alert`. Without explicit frontend routing,
both events arrive at the same subscriber or one is silently dropped.
**Resolution**: In `api.ts`/`networkSocket.ts`, add explicit `soc_alert`
subscription handler. In `OverviewView.tsx`, display correlated alerts (from
`soc_alert`) in a separate panel or severity band from per-domain fusion alerts.

### Conflict 4 — MongoDB collection cap not updated for new collections
**Root cause**: `_COLLECTION_CAP` (L77-87 of `backend.py`) controls Atlas M0
trim. The three new collections are not listed. First write to `raw_events` will
succeed; subsequent trim checks will never run against it; Atlas will fill.
**Resolution**: Add before shipping:
```python
"raw_events":           2_000,
"correlated_alerts":      500,
"high_severity_alerts":   200,
```

### Conflict 5 — sklearn version mismatch affects Gate 1 of hybrid detector
**Root cause**: `personal_baseline_model.pkl` and `system_scaler.pkl` were
pickled with scikit-learn 1.7.2 but the current venv runs 1.8.0. This means
Gate 1 of the hybrid detector (`personal_baseline_model.pkl`) may be failing
silently — all flows pass to Gate 2 unconditionally. If the new fusion engine's
EventBuffer ingests Gate 1 status as a feature, it will receive a false
"Gate 1 passed" signal for every flow.
**Resolution**: `pip install scikit-learn==1.7.2` in venv OR retrain:
`python collect_baseline.py && python train_personal_model.py`.

---

## SECTION 5: NEXT STEPS AND IMPLEMENTATION ROADMAP

### Immediate Actions (0-2 weeks) — Critical fixes before or during redesign

1. **[SEC] Add API key auth to /simulate-user-attack**
   - File: `D:\Cyber Sentinal\Backend\backend.py` L882
   - Change: Add `dependencies=[Depends(_require_key)]` to the `@app.post` decorator
   - Effort: 2 minutes

2. **[SEC] Introduce asyncio.Lock for _latest_scores**
   - File: `backend.py` — add `_scores_lock = asyncio.Lock()` at module level
   - Wrap all assignments to `_latest_scores[k]` in `async with _scores_lock`
   - Note: This is especially important for the redesign since `ingest_event()`
     will add another concurrent mutation path.
   - Effort: 30 minutes

3. **[BUG] Fold _latest_system_score and _latest_sysmon_score into TTL dict**
   - Replace bare float globals with `_latest_scores["system_lstm"]` and
     `_latest_scores["system_sysmon"]` with timestamps
   - Update `_handle_system_result` and `_handle_sysmon_result` accordingly
   - Update `_get_current_scores()` to compute `combined_system` from both
   - Effort: 45 minutes

4. **[FUSION] Pre-register new MongoDB collections in _COLLECTION_CAP**
   - Add raw_events (2000), correlated_alerts (500), high_severity_alerts (200)
   - Do this before writing a single document from the new fusion module
   - Effort: 5 minutes

5. **[BUG] Fix sklearn version mismatch**
   - Run: `pip install scikit-learn==1.7.2` in venv
   - OR retrain: `python collect_baseline.py` (30-60 min) then
     `python train_personal_model.py`
   - Verify Gate 1 is active: check that `hybrid_detector.py` logs
     "Personal baseline model loaded" and that some flows are filtered at Gate 1
   - Effort: 30 minutes (pip downgrade) to 90 minutes (full retrain)

### Short-term (2-6 weeks) — Fusion redesign implementation

6. **[FEATURE] Implement fusion_engine.py with EventBuffer + CorrelationEngine**
   - `EventBuffer`: deque with maxlen computed from 300s / avg event rate;
     each entry: `{domain, score, ts, attack_type, features_snapshot}`
   - `CorrelationEngine`: maps sequences of (domain, attack_type) tuples to
     MITRE ATT&CK technique IDs; detect patterns like
     [PortScan → BruteForce], [Infiltration → Botnet], [UserAnomaly + MalwareHit]
   - `FusionDecisionEngine.fuse()`: output schema:
     ```json
     {
       "alerts": [{"domain": str, "score": float, "ts": str, "attack_type": str}],
       "correlation": {
         "pattern": str,
         "mitre_techniques": ["T####", "T####"],
         "confidence": float,
         "event_count": int
       },
       "final_decision": {
         "threat_score": float,
         "severity": str,
         "should_respond": bool,
         "reasons": [str]
       }
     }
     ```
   - Effort: 3-5 days

7. **[FEATURE] Wire ingest_event() into all _handle_* handlers in backend.py**
   - Call `_fusion_engine.ingest_event(domain, score, attack_type, ts)` at each
     of the 8 handler call sites identified in Conflict 1
   - Gate behind `USE_CORRELATION_ENGINE` config flag to avoid double-alerting
   - Emit `soc_alert` only when CorrelationEngine detects a pattern
     (correlation.confidence >= threshold)
   - Effort: 2-3 days

8. **[FEATURE] Fix OverviewView.tsx threat gauge**
   - Subscribe to `fusion_alert` Socket.IO event (not `threat_score` which uses
     old `/fusion` endpoint)
   - Use `threat_score * 100` from the event payload directly
   - Add a `fusion_heartbeat` background task (every 10s) to keep gauge current
     during quiet periods
   - Effort: 2 hours

9. **[FEATURE] Add CorrelationView.tsx or panel**
   - Display correlated alerts from `soc_alert` events
   - Show MITRE ATT&CK technique badges, event chain timeline, confidence score
   - Link to individual domain alert details from AlertsView
   - Effort: 1-2 days

10. **[CONFIG] Winlogbeat configuration for user behavior**
    - Set `START_WINLOGBEAT=true` in `.env`
    - Configure `winlogbeat.yml` to ship Security event logs to `C:\XDR_Logs\`
    - Verify `xdr_runtime.py` reads events: check log for "events_count > 0"
    - This is the highest-ROI single fix for coverage — currently user behavior
      reads 0 events in production
    - Effort: 2-4 hours

### Medium-term (6-12 weeks) — Architecture enhancements

11. **[TRAIN] Train system_model.pt (LSTM Autoencoder)**
    - Run: `python train_system_model.py --collect-minutes 60`
    - Verify: system score returns values in [0, 0.5] range (not 1.0) for
      normal workload
    - This unblocks the system monitoring layer from heuristic-only mode
    - Effort: 2-3 hours (collection) + 30 minutes (training)

12. **[SEC] Restrict CORS to dashboard origin**
    - `backend.py` L414: Change `cors_allowed_origins="*"` to
      `cors_allowed_origins=["http://localhost:3000"]` (or the deployed origin)
    - Apply same restriction to `CORSMiddleware` at L417
    - Effort: 10 minutes; block on knowing the production dashboard URL

13. **[SHAP] Implement SHAP/LIME for Sysmon behavioral detections**
    - `shap_agent.py`: Add `explain_sysmon()` method using LIME on the TF-IDF
      token weights (LinearExplainer or KernelExplainer for the IsolationForest)
    - Wire into `_handle_sysmon_result()` in backend.py
    - Effort: 1-2 days

14. **[SOAR] Add quarantine_file path allowlist (CWE-22)**
    - `endpoint_agent.py` `quarantine_file` action: validate target path against
      a configured allowlist before executing file moves
    - Mirror the `scan_allowed_roots` pattern from `/scan/malware`
    - Effort: 1 hour

15. **[SOAR] Wire kill_process SOAR action to Sysmon HIGH/CRITICAL alerts**
    - When `_handle_sysmon_result` receives severity == "CRITICAL", write a
      `kill_process` command to MongoDB with the offending PID
    - Add PID validation (must be > 4, not in a protected-process allowlist)
    - Effort: 2-3 hours

16. **[FEATURE] OCEAN personality features data source**
    - Add `POST /users/ocean` endpoint accepting OCEAN scores per username
    - Create `user_profiles` MongoDB collection
    - Wire into `xdr_runtime.py` feature construction
    - Effort: 1-2 days

### Long-term (3-6 months) — Advanced capabilities

17. **[ML] Online learning pipeline for fusion weights**
    - Implement feedback loop: SOC analyst confirms or dismisses `soc_alert`
    - Adjust domain weights based on analyst-confirmed true-positive rate per
      domain over rolling 30-day window
    - Use Bayesian weight update: `w_i_new = w_i + alpha * (TP_rate_i - mean_TP_rate)`

18. **[ML] Flow micro-fragmentation fix**
    - Aggregate micro-flows (< 1s duration, same 5-tuple) before CIC feature
      computation in `network_detection_agent.py`
    - Current behavior computes 76 CIC features on individual packets; true
      CIC-IDS2017 features are computed over full flow windows (10-60s)

19. **[ARCH] Zeek integration**
    - Zeek configs exist in `Backend/ZEEK/` but the backend does not start or
      parse Zeek logs
    - Zeek provides protocol-level features (SSL cert anomalies, DNS tunneling,
      HTTP headers) that complement Suricata's flow-level detection
    - Add Zeek log reader to `NetworkDetectionAgent`

20. **[ARCH] Multi-endpoint support**
    - Current SOAR commands target a single host; `endpoint_agent.py` is
      designed for one-host deployment
    - Add endpoint registration endpoint (`POST /endpoints/register`) and
      per-host command queuing to support distributed deployment

---

## SECTION 6: METRICS AND KPIs TO TRACK

### Fusion Engine Effectiveness (Post-Redesign)

| Metric | Target | How to Measure |
|--------|--------|----------------|
| Correlated Alert False Positive Rate | < 5% | SOC analyst dismissal rate on `soc_alert` events |
| Attack Chain Detection Latency | < 60s from first event | Timestamp delta: first EventBuffer entry → `soc_alert` emission |
| Single-Domain False Negative Rate | < 10% | Confirmed attacks not caught by individual models but caught by correlation |
| EventBuffer Fill Rate | < 80% at normal traffic | `len(event_buffer) / maxlen` logged every monitoring cycle |
| MITRE Technique Coverage | >= 10 techniques mapped | Count of unique MITRE technique IDs in `correlated_alerts` collection |

### System-Wide Health KPIs

| Metric | Target | Current State |
|--------|--------|---------------|
| Network Detection Coverage | > 95% of labeled attack types | 99.6% on CIC-IDS2017 test set |
| User Behavior Events/Cycle | > 0 | Currently 0 (Winlogbeat not configured) |
| System Monitor Mode | LSTM (not heuristic) | Currently heuristic (system_model.pt missing) |
| Malware Scan Coverage | All new PE files < 120s | File watcher at 120s interval |
| SOAR Command Execution Lag | < 30s from command write | Poll interval in endpoint_agent.py |
| Atlas M0 Storage Utilization | < 70% per collection | `/storage-status` endpoint |
| SHAP Coverage | 4 of 4 models | Currently 2 of 4 (network + malware) |

### Security Health

| Metric | Target |
|--------|--------|
| Endpoints with default API key | 0 (should be 0 in production) |
| Unauthenticated endpoints (excluding /health, /start-monitoring) | 0 |
| CORS wildcard origins | 0 |
| Uncapped MongoDB collections | 0 |

---

## SECTION 7: UPDATED COMPLETENESS TABLE

Based on this analysis, the revised layer-by-layer table replacing the version
in CLAUDE.md (as of 2026-04-25, post-redesign planning):

| Layer | Pre-Redesign % | Post-Redesign Target % | Blocking Items |
|-------|---------------|----------------------|----------------|
| Network Detection | 90% | 92% | Flow micro-fragmentation fix |
| User Behavior | 55% | 70% | Winlogbeat config (highest ROI) |
| System Monitor (LSTM) | 60% | 75% | Train system_model.pt |
| Sysmon Behavioral | 70% | 78% | SHAP/LIME, kill_process SOAR |
| Malware Detection | 95% | 97% | quarantine_file path allowlist |
| Fusion Engine | 65% | 88% | EventBuffer + CorrelationEngine + heartbeat |
| SHAP Explainability | 80% | 88% | system + sysmon models |
| SOAR / Endpoint Agent | 90% | 93% | Path allowlist + kill_process wiring |
| MongoDB / Persistence | 95% | 97% | Pre-register 3 new collection caps |
| Frontend / SOC Dashboard | 85% | 92% | OverviewView gauge fix + CorrelationView |
| **Overall** | **~82%** | **~88%** | See roadmap above |

Note: The Fusion Engine layer is rated 65% pre-redesign (not 100% as in CLAUDE.md)
because the CLAUDE.md rating reflected only the weighted scoring pipeline being
complete. When scored against full IDPS fusion requirements (temporal correlation,
MITRE mapping, structured output schema, multi-domain pattern detection), the
current implementation covers approximately 65% of the required functionality.

================================================================================
END OF REPORT
Files analyzed:
  D:\Cyber Sentinal\Backend\agents\fusion_engine_agent.py
  D:\Cyber Sentinal\Backend\backend.py
  D:\Cyber Sentinal\Backend\agents\shap_agent.py
  D:\Cyber Sentinal\Cyber Sentinal XDR Frontend\src\components\views\OverviewView.tsx
  D:\Cyber Sentinal\Backend\config.py
  D:\Cyber Sentinal\.claude\agent-memory\idps-project-analyst\project_cyber_sentinel_xdr.md
Next Analysis Recommended: After fusion_engine.py implementation is complete
  and wired into backend.py — trigger a focused integration review of EventBuffer
  TTL alignment, ingest_event() concurrency safety, and soc_alert frontend routing.
================================================================================
