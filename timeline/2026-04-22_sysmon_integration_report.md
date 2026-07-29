================================================================================
IDPS PROJECT ANALYSIS REPORT
================================================================================
Timestamp     : 2026-04-22 10:30:00 UTC
Analyst       : IDPS Project Analyst Agent
Scope         : Sysmon Behavior Detection Layer — full integration review
                (sysmon_behavior_agent.py, train_sysmon_model.py,
                 sysmon_event_reader.py, SysmonBehaviorView.tsx,
                 backend.py wiring, config.py additions)
Project Phase : Layer 5 of 7 active — Sysmon Behavior fully wired in;
                LSTM System Monitor (layer 4) still in degraded mode
================================================================================

## EXECUTIVE SUMMARY

The Sysmon Behavior detection layer has been successfully integrated into Cyber
Sentinel XDR.  All five components (agent, trainer, event reader, frontend panel,
backend wiring) are present and structurally correct.  The live log confirms
sysmon_event_reader.py is producing well-formed NDJSON at high volume
(500+ events/min).  The model loaded successfully (vocab=8524,
iso_threshold=0.1060).  Several quality and security issues require attention:
the most important are the pickle deserialization approach (moderate security
risk), silent score suppression for whitelisted processes that emit high-risk
events, fusion weight mis-assignment (sysmon alerts feed system_score instead of
a dedicated channel), and the absence of persistent storage for sysmon alerts
in MongoDB.  Overall project health is assessed at 7.2/10 — the Sysmon layer
is functional but needs hardening before production use.

---

## SECTION 1: CODE QUALITY ASSESSMENT

### 1.1 Strengths

- Clean separation of concerns: agent / trainer / reader are independent files
  with no circular imports.
- _sysmon_event_to_token() duplicated inline from windows_detector_final.py
  with an explicit comment explaining why — prevents import coupling to a
  standalone CLI script.  Correct design choice.
- Graceful degradation throughout: missing model file, missing log file, model
  load failure, and missing Torch all handled without crashing the backend.
- Per-PID rolling deque with configurable window size and stride is memory
  efficient and correctly bounded.
- Cooldown tracker (_ALERT_COOLDOWN_S=120) prevents alert flooding for
  persistent anomalous PIDs.  Implementation is correct.
- asyncio.to_thread() correctly offloads the blocking _tail_file() loop,
  keeping the FastAPI event loop unblocked.
- loop.call_soon_threadsafe + asyncio.ensure_future is the correct pattern
  for scheduling async callbacks from a synchronous thread.
- SysmonBehaviorView.tsx: duplicate Socket.IO connection created inside the
  component is correctly cleaned up in the useEffect teardown.
- train_sysmon_model.py: --sysmon_benign flag for live-data augmentation is
  a good design that will reduce false positives once operational benign data
  accumulates.
- sysmon_event_reader.py: bookmark file for resume-on-restart prevents event
  loss across restarts.  Validation (startswith "20") guards against corrupt
  bookmark.

### 1.2 Issues Found

| Severity | Component | Issue | Recommendation |
|----------|-----------|-------|----------------|
| HIGH | sysmon_behavior_agent.py L247-252 | Custom Unpickler falls back to super().find_class() for all non-WindowsAnomalyDetector classes, allowing arbitrary deserialization of classes in the pickle stream | Add an explicit allowlist of permitted classes; raise UnpicklingError for anything outside it |
| HIGH | backend.py L1048 | _handle_sysmon_result feeds score into fuse(system_score=score), sharing the system weight (0.15) with the LSTM autoencoder — both agents can saturate the same fusion channel simultaneously | Add a dedicated sysmon_score parameter to FusionEngineAgent.fuse() or remap weights to include a sysmon channel |
| MEDIUM | sysmon_behavior_agent.py L432 | Whitelisted processes are suppressed even on high_risk events when is_whitelisted=True AND high_risk=True — the condition `if is_whitelisted and not high_risk` correctly passes them through, BUT the should_alert block on L455 only fires for high_risk if `not is_whitelisted`. A whitelisted process doing CreateRemoteThread will be scored but never alert | Fix should_alert: `(high_risk and not is_whitelisted)` should be `(high_risk)` — high-risk EventIDs must always alert regardless of whitelist |
| MEDIUM | sysmon_behavior_agent.py L408 | _score_pid called immediately on high-risk events before the window has more than MIN_FEAT_HITS=5 tokens (the guard at L403 returns early, but high_risk check at L407 precedes the window-length check) — high_risk path bypasses the minimum window guard | Move the `len(ps["window"]) < _MIN_FEAT_HITS` check before both branches, or explicitly re-apply it inside _score_pid for high-risk events |
| MEDIUM | backend.py L1041-1063 | _handle_sysmon_result saves to MongoDB alerts collection but there is no sysmon_alerts collection write, unlike malware and user_behavior which each have dedicated collections | Add _save("sysmon_alerts", event) before the alerts write for dedicated historical storage and cap management |
| MEDIUM | sysmon_event_reader.py L54-58 | PowerShell time_filter constructs a string like `StartTime = [datetime]::Parse('2026-04-22T...');` which is injected without sanitization into the PS script | Validate last_ts is a well-formed ISO timestamp before injection (regex match); already partially done by the "startswith 20" check but that is insufficient |
| MEDIUM | SysmonBehaviorView.tsx L130-147 | Component creates its own Socket.IO connection independent of the parent NetworkMonitor.tsx Socket.IO instance — results in two parallel connections to the backend for the sysmon view | Pass the shared socket down as a prop or use a React context / custom hook to share one connection |
| LOW | sysmon_behavior_agent.py L492 | asyncio.get_event_loop() is deprecated in Python 3.10+ when called from a non-async context; may raise DeprecationWarning or fail in future Python versions | Replace with asyncio.get_running_loop() — safe to call from the sync thread that was started via asyncio.to_thread() because the loop is still running |
| LOW | train_sysmon_model.py L122-137 | `import pandas as pd` appears three times inside the sysmon_benign block due to copy-paste duplication | Consolidate to a single import at the top of the function |
| LOW | sysmon_event_reader.py L83-86 | Temp .ps1 files written to the system temp dir on every 3-second poll (up to 20 files/min) — could accumulate if unlink fails | Pre-create a single persistent .ps1 script file at startup and reuse it; this also eliminates the per-call write overhead |
| LOW | sysmon_behavior_agent.py L209 | _total_events counter is not thread-safe (incremented in sync thread, read in async status()) — race condition on 32/64-bit non-atomic int operations | Use threading.Lock or collections.Counter, or accept the minor count inaccuracy for a status display |
| LOW | SysmonBehaviorView.tsx L5 | BACKEND_URL hardcoded to "http://localhost:8000" duplicated from other view files | Consolidate into a shared constants file (src/constants.ts or src/config.ts) |

---

## SECTION 2: SECURITY VULNERABILITY ANALYSIS

### 2.1 Critical Vulnerabilities

None identified at CRITICAL level.

### 2.2 High Severity

**[HIGH-1] Pickle Deserialization — Partial Mitigation Only**
- Description: The custom _DetectorUnpickler restricts WindowsAnomalyDetector
  resolution to the known source file, which is correct.  However, the
  `super().find_class()` fallback is unconditional.  Any class referenced in
  the pickle stream (e.g., numpy.ndarray, sklearn TfidfVectorizer internals,
  or a malicious injected class) is passed through to the default unpickler
  with no restriction.
- Impact: If detector.pkl is replaced by an attacker (compromised model
  artifact supply chain), arbitrary code execution on the backend process is
  possible.  The backend runs as the XDR service, likely with elevated
  privileges.
- CWE: CWE-502 (Deserialization of Untrusted Data)
- Remediation:
  1. Add a SHA-256 integrity check of detector.pkl before unpickling:
     compute hash at training time, store in detector.pkl.sha256, verify on
     load.
  2. Implement a strict allowlist in _DetectorUnpickler.find_class():
     permitted_classes = {
       ("sklearn.feature_extraction.text", "TfidfVectorizer"),
       ("sklearn.ensemble._iforest", "IsolationForest"),
       ("sklearn.ensemble._forest", "RandomForestClassifier"),
       ("sklearn.preprocessing._label", "LabelEncoder"),
       ("numpy", "ndarray"), ("numpy.core.multiarray", "_reconstruct"),
       ...
     }
     Reject anything outside this set.
  3. Long-term: replace pickle with joblib (sklearn native) or ONNX export
     which do not carry the same arbitrary-code risk surface.

**[HIGH-2] sysmon_behavior_agent Alerts Miss High-Risk Whitelisted Processes**
- Description: Line 455 — `(high_risk and not is_whitelisted)` — explicitly
  suppresses alerts for whitelisted processes even when the event is
  CreateRemoteThread (EventID 8) or ProcessTampering (EventID 25).  Known-
  bad actors (Mimikatz, Meterpreter) that manage to rename themselves to
  svchost.exe or explorer.exe would be silenced.
- Impact: Detection blind spot for process-masquerading attacks, a common
  living-off-the-land technique.  MITRE ATT&CK T1036.005 (Match Legitimate
  Name or Location).
- CWE: CWE-390 (Detection of Error Condition Without Action)
- Remediation: Change should_alert to:
  ```python
  should_alert = (
      is_high_alert
      or high_risk            # ALWAYS alert on EventID 8/25, regardless of whitelist
      or (is_anomaly and not is_whitelisted and not in_cooldown and not low_feats)
  )
  ```

### 2.3 Medium / Low Severity

**[MED-1] PowerShell Script Injection via Timestamp**
- Description: sysmon_event_reader.py L54-58 embeds `last_ts` into the
  PowerShell script string.  While the bookmark validation (startswith "20")
  reduces risk, a crafted bookmark file containing `'; Invoke-Expression ...`
  could inject PS commands.
- Impact: Local privilege escalation if bookmark file is world-writable.
  CWE-78 (Improper Neutralization of Special Elements in OS Command).
- Remediation: Validate last_ts with a strict regex before embedding:
  `re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z', last_ts)`.

**[MED-2] sysmon_events.json Log File Permissions**
- Description: sysmon_event_reader.py writes to C:\winlogbeat\logs\
  sysmon_events.json.  If this path is writable by non-admin users, an
  attacker can inject crafted Sysmon events to poison the detection model's
  inference window and suppress legitimate alerts.
- Impact: Alert suppression / false-negative injection attack.
  CWE-284 (Improper Access Control).
- Remediation: Verify C:\winlogbeat\logs\ ACLs restrict write access to the
  service account running sysmon_event_reader.py (SYSTEM or a dedicated
  service user) and deny write to standard user accounts.

**[MED-3] No Authentication on Socket.IO sysmon_behavior_alert Event**
- Description: The sysmon_behavior_alert Socket.IO event is emitted to all
  connected clients.  The Socket.IO server has cors_allowed_origins="*".
  Any browser tab on localhost can receive all sysmon alert data without
  presenting an API key.
- Impact: Information disclosure — alert details (process names, PIDs,
  anomaly scores) are visible to any local process that connects to port 8000
  via Socket.IO.  Low severity in a single-operator workstation context; high
  severity in a shared environment.
- Remediation: Implement Socket.IO namespace authentication (token in handshake
  auth object, verified in the connect handler).  This is a systemic gap across
  all Socket.IO events, not unique to Sysmon.

**[LOW-1] asyncio.get_event_loop() Deprecation**
- Python 3.12 will raise DeprecationWarning; future Python 4 may remove it.
  Use asyncio.get_running_loop() instead (line 492 of sysmon_behavior_agent.py).

**[LOW-2] PID Reuse — False PID-to-Process Association**
- Description: _processes dict keys on PID string.  Windows PID reuse means
  a new process can inherit the window of a previous process with the same PID.
- Impact: Low false-positive risk; new benign process appears anomalous
  because it inherits a prior malicious process's token window.
- Remediation: Key on (pid, process_create_timestamp) or reset the window
  when a ProcessTerminate (EventID 5) is observed for the PID.  Note that
  EventID 5 is already in SYSMON_EVENTS but not currently handled.

---

## SECTION 3: ARCHITECTURE GAP ANALYSIS

| Layer | Component | Status | Notes |
|-------|-----------|--------|-------|
| Network Monitoring | Suricata + rule_detector.py + hybrid_detector.py | Implemented | Personal baseline (Gate 1) still untrained |
| Endpoint/Host Monitoring | sysmon_behavior_agent.py + sysmon_event_reader.py | Implemented | Running, 500+ events/min confirmed |
| Endpoint/Host Monitoring | system_monitor_agent.py (LSTM Autoencoder) | Degraded | system_model.pt not yet trained |
| Log Collection | sysmon_event_reader.py (replaces Winlogbeat for Sysmon) | Implemented | Winlogbeat still used for Windows Security events (user behavior) |
| Log Collection | Winlogbeat for C:\XDR_Logs | Not Configured | User behavior inference reads 0 events until configured |
| AI/ML — Network | RandomForest (CIC-IDS2017) | Implemented | 99.6% accuracy |
| AI/ML — User Behavior | One-Class SVM (CERT r4.2) | Implemented | OCEAN features still hardcoded to 0.0 |
| AI/ML — Sysmon Behavior | TF-IDF + IsolationForest/XGBoost (GHC dataset) | Implemented | vocab=8524, iso_threshold=0.1060 |
| AI/ML — System | LSTM Autoencoder (live telemetry) | Not Trained | Runs in degraded mode; needs 60 min baseline collection |
| AI/ML — Malware | LightGBM (EMBER 2018) | Implemented | AUC=0.9803, F1=0.9298 |
| Fusion Engine | FusionEngineAgent | Implemented with Gap | Sysmon feeds system_score channel, overloading it alongside LSTM agent |
| SHAP Explainability | shap_agent.py | Implemented for Network + Malware | No SHAP support for Sysmon behavior alerts |
| Response / SOAR | endpoint_agent.py | Implemented | No dedicated SOAR action for Sysmon-triggered process kill |
| Storage | MongoDB — sysmon_alerts collection | Missing | sysmon alerts saved to generic "alerts" only; no dedicated cap or history view |
| Storage | MongoDB — sysmon_alerts cap | Missing | _COLLECTION_CAP does not include sysmon-specific collection |
| Visualization | SysmonBehaviorView.tsx | Implemented | Duplicate Socket.IO connection; sysmon alerts absent from AlertsView |
| Visualization | AlertsView.tsx — sysmon column | Missing | Sysmon alerts visible only in dedicated view, not in unified alert table |

### Key Fusion Weight Issue

Current config.py weights: network=0.35, user=0.30, system=0.15, malware=0.20.
Total = 1.00.  Both SystemMonitorAgent and SysmonBehaviorAgent call
`fuse(system_score=score)`.  If both fire simultaneously, whichever fires last
overwrites the contribution — there is no additive combination.  Additionally,
a 0.15 system weight means even a perfect sysmon anomaly score of 1.0 only
contributes 0.15 to the threat score, which cannot alone reach the HIGH
threshold of 0.65.  Sysmon behavioral signals are currently under-weighted
given their high specificity.

---

## SECTION 4: CONFLICTS AND INCOMPATIBILITIES

| # | Conflict | Root Cause | Resolution |
|---|----------|------------|------------|
| 1 | SysmonBehaviorAgent and SystemMonitorAgent both use system_score in fusion | _handle_sysmon_result (L1048) and _handle_system_result (L1026) both call fuse(system_score=...) — the weight is shared and scores are not combined, just last-writer-wins | Add sysmon_score as a fifth fusion parameter OR reroute sysmon to combine with system via max(system_score, sysmon_score) before calling fuse() |
| 2 | Duplicate Socket.IO connection in SysmonBehaviorView.tsx | View creates its own io() connection instead of using parent's socket | Pass socket ref as prop or extract a shared socket context |
| 3 | sysmon_behavior_alert event not in monitoring_status broadcast | _monitoring_loop emits monitoring_status but does not include sysmon_active flag | Add `"sysmon_active": _sysmon_agent is not None and _sysmon_agent.status().get("model_loaded", False)` to monitoring_status dict |
| 4 | SysmonBehaviorView empty-state text still mentions "Winlogbeat" | L393: "ensure Sysmon + Winlogbeat are running" — Winlogbeat has been replaced by sysmon_event_reader.py | Update UI text to reference sysmon_event_reader.py or Task Scheduler task name |
| 5 | BENIGN_WHITELIST contains "powershell_ise.exe" and "unknown" | "unknown" is the fallback process name used when image path cannot be resolved — any process whose image path fails to parse gets whitelisted by name, bypassing all detection | Remove "unknown" from BENIGN_WHITELIST; treat unknown process names as suspicious, not benign |
| 6 | sysmon_alerts collection absent from _COLLECTION_CAP | backend.py L66-76 defines caps but sysmon_alerts is missing | Add "sysmon_alerts": 1_000 to _COLLECTION_CAP and add _save("sysmon_alerts", event) in _handle_sysmon_result |

---

## SECTION 5: NEXT STEPS AND IMPLEMENTATION ROADMAP

### Immediate Actions (0-2 weeks) — Critical Fixes

1. **Fix high-risk event alerting for whitelisted processes**
   File: Backend/agents/sysmon_behavior_agent.py, line 455
   Change `(high_risk and not is_whitelisted)` to `high_risk`.
   This closes the T1036.005 process-masquerading blind spot.

2. **Remove "unknown" from BENIGN_WHITELIST**
   File: Backend/agents/sysmon_behavior_agent.py, line 73
   Processes that fail image-path resolution should not be silently suppressed.
   Replace with a warning log if proc_name == "unknown".

3. **Add sysmon_alerts MongoDB collection**
   File: Backend/backend.py, function _handle_sysmon_result (~line 1055)
   Add: `_save("sysmon_alerts", event)`
   File: Backend/backend.py, _COLLECTION_CAP dict
   Add: `"sysmon_alerts": 1_000`

4. **Fix asyncio.get_event_loop() deprecation**
   File: Backend/agents/sysmon_behavior_agent.py, line 492
   Replace: `asyncio.get_event_loop()` with `asyncio.get_running_loop()`

5. **Add high-risk event window-size guard**
   File: Backend/agents/sysmon_behavior_agent.py, _handle_event()
   Move the `len(ps["window"]) < _MIN_FEAT_HITS` check before the high_risk
   branch so that EventID 8/25 events also require a minimum token window
   for reliable scoring (though they should still log a separate raw alert).

### Short-term (2-6 weeks) — High Priority Improvements

6. **Harden pickle deserialization**
   File: Backend/agents/sysmon_behavior_agent.py, _DetectorUnpickler
   Implement a strict class allowlist instead of falling back to super().
   Simultaneously, add a SHA-256 integrity file (detector.pkl.sha256) written
   at training time and verified before loading.

7. **Resolve fusion weight conflict between Sysmon and System agents**
   Options (choose one based on operational priority):
   A. Add sysmon_score as a fifth fusion input with dedicated weight; adjust
      all weights to sum to 1.0 (e.g., network=0.30, user=0.25, system=0.15,
      sysmon=0.15, malware=0.15).
   B. Keep four channels; combine system and sysmon via max() before fusion.
   Update: fusion_engine_agent.py, backend.py, config.py.

8. **Fix duplicate Socket.IO connection in SysmonBehaviorView.tsx**
   Extract Socket.IO client to a shared React context (src/context/SocketContext.tsx)
   and consume it in SysmonBehaviorView, UserBehaviorView, and MalwareView to
   reduce from 3-4 connections to 1.

9. **Add Sysmon column to AlertsView.tsx**
   Sysmon HIGH/CRITICAL alerts should appear in the unified alert table alongside
   network and malware alerts, not only in the dedicated view.

10. **Validate PS timestamp injection**
    File: Backend/sysmon_event_reader.py, tail_sysmon(), bookmark validation block
    Add: `if not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z', last_ts): last_ts = None`

11. **Verify C:\winlogbeat\logs ACL**
    Run: `icacls C:\winlogbeat\logs` and ensure only SYSTEM and Administrators
    have write access.  Document in COMMANDS.md.

### Medium-term (6-12 weeks) — Architecture Enhancements

12. **Train system_model.pt (LSTM Autoencoder)**
    The system monitor has been in degraded mode since initial integration.
    Run: `python train_system_model.py --collect-minutes 60` during normal
    operation.  This is the highest-value untrained model remaining.

13. **Train personal_baseline_model.pkl**
    Run collect_baseline.py as Administrator (30 min TShark capture).
    Hybrid detector Gate 1 bypass is a detection coverage gap.

14. **Add EventID 5 (ProcessTerminate) handler to reset PID windows**
    File: Backend/agents/sysmon_behavior_agent.py, _handle_event()
    When EventID 5 is received, call `self._processes.pop(pid, None)` to
    clear the stale window and prevent PID-reuse false positives.

15. **Add SHAP explainability for Sysmon alerts**
    The Sysmon model uses TF-IDF features which support LIME or SHAP
    (text-based explainability).  Extend SHAPAgent with an explain_sysmon()
    method using shap.LinearExplainer or shap.KernelExplainer on the
    TF-IDF + classifier pipeline.  Surface top tokens in alert reason strings.

16. **Connect OCEAN features for user behavior model**
    Currently all five OCEAN personality scores are hardcoded to 0.0.
    Investigate data sources: Active Directory attributes, user survey, or
    behavioral proxy metrics.

17. **Add sysmon_active to monitoring_status broadcast**
    File: Backend/backend.py, _monitoring_loop (~line 928)
    Add `"sysmon_active": _sysmon_agent is not None and _sysmon_agent.status().get("model_loaded", False)`
    to allow frontend to reflect sysmon agent health in the monitoring status bar.

### Long-term (3-6 months) — Advanced Capabilities

18. **Replace pickle artifacts with joblib + model signing**
    Train scripts should save via joblib.dump() with a detached HMAC or
    code-signing certificate.  Load scripts verify before deserializing.

19. **Add SOAR action for Sysmon-triggered process kill**
    High-confidence Sysmon CRITICAL alerts (score >= 0.85, label != Background)
    should write a kill_process command to MongoDB, analogous to the malware
    quarantine_file command.  This closes the automated response gap for
    behavioral detections.

20. **Sysmon model retraining with live benign data**
    Run: `python train_sysmon_model.py --sysmon_benign C:/winlogbeat/logs/sysmon_events.json`
    after 1-2 weeks of clean operation to reduce false positives against the
    specific application mix on this endpoint.

21. **Socket.IO authentication**
    Implement token-based auth in the Socket.IO connect handler to prevent
    unauthorized clients from receiving alert streams.

---

## SECTION 6: METRICS AND KPIs TO TRACK

| Metric | Target | How to Measure |
|--------|--------|----------------|
| Sysmon alert false-positive rate | < 5% | Manual review of LOW/MEDIUM alerts over 48 hrs |
| High-risk event detection latency | < 500 ms from EventID 8/25 write to Socket.IO emit | Add timing log in _score_pid and _handle_sysmon_result |
| sysmon_event_reader lag (bookmark vs. wall clock) | < 10 s | Compare last_ts in bookmark vs. current time |
| Events processed per minute | > 400 | Monitor sysmon_health.total_events delta via /health |
| Model coverage (non-whitelisted PIDs scored) | > 60% of active PIDs | Add scored_pids counter to agent status |
| Fusion sysmon contribution (when active) | > 0.08 at MEDIUM | Observe threat_score components in fusion output |
| MongoDB sysmon_alerts collection fill rate | < 80% of cap | /storage-status endpoint |
| Alert cooldown hit rate | < 30% | Add cooldown_hits counter alongside total_alerts |

---

## APPENDIX: SYSTEM-WIDE OUTSTANDING ITEMS (from CLAUDE.md)

The following pre-existing items remain unresolved and are unchanged by today's
Sysmon integration:

| Item | Status | Priority |
|------|--------|----------|
| system_model.pt (LSTM Autoencoder) not trained | Outstanding | HIGH — next training task |
| personal_baseline_model.pkl not trained — Hybrid Gate 1 bypassed | Outstanding | HIGH |
| Winlogbeat not configured for C:\XDR_Logs — user behavior reads 0 events | Outstanding | HIGH |
| OCEAN personality features hardcoded to 0.0 | Outstanding | MEDIUM |
| Flow micro-fragmentation in CIC feature extraction | Outstanding | MEDIUM |

================================================================================
END OF REPORT
Next Analysis Recommended: After system_model.pt training completes, or after
the fusion weight conflict (Item 7 above) is resolved — whichever comes first.
================================================================================
