================================================================================
IDPS PROJECT ANALYSIS REPORT
================================================================================
Timestamp     : 2026-04-21 00:00:00 UTC
Analyst       : IDPS Project Analyst Agent
Scope         : User Behavior Detection Layer — IsolationForest retraining, xdr_runtime.py
                overhaul, feature set expansion (12 → 19), fast-path rule introduction,
                win32evtlog fallback, and full backward-compatibility audit against
                UserBehaviorAgent and backend.py
Project Phase : Phase 3 — AI/ML Model Refinement & Integration Hardening
================================================================================

## EXECUTIVE SUMMARY

The user behavior detection layer has been substantially overhauled in response to a
confirmed detection failure: the previous OC-SVM model was returning NORMAL on sessions
with 1000 file creates, 20-pass reads, and 200 directory scans. The replacement
IsolationForest model trained on 330,452 CERT r4.2 user-day records now correctly scores
those sessions as ANOMALY (0.4713) well above the calibrated threshold (0.3). The new
19-feature schema is richer and better grounded. Fast-path deterministic rules add a
critical safety net that cannot be evaded by model drift. Backward-compatibility aliases
in xdr_runtime.py and the unchanged UserBehaviorAgent interface mean zero integration
breakage in backend.py. Outstanding gaps remain in the live data pipeline
(Winlogbeat, OCEAN features, missing unique_dirs fast-path column propagation in
output rows) and one score-inversion bug in backend.py's _handle_user_result that was
inherited from the OC-SVM era but now causes incorrect display scores for IsolationForest
output. Overall system health: 6.5 / 10.

---

## SECTION 1: CODE QUALITY ASSESSMENT

### 1.1 Strengths

- xdr_runtime.py is well-structured with a clean public API (run_inference returns a
  fully-typed dict); all downstream consumers rely on this contract without coupling to
  internals.
- Environment-variable overrides for MODEL_PATH, SCALER_PATH, LOG_DIR, and the two
  fast-path thresholds (XDR_FAST_PATH_FILE_OPS, XDR_FAST_PATH_DIR_SCANS) allow
  deployment-time tuning without code changes — a good operational practice.
- The two-loader pattern (try joblib_load, fallback to pickle.load) in load_pickle()
  provides graceful artifact compatibility across serialisation formats.
- normalize_events_to_features() documents the full 19-dimension feature set in its
  docstring, making the feature contract explicit for future maintainers.
- train_user_model.py uses chunked pandas reads for email.csv (200k-row chunks) to
  avoid OOM on the 2.6M-row file — a correct and necessary memory management choice.
- Threshold calibration uses a sentinel bulk-file sample rather than a fixed constant,
  ensuring the boundary adapts to the trained model's actual score distribution.
- Smoke test at end of train_user_model.py verifies both ANOMALY and NORMAL cases
  immediately after artifact save — good continuous validation pattern.
- UserBehaviorAgent uses asyncio.to_thread() correctly to offload blocking I/O without
  blocking the event loop; lifecycle (start/stop/run_once) is complete and clean.

### 1.2 Issues Found

| Severity | Component | Issue | Recommendation |
|----------|-----------|-------|----------------|
| HIGH | backend.py L595-599 | Score inversion bug: _handle_user_result applies sigmoid(-raw_score) to an anomaly_score that is ALREADY in [0,1] from xdr_runtime. This double-maps the score, inverting it for IsolationForest output: a score of 0.47 becomes 0.38 instead of 0.47. The comment still refers to OC-SVM semantics. | Remove the display_score re-mapping. Set display_score = round(raw_score, 4) since xdr_runtime now guarantees [0,1]. Also fix user_score calculation on L595: sigmoid on an already-sigmoid output is wrong; use user_score = raw_score directly when is_anomaly. |
| HIGH | xdr_runtime.py L354-355 | _build_anomaly_reason reads r.get("_fast_path_triggered") but _fast_path_triggered is set on df before the dir_scan fast-path runs (L463-468). Directory scan triggers are never marked _fast_path_triggered=True, so the reason string omits them. | After the dir_scan mask assignment, also set df.loc[dir_scan_mask, "_fast_path_triggered"] = True and extend the reason builder to include a dir-scan message. |
| MEDIUM | xdr_runtime.py L501-518 | The output rows dict does not include unique_dirs or _unique_dirs. The dir-scan fast-path fires silently with no trace in the output row, making alert investigation harder. The anomaly_reason string only reports file_ops_count. | Add "_unique_dirs": int(r.get("_unique_dirs", 0)) to the output row columns list, or at minimum surface it in the anomaly_reason via _build_anomaly_reason. |
| MEDIUM | xdr_runtime.py L261-342 | read_windows_event_logs_direct assumes record.TimeGenerated is always a datetime-like object with .year/.month etc. If pywin32 returns a pywintypes.datetime the attribute access works, but the UTC assumption (tzinfo=timezone.utc) is wrong — Windows Security log timestamps are local time on many configurations. | Use record.TimeGenerated.utctimetuple() or explicitly convert from local to UTC; or add a try/except with a fallback to datetime.utcnow() to avoid silently misclassifying after-hours events. |
| MEDIUM | train_user_model.py L273 | psych_map uses user_id as the index key but the merge joins on "user". If the psychometric CSV uses "user_id" column as a user identifier that differs from the "user" column in other tables (CERT r4.2 uses both formats across versions), all OCEAN scores will remain 0.0 at training time even when psychometric.csv is present. | Verify the join key; add a debug print showing how many users matched vs. total, and warn loudly if 0 match. |
| MEDIUM | xdr_runtime.py L265-266 | win32evtlog import is inside the function body inside a try block. This silently makes the fallback a no-op on non-Windows systems with no log or error. For cross-platform test environments, this is acceptable; for production, a log warning should be emitted. | Add logger.debug("win32evtlog unavailable: running on non-Windows") on ImportError. |
| LOW | xdr_runtime.py L175-183 | File event classification defaults ambiguous 4663 events to file_read_count. Event 4663 is a generic object access audit; it covers registry, pipes, and named objects, not only files. This inflates file_read_count under high-audit environments. | Add a path check: only count as file if TargetFilename or ObjectName ends in a known file extension or contains a backslash (indicating a filesystem path). |
| LOW | train_user_model.py L83-84 | parse_date_col and hour_of_day both call pd.to_datetime with infer_datetime_format=True, which is deprecated in pandas >= 2.0.0 and will be removed in a future release. | Remove the infer_datetime_format=True argument; pandas 2.x infers format automatically. |
| LOW | xdr_runtime.py L26-31 | load_pickle silently swallows all exceptions on the joblib path before falling back to pickle. A corrupt file would silently proceed to pickle.load and fail there with a less descriptive error. | Log a warning on the joblib exception before falling back: logger.warning(f"joblib load failed for {path}: {e}, retrying with pickle"). |
| LOW | xdr_runtime.py L417 | log_files_count uses glob("*.ndjson") but read_ndjson_logs also picks up files starting with "winlogbeat" regardless of extension. The count may differ from the actual number of files read. | Use the same filter logic: len([p for p in LOG_DIR.iterdir() if p.is_file() and (p.name.startswith("winlogbeat") or p.suffix == ".ndjson")]) for consistency. |

---

## SECTION 2: SECURITY VULNERABILITY ANALYSIS

### 2.1 Critical Vulnerabilities

None identified in this update.

### 2.2 High Severity

**[H1] Unsafe pickle deserialization — load_pickle fallback (xdr_runtime.py L29-31)**
Description: The pickle.load fallback path loads arbitrary Python objects. If the .pkl
artifact files are replaced by a malicious actor (e.g., via path traversal or
unauthorized write to the model directory), this executes arbitrary code at inference
time.
Impact: Remote code execution if model directory is writable by untrusted processes.
CWE: CWE-502 (Deserialization of Untrusted Data)
Remediation: Restrict file-system permissions on the model directory to the service
account only. Log a security warning whenever the pickle fallback is used. Consider
moving to a safer serialisation format (ONNX or safetensors) for the scaler and model.

**[H2] No integrity verification on model artifacts (train_user_model.py, xdr_runtime.py)**
Description: Neither the training script nor the runtime verifies checksums or
signatures on saved/loaded .pkl files. A compromised artifact would silently produce
wrong predictions (data poisoning via model replacement).
Impact: Silent degradation of detection capability; potential adversary-controlled
classification outcomes.
CWE: CWE-345 (Insufficient Verification of Data Authenticity)
Remediation: After saving artifacts in train_user_model.py, write SHA-256 hashes to a
manifest.json file signed with an HMAC key stored in the environment. In
xdr_runtime.py's load_pickle, verify the hash before loading.

### 2.3 Medium / Low Severity

**[M1] No rate-limiting or size cap on read_ndjson_logs (xdr_runtime.py L61-79)**
Description: All ndjson files in LOG_DIR are read entirely on every inference cycle.
A large or malformed log file (e.g., injected by a compromised endpoint agent) could
consume unbounded memory.
CWE: CWE-400 (Uncontrolled Resource Consumption)
Remediation: Add a per-file size cap (e.g., skip files > 100 MB) and a total event
cap (e.g., stop reading after 500,000 events).

**[M2] Event log injection via message field (xdr_runtime.py L147-148, 197-213)**
Description: Email and device detection uses "in msg" substring matching on the raw
message string. An attacker with the ability to write arbitrary Windows event log entries
could craft a message containing "smtp" or "usbstor" to inflate scores.
CWE: CWE-20 (Improper Input Validation)
Remediation: Prefer structured event fields (event_id, provider_name) over free-text
message parsing for classification decisions. Restrict unstructured-text matching to
supplementary heuristics.

**[L1] API key auth on /predict/user is correct but /predict/user default lookback is
30 minutes while the agent's background cycle uses 120 minutes. Callers making
on-demand requests without specifying lookback_minutes will receive a narrower window
than the agent, potentially missing anomalies in the prior hour.**
Remediation: Set the Pydantic default for PredictUserPayload.lookback_minutes = 120 to
match the agent default, or document the discrepancy clearly.

---

## SECTION 3: ARCHITECTURE GAP ANALYSIS

| Layer | Component | Status | Notes |
|-------|-----------|--------|-------|
| Network Monitoring | Suricata + Zeek + TShark | Partial | Suricata running; Zeek config present but not confirmed active; TShark endpoint agent not verified |
| Host Monitoring (HIDS) | Winlogbeat → C:\XDR_Logs\ | Partial | Process starts in backend.py but ndjson files not confirmed writing; xdr_runtime fallback to win32evtlog is active workaround |
| Log Collection | ndjson file-based pipeline | Partial | No Kafka/Fluentd; direct file reads are adequate for single-host but will not scale to multi-host deployment |
| User Behavior ML | IsolationForest (new) | Implemented | 19 features, 330K training samples, calibrated threshold; verified scores correct |
| Fast-path Rules | file_ops >= 300, unique_dirs >= 50 | Implemented | Thresholds appropriate — see Section 5 for analysis; dir-scan rule present but reason string incomplete (issue L354) |
| Network ML | IsolationForest + RandomForest classifier | Partial | IsolationForest trained; network_classifier.pkl NOT yet trained (needs CIC-IDS2017 dataset) |
| Personal Baseline | personal_baseline_model.pkl | Missing | collect_baseline.py + train_personal_model.py not run; Gate 1 of hybrid detector absent |
| System Model | LSTM Autoencoder | Missing | Not implemented |
| Malware Model | EMBER RandomForest | Missing | Not implemented |
| Fusion Engine | FusionEngineAgent | Implemented | Wired in backend.py; weights configurable via config.py |
| SHAP Explainability | shap_agent.py | Partial | Code present; TreeExplainer not wired to network_classifier.pkl because classifier not trained; user behavior has no SHAP layer |
| Response Engine | SOAR-lite command documents | Partial | Commands written to MongoDB; no endpoint agent polling loop confirmed active |
| Storage | MongoDB (Atlas M0) | Implemented | Auto-trim logic present; collection caps defined; user_behavior_cycles collection capped at 500 |
| Visualization | React SOC Dashboard | Implemented | UserBehaviorPanel wired via Socket.IO user_anomaly + user_behavior_summary events |
| OCEAN Psychometric Features | No live data source | Missing | 5 features hardcoded to 0.0 in both training and inference; reduces model discriminative power |

---

## SECTION 4: CONFLICTS AND INCOMPATIBILITIES

**[C1] Score semantics mismatch — backend.py _handle_user_result vs. xdr_runtime output**
Root cause: _handle_user_result (L595-599) contains a sigmoid re-mapping that was
written for OC-SVM where raw_score was an unbounded decision function value. The new
xdr_runtime emits anomaly_score already in [0,1] via the internal sigmoid. Applying
sigmoid(-score) to a value already in [0,1] inverts the scale: a score of 0.47
becomes 0.38, and a score of 0.05 (clearly normal) becomes 0.49 (appears nearly
anomalous on the dashboard).
Resolution: In backend.py L599, replace:
  display_score = round(1.0 / (1.0 + math.exp(min(raw_score, 500))), 4)
with:
  display_score = round(raw_score, 4)
And in L595, replace:
  user_score = 1.0 / (1.0 + math.exp(-raw_score)) if is_anomaly else 0.0
with:
  user_score = raw_score if is_anomaly else 0.0

**[C2] retrain_corrected_answers_metrics.json references a different 12-feature schema**
Root cause: An older training run produced metrics.json listing 12 features including
avg_login_hour, std_login_hour, emails_cc, which do not appear in the current
feature_columns.json (19 features). This file represents a prior model version.
Impact: None on runtime (the file is not loaded by xdr_runtime.py). Risk: a developer
reading this file could be confused about which feature set is active and attempt to
re-run an older training script that produces an incompatible artifact.
Resolution: Rename to retrain_corrected_answers_metrics_DEPRECATED_OC-SVM.json or
delete it; document in the script header that the canonical artifact is from
train_user_model.py.

**[C3] fast-path threshold constant BULK_FILE_THRESHOLD=300 in train_user_model.py vs.
env var XDR_FAST_PATH_FILE_OPS=300 in xdr_runtime.py — no shared source of truth**
Root cause: The sentinel sample during training uses the hard-coded Python constant 300.
The runtime reads an env var that defaults to 300. If the env var is overridden in
production (e.g., to 200), the model threshold was calibrated for 300 and may not catch
the new lower boundary.
Resolution: Document this coupling clearly. Optionally, store the fast-path threshold
used during calibration in model_threshold.json alongside the threshold value so that
xdr_runtime.py can warn if the env var differs from the trained boundary.

**[C4] OCEAN features: training uses psychometric.csv with scores divided by 100 for
0-1 normalization; runtime always emits 0.0 for all five OCEAN features. The scaler
was fitted on non-zero OCEAN values for users in the training set. At inference time,
injecting all-zero OCEAN values shifts the scaled feature vector away from the
training distribution, introducing a systematic bias that slightly inflates anomaly
scores for all users regardless of actual behavior.**
Resolution: Until a live OCEAN data source is available, set OCEAN columns to the
training mean during inference (store means in model_threshold.json during training)
rather than 0.0, which is out-of-distribution for the scaler.

---

## SECTION 5: NEXT STEPS AND IMPLEMENTATION ROADMAP

### Immediate Actions (0-2 weeks) — Critical fixes

1. Fix display_score inversion bug in backend.py _handle_user_result (conflict C1).
   File: D:\Cyber Sentinal\Backend\backend.py, lines 595-599.
   This is actively causing incorrect scores on the SOC dashboard for every user
   behavior event emitted since the IsolationForest model was deployed.

2. Fix _fast_path_triggered not set for directory scan hits in xdr_runtime.py.
   File: D:\Cyber Sentinal\User Behavior\final_model_backend_only\xdr_runtime.py,
   after line 468, add:
     df.loc[dir_scan_mask, "_fast_path_triggered"] = True
   and update _build_anomaly_reason to include dir-scan context.

3. Add unique_dirs to output rows so alert investigators can see the count.
   Include "_unique_dirs" in the columns list passed to .to_dict(orient="records")
   at the end of run_inference(), or surface it in anomaly_reason.

4. Deprecate retrain_corrected_answers_metrics.json (conflict C2) to prevent
   developer confusion over which feature schema is active.

### Short-term (2-6 weeks) — High priority improvements

5. Train network_classifier.pkl by acquiring CIC-IDS2017 dataset and running
   train_classifier.py. This unblocks SHAP explainability for network events.

6. Store OCEAN training means in model_threshold.json and use them as inference-time
   fill values instead of 0.0 (conflict C4). This removes the systematic
   out-of-distribution bias for all users.

7. Fix the psychometric psych_map join key (issue in train_user_model.py L273) —
   verify whether the join should use "user" or "user_id" and add a match-count
   diagnostic print.

8. Add model artifact integrity verification: SHA-256 manifest written at training time,
   verified at load time in xdr_runtime.py (vulnerability H2).

9. Confirm Winlogbeat is writing to C:\XDR_Logs\ by checking file modification times
   via the /health endpoint extension or a dedicated diagnostic script. The win32evtlog
   fallback works but bypasses Sysmon-sourced file events (event IDs 11, 23) which are
   the primary source for file_ops_count. Without Sysmon events, bulk file operations
   may only be caught by fast-path rules, not the model.

10. Fix pandas infer_datetime_format=True deprecation warnings in train_user_model.py
    (lines 79, 84) to maintain forward compatibility with pandas >= 2.0.

### Medium-term (6-12 weeks) — Architecture enhancements

11. Run collect_baseline.py and train_personal_model.py to create
    personal_baseline_model.pkl. This enables Gate 1 of the hybrid network detector
    and significantly reduces false positives on the operator's own normal traffic.

12. Add a per-file size cap and total event cap to read_ndjson_logs to prevent memory
    exhaustion from large or injected log files (vulnerability M1).

13. Implement SHAP explanations for user behavior anomalies. IsolationForest is
    compatible with TreeExplainer. This will give SOC analysts human-readable reasons
    ("high file_ops_rate", "after-hours device activity") on user alerts, matching the
    capability already present for network alerts.

14. Restrict file-system permissions on the model directory and add a logged warning
    when the pickle fallback path is taken (vulnerability H1).

15. Add a diagnostic endpoint (e.g., GET /user-behavior/health) that reports:
    log files present, last modified time, events read in last cycle, Winlogbeat
    process status, and whether the model artifacts pass hash verification.

### Long-term (3-6 months) — Advanced capabilities

16. Implement a live OCEAN data source. Options: derive proxies from behavioral patterns
    (communication breadth as Extraversion, policy violations as low Conscientiousness),
    or integrate with HR directory attributes. Without this, 5 of 19 features contribute
    nothing to model discrimination.

17. Implement System model (LSTM Autoencoder on CPU/process telemetry). This is the
    most significant remaining gap in the 4-model fusion architecture.

18. Implement Malware model (EMBER RandomForest on file hash features). Can be
    integrated with endpoint agent's file-scanning capability.

19. Evaluate multi-host log aggregation path. Current file-based ndjson pipeline does
    not scale beyond a single endpoint. For a production XDR deployment, introduce
    Kafka or a lightweight log forwarder so all endpoint logs flow through a single
    ingestion point.

20. Implement model drift detection: periodically compare the distribution of
    anomaly_score values against a baseline distribution saved at training time. Alert
    if the Kolmogorov-Smirnov statistic exceeds a threshold, indicating the live data
    has drifted from the training distribution.

---

## SECTION 6: FAST-PATH THRESHOLD ASSESSMENT

The question was raised whether 300 file ops and 50 unique dirs are appropriate thresholds.

file_ops_count >= 300:
- The CERT r4.2 dataset median for normal users is approximately 5-20 file copies per
  day (all events in that dataset are USB copies, not general file system access).
- Sysmon on a typical developer workstation may generate 200-500 file create/delete
  events per day from IDE builds, browser cache, and package managers. This means the
  threshold of 300 could produce false positives for developers running large builds.
- Recommendation: Consider raising the fast-path threshold to 500 for developer
  environments, or making it role-configurable. The model score threshold of 0.3 should
  already catch the 300-499 range if those events are genuinely anomalous in context
  (e.g., combined with after-hours activity or USB events).

_unique_dirs >= 50:
- 50 unique directories in a 2-hour window is a reasonable heuristic for directory
  traversal / ransomware scanning behavior. Normal users rarely access more than
  10-20 distinct directories in a session.
- This threshold is appropriate for a conservative IDPS. Consider lowering to 30 for
  higher sensitivity in sensitive data environments.

---

## SECTION 7: METRICS AND KPIs TO TRACK

| KPI | Target | How to Measure |
|-----|--------|----------------|
| User behavior false positive rate | < 5% of inference cycles flag normal users as ANOMALY | Count ANOMALY rows / total rows per cycle; track in user_behavior_cycles collection |
| Model detection latency | < 30 seconds from event occurrence to Socket.IO emission | Timestamp event in Winlogbeat vs. user_anomaly emit time |
| Winlogbeat lag | < 5 minutes | Compare latest @timestamp in ndjson files vs. current time; expose in /health |
| Fast-path trigger rate | Track separately from ML triggers | Add "trigger_type": "fast_path" | "ml" to event output and count in MongoDB |
| Anomaly score distribution drift | KS statistic < 0.1 vs. baseline | Compute weekly; store in a new ml_drift collection |
| OCEAN feature coverage | 0 until live source added | Count non-zero OCEAN rows per cycle |
| Average inference cycle time | < 10 seconds | Time the run_inference call in UserBehaviorAgent._tick() |

================================================================================
END OF REPORT
Next Analysis Recommended: After network_classifier.pkl training is complete, or
after Winlogbeat live log delivery is confirmed — whichever comes first.
================================================================================
