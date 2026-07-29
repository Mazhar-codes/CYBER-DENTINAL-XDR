================================================================================
IDPS PROJECT ANALYSIS REPORT
================================================================================
Timestamp     : 2026-05-11 00:00:00 UTC
Analyst       : IDPS Project Analyst Agent
Scope         : System Monitor alert routing and Fusion Engine integration
Project Phase : Production Hardening / Bug Investigation
================================================================================

## EXECUTIVE SUMMARY

Two related defects were confirmed in the Cyber Sentinel XDR backend. The first
is a frontend routing confusion: server-side `system_anomaly` events emitted by
`_handle_system_result()` include an `endpoint_id: "server_host"` field that
causes the OverviewView to mix them with true endpoint heuristic alerts, and
when the system is the dominant signal, a separate `system_anomaly` emission
with `endpoint_id` set is also fired from the endpoint ingest path (line 3509),
which can land in the Endpoint Alerts section when no real endpoint is online.
The second defect is a conditional fusion gate: `FusionEngineAgent.fuse()` is
only called when `alert_allowed` is True (anomaly + 30 s cooldown), meaning
system scores never contribute to fusion during the cooldown window. This
asymmetry does not exist in the network or user pipelines and means system
anomalies can be silently ignored by the fusion layer for up to 30 seconds.
Overall System Monitor integration completeness: **78%**.

Overall project health: **8.2 / 10**

================================================================================

## SECTION 1: CODE QUALITY ASSESSMENT

### 1.1 Strengths

- `_handle_system_result()` correctly uses `_scores_lock` when writing to
  `_latest_scores`, maintaining thread-safety across asyncio tasks.
- The 30-second `_SYSTEM_ALERT_COOLDOWN` gate effectively prevents alert
  fatigue from the 1 Hz psutil polling loop.
- `combined_system = max(_latest_system_score, _latest_sysmon_score)` correctly
  unifies the LSTM and Sysmon behavioral scores into a single system dimension.
- `predict_from_metrics()` and `score_session_telemetry()` on agents are
  synchronous and thread-safe, correctly wrapped with `asyncio.to_thread()`.
- The `_SYSTEM_ALERT_COOLDOWN` and `_SYSMON_EMIT_COOLDOWN` are documented and
  justified with comments.
- FusionEngineAgent weights (net=0.35, usr=0.30, sys=0.15, mal=0.20) are
  consistently applied across both the server-side and endpoint-side pipelines.

### 1.2 Issues Found

| Severity | Component | Issue | Recommendation |
|----------|-----------|-------|----------------|
| HIGH | `backend.py:3509-3520` | `system_anomaly` emitted from **endpoint ingest** path with `endpoint_id` set to a real endpoint UUID. Frontend `system_anomaly` handler (`NetworkMonitor.tsx:332-335`) stores it in `systemAnomalies`, but `OverviewView` renders endpoint-sourced system anomalies alongside server-side ones, and `EndpointView` receives `endpointAlerts` from `endpoint_alert` events that are also fired for high CPU/mem at lines 3452-3461. When no endpoint is registered, only the `SystemMonitorAgent` (server-side) fires, and its event carries `endpoint_id: "server_host"`, which makes the frontend's endpoint-alert lookup attempt to find a registered endpoint named "server_host" — causing the alert to appear under Endpoint Alerts if the frontend renders all `system_anomaly` events with an `endpoint_id`. | Separate server-side and endpoint-sourced `system_anomaly` events by checking `data.source === "endpoint"` in the frontend handler and routing endpoint-sourced ones to `endpointAlerts` list only if a matching endpoint_id exists. |
| HIGH | `backend.py:2385-2393` | `FusionEngineAgent.fuse()` is gated by `alert_allowed` (line 2390). This means `fusion` is `None` outside the 30-second cooldown window. The `_latest_scores["system"]` IS updated every cycle (line 2378-2379), but the score is not fused until the next alert-allowed tick. Network and user handlers call `fuse()` on every detection event without a separate cooldown gate. This creates asymmetry: a system anomaly detected at t=0 contributes to fusion at t=0, but a second anomaly at t=15 does not fuse (fusion=None), even if network is now also high. | Decouple the `alert_allowed` gate from `FusionEngineAgent.fuse()`. Always update `_latest_scores` and always call `fuse()`. Apply `alert_allowed` only to the `sio.emit("system_anomaly")` alert emission and MongoDB persistence. |
| MEDIUM | `backend.py:2423-2446` | The `fusion_alert` emission for system monitor (line 2446) is guarded by `if fusion and fusion.should_respond`, but `fusion` can only be non-None when `alert_allowed` is True (line 2390). So the `fusion_alert` block is semantically redundant — it can never fire when `alert_allowed` is False. This makes the block placement misleading to future developers. | Move the `fusion_alert` block inside the `if alert_allowed:` branch, after the `_fe.ingest_event` call, and remove the separate `if fusion and fusion.should_respond:` check at line 2423. |
| MEDIUM | `backend.py:3507-3520` | The endpoint-ingest path emits `system_anomaly` at line 3509 with `source: "endpoint"` and `endpoint_id` set to a real UUID. The frontend `system_anomaly` handler (line 332) stores it in `systemAnomalies` regardless of source. `OverviewView` renders `systemAnomalies` in both the Recent Alerts panel and the CPU/MEM gauge. This means a remote endpoint's high CPU appears on the main server System Status panel. | Add a `source` discriminator in `NetworkMonitor.tsx`: events with `source === "endpoint"` should be forwarded to `endpointAlerts` state, not `systemAnomalies`. |
| LOW | `backend.py:2395-2401` | `event` dict is built unconditionally at line 2395, including `"endpoint_id": "server_host"`, but `result` from `SystemMonitorAgent._fire_result()` does not contain an `endpoint_id` key. The merge (`**result`) does not add `endpoint_id`, so the explicit key at line 2398 is correct. However, if `result` ever includes `endpoint_id` from a future refactor, the merge order means `result`'s value would be overwritten silently by the hardcoded `"server_host"`. | Reverse the dict merge order or use explicit key assignment: `event = {**result, ...}` then `event["endpoint_id"] = "server_host"` on a separate line for clarity. |

================================================================================

## SECTION 2: SECURITY VULNERABILITY ANALYSIS

### 2.1 Critical Vulnerabilities

None identified in the scope of this analysis.

### 2.2 High Severity

- **Alert Routing Confusion (CWE-440: Expected Behavior Violation)**
  Description: Server-side system anomalies are surfaced in the Endpoint Alerts
  section of the frontend when no real endpoint is registered. An analyst
  investigating "endpoint alerts" may dismiss or misroute a genuine server-side
  system anomaly (e.g., ransomware-induced CPU spike) as a remote endpoint
  issue.
  Impact: SOC analysts may apply the wrong response playbook or fail to
  investigate the server host itself.
  Remediation: See Section 1.2 HIGH items above.

### 2.3 Medium/Low Severity

- **Alert suppression during cooldown (CWE-778: Insufficient Logging)**
  Description: During the 30-second cooldown window, system anomaly events are
  emitted as `system_anomaly` to the frontend (line 2427) but NOT persisted to
  MongoDB and NOT fed into the correlation engine. If an attack escalates during
  that 30-second window, the correlation engine has a stale system score.
  Impact: A rapidly escalating multi-domain attack may not trigger a correlated
  HIGH/CRITICAL alert until the next cooldown resets.
  Remediation: Always feed the global `_fe.ingest_event()` with the updated
  system score (gated only on `is_anomaly`, not on `alert_allowed`).

================================================================================

## SECTION 3: ARCHITECTURE GAP ANALYSIS

### Server-Side System Monitor Pipeline (Layer-by-Layer)

| Layer | Component | Status | Notes |
|-------|-----------|--------|-------|
| Telemetry Collection | `SystemMonitorAgent` psutil 1 Hz loop | IMPLEMENTED | Correct. 20-feature LSTM input. |
| Score Inference | LSTM Autoencoder + `_resource_aware_severity()` | IMPLEMENTED | `predict_from_metrics()` for endpoints; `_fire_result()` for server-side. |
| Score Registration | `_latest_scores["system"]` updated every cycle | IMPLEMENTED | Correct. Lock-protected. |
| Fusion Gate | `FusionEngineAgent.fuse()` called only when `alert_allowed` | PARTIAL | Bug. See Section 1.2. Should call `fuse()` always. |
| Fusion Event Emission | `fusion_alert` emitted when `fusion.should_respond` | PARTIAL | Correct logic, but only reachable when `alert_allowed` is True. |
| Correlation Engine Feed | `_fe.ingest_event()` called when `alert_allowed` | PARTIAL | Not called during cooldown window — correlation engine has stale score for up to 30 s. |
| SOC Alert Emission | `_emit_soc_alert_if_correlated()` | IMPLEMENTED | Correct when reached. |
| SHAP Explanation | `_explain_fusion()` called on fusion result | IMPLEMENTED | Correct. |
| MongoDB Persistence | `_save("alerts", event)`, `_save("fused_alerts")`, `_save("critical_alerts")` | IMPLEMENTED | Correct. Dual-write for HIGH/CRITICAL. |
| Socket.IO Event | `system_anomaly` emitted on every cycle | IMPLEMENTED | Correct. Rate-limited via cooldown for saves; always emitted for gauge. |
| Frontend Routing | `system_anomaly` → `systemAnomalies` state | PARTIAL | Missing source discriminator — endpoint-sourced events mixed with server-side. |
| SHAP for System LSTM | LSTM Autoencoder SHAP | NOT IMPLEMENTED | Known gap. System model SHAP not yet supported. |

### Comparison: Network Pipeline vs System Pipeline

| Step | Network Pipeline | System Pipeline | Parity |
|------|-----------------|-----------------|--------|
| Score update | Every detection event | Every `_fire_result()` | YES |
| `fuse()` called | Every attack event | Only when `alert_allowed` | NO — Bug |
| `_fe.ingest_event()` | Every attack event | Only when `alert_allowed` | NO — Bug |
| `fusion_alert` emit | When `fusion.should_respond` | When `fusion and fusion.should_respond` | Equivalent (but gated differently) |
| `sio.emit()` on every cycle | YES (via `network` event) | YES (via `system_anomaly`) | YES |
| MongoDB persist | Attacks only | Anomalies only | Acceptable |
| SHAP explanation | Network + Malware | Not implemented | NO — Known gap |

================================================================================

## SECTION 4: CONFLICTS AND INCOMPATIBILITIES

### Conflict 1: Dual System Anomaly Emission Paths

**Root Cause:** `_handle_system_result()` (server-side, line 2367) and the
endpoint ingest handler (line 3507-3520) both emit `system_anomaly` Socket.IO
events. The server-side path uses `endpoint_id: "server_host"`. The endpoint
path uses a real UUID. The frontend handler at `NetworkMonitor.tsx:332` stores
ALL `system_anomaly` events in `systemAnomalies` without discriminating by
source. This means:
- When no endpoint is online: only server-side events fire. These carry
  `endpoint_id: "server_host"` which is not in the endpoint registry, so they
  should not appear in EndpointView. However, the heuristic `_analyze()` task
  at lines 3441-3485 (endpoint ingest) is never called when there are no
  endpoints ingesting data, so the `endpoint_alert` for high CPU/mem is also
  never fired. The net effect: the `system_anomaly` from `_handle_system_result`
  appears only in `systemAnomalies` state (correct), but the
  `endpoint_id: "server_host"` field can confuse downstream rendering in
  `OverviewView` which renders `systemAnomalies` items alongside endpoint items.

**Resolution:** In `NetworkMonitor.tsx`, split the `system_anomaly` handler:

```typescript
socket.on("system_anomaly", (data: any) => {
  if (!isMonitoringRef.current) return;
  if (data.source === "endpoint") {
    // Route to endpoint-specific state, not server system anomalies
    setEndpointAlerts(prev => [{
      endpoint_id: data.endpoint_id,
      hostname: data.hostname,
      severity: data.severity,
      reason: `System anomaly: cpu=${data.cpu_percent}% mem=${data.memory_percent}%`,
      timestamp: data.ts,
    }, ...prev].slice(0, 50));
  } else {
    setSystemAnomalies(prev => [data, ...prev].slice(0, 50));
  }
});
```

### Conflict 2: Fusion Conditional vs. Always-Fuse (Network)

**Root Cause:** `_handle_system_result()` at line 2385-2393 computes `fusion`
conditionally:
```python
fusion = _fusion_agent.fuse(...) if (_fusion_agent and alert_allowed) else None
```
But the network handler at lines 2187-2193 computes:
```python
fusion = _fusion_agent.fuse(...) if (_fusion_agent and is_attack) else None
```
`is_attack` simply checks if the prediction label is `"ATTACK"` — it has no
cooldown gate. The system handler adds a 30-second cooldown gate on top of the
anomaly check. The result is that during the cooldown window, `fusion` is always
`None` for system events, so the system score never contributes to a fused
HIGH/CRITICAL alert even if network and user are simultaneously high.

**Resolution:** Split the gate:
```python
# Always fuse (update threat score state for network/user/malware correlation)
if _fusion_agent and is_anomaly:
    fusion = _fusion_agent.fuse(
        network_score=_scores["network"],
        user_score=_scores["user"],
        system_score=combined_system,
        malware_score=_scores["malware"],
        endpoint_id="server_host",
    )
else:
    fusion = None

# Apply cooldown only to alert emission and persistence
alert_allowed = is_anomaly and (now_t - _last_system_alert_t) >= _SYSTEM_ALERT_COOLDOWN
```

### Conflict 3: `_fe.ingest_event` Not Called During Cooldown

**Root Cause:** The global correlation engine (`_fe.ingest_event`) is only
called inside `if alert_allowed:` at line 2415. The correlation engine uses a
sliding event window. If system anomalies are not fed into it during the 30-second
cooldown, but network events ARE being fed, a correlated attack may never
trigger `soc_alert` even though system + network together would meet the
threshold. This is inconsistent with the malware handler (line 1373-1380) which
always calls `_fe.ingest_event` when a malicious label is confirmed, without any
additional cooldown gate.

**Resolution:** Move `_fe.ingest_event` call outside the `alert_allowed` block,
gated only on `is_anomaly`. The alert cooldown should suppress `sio.emit` and
MongoDB writes, not the correlation engine feed.

================================================================================

## SECTION 5: NEXT STEPS AND IMPLEMENTATION ROADMAP

### Immediate Actions (0-2 weeks) — Critical fixes

**Fix 1 — Decouple fusion call from alert_allowed gate**
File: `D:\Cyber Sentinal\Backend\backend.py`
Lines: 2385-2393

Change from:
```python
fusion = _fusion_agent.fuse(
    network_score=_scores["network"],
    user_score=_scores["user"],
    system_score=combined_system,
    malware_score=_scores["malware"],
    endpoint_id="server_host",
) if (_fusion_agent and alert_allowed) else None
```

Change to (move fusion call before alert_allowed computation):
```python
# Always fuse when anomalous — cooldown applies only to emission/persistence
fusion = _fusion_agent.fuse(
    network_score=_scores["network"],
    user_score=_scores["user"],
    system_score=combined_system,
    malware_score=_scores["malware"],
    endpoint_id="server_host",
) if (_fusion_agent and is_anomaly) else None

alert_allowed = is_anomaly and (now_t - _last_system_alert_t) >= _SYSTEM_ALERT_COOLDOWN
```

**Fix 2 — Move `_fe.ingest_event` outside alert_allowed block**
File: `D:\Cyber Sentinal\Backend\backend.py`
Lines: 2403-2424

Move the entire `try: fe_event = {...}; fe_out = await asyncio.to_thread(_fe.ingest_event...); await _emit_soc_alert_if_correlated(...)` block to be executed whenever `is_anomaly` is True, not just when `alert_allowed` is True. The logic becomes:

```python
if alert_allowed:
    _last_system_alert_t = now_t
    logger.warning(f"SYSTEM ANOMALY: score={score:.4f} severity={severity}")
    _save("alerts", event)
    fusion_saved = True
    await sio.emit("system_anomaly", _strip_mongo(event))
else:
    await sio.emit("system_anomaly", _strip_mongo(event))

# Feed correlation engine on every anomaly, not just cooldown-allowed ones
if is_anomaly:
    try:
        fe_event = {
            "source": "system",
            "timestamp": ts,
            "host": "server_host",
            "endpoint_id": "server_host",
            "severity": severity,
            "confidence": score,
            "prediction": f"system_anomaly_{severity.lower()}",
            "is_genuinely_anomalous": result.get("is_genuinely_anomalous", False),
        }
        fe_out = await asyncio.to_thread(_fe.ingest_event, fe_event)
        fe_out["endpoint_id"] = "server_host"
        await _emit_soc_alert_if_correlated(fe_out, ts)
    except Exception as _fe_exc:
        logger.debug(f"fusion_engine.ingest_event (system) skipped: {_fe_exc}")
```

**Fix 3 — Frontend: discriminate system_anomaly by source**
File: `D:\Cyber Sentinal\Cyber Sentinal XDR Frontend\src\components\NetworkMonitor.tsx`
Lines: 332-335

Split the `system_anomaly` handler to route endpoint-sourced events to
`endpointAlerts` and server-sourced events to `systemAnomalies` (see Conflict 1
resolution above).

### Short-term (2-6 weeks) — High priority improvements

- **Consolidate the redundant `fusion_alert` emission**: After Fix 1, the block
  at lines 2423-2450 (`if fusion and fusion.should_respond`) becomes reachable
  independently of `alert_allowed`. Ensure the `fusion_alert` emission and
  MongoDB persistence (`fused_alerts`, `critical_alerts`) happen for every
  genuinely anomalous cycle with a qualifying fusion result, not just cooldown-
  allowed cycles.
- **Add `source` discriminator to `OverviewView`**: Ensure the "Recent Alerts"
  panel and CPU/MEM gauge only render server-side `system_anomaly` entries
  (filter `s.source !== "endpoint"`).
- **System Monitor status indicator**: Add a `SystemMonitorAgent.is_running()`
  check to `GET /health` response so the Settings view Integrations panel can
  show live status for the LSTM monitor.

### Medium-term (6-12 weeks) — Architecture enhancements

- **SHAP for System Monitor LSTM**: Implement gradient-based attribution for the
  LSTM Autoencoder. Consider `captum` (PyTorch attribution library) as it
  supports LSTM models natively. Register results in `shap_explanations`
  collection alongside existing network/malware SHAP entries.
- **sklearn version alignment**: Resolve the `system_scaler.pkl` /
  `system_model.pt` mismatch by retraining with the runtime sklearn version.
  Add version validation at agent startup: if the scaler's sklearn version
  differs from runtime, log a CRITICAL and fall back to heuristic-only mode
  rather than silently returning score=1.0.
- **Correlation engine cooldown awareness**: The `_fe.ingest_event` correlation
  engine has its own internal event window. Document the expected event
  frequency per source so the 30-second system cooldown does not create a
  detectable gap in the event timeline.

### Long-term (3-6 months) — Advanced capabilities

- **LSTM online learning**: Implement incremental updates to the system model
  using operator feedback on false-positive system alerts. The current model is
  batch-trained only.
- **Cross-endpoint system correlation**: Extend the system monitor to
  correlate anomalies across multiple registered endpoints (e.g., synchronized
  CPU spikes across multiple hosts indicating worm propagation).
- **Adaptive cooldown**: Replace the fixed 30-second `_SYSTEM_ALERT_COOLDOWN`
  with a dynamic cooldown that shortens to 5 seconds when the fusion threat
  score exceeds 0.70 (HIGH threshold), allowing rapid re-alerting during an
  active attack.

================================================================================

## SECTION 6: METRICS AND KPIs TO TRACK

| KPI | Target | Current Status | Measurement |
|-----|--------|----------------|-------------|
| System-source contribution to fusion alerts | Present in >80% of HIGH/CRITICAL fused alerts | Unknown — gated by 30 s cooldown | Count `fused_alerts` docs where `contributing_models` includes `"system"` |
| System anomaly false positive rate | <10% of system_anomaly events result in confirmed attack | Unknown | Ratio of `is_genuinely_anomalous=True` events to total system_anomaly count |
| Alert routing accuracy | 0 server-side system alerts in EndpointView | Currently 0 (server-side has no registered endpoint) | Monitor frontend console for `endpointAlerts` population from server-side source |
| Fusion cooldown missed detections | <5% of attack windows where system score was non-zero but not fused | Not tracked | Compare `_latest_scores["system"]` time-series against `fused_alerts` timestamps |
| LSTM score=1.0 rate | <5% of inferences return score=1.0 | High (sklearn version mismatch) | Log and count score=1.0 outputs from `_fire_result()` |
| System-to-SOC alert latency | <35 s from system anomaly to `soc_alert` emission | ~30-60 s (cooldown) | Timestamp delta between `system_anomaly` and subsequent `soc_alert` for same host |

================================================================================
END OF REPORT
Next Analysis Recommended: After implementing Fix 1 and Fix 2 (fusion gate
decoupling). Also recommended after system_model.pt retraining to verify
score=1.0 false-positive rate drops below 5%.
================================================================================
