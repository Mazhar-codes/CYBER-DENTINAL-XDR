================================================================================
IDPS PROJECT ANALYSIS REPORT
================================================================================
Timestamp     : 2026-04-28 00:00:00 UTC
Analyst       : IDPS Project Analyst Agent
Scope         : Endpoint Management Layer Extension — Gap analysis for 6 additive features
                against current state of backend.py, fusion_engine.py,
                fusion_engine_agent.py, shap_agent.py, config.py,
                EndpointView.tsx, NetworkMonitor.tsx, endpoint_agent/agent.py
Project Phase : Post-SOAR Endpoint Layer (Phase 7.5 of 8)
================================================================================

## EXECUTIVE SUMMARY

All six requested endpoint management extensions are ABSENT from the current
codebase. The existing layer (endpoint_agent package, 6 API endpoints, 3
MongoDB collections, EndpointView.tsx) is a solid operational foundation, but
it has zero per-endpoint fusion, no endpoint_timelines collection, no SHAP
attachment to endpoint events, no global-vs-per-endpoint correlation split, and
no Endpoint Detail sub-view. The additive work is moderate in scope (~400 lines
of backend Python, ~350 lines of frontend TypeScript). Zero backward-compat
breaks are introduced if the implementation rules below are followed. Overall
endpoint layer readiness for the requested extensions: 2/10 (foundation only).

================================================================================

## SECTION 1: CODE QUALITY ASSESSMENT

### 1.1 Strengths — Existing Endpoint Foundation

- `endpoint_ingest()` rate-limiter, atomic upsert, and non-blocking `_analyze()`
  task pattern are clean and extensible without modification.
- `_endpoint_heartbeat_loop()` is already cancellation-safe and integrated with
  stop-monitoring lifecycle.
- `fusion_engine.py` `FusionDecisionEngine` is stateless-correlator + shared-
  buffer architecture — wrapping per-endpoint instances is straightforward.
- `FusionEngineAgent.fuse()` signature (`network_score, user_score, system_score,
  malware_score`) takes only floats; adding `endpoint_id` is a pure keyword
  addition with a default that preserves all existing call sites.
- `SHAPAgent` is fully decoupled; `explain()` and `explain_fusion()` take plain
  dicts and return plain dicts — no agent state mutation needed to attach SHAP to
  endpoint events.
- `EndpointView.tsx` receives all state via props from `NetworkMonitor.tsx`;
  adding `onSelectEndpoint` and `selectedEndpointId` props for detail navigation
  requires no structural refactor.

### 1.2 Issues Found

| Severity | Component | Issue | Recommendation |
|----------|-----------|-------|----------------|
| HIGH | `_analyze()` in `endpoint_ingest` | Heuristic-only; does NOT feed the Fusion Engine or per-endpoint correlation engine. Endpoint telemetry is a detached silo. | Wire telemetry scores from `_analyze()` into a per-endpoint `FusionDecisionEngine` instance (Item 2 below). |
| HIGH | `fusion_engine.py` module singletons | `_buffer`, `_correlator`, `_engine` are global — all endpoints share one correlation window. A port-scan from Endpoint A will correlate with a malware hit from Endpoint B. | Introduce per-endpoint `FusionDecisionEngine` instances (dict keyed by endpoint_id) alongside the existing global instance. Global instance is preserved. |
| MEDIUM | `EndpointView.tsx` | No click-through to a detail view. Endpoint cards are clickable but only toggle `highlightedId` (CSS ring). SHAP reasons and per-endpoint timelines are unreachable by the user. | Add `onSelectEndpoint(id)` prop; render `EndpointDetailView` in `NetworkMonitor.tsx` router. |
| MEDIUM | `backend.py` `_analyze()` | Does not save to any time-series collection. `endpoint_logs` is already written but there is no `endpoint_timelines` collection or timeline-indexed query path. | Add `endpoint_timelines` collection with compound index `{endpoint_id, timestamp}` for O(log n) per-endpoint timeline range queries. |
| MEDIUM | `shap_agent.py` | `explain_fusion()` exists and works for global fusion results, but is never called in the endpoint telemetry path. No SHAP explanation is attached to `endpoint_alert` Socket.IO events. | In the per-endpoint fusion path (Item 2), call `_shap_agent.explain_fusion(fe_result)` and attach the result to the `endpoint_alert` payload. `shap_agent.py` needs zero modifications. |
| LOW | `config.py` | No `server_host_id` config key. The sentinel value `"server_host"` would be hardcoded in backend.py without a config entry, making it hard to override in multi-backend deployments. | Add `server_host_id: str = _env("SERVER_HOST_ID", "server_host")` to `_Settings`. |
| LOW | `NetworkMonitor.tsx` | No `selectedEndpointId` / detail routing in `AnimatePresence` router. The `"endpoints"` branch only renders `EndpointView`; there is no nested detail state. | Add `activeEndpointId: string | null` state in `NetworkMonitor.tsx`; pass as prop; `EndpointView` calls `onSelectEndpoint` when card is double-clicked. |

================================================================================

## SECTION 2: SECURITY VULNERABILITY ANALYSIS

### 2.1 Critical Vulnerabilities
None introduced by the proposed additions themselves. The existing auth layer
(`_require_key_or_jwt`) will cover all new endpoints if the implementation
follows the existing pattern.

### 2.2 High Severity

- **Per-endpoint buffer isolation (data leakage risk)**: If a shared global
  `EventBuffer` is used for per-endpoint fusion, events from different hosts
  will cross-contaminate correlation results. CWE-200 (Information Exposure).
  Mitigation: use a `dict[str, FusionDecisionEngine]` keyed by `endpoint_id`.

- **`server_host` registry pre-seeding**: When the backend creates a synthetic
  `endpoint_registry` document for `server_host`, it will contain
  `ip_address=127.0.0.1`. If `POST /endpoint/command` validates endpoint
  existence against this document, SOAR commands (including `isolate_host`)
  can be dispatched to the server itself. The existing `endpoint_send_command`
  validation does a `find_one` on `endpoint_registry` — it will succeed for
  `server_host` from day one. Mitigation: add an `is_server` flag to the
  registry doc and block `isolate_host` / `block_ip` SOAR actions for
  `is_server=True` endpoints in `endpoint_send_command`.

### 2.3 Medium/Low Severity

- **`endpoint_timelines` without TTL index**: Without a TTL or cap, timeline
  data will grow unbounded. Add a TTL index (`expireAfterSeconds=604800`, 7
  days) or a cap entry in `_COLLECTION_CAP`. CWE-400 (Resource Exhaustion).

- **SHAP payloads in Socket.IO `endpoint_alert`**: SHAP feature vectors may
  contain file paths or process names from the host. Ensure `explain_fusion()`
  output (which only includes model weights, not raw host feature values) is
  used in endpoint alerts rather than the raw feature dict from
  `_analyze()`. The existing `explain_fusion()` method is safe by design.

================================================================================

## SECTION 3: ARCHITECTURE GAP ANALYSIS

| # | Feature | Status | Files Requiring New Code | Files Requiring Light Wiring |
|---|---------|--------|--------------------------|------------------------------|
| 1 | `server_host` special endpoint | MISSING | `backend.py` (startup upsert) | `config.py` (one setting) |
| 2 | Per-endpoint fusion wrapping | MISSING | `backend.py` (per-endpoint engine dict + `_analyze()` extension) | `agents/fusion_engine_agent.py` (no change needed) |
| 3 | `endpoint_timelines` collection | MISSING | `backend.py` (collection cap entry, index creation, write in `_analyze()`) | None |
| 4 | SHAP per-endpoint | MISSING | `backend.py` (call `_shap_agent.explain_fusion()` in `_analyze()`) | None — `shap_agent.py` unchanged |
| 5 | Multi-endpoint correlation | MISSING | `backend.py` (per-endpoint `FusionDecisionEngine` dict; global instance kept) | `fusion_engine.py` (no change) |
| 6 | Endpoint Detail View | MISSING | `EndpointDetailView.tsx` (new component) | `EndpointView.tsx` (add `onSelectEndpoint` prop), `NetworkMonitor.tsx` (add state + router branch) |

Layer-by-layer status:

| IDPS Layer | Status | Notes |
|------------|--------|-------|
| Endpoint Agent (telemetry) | IMPLEMENTED | endpoint_agent/ package complete |
| Endpoint Backend API (6 endpoints) | IMPLEMENTED | All 6 endpoints operational |
| Endpoint MongoDB (3 collections) | IMPLEMENTED | endpoint_logs, registry, commands |
| Endpoint heartbeat loop | IMPLEMENTED | 30s cadence |
| Per-endpoint fusion | MISSING | Global fusion only |
| server_host sentinel | MISSING | Server machine not self-registered |
| endpoint_timelines collection | MISSING | No time-series index path |
| SHAP attachment to endpoint alerts | MISSING | SHAP never called from `_analyze()` |
| Multi-endpoint correlation | MISSING | Single global EventBuffer |
| Endpoint Detail View (frontend) | MISSING | No sub-view component exists |

================================================================================

## SECTION 4: CONFLICTS AND INCOMPATIBILITIES

### 4.1 Per-Endpoint Fusion vs. Global Fusion — Duplicate Socket.IO Events

**Risk**: If per-endpoint fusion emits `fusion_alert` for each endpoint AND the
existing global fusion also emits `fusion_alert`, the frontend will fire the
AlertSiren for every endpoint's individual score plus the global score. This
will produce N+1 siren triggers per monitoring cycle.

**Root cause**: `backend.py` currently emits one `fusion_alert` event from the
global `_fe.ingest_event()` / `_fe.fuse()` path. Per-endpoint fusion must emit
a DIFFERENT event name: `endpoint_fusion_alert` (with `endpoint_id` field).
The global `fusion_alert` event is consumed by `NetworkMonitor.tsx` for the
siren and overview score — this must not change.

**Resolution**: Use `endpoint_fusion_alert` as the Socket.IO event name for
per-endpoint results. `NetworkMonitor.tsx` subscribes to this new event only in
the detail view state.

### 4.2 `server_host` Retroactive Log Tagging

**Risk**: The request mentions "existing logs retroactively tagged" for
`server_host`. The `endpoint_logs` collection already contains legacy documents
from `POST /ingest` (the old single-host endpoint) with `host` field but no
`endpoint_id` field. A retroactive tag via `update_many` on startup may time
out on Atlas M0 free tier if the collection has thousands of docs, and will
consume write quota.

**Resolution**: Do NOT retroactively update existing docs. Instead, during
startup, the backend should upsert a single `endpoint_registry` doc for
`server_host` and write new logs under `endpoint_id="server_host"` going
forward. Old `endpoint_logs` docs without `endpoint_id` can be queried with a
separate filter (`{"endpoint_id": {"$exists": false}}`) if historical data is
needed; no schema migration is necessary.

### 4.3 `endpoint_timelines` Index Conflict

**Risk**: If `endpoint_timelines` is added to `_COLLECTION_CAP` and then
indexed in the startup `create_index` block, the startup will fail silently
(caught by the existing try/except) if the collection does not yet exist in
Atlas. This is safe but means the index is not created on first run.

**Resolution**: The existing pattern of calling `create_index` at startup with
`background=True` handles this correctly — MongoDB creates the collection
implicitly on first insert, and the index is built in background. No special
handling needed. Just add the collection to `_COLLECTION_CAP` and the startup
index block.

### 4.4 `FusionEngineAgent.fuse()` Signature Extension

**Risk**: Adding `endpoint_id` as a parameter to `FusionEngineAgent.fuse()`
would break all existing call sites in `backend.py` that call it as
`_fusion_agent.fuse(network_score=..., user_score=..., ...)`.

**Resolution**: Do NOT modify `FusionEngineAgent.fuse()`. The per-endpoint
fusion should use `fusion_engine.FusionDecisionEngine` instances directly (one
per endpoint_id). `FusionEngineAgent` remains untouched. The request to "wrap
`fuse(endpoint_id, signals)`" should be implemented as a NEW helper function
`_endpoint_fuse(endpoint_id, network, user, system, malware)` in `backend.py`
that routes to the correct per-endpoint engine instance.

### 4.5 `EndpointDetailView` vs. Existing `EndpointView` Panel Router

**Risk**: `EndpointView.tsx` renders inside `AnimatePresence` with
`key="endpoints"`. If `EndpointDetailView` is mounted as a child inside
`EndpointView`, React's `AnimatePresence` will animate out the entire panel on
every drill-down, causing a jarring full-panel transition.

**Resolution**: Manage drill-down state in `NetworkMonitor.tsx` (not inside
`EndpointView`). When `activeEndpointId` is non-null and `activeView ===
"endpoints"`, render `EndpointDetailView` in place of `EndpointView` within the
same `AnimatePresence` slot but with `key="endpoint-detail-{activeEndpointId}"`.
This gives a smooth per-ID enter/exit animation.

================================================================================

## SECTION 5: NEXT STEPS AND IMPLEMENTATION ROADMAP

### Immediate Actions (0–2 weeks) — Backend

**Item 1: server_host self-registration (backend.py, config.py)**
- Add `server_host_id = _env("SERVER_HOST_ID", "server_host")` to `config.py`.
- In `_do_startup()` (after MongoDB indexes), upsert an `endpoint_registry` doc:
  `{"endpoint_id": settings.server_host_id, "hostname": socket.gethostname(),
   "ip_address": "127.0.0.1", "os": "Windows", "status": "online",
   "is_server": True, "last_seen": _now()}`.
- In `endpoint_send_command`: add guard — if registry doc has `is_server=True`,
  reject `isolate_host` and `block_ip` with HTTP 422.
- Estimated: ~30 lines.

**Item 3: endpoint_timelines collection (backend.py)**
- Add `"endpoint_timelines": 50_000` to `_COLLECTION_CAP`.
- In startup index block: `create_index([("endpoint_id", ASCENDING),
  ("timestamp", DESCENDING)], background=True)` on `endpoint_timelines`.
  Optionally add TTL: `create_index("timestamp", expireAfterSeconds=604800)`.
- In `endpoint_ingest()`, after `_save("endpoint_logs", log_doc)`, call
  `_save("endpoint_timelines", {"endpoint_id": ep.endpoint_id,
   "timestamp": now_iso, "cpu": cpu_val, "memory": mem_val,
   "connections": len(network.get("connections", [])),
   "suspicious_ports": len(suspicious_ports)})`.
- Estimated: ~20 lines.

### Short-term (2–6 weeks) — Backend

**Item 2 + 5: Per-endpoint fusion + multi-endpoint correlation (backend.py)**
- Add module-level dict: `_endpoint_engines: dict[str, FusionDecisionEngine] = {}`.
- Add helper `_get_endpoint_engine(endpoint_id: str) -> FusionDecisionEngine` that
  creates a new `FusionDecisionEngine(EventBuffer(), CorrelationEngine())` on first
  call and caches it. This gives each endpoint its own 5-minute sliding window.
- The global `_fe` instance is preserved and continues to receive ALL events (for
  global cross-endpoint correlation).
- Extend `_analyze()` in `endpoint_ingest()`:
  - Compute lightweight scores from telemetry (cpu/mem/suspicious_files/ports).
  - Call `_get_endpoint_engine(ep.endpoint_id).ingest_event({...})`.
  - If result `final_decision.severity` in HIGH/CRITICAL, emit
    `endpoint_fusion_alert` Socket.IO event (NOT `fusion_alert`) with `endpoint_id`.
- Estimated: ~80 lines.

**Item 4: SHAP per-endpoint (backend.py)**
- After per-endpoint `FusionDecisionEngine.ingest_event()` returns a result, call
  `_shap_agent.explain_fusion(result["final_decision"])` (already exists in
  `shap_agent.py` — zero modifications needed).
- Attach `shap_explanation` key to the `endpoint_fusion_alert` Socket.IO event
  and persist it to `shap_explanations` collection with `endpoint_id` field.
- Estimated: ~15 lines.

### Medium-term (6–12 weeks) — Frontend

**Item 6: Endpoint Detail View (new EndpointDetailView.tsx)**

Component structure:
```
EndpointDetailView
  props: endpoint: EndpointInfo, alerts: EndpointAlert[], 
         commandResults: CommandResult[], onBack: () => void,
         onSendCommand: (cmd: EndpointCommand) => void
  panels:
    1. Header bar: hostname, status dot, back button, last-seen
    2. Timeline panel: sparkline of CPU/MEM from endpoint_timelines
       — REST GET /endpoint/timeline/{endpoint_id}?minutes=60
       — No Socket.IO polling needed; fetch on mount + 30s interval
    3. Per-endpoint alerts table (filtered endpointAlerts by endpoint_id)
       with SHAP reasons column (from endpoint_fusion_alert events)
    4. SOAR Response Panel (reuse logic from EndpointView Section 3;
       pre-selected endpoint; same ACTIONS list)
```

`NetworkMonitor.tsx` changes:
- Add `activeEndpointId: string | null` state (init null).
- Subscribe to `endpoint_fusion_alert` Socket.IO event; store in
  `endpointFusionAlerts: EndpointFusionAlert[]` state (keyed by endpoint_id).
- In view router `"endpoints"` branch: if `activeEndpointId` is non-null render
  `EndpointDetailView`; else render `EndpointView` with
  `onSelectEndpoint={(id) => setActiveEndpointId(id)}` prop.
- Estimated: ~350 lines (new component + wiring).

**New backend endpoint for timeline data**:
- `GET /endpoint/timeline/{endpoint_id}?minutes=60` — query
  `endpoint_timelines` for the last N minutes; return list of
  `{timestamp, cpu, memory, connections, suspicious_ports}` sorted ascending.
- Auth: `_require_key_or_jwt`.
- Estimated: ~30 lines.

### Long-term (3–6 months) — Architecture Enhancements

- **Endpoint ML integration**: Feed `endpoint_logs` system/network telemetry
  through the existing `SystemMonitorAgent` and `NetworkDetectionAgent` per
  endpoint (currently they only run on the server host). This closes the gap
  between "lightweight heuristic analysis" and full ML scoring.
- **Per-endpoint SHAP for system LSTM**: Once `system_model.pt` is retrained
  (known outstanding bug), extend `shap_agent.py` to support the autoencoder
  and wire it into the per-endpoint fusion path.
- **Endpoint agent Windows Service**: Package `endpoint_agent/` with NSSM or
  a `pywin32 servicemanager` wrapper for production persistence.
- **mTLS agent-backend channel**: Add TLS certificate pinning between
  `endpoint_agent/sender.py` and the backend to close the plaintext API key
  exposure (known outstanding issue per CLAUDE.md).

================================================================================

## SECTION 6: METRICS AND KPIs TO TRACK

| Metric | Target | Measurement Point |
|--------|--------|------------------|
| Per-endpoint fusion latency | < 50 ms from ingest to Socket.IO emit | Timestamp delta in `endpoint_fusion_alert` events |
| endpoint_timelines write success rate | > 99% | MongoDB write error counter in backend logs |
| SHAP explanation availability per endpoint alert | > 90% | Ratio of `endpoint_fusion_alert` events with non-empty `shap_explanation` |
| Global vs. per-endpoint correlation false positive rate | Monitor for divergence | Compare `fusion_alert` severity vs. `endpoint_fusion_alert` severity histograms |
| endpoint_timelines collection size | < 50k docs (cap) | Atlas collection stats |
| server_host online status continuity | 100% during monitoring | `endpoint_registry.status` for `endpoint_id="server_host"` |
| Endpoint Detail View load time (timeline panel) | < 500 ms | Browser performance timeline on `GET /endpoint/timeline/{id}` |

================================================================================
END OF REPORT
Files analyzed:
  D:\Cyber Sentinal\Backend\backend.py
  D:\Cyber Sentinal\Backend\agents\fusion_engine_agent.py
  D:\Cyber Sentinal\Backend\agents\shap_agent.py
  D:\Cyber Sentinal\Backend\fusion_engine.py
  D:\Cyber Sentinal\Backend\config.py
  D:\Cyber Sentinal\Cyber Sentinal XDR Frontend\src\components\views\EndpointView.tsx
  D:\Cyber Sentinal\Cyber Sentinal XDR Frontend\src\components\NetworkMonitor.tsx
  D:\Cyber Sentinal\endpoint_agent\agent.py

Next Analysis Recommended: After per-endpoint fusion (Items 2+5) and
  EndpointDetailView (Item 6) are implemented — verify no fusion event
  duplication and confirm SHAP payloads reach the frontend correctly.
================================================================================
