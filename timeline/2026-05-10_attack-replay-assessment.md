================================================================================
IDPS PROJECT ANALYSIS REPORT
================================================================================
Timestamp     : 2026-05-10 23:50:43 UTC
Analyst       : IDPS Project Analyst Agent
Scope         : Attack Reconstruction / Replay Feature + Tiered Storage Assessment
Project Phase : Feature Expansion — Post-Core-Platform (Cyber Sentinel XDR v1.0)
================================================================================

## EXECUTIVE SUMMARY

Cyber Sentinel XDR already possesses a substantial scaffold for attack reconstruction
that is not yet surfaced as a unified SOC workflow. The attack graph engine, endpoint
timeline collection, SHAP explanations, response plans, and PDF incident reports are
all independently functional — but they are siloed across five different views with no
single "replay mode" tying them together. The desired Attack Reconstruction feature
requires approximately 30% new backend work and 70% new frontend work; no existing
system needs to be torn out or replaced. The tiered storage / retention policy is
entirely absent from the codebase. Overall readiness for this feature: 4/10 (strong
foundation, missing the connective tissue and the storage tier).

================================================================================

## SECTION 1: WHAT IS ALREADY BUILT
(File references are absolute paths)

### 1.1 Backend Infrastructure

| Component | Status | File | Notes |
|-----------|--------|------|-------|
| Endpoint telemetry time-series | BUILT | Backend/backend.py:3500-3510 | Writes cpu/mem/connections/threat_score/severity to `endpoint_timelines` (50k cap) every ingest cycle |
| `/endpoint/timeline/{id}` REST endpoint | BUILT | Backend/backend.py:3834-3855 | Returns up to 500 sorted entries; used by EndpointDetailView sparkline |
| `/attack-graph/timeline` REST endpoint | BUILT | Backend/backend.py:4333-4342 | Returns node/edge creation events sorted by timestamp; `hours` param (max 168) |
| `/attack-graph/snapshot` REST endpoint | BUILT | Backend/backend.py:4321-4330 | Returns all graph nodes+edges active in last N hours |
| AttackGraphEngine — node/edge upsert | BUILT | Backend/attack_graph.py:16-200 | process_network_anomaly, process_fusion_alert, process_malware_alert, process_user_anomaly, process_endpoint_telemetry all feed the graph |
| `attack_graph_nodes` + `attack_graph_edges` MongoDB collections | BUILT | Backend/backend.py:121-122 | 5k/10k caps; compound indexes on node_id, endpoint_id, timestamp |
| `fused_alerts` collection | BUILT | Backend/backend.py:99 | 1k cap; stores threat_score, severity, attack_type, contributing_models, contributing_reasons, source, endpoint_id, ts |
| `shap_explanations` collection | BUILT | Backend/backend.py:93 | 1k cap; tagged with endpoint_id + alert_ts since 2026-05-03 |
| `response_plans` collection | BUILT | Backend/backend.py:118 | 2k cap; stores plan_id, endpoint_id, severity, attack_type, mitre_technique, recommended_actions, shap_explanation |
| PDF incident report generator | BUILT | Backend/report_generator.py | 5-section ReportLab PDF: header, incident summary, attack timeline (sorted contributing signals), SHAP table, response actions, final status |
| `incident_reports` MongoDB metadata | BUILT | Backend/backend.py | incident_id, plan_id, endpoint_id, severity, attack_type, pdf_path, generated_by, generated_at |
| `endpoint_commands` history | BUILT | Backend/backend.py:116 | 2k cap; action, target, status (pending/sent/completed/failed), created_at |
| Sysmon event reader (file-tail) | BUILT | Backend/sysmon_winevent_reader.py | Tails C:\winlogbeat\logs\sysmon_events.json; feeds SysmonBehaviorAgent |
| `case_notes` MongoDB collection + endpoints | BUILT | Backend/backend.py:892-900, 4967-5092 | Analyst notes per endpoint; GET/POST/DELETE; indexed on endpoint_id + created_at |

### 1.2 Frontend Infrastructure

| Component | Status | File | Notes |
|-----------|--------|------|-------|
| AttackGraphView with replay controls | BUILT | Cyber Sentinal XDR Frontend/src/components/views/AttackGraphView/AttackGraphView.tsx | replayStep state; auto-ticker at 900ms; REPLAY / PAUSE / step buttons; scrubber |
| GraphControls — scrubber bar | BUILT | Cyber Sentinal XDR Frontend/src/components/views/AttackGraphView/GraphControls.tsx | Tick-based progress bar; keyboard accessible; step-forward button |
| NodeDetailPanel — SHAP / Timeline / Response tabs | BUILT | Cyber Sentinal XDR Frontend/src/components/views/AttackGraphView/NodeDetailPanel.tsx | 3-tab panel: SHAP bar chart, Timeline events list (per-node), Suggested Responses |
| RecentEvents list | BUILT | Cyber Sentinal XDR Frontend/src/components/views/AttackGraphView/RecentEvents.tsx | Shows last N TIMELINE entries from GraphData |
| GraphData.TIMELINE type | BUILT | Cyber Sentinal XDR Frontend/src/components/views/AttackGraphView/types.ts:68-76 | {ts, src, dst, action, severity, nodeId} |
| EndpointDetailView — threat sparkline | BUILT | Cyber Sentinal XDR Frontend/src/components/views/EndpointDetailView.tsx:232-276 | Fetches /endpoint/timeline; renders SVG sparkline; "THREAT TIMELINE" panel |
| AttackGraph force-graph | BUILT | Cyber Sentinal XDR Frontend/src/components/views/AttackGraphView/AttackGraph.tsx | D3 force simulation; lit edges per replayStep; malicious/chain edge highlighting |
| ResponseModal — SHAP + action checklist | BUILT | Cyber Sentinal XDR Frontend/src/components/ResponseModal.tsx | Full-screen modal; SHAP bar chart; role-gated execute; per-action status; PDF download |
| Network Flow Timeline chart (ECharts) | BUILT | Cyber Sentinal XDR Frontend/src/components/views/NetworkView.tsx:92-218 | Area chart: attacks vs normal over time |
| `useAttackGraphData` hook — live TIMELINE feed | BUILT | Cyber Sentinal XDR Frontend/src/components/views/AttackGraphView/useAttackGraphData.ts:314-325 | Appends incoming events to TIMELINE state |
| case_notes panel in ProfileView | BUILT | Cyber Sentinal XDR Frontend/src/components/views/ProfileView/ | Analyst case notes per endpoint |

### 1.3 Key Data Already Available for Replay

The following fields exist in MongoDB and can be fetched without new backend work:

- `fused_alerts`: threat_score, severity, attack_type, components (per-model scores +
  weights + contributions), contributing_models, contributing_reasons, endpoint_id, ts
- `shap_explanations`: feature importance list, endpoint_id, alert_ts
- `response_plans`: plan_id, mitre_technique, recommended_actions, severity, attack_type
- `attack_graph_nodes`: risk_score, severity, type, label, metadata, timestamp
- `attack_graph_edges`: source, target, relation, metadata.severity, timestamp (chain
  ordering implicit via timestamp)
- `endpoint_timelines`: cpu, memory, connections, threat_score, severity per timestamp
- `endpoint_commands`: action, target, status, created_at (SOAR execution trail)

================================================================================

## SECTION 2: WHAT IS NOT YET IMPLEMENTED

### Priority: HIGH (Blockers for the feature)

| # | Missing Component | Gap Description |
|---|-------------------|-----------------|
| H1 | Unified Incident Replay API endpoint | No single endpoint that bundles fused_alerts + shap + response_plan + endpoint_timeline + attack_graph events into one time-sorted incident package. Frontend must make 5+ separate calls and correlate by timestamp itself. |
| H2 | Attack Timeline Replay UI | No dedicated view/component that renders an animated step-by-step event log ("00:01 PowerShell launched → 00:02 DLL injected → …"). AttackGraphView's replay is graph-edge-step-based only; it has no textual event log linked to real event timestamps. |
| H3 | Process Tree visualization | No process tree view exists anywhere. Sysmon EventID 1 (Process Create) data is parsed by sysmon_behavior_agent.py and emitted via Socket.IO as `sysmon_alert`, but it is never assembled into a parent→child tree structure in either MongoDB or the frontend. |
| H4 | Fusion Decision Replay panel | FusionResult.components (per-model scores + weights + contribution) is persisted to `fused_alerts` and available, but no UI panel displays "why fusion escalated" — which domain contributed how much, which escalation rule triggered (Rules A–D in fusion_engine_agent.py). |
| H5 | Tiered storage — HOT/COLD tiers | Zero tiered storage exists. All collections use simple MongoDB caps (oldest document evicted when cap hit). No cold archive (zip/JSON export), no severity-based retention policy, no explicit HOT-tier TTL. |
| H6 | Retention policy enforcement | No TTL indexes on any collection. LOW-severity alerts age out only via MongoDB cap eviction order (not by time). HIGH/CRITICAL alerts have no "permanent" protection and will be evicted if `fused_alerts` (1k cap) fills. |

### Priority: MEDIUM (Important for completeness)

| # | Missing Component | Gap Description |
|---|-------------------|-----------------|
| M1 | Network Flow Replay — connection-by-connection | NetworkView shows an aggregate attack-vs-normal ECharts area chart over time. No per-flow replay: no ability to scrub to T+30s and see which specific connections were active at that moment. `endpoint_timelines` stores only a connection count, not individual connection records at each tick. |
| M2 | Evidence Locker | No dedicated "evidence_locker" MongoDB collection or UI. Suspicious file hashes (from malware_analysis_agent), flagged IPs (from network pipeline), quarantined files, and related Sysmon events are stored in separate collections but never grouped under a single incident reference. |
| M3 | "Attack Reconstruction Mode" 3-panel layout | The desired layout (left: attack graph + MITRE, center: animated replay, right: SHAP + analyst notes) does not exist as a unified view. The components exist independently but are never composed into this layout. |
| M4 | Process tree data collection in backend | Sysmon EventID 1 records parent_process_id + process_id but SysmonBehaviorAgent does not build a PID→PPID adjacency map or persist it to MongoDB. The raw data exists in sysmon_events.json but is not structured for tree rendering. |
| M5 | chain field ordering for attack graph edges | AttackGraph.tsx uses `edge.chain` for replay step ordering, but `attack_graph_edges` in MongoDB has no `chain` field. The AttackGraphEngine upsert_edge() method never sets it. Replay ordering is therefore mock-only (mockData.ts has hardcoded chain values); live edges have `chain = undefined` so never light up in step mode. |
| M6 | Cold archive export endpoint | No `GET /incidents/{id}/export` or `GET /alerts/archive?from=&to=` endpoint that produces a zipped JSON/NDJSON bundle for long-term offline storage. |
| M7 | Severity-based alert pinning | No mechanism to mark CRITICAL alerts as "pinned" to prevent cap eviction. The 1k cap on `fused_alerts` will silently drop old CRITICAL events when the collection fills. |

### Priority: LOW (Enhancement / Nice-to-have)

| # | Missing Component | Gap Description |
|---|-------------------|-----------------|
| L1 | Replay playback speed control | GraphControls has a fixed 900ms tick interval. No speed selector (0.5x / 1x / 2x / 4x). |
| L2 | SHAP not implemented for LSTM system monitor | shap_agent.py covers network (RandomForest TreeExplainer) and malware (LightGBM TreeExplainer). System monitor LSTM Autoencoder and Sysmon TF-IDF have no SHAP integration. These appear as blank SHAP panels in replay. |
| L3 | Analyst notes not linked to specific alerts | case_notes are per-endpoint only (endpoint_id key). No note can be pinned to a specific fused_alert, plan_id, or incident_id. |
| L4 | No replay "bookmark" / shareable URL | No URL param encoding for a specific replay state (incident_id + step number) so analysts cannot share a specific reconstruction moment via URL. |
| L5 | Sysmon alert rate-limiting in replay context | _handle_sysmon_result has no cooldown; high event rates produce hundreds of attack graph edge upserts/min. During replay, this creates very dense graph paths that are hard to follow. |

================================================================================

## SECTION 3: ARCHITECTURE GAP ANALYSIS

| Layer | Component | Status | Notes |
|-------|-----------|--------|-------|
| Storage — HOT tier | MongoDB capped collections | PARTIAL | Present but no TTL index; no severity-based protection; CRITICAL alerts can be evicted |
| Storage — COLD tier | Compressed archive | MISSING | Not implemented anywhere |
| Storage — Retention policy | Severity-based TTL (LOW=7d, MEDIUM=30d, HIGH=90d, CRITICAL=permanent) | MISSING | No TTL indexes exist on any collection |
| Backend — Incident bundle API | GET /replay/{incident_id} | MISSING | No unified endpoint |
| Backend — Process tree builder | PID→PPID graph from Sysmon EventID 1 | MISSING | Data in sysmon_events.json but not parsed into tree |
| Backend — Cold archive export | GET /archive/export | MISSING | Not implemented |
| Backend — Evidence grouping | evidence_locker collection + index by incident_id | MISSING | No collection; hashes/IPs scattered |
| Backend — Alert pinning | CRITICAL fused_alerts protection from cap eviction | MISSING | No flag/separate collection |
| Frontend — Attack Reconstruction view | 3-panel layout | MISSING | AttackGraphView, EndpointDetailView exist separately |
| Frontend — Animated event timeline | Step-by-step text event log with timestamps | MISSING | GraphControls drives graph edges only |
| Frontend — Process tree | D3 tree / dagre layout | MISSING | No component exists |
| Frontend — Fusion decision panel | Per-model contribution breakdown + escalation rule | MISSING | FusionResult.components available but never rendered |
| Frontend — Network flow replay | Per-connection scrubber | MISSING | Only aggregate chart exists |
| Frontend — Evidence Locker tab | Hashes, IPs, quarantine files per incident | MISSING | No component |
| AttackGraph chain ordering | edge.chain field in live data | MISSING | chain=undefined for all live edges; only mock data has values |

================================================================================

## SECTION 4: CONFLICTS AND INCOMPATIBILITIES

| # | Conflict | Root Cause | Resolution |
|---|----------|------------|------------|
| C1 | `fused_alerts` 1k cap will silently drop CRITICAL alerts before cold-tier archival can run | MongoDB capped collections evict on insertion order, not severity; no protection for high-value events | Create a separate `critical_alerts` collection (uncapped) that mirrors any CRITICAL fused_alert, or add a TTL-indexed `alerts_archive` collection |
| C2 | AttackGraph replay uses `edge.chain` but live edges never have this field set | `AttackGraphEngine.upsert_edge()` in attack_graph.py has no `chain` parameter; mockData.ts hardcodes chain values 1–N | Add `chain_seq` counter per endpoint_id to AttackGraphEngine; increment on each malicious edge insert; persist to MongoDB |
| C3 | `endpoint_timelines` stores only connection count, not individual connection records | timeline_entry dict (backend.py:3501-3509) aggregates `len(network_data.connections)` | For network flow replay, the raw `network_data.connections` list must be stored separately (rate-limited) in a `connection_snapshots` collection |
| C4 | Process tree data exists in Sysmon NDJSON but is never structured | SysmonBehaviorAgent._handle_event() emits individual events; no PID→PPID adjacency map is built or persisted | Add `_build_process_tree()` to sysmon_behavior_agent.py that maintains an in-memory dict and periodically flushes to `process_trees` MongoDB collection |
| C5 | SHAP explanations are per-alert-ts but not linked to plan_id or incident_id | shap_explanations are saved with endpoint_id + alert_ts, but response_plans store their own shap_explanation copy | Add `plan_id` index to shap_explanations; or rely on the copy in response_plans (already present at plan.shap_explanation) |
| C6 | PDF "Attack Timeline" section uses `contributing_signals` which is a list of model names, not timestamped events | report_generator.py:_build_attack_timeline() sorts by .timestamp field in each signal dict, but fusion.contributing_models is just ["network","user"] strings | Pass the full per-domain score dict (from FusionResult.components) as contributing_signals when calling generate_response_plan() |

================================================================================

## SECTION 5: IMPLEMENTATION ROADMAP

### Immediate Actions (0–2 weeks) — Critical fixes enabling replay at all

**5.1 Fix AttackGraph chain ordering for live data** (HIGH — C2 above)
- File: `Backend/attack_graph.py`, method `upsert_edge()`
- Add a `chain_seq: int` field. Use a per-`endpoint_id` counter stored in MongoDB
  (`attack_graph_nodes` metadata or a separate counter collection).
- Emit `chain` in the `/attack-graph/timeline` response so frontend replay steps are real.
- Effort: ~3 hours backend

**5.2 Protect CRITICAL alerts from cap eviction** (HIGH — C1)
- File: `Backend/backend.py`, `_COLLECTION_CAPS` dict + `_save()` call sites
- When severity == "CRITICAL", dual-write to `fused_alerts` (capped) AND `critical_alerts`
  (uncapped, TTL-indexed at 180 days via MongoDB TTL index on `ts` field).
- Backend change: add `"critical_alerts"` to collection initialization; update
  `_save("fused_alerts", ...)` call sites to check severity and dual-write.
- Effort: ~2 hours backend

**5.3 Add TTL indexes for retention policy** (HIGH — H6)
- File: `Backend/backend.py`, `_setup_indexes()` function (around line 880)
- Add MongoDB TTL indexes on `ts` / `timestamp` fields:
  - `endpoint_timelines`: expireAfterSeconds=86400*30 (30d)
  - `fused_alerts`: expireAfterSeconds=86400*90 (90d, HIGH/MEDIUM mixed)
  - `shap_explanations`: expireAfterSeconds=86400*90
  - `sysmon_alerts`: expireAfterSeconds=86400*30
  - `critical_alerts` (new): expireAfterSeconds=86400*180 (6 months)
- Note: MongoDB TTL indexes work on datetime fields; ensure all `ts` fields are stored as
  datetime objects, not ISO strings. The `_save()` helper currently stores `"ts": _now()`
  which returns an ISO string — change `_now()` to return `datetime.utcnow()` or add a
  secondary datetime field for TTL use.
- Effort: ~4 hours backend

**5.4 Build unified Incident Replay API endpoint** (HIGH — H1)
- New endpoint: `GET /replay/{incident_id}` (auth: JWT analyst/admin)
- Fetches and correlates:
  1. `incident_reports` doc by incident_id
  2. `response_plans` doc by plan_id (from incident doc)
  3. `fused_alerts` doc by endpoint_id + ts window (±60s around plan.created_at)
  4. `shap_explanations` for same endpoint_id + ts window
  5. `endpoint_timelines` for endpoint_id in the ±300s window
  6. `attack_graph_nodes` + `attack_graph_edges` for endpoint_id
  7. `endpoint_commands` for endpoint_id sorted by created_at
  8. `sysmon_alerts` for endpoint_id in ts window (if available)
- Returns a single JSON bundle: `{incident, fusion_decision, timeline_entries, attack_graph, shap, response_actions, sysmon_events, case_notes}`
- File: `Backend/backend.py` — add after `/reports` endpoints
- Effort: ~6 hours backend

---

### Short-term (2–6 weeks) — Core replay UI

**5.5 Attack Reconstruction View — 3-panel layout** (HIGH — M3)
- New file: `Cyber Sentinal XDR Frontend/src/components/views/AttackReconstructionView/`
  - `AttackReconstructionView.tsx` — 3-column layout:
    - Left (280px): AttackGraph (reused) + MITRE technique badge + incident metadata
    - Center: Animated event timeline (new `ReplayTimeline` component — see 5.6)
    - Right (320px): SHAP bar chart (from ResponseModal) + analyst case notes (existing CaseNotesPanel)
  - `ReplayTimeline.tsx` — vertical scrolling event log; each entry is a timestamped row
    with icon, source domain, description, severity badge; "active" entry highlighted as
    replay step advances
  - `FusionDecisionPanel.tsx` — displays FusionResult.components as a horizontal bar chart
    (net/usr/sys/mal contribution bars + escalation rule labels from contributing_reasons)
- Wire into `NetworkMonitor.tsx` router as ViewId `"attack-reconstruction"`
- Sidebar nav entry: "Reconstruction" (icon: rewind symbol), visible to admin/analyst only
- Effort: ~3 days frontend

**5.6 ReplayTimeline component** (HIGH — H2)
- The center panel component. Receives the `/replay/{incident_id}` bundle.
- Renders events in chronological order as vertical timeline rows:
  - Sysmon events: process launches, network connects (EventID 1, 3)
  - Fusion escalation events: which model fired, score delta
  - SOAR actions: block_ip, kill_process, quarantine_file executed
  - Network flow anomalies: src→dst, attack_type, confidence
- Play/Pause/Speed controls (0.5x/1x/2x/4x) shared with AttackGraph replayStep state
- Each row click jumps the AttackGraph to the corresponding chain step
- Effort: ~2 days frontend

**5.7 FusionDecisionPanel component** (HIGH — H4)
- Renders FusionResult.components: {"network": {score, weight, contribution}, ...}
- Horizontal stacked bar: each domain's contribution as a % of total threat_score
- Labels the escalation rule that fired (Rules A–D from contributing_reasons array)
- Colour-coded by domain: network=cyan, user=green, system=amber, malware=red
- File: part of AttackReconstructionView/
- Effort: ~4 hours frontend

**5.8 Process Tree data collection in backend** (MEDIUM — M4, H3)
- File: `Backend/agents/sysmon_behavior_agent.py`
- Add `_process_registry: dict[str, dict]` — keyed by PID, stores {pid, ppid, name, cmd, ts}
- On EventID 1 (Process Create): register entry; on EventID 5 (Process Terminate): remove.
- Add `get_process_tree(root_pid: int) -> dict` that recursively builds parent→children tree.
- Persist snapshot to `process_trees` MongoDB collection every 60s (new collection, 2k cap).
- New backend endpoint: `GET /process-tree/{endpoint_id}` — returns most recent snapshot.
- Effort: ~6 hours backend

---

### Medium-term (6–12 weeks) — Complete the feature set

**5.9 Process Tree visualization component** (MEDIUM — H3)
- File: new `Cyber Sentinal XDR Frontend/src/components/views/AttackReconstructionView/ProcessTreePanel.tsx`
- Use D3 tree layout (d3.tree()) or `react-d3-tree` library
- Highlight malicious PIDs (those matching IOC list in malware_collector.py) in red
- Animate: as replayStep advances, new process nodes appear with a fade-in
- Effort: ~2 days frontend + 1 day integration

**5.10 Network Flow Replay — connection snapshot storage** (MEDIUM — M1, C3)
- File: `Backend/backend.py`, endpoint `/endpoint/ingest` handler (around line 3500)
- Add a `connection_snapshots` MongoDB collection (5k cap, TTL 30d)
- Store: `{endpoint_id, timestamp, connections: [...top 20 by bytes_sent...]}` every ingest.
- New backend endpoint: `GET /replay/{incident_id}/connections?t={iso_timestamp}` — returns
  connection snapshot nearest to requested timestamp.
- Frontend: Add a scrubber to AttackReconstructionView center panel; at each tick, fetch
  and render a mini connection table (src, dst, port, proto, bytes_sent, suspicious flag).
- Effort: ~1 day backend + 1 day frontend

**5.11 Evidence Locker** (MEDIUM — M2)
- New MongoDB collection: `evidence_locker` (no cap; TTL-indexed 180d)
- Schema: `{incident_id, plan_id, endpoint_id, type: "hash"|"ip"|"file"|"process", value, context, severity, timestamp, analyst_note}`
- Backend: auto-populate on CRITICAL events — malware sha256 hashes, blocked IPs from
  endpoint_commands, quarantined file paths, flagged process names from Sysmon.
- New endpoints: `GET /evidence/{incident_id}`, `POST /evidence` (analyst can add manually)
- Frontend: Add "Evidence" tab in AttackReconstructionView right panel; table with type icon,
  value, context, analyst note field inline.
- Effort: ~1 day backend + 1 day frontend

**5.12 Cold archive export** (MEDIUM — M6)
- New endpoint: `GET /archive/export?from={iso}&to={iso}&severity={min}` (JWT admin only)
- Exports: fused_alerts + shap_explanations + response_plans + incident_reports metadata
  for the time range as a single zipped NDJSON bundle (one .jsonl per collection).
- Implementation: use Python `zipfile` + `io.BytesIO`; stream via `StreamingResponse`.
- File: `Backend/backend.py`
- Effort: ~4 hours backend

---

### Long-term (3–6 months) — Advanced capabilities

**5.13 Analyst note linking to specific alerts** (LOW — L3)
- Extend `case_notes` schema with optional `plan_id` and `fused_alert_id` fields.
- Frontend: in ReplayTimeline, each row gets an "Add Note" icon that pre-fills the note
  context with the alert timestamp and attack_type.

**5.14 Replay bookmark / shareable URL** (LOW — L4)
- Encode `?incident={incident_id}&step={N}` in the URL via React Router `useSearchParams`.
- On mount, AttackReconstructionView reads params, fetches the replay bundle, and seeks to step N.

**5.15 SHAP for system monitor (LSTM)** (LOW — L2)
- Requires gradient-based attribution (SHAP GradientExplainer or Integrated Gradients)
  since TreeExplainer does not support PyTorch LSTM.
- Adds ~200ms per inference; acceptable if run only on CRITICAL events.

================================================================================

## SECTION 6: BACKEND CHANGES SUMMARY

### New Endpoints Required

| Endpoint | Auth | Purpose | Priority |
|----------|------|---------|----------|
| `GET /replay/{incident_id}` | JWT analyst/admin | Unified incident replay bundle | HIGH |
| `GET /process-tree/{endpoint_id}` | JWT analyst/admin | Current process tree snapshot | MEDIUM |
| `GET /replay/{incident_id}/connections` | JWT analyst/admin | Connection snapshots near timestamp | MEDIUM |
| `GET /evidence/{incident_id}` | JWT analyst/admin | Evidence locker entries for incident | MEDIUM |
| `POST /evidence` | JWT analyst/admin | Add evidence item manually | MEDIUM |
| `GET /archive/export` | JWT admin | Zipped NDJSON cold archive export | MEDIUM |

### New MongoDB Collections Required

| Collection | Cap | TTL | Purpose |
|------------|-----|-----|---------|
| `critical_alerts` | None | 180d | Mirror of CRITICAL fused_alerts; eviction-protected |
| `process_trees` | 2,000 | 30d | PID→PPID snapshots from Sysmon |
| `connection_snapshots` | 5,000 | 30d | Per-tick raw connection list per endpoint |
| `evidence_locker` | None | 180d | Grouped evidence items per incident |

### Modified Collections (TTL indexes to add)

| Collection | Field | TTL |
|------------|-------|-----|
| `endpoint_timelines` | `timestamp` | 30d |
| `fused_alerts` | `ts` | 90d |
| `shap_explanations` | `alert_ts` | 90d |
| `sysmon_alerts` | `ts` | 30d |
| `response_plans` | `created_at` | 90d |

### Backend Code Changes Required

| File | Change | Priority |
|------|--------|----------|
| `Backend/attack_graph.py` | Add chain_seq counter to upsert_edge(); persist to MongoDB | HIGH |
| `Backend/backend.py` | Dual-write CRITICAL alerts to critical_alerts; add TTL indexes; add /replay endpoint; add connection_snapshots write in /endpoint/ingest; add /archive/export | HIGH |
| `Backend/agents/sysmon_behavior_agent.py` | Add _process_registry; get_process_tree(); periodic flush to process_trees | MEDIUM |
| `Backend/backend.py` | Add /process-tree, /evidence, /replay/.../connections endpoints | MEDIUM |
| `Backend/report_generator.py` | Pass FusionResult.components dict (not just model name strings) as contributing_signals to get per-domain detail in PDF attack timeline | LOW |

================================================================================

## SECTION 7: FRONTEND CHANGES SUMMARY

### New Files/Components Required

| File | Description | Priority |
|------|-------------|----------|
| `views/AttackReconstructionView/AttackReconstructionView.tsx` | 3-panel reconstruction layout | HIGH |
| `views/AttackReconstructionView/ReplayTimeline.tsx` | Animated step-by-step event log | HIGH |
| `views/AttackReconstructionView/FusionDecisionPanel.tsx` | Per-domain contribution bar chart | HIGH |
| `views/AttackReconstructionView/ProcessTreePanel.tsx` | D3 process tree | MEDIUM |
| `views/AttackReconstructionView/EvidenceLockderPanel.tsx` | Evidence locker tab | MEDIUM |

### Modified Files

| File | Change | Priority |
|------|--------|----------|
| `NetworkMonitor.tsx` | Add `"attack-reconstruction"` ViewId; Socket.IO state for replay bundle | HIGH |
| `Sidebar.tsx` | Add "Reconstruction" nav entry (analyst/admin only) | HIGH |
| `views/AttackGraphView/AttackGraphView.tsx` | Accept external `replayStep` prop so ReconstructionView can drive it | HIGH |
| `src/services/api.ts` | Add `fetchReplayBundle(incident_id)`, `fetchProcessTree(endpoint_id)`, `fetchEvidence(incident_id)` | HIGH |

================================================================================

## SECTION 8: METRICS AND KPIs TO TRACK

| KPI | Target | Source |
|-----|--------|--------|
| Time-to-reconstruct (analyst opens replay → full bundle loaded) | < 3 seconds | Frontend performance timer |
| Replay bundle completeness (% incidents with all 6 data sources) | > 90% | Backend /replay endpoint; count non-null fields |
| CRITICAL alert retention rate (% CRITICAL alerts surviving 90 days) | 100% | critical_alerts collection count vs fused_alerts |
| Cold archive export coverage (% HIGH/CRITICAL incidents exported monthly) | 100% | Archive job audit log |
| Process tree coverage (% endpoints with process_trees snapshot < 60s old) | > 85% | process_trees.timestamp age query |
| Evidence locker population rate (% CRITICAL incidents with ≥ 1 evidence item) | 100% | evidence_locker count per incident_id |
| Analyst note attachment rate per CRITICAL incident | > 70% | case_notes count with plan_id set |

================================================================================
END OF REPORT
Next Analysis Recommended: After completing Immediate Actions (5.1–5.4) and before
starting the 3-panel UI (5.5), to confirm the /replay endpoint payload contract is
correct and chain_seq live data is flowing to the graph before frontend build begins.
================================================================================
