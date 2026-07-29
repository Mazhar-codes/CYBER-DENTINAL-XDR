---
name: Endpoint Layer Extension — Gap Analysis 2026-04-28
description: All 6 endpoint management extensions are absent; per-endpoint fusion, server_host, endpoint_timelines, SHAP attachment, multi-endpoint correlation, and EndpointDetailView all need to be built additively
type: project
---

As of 2026-04-28, the 6 requested endpoint management extensions are all ABSENT:

1. **server_host sentinel** — backend server machine not self-registered in endpoint_registry. Should upsert on startup with `is_server=True` flag; `isolate_host` / `block_ip` SOAR actions must be blocked for this endpoint.

2. **Per-endpoint fusion** — `_analyze()` in `endpoint_ingest` is heuristic-only; does not call `FusionDecisionEngine`. Solution: `_endpoint_engines: dict[str, FusionDecisionEngine]` in `backend.py`; global `_fe` instance kept for cross-endpoint correlation. New Socket.IO event: `endpoint_fusion_alert` (NOT `fusion_alert` — avoids N+1 siren triggers).

3. **endpoint_timelines collection** — does not exist. Add to `_COLLECTION_CAP` (50k cap), create compound index `{endpoint_id, timestamp}` + optional TTL 7 days. Write lightweight telemetry metrics there on every ingest.

4. **SHAP per-endpoint** — `shap_agent.py` unchanged; just call `_shap_agent.explain_fusion()` in the per-endpoint fusion path in `backend.py` and attach to `endpoint_fusion_alert` payload.

5. **Multi-endpoint correlation** — already solved by per-endpoint engine dict (Item 2). Global engine preserved for APT-style cross-endpoint chains.

6. **EndpointDetailView.tsx** — new component; drill-down from EndpointView card. State managed in `NetworkMonitor.tsx` as `activeEndpointId`. Panels: header, timeline sparkline (REST GET /endpoint/timeline/{id}), per-endpoint alerts with SHAP column, SOAR panel.

**Key risks:**
- Global `fusion_alert` vs. per-endpoint `endpoint_fusion_alert` event naming must be kept separate to avoid N+1 AlertSiren fires.
- Retroactive `server_host` log tagging should NOT be done (Atlas M0 write quota risk); only forward-tag new logs.
- `FusionEngineAgent.fuse()` signature must NOT be changed; use new `_endpoint_fuse()` helper in backend.py instead.
- `EndpointDetailView` drill-down state must live in `NetworkMonitor.tsx`, not inside `EndpointView`, to avoid AnimatePresence full-panel flash on navigation.

**Why:** User wants per-endpoint threat scoring, timeline visualization, SHAP drill-down, and a detail UI panel — all additive over the existing 6-endpoint API + EndpointView.

**How to apply:** When backend-agent or frontend-agent implements these, reference the above risk mitigations. Specifically enforce `endpoint_fusion_alert` event name and `is_server` SOAR guard.
