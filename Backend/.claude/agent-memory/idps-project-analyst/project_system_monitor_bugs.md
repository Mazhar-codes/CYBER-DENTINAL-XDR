---
name: System Monitor Known Bugs (2026-05-11)
description: Two confirmed bugs in _handle_system_result and frontend routing; fix locations and patches recorded
type: project
---

Two confirmed bugs investigated on 2026-05-11:

**Bug 1 — Fusion gate tied to alert_allowed cooldown**
`backend.py` lines 2385-2393: `FusionEngineAgent.fuse()` and `_fe.ingest_event()` are only
called when `alert_allowed` is True (anomaly detected AND 30-second cooldown elapsed). The
network and user pipelines have no such secondary gate. During the cooldown window the
system score is updated in `_latest_scores` but never fused, so a concurrent network+system
attack may not produce a HIGH/CRITICAL soc_alert.

Fix: move `fuse()` call before `alert_allowed` computation; gate only on `is_anomaly`.
Move `_fe.ingest_event` block outside `if alert_allowed:`, gate only on `is_anomaly`.

**Bug 2 — system_anomaly events include endpoint_id, confusing frontend routing**
Server-side `_handle_system_result` emits `system_anomaly` with `endpoint_id: "server_host"`
(line 2398). Endpoint ingest path (line 3509) also emits `system_anomaly` with a real UUID
and `source: "endpoint"`. Frontend `NetworkMonitor.tsx:332-335` stores ALL `system_anomaly`
events in `systemAnomalies` without discriminating by source. When no endpoint is online,
server-side anomalies with `endpoint_id: "server_host"` can appear misleadingly in
endpoint-oriented panels in OverviewView.

Fix: split `system_anomaly` handler in NetworkMonitor.tsx; route `source === "endpoint"`
events to `endpointAlerts`, route server-side events to `systemAnomalies`.

**Why:** User reported "system anomaly appeared on Endpoint alerts section instead of main host alert system" when no endpoint was online.

**How to apply:** When reviewing system monitor or endpoint ingest changes, check these two
code paths are kept consistent. If system monitor is re-implemented, ensure fusion is always
called on anomaly detection, not only when cooldown permits.
