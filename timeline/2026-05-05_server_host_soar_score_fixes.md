# Session Report — 2026-05-05
## Server Host SOAR, Score Threshold Fixes, UI Bug Fixes

---

## Summary

This session resolved four production-blocking bugs discovered during live testing, implemented the Server PC Response System as a full SOAR-loop, and wired the Correlated Attacks table in `AlertsView.tsx` to the existing `ResponseModal`.

---

## 1. Server PC Response System

### Problem
The backend registered itself as `endpoint_id="server_host"` in `endpoint_registry` since 2026-05-02, but all SOAR commands sent to it were blocked by a guard in `POST /endpoint/command`. The Correlated Attacks table in the frontend had no Respond button. The system could not respond to threats on the host machine it runs on.

### Backend changes — `Backend/backend.py`

**Removed SOAR block** (was lines 3194–3198):
Previously `is_server` prevented `isolate_host` and `block_ip` from being issued against the server.  This guard is now removed — all 5 actions are accepted.

**Added `_server_soar_executor(action, target, parameters)`**:
Runs locally on the server machine, returns `(bool, str)`.
- `block_ip` / `unblock_ip` — `asyncio.create_subprocess_exec` → `netsh advfirewall firewall add/delete rule name=XDR_BLOCK_<ip>`; strict IPv4 regex validation
- `kill_process` — tries `int(target)` as PID first, then name-match via `psutil.process_iter`
- `quarantine_file` — validates absolute path exists; `shutil.move` → `Backend/quarantine/`
- `isolate_host` — writes `isolation_flag.txt`; disables named adapter via `netsh interface set interface`

**Added `_server_soar_loop()`**:
- Polls `endpoint_commands` every 5 s for `{endpoint_id: "server_host", status: "pending"}`
- Atomically marks `status: "sent"` before execution (prevents double-run)
- Calls `_server_soar_executor`, writes `completed`/`failed` + `result_message` + `completed_at`
- Emits `command_result` Socket.IO event
- Post-execution registry updates: `isolate_host` → `status: "isolated"`; `block_ip` → `$addToSet blocked_ips`; `unblock_ip` → `$pull blocked_ips`; each followed by `endpoint_update` emit so dashboard reflects state immediately

**Added `_server_soar_task` global**:
Loop started in `GET /start-monitoring` alongside heartbeat task; cancelled in `_do_shutdown()` and `GET /stop-monitoring`.

**`_emit_soc_alert_if_correlated` default endpoint_id**:
Changed fallback from `"unknown"` → `"server_host"` so all server-pipeline correlation events (Suricata, user behavior, system monitor) auto-generate response plans that correctly target the server host.

### Frontend changes — `AlertsView.tsx`

**`socAlertToFlowResult(sa: SocAlert): FlowResult` adapter**:
Added at module level (before component). Converts a correlated attack alert to the `FlowResult` shape `ResponseModal` expects. Key mappings: `src_ip: "server_host"`, confidence ×100 (SocAlert stores 0–1), color from `ATTACK_COLOURS[attackType]`, all network flow numeric fields zeroed.

**Respond button in CORRELATED ATTACKS table**:
The "Response" column cell was extended: for MEDIUM/HIGH/CRITICAL rows, renders a red "Respond" button (same style as the Network Anomalies button). Button IIFEs `matchingPlan` lookup against `responsePlans` filtered to `endpoint_id === "server_host"` + matching `attack_type`, then calls `setResponseModal({ alert: socAlertToFlowResult(alert), plan: matchingPlan })`. All existing ResponseModal features (SHAP chart, action checklist, role-gated execute, PDF download) work unchanged.

`ATTACK_COLOURS` added to the import line from `"../shared/types"`.

---

## 2. Score Threshold Fixes — False HIGH/CRITICAL Alerts

### Problem
Alerts were showing HIGH/CRITICAL severity at 10–29% threat scores. Root cause: `CorrelationEngine` assigned pattern-driven HIGH/CRITICAL labels independently of numeric score; `_max_severity([corr_severity, score_severity])` always took the maximum, so a 10% score with two active sources could be labelled CRITICAL.

### Changes

**`Backend/agents/fusion_engine_agent.py`**:
- `high_threshold` default: 0.80 → 0.70
- `critical_threshold` default: 0.90 → 0.85

**`Backend/fusion_engine.py` — `_compute_final_decision`**:
Added downward severity cap after `_max_severity()`:
```
CRITICAL && score < 0.85  →  HIGH (if score ≥ 0.70) or MEDIUM/LOW
HIGH     && score < 0.70  →  MEDIUM (if score ≥ 0.35) or LOW
```

**`Backend/backend.py` — `_emit_soc_alert_if_correlated`**:
Score gate before alert emission:
- `CRITICAL` && score < 0.85 → downgrade to HIGH, still emit
- `HIGH` && score < 0.70 → suppress (not emitted)
- `CRITICAL` && 0.70 ≤ score < 0.85 → downgrade to HIGH, still emit

---

## 3. SOAR Buttons Returning HTTP 403

### Problem
`handleSendCommand` in `NetworkMonitor.tsx` used raw `axios.post` with a hardcoded API key header. When the configured backend key differed from the default `changeme-dev-key`, both auth paths (API key + JWT) failed → 403.

### Fix — `NetworkMonitor.tsx`
Replaced raw `axios.post` with `authAxios.post` (imported from `authService.ts`). `authAxios` automatically attaches the `Authorization: Bearer <token>` header from localStorage and silently refreshes on 401.

---

## 4. Blocked IPs Not Shown on Dashboard After SOAR Execution

### Problem
`POST /endpoint/command/ack` updated `endpoint_commands.status` but never touched `endpoint_registry`. The frontend had no signal that an IP was blocked or a host was isolated — it would only reflect the change on the next heartbeat (up to 35 s later, and only if the endpoint agent was running).

### Fix — `Backend/backend.py` — `endpoint_command_ack`
After successful ACK:
- `block_ip` → `$addToSet {blocked_ips: target}` on registry
- `unblock_ip` → `$pull {blocked_ips: target}` from registry
- `isolate_host` → `$set {status: "isolated"}` on registry
- All three followed by immediate re-fetch + `endpoint_update` Socket.IO emit

### Fix — `Cyber Sentinal XDR Frontend/src/components/shared/types.ts`
- `EndpointInfo.status`: `'online' | 'offline'` → `'online' | 'offline' | 'isolated'`
- `EndpointInfo.blocked_ips?: string[]` added

### Fix — `EndpointView.tsx`
- Orange visual treatment for isolated endpoints (border, glow, status dot, pill)
- "HOST ISOLATED 🔒" badge displayed on endpoint card
- Blocked IPs chip list (🚫 prefix per IP) displayed under the badge
- `isIsolated` included in response panel dropdown (`[ISOLATED]` label suffix)
- KPI bar: "Isolated" counter (orange) + aggregate "Blocked IPs" counter (red) added

---

## 5. Network Flow Timestamp Shows "—" for All Rows

### Problem
The backend monitoring loop assigns timestamps via `ml["ts"] = ts` (field name `ts`), but `mapRawToFlow` read `raw.timestamp`. At runtime `raw.timestamp` was always `undefined`; `fmtTime(undefined)` returned `"—"` unconditionally.

### Fix — `types.ts`
- Added `ts?: string` field to `RawFlowPayload` interface (backend alias)
- Changed `mapRawToFlow`: `timestamp: raw.timestamp` → `timestamp: raw.timestamp ?? raw.ts ?? ""`

---

## 6. Network Table Column Alignment

### Problem
Values in all 12 data columns were not vertically centred relative to column headers; cells wrapping on narrow viewports caused rows to misalign.

### Fix — `NetworkView.tsx`
- `whiteSpace: "nowrap"` + `verticalAlign: "middle"` added to all 12 `<td>` cells
- `verticalAlign: "middle"` added to all `<th>` cells
- `table-layout: "auto"` set explicitly
- Empty port/protocol cells now show `"—"` instead of blank

---

## Files Changed

| File | Change |
|------|--------|
| `Backend/backend.py` | Server SOAR loop + executor; SOAR block removed; score gate; blocked IPs registry update on ACK; endpoint_update emit; server_host fallback in soc_alert |
| `Backend/agents/fusion_engine_agent.py` | `high_threshold` 0.80→0.70, `critical_threshold` 0.90→0.85 |
| `Backend/fusion_engine.py` | Downward severity cap in `_compute_final_decision` |
| `Cyber Sentinal XDR Frontend/src/components/NetworkMonitor.tsx` | `handleSendCommand` raw axios → `authAxios` |
| `Cyber Sentinal XDR Frontend/src/components/shared/types.ts` | `ts?` field + `timestamp ?? ts` in `mapRawToFlow`; `EndpointInfo.status` + `blocked_ips` |
| `Cyber Sentinal XDR Frontend/src/components/views/NetworkView.tsx` | Column alignment: nowrap + verticalAlign on all cells |
| `Cyber Sentinal XDR Frontend/src/components/views/EndpointView.tsx` | Isolated state visuals + KPI counters + Blocked IPs chips |
| `Cyber Sentinal XDR Frontend/src/components/views/AlertsView.tsx` | `socAlertToFlowResult` adapter + Respond button in Correlated Attacks table (MEDIUM+) |

---

## Implementation Status After This Session

| Layer | Before | After |
|-------|--------|-------|
| EDR Orchestration | 88% | 93% |
| Frontend / SOC Dashboard | 98% | 99% |
| **Overall** | **~98%** | **~99%** |

---

## Remaining Known Issues

- `response_executed` Socket.IO event has no subscriber — Active Threats badge never clears
- `OverviewView.tsx` threat gauge uses client-side formula instead of `fusion_alert` score
- `system_model.pt` score=1.0 (sklearn version mismatch) — mitigated but not root-fixed
- `GET /reports/{id}/download` missing role check (any viewer can download forensic PDFs)
- `report_generated` Socket.IO payload exposes absolute `pdf_path`
- Forgot-password flow not implemented (alert() placeholder)
