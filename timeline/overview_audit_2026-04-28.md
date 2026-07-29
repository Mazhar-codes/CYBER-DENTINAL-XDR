================================================================================
IDPS PROJECT ANALYSIS REPORT
================================================================================
Timestamp     : 2026-04-28 00:00:00 UTC
Analyst       : IDPS Project Analyst Agent
Scope         : OverviewView.tsx logical correctness audit — all widgets vs. backend truth
Project Phase : Production-hardening / SOC Dashboard Polish
================================================================================

## EXECUTIVE SUMMARY

The Overview screen has 7 confirmed defects across data-source correctness, metric
scope, and status-panel accuracy. The most severe issue (CRITICAL) is already
partially mitigated: the threat-score gauge now receives real `fusion_alert` data
via `latestFusionScore`, but a one-directional ratchet and a `soc_alert` overwrite
bug mean the displayed score diverges under normal conditions. Three KPI stat cards
are scope-incorrect (network-only counts presented as system-wide totals), two
System Status rows use wrong liveness proxies, and the Recent Alerts feed omits
system/sysmon/endpoint-fusion sources entirely. The screen has no CPU/memory system
health widget despite the backend emitting live telemetry every cycle. Overall
dashboard health: 5/10.

---

## SECTION 1: CODE QUALITY ASSESSMENT

### 1.1 Strengths
- `fusionScore` prop is wired from `fusion_alert` Socket.IO event (correct source), not a client-side formula. The documented known issue is therefore already resolved at the prop-passing layer.
- `MalwareSummary` widget correctly aggregates `malware_alert` + `malware_scan` Socket.IO events; counters split cleanly by `label` field.
- `recentAlerts` useMemo correctly sources from `socAlerts` (correlated events) in addition to per-flow network and user streams.
- `mongoOk` is polled every 30 s from `/storage-status` — not hardcoded.
- Timeline chart is driven purely from Socket.IO `network` events with correct time-bucketing.

### 1.2 Issues Found

| Severity | Component | Issue | Recommendation |
|----------|-----------|-------|----------------|
| CRITICAL | NetworkMonitor.tsx:354 | `soc_alert` handler calls `setLatestFusionScore(score)` — plain assignment, not `Math.max`. This DOWNGRADES the gauge whenever a low-threat correlated alert arrives after a high-threat `fusion_alert`. | Change to `setLatestFusionScore(prev => Math.max(prev, score))` to match the `fusion_alert` handler pattern. |
| CRITICAL | NetworkMonitor.tsx:341 | `latestFusionScore` is a monotonic ratchet (`Math.max`). It never decreases, so the gauge freezes at the peak score for the entire session and never recovers to LOW after a threat resolves. | Replace with a time-decaying or last-N-seconds max. Simplest fix: just use `fusionScore` (last received value) and drop `latestFusionScore` entirely; let the gauge reflect the most-recent backend emission. |
| HIGH | OverviewView.tsx:244-280 | "Active Threats" StatCard shows `stats.attacks` — count of network ATTACK flows only. Does not include user anomalies, malware hits, sysmon alerts, or fused alerts. Label is misleading to SOC analysts. | Rename to "Network Attacks" or compute a cross-source active-threats count: `stats.attacks + userAnomalies.filter(ANOMALY).length + malwareSummary.malware_count`. |
| HIGH | OverviewView.tsx:469-509 | System Status panel: "Backend API" and "Socket.IO" are hardcoded `ok: true`. If the backend crashes, the panel shows both as OK because the React component is still mounted. | Source "Backend API" from a `/health` heartbeat poll (already done for `isMonitoring`); source "Socket.IO" from `socket.connected` state propagated down from NetworkMonitor. |
| HIGH | OverviewView.tsx:469-509 | System Status panel: "Fusion Engine" uses `ok: isMonitoring`. The fusion engine can be running (backend started) while monitoring is not — and vice versa: monitoring can be active while `_fusion_agent` is None (init failure). The two states are independent. | Source "Fusion Engine" from `fusionScore !== undefined` (true only after at least one `fusion_alert` received). |
| MEDIUM | OverviewView.tsx:18-30 | `endpoints` and `endpointAlerts` are never passed as props to OverviewView. No endpoint-online count or endpoint health metric exists on the Overview screen. | Add `endpoints: EndpointInfo[]` prop. Display an "Endpoints Online" StatCard: `endpoints.filter(e => e.status === 'online').length`. This data is already in NetworkMonitor state. |
| MEDIUM | OverviewView.tsx:184-217 | `recentAlerts` omits `system_anomaly` (SystemMonitorAgent) and `endpoint_alert` (SOAR endpoint) events. Both are emitted by the backend and held in NetworkMonitor state but never forwarded. | Add `systemAnomalies` and `endpointAlerts` props to OverviewView; include HIGH/CRITICAL entries in the `recentAlerts` array with source labels "System" and "Endpoint". |
| MEDIUM | OverviewView.tsx:469-509 | System Status panel: "User Behavior" shows OK only when `userSummary.total_users > 0`. This is false-negative when the user behavior agent is running but all events produce NORMAL scores (total_users remains 0 between Winlogbeat cycles). | Change to `ok: isMonitoring` (same proxy as "Network Detection"), or add an explicit `userAgentRunning` boolean prop sourced from the `/health` endpoint response. |
| LOW | OverviewView.tsx (missing widget) | No CPU/memory system health widget. `system_anomaly` events carry `cpu_percent`, `memory_percent`, and `score` fields. The backend emits these every cycle (benign and anomalous). SOC analysts have no situational awareness on host resource state from the Overview. | Add a "System Health" mini-widget or mini-gauge below the Malware Summary row, driven by `systemAnomalies[0]?.cpu_percent` and `systemAnomalies[0]?.memory_percent`. Requires passing `systemAnomalies` prop. |
| LOW | OverviewView.tsx:47 | `globalThreatScore` falls back to `0` (`fusionScore ?? 0`). On initial load before any `fusion_alert` arrives, the gauge shows 0/LOW permanently, creating a false sense of security during the model warm-up period. | Show a "Waiting for data..." skeleton or an indeterminate state until the first `fusion_alert` arrives. Track `hasFusionData: boolean` prop. |

---

## SECTION 2: SECURITY VULNERABILITY ANALYSIS

### 2.1 Critical
None specific to OverviewView beyond the data-correctness issues.

### 2.2 High
- **Misleading threat status to SOC operators**: The gauge ratchet bug (CRITICAL defects above) means a prior HIGH event permanently renders the score high even if the system has returned to baseline. SOC analysts may ignore real alerts believing the system is already elevated.

### 2.3 Medium/Low
- No sensitive data rendered in this view; all displayed values are aggregated counts or scores.

---

## SECTION 3: ARCHITECTURE GAP ANALYSIS

| Widget | Source Expected | Source Actual | Status |
|--------|----------------|---------------|--------|
| Global Threat Score gauge | `fusion_alert` Socket.IO → `threat_score * 100` | `latestFusionScore` (from `fusion_alert` + `soc_alert`) | Partial — ratchet + overwrite bugs |
| Active Threats StatCard | Cross-source fused count | `stats.attacks` (network flows only) | Needs Revision |
| Network Flows StatCard | `network` socket events | `stats.total` | OK |
| Users Monitored StatCard | `user_behavior_summary` | `userSummary.total_users` | OK |
| Capture Cycles StatCard | `network` socket events | `stats.cycles` | OK |
| Attack Rate StatCard | `stats.attacks / stats.total` | Correct derivation | OK |
| Malware Summary widget | `malware_alert` + `malware_scan` events | Correct 3-field aggregation | OK |
| Endpoints Online StatCard | `endpoint_registry` / `endpoint_update` | MISSING — not in OverviewView | Missing |
| System Health widget (CPU/mem) | `system_anomaly` events | MISSING | Missing |
| Threat Timeline chart | `network` events (time-bucketed) | Correct | OK |
| Attack Distribution donut | `attackTypeData` from `network` events | Correct | OK |
| Recent Alerts feed | All sources (network, user, correlated, system, endpoint) | Only network + user + socAlerts | Partial |
| System Status — Backend API | `/health` heartbeat | Hardcoded `true` | Needs Revision |
| System Status — Socket.IO | `socket.connected` state | Hardcoded `true` | Needs Revision |
| System Status — Fusion Engine | `fusion_alert` received | `isMonitoring` proxy | Needs Revision |
| System Status — User Behavior | `userAgentRunning` flag | `userSummary.total_users > 0` (unreliable) | Needs Revision |
| System Status — MongoDB Atlas | `/storage-status` poll | Correct | OK |
| System Status — Network Detection | `isMonitoring` | Correct | OK |

---

## SECTION 4: CONFLICTS AND INCOMPATIBILITIES

### Defect 1 — `soc_alert` downgrades gauge (NetworkMonitor.tsx line 354)
**Root cause**: `fusion_alert` handler uses `prev => Math.max(prev, score)` (monotonic).
`soc_alert` handler uses plain `setLatestFusionScore(score)` (overwrite). When a `soc_alert`
carries a lower threat_score than the last `fusion_alert`, it decreases the displayed gauge —
but only sometimes, creating non-deterministic gauge behavior.
**Resolution**: Change line 354 to: `setLatestFusionScore(prev => Math.max(prev, score));`

### Defect 2 — Monotonic ratchet never resets
**Root cause**: `latestFusionScore` initialised to 0 and only ever goes up within a session.
After the threat resolves, the backend may emit lower `fusion_alert` scores (or none at all),
but the gauge stays pinned.
**Resolution**: Drop `latestFusionScore` state entirely. Pass `fusionScore` directly to
`OverviewView`. `fusionScore` is the most recent `fusion_alert` value and reflects current state.
If `soc_alert` should also feed the gauge, apply `Math.max` in the `soc_alert` handler but
also allow decay: add a `useEffect` that resets `fusionScore` toward 0 by 5 points every 60s
when no new `fusion_alert` is received.

### Defect 3 — `stats.attacks` labelled "Active Threats"
**Root cause**: `stats` is populated exclusively by the `network` Socket.IO event handler.
User, system, malware, sysmon sources never increment `stats.attacks`. The label "Active Threats"
implies a fused view but delivers only network flows.
**Resolution**: Either rename label to "Network Attacks" (quick fix, no logic change), or
compute a separate `activeThreatCount` in NetworkMonitor: `stats.attacks + anomalyCount + malwareCount`.

### Defect 4 — Hardcoded `ok: true` for Backend API and Socket.IO in System Status
**Root cause**: These two rows were set to constant `true` during initial scaffolding and
never wired to real observability.
**Resolution**: Propagate `socketConnected: boolean` prop from NetworkMonitor (use
`socket.connected` property sampled in a `useEffect` on `socket.on('connect')` /
`socket.on('disconnect')`). For "Backend API", use the existing `isMonitoring` health-check
result or add a `backendReachable` boolean from the `/health` poll.

---

## SECTION 5: NEXT STEPS AND IMPLEMENTATION ROADMAP

### Immediate Actions (0–2 weeks) — Critical fixes

1. **Fix `soc_alert` overwrite bug** (NetworkMonitor.tsx line 354)
   - Change: `setLatestFusionScore(score)` → `setLatestFusionScore(prev => Math.max(prev, score))`
   - Owner: xdr-frontend-agent

2. **Remove monotonic ratchet — use `fusionScore` for gauge**
   - Delete `latestFusionScore` state variable.
   - Change OverviewView prop passing (line 855) from `latestFusionScore > 0 ? latestFusionScore : fusionScore` to just `fusionScore`.
   - If score-decay is desired, add a `useEffect` timer that calls `setFusionScore(prev => Math.max(0, (prev ?? 0) - 5))` every 60 s when no new `fusion_alert` arrives.
   - Owner: xdr-frontend-agent

3. **Fix System Status hardcoded rows**
   - Add `socketConnected` boolean state to NetworkMonitor, set via `socket.on('connect')`/`socket.on('disconnect')`.
   - Pass as prop to OverviewView; replace hardcoded `true` for "Backend API" and "Socket.IO".
   - Change "Fusion Engine" ok condition to `fusionScore !== undefined`.
   - Owner: xdr-frontend-agent

### Short-term (2–6 weeks) — High priority improvements

4. **Rename "Active Threats" → "Network Attacks" or build cross-source count**
   - Quickest: rename the label.
   - Better: pass `activeThreatCount = stats.attacks + anomalyCount + malwareCount + sysmonCount` from NetworkMonitor.
   - Owner: xdr-frontend-agent

5. **Add "Endpoints Online" StatCard**
   - Pass `endpoints: EndpointInfo[]` prop to OverviewView.
   - Add StatCard: label="Endpoints Online", value=`endpoints.filter(e => e.status === 'online').length`, accent="#10b981".
   - Owner: xdr-frontend-agent

6. **Extend recentAlerts to include system and endpoint sources**
   - Pass `systemAnomalies: any[]` and `endpointAlerts: EndpointAlert[]` props.
   - In `recentAlerts` useMemo, append HIGH/CRITICAL `systemAnomalies` (source="System") and `endpointAlerts` (source="Endpoint").
   - Owner: xdr-frontend-agent

### Medium-term (6–12 weeks) — Architecture enhancements

7. **Add System Health mini-widget**
   - Pass `systemAnomalies` prop; render the latest entry's `cpu_percent` and `memory_percent` as horizontal progress bars in the System Status panel.
   - Owner: xdr-frontend-agent

8. **Fix "User Behavior" status indicator**
   - Source from `/health` endpoint `user_agent` field or from `isMonitoring` (simpler).
   - Owner: xdr-frontend-agent

9. **Add "Waiting for data..." skeleton for gauge**
   - When `fusionScore === undefined`, render a grey gauge with "Awaiting telemetry" text instead of 0/LOW.
   - Owner: xdr-frontend-agent

---

## SECTION 6: METRICS AND KPIs TO TRACK

| Metric | Source | Target |
|--------|--------|--------|
| Gauge-to-backend drift | Compare `fusionScore` vs `/fusion` last result | 0 — must match within 1 cycle (10s) |
| Active Threats count accuracy | Cross-source count vs per-source counts | Verified equal to sum of all source alert counts |
| Endpoint online count display | `GET /endpoint/list` | Must equal `endpoints.filter(online).length` |
| System Status false-positive OK | Backend offline test | All 4 non-hardcoded rows must show IDLE within 30s of backend stop |
| Recent Alerts completeness | Manual injection of system, sysmon, endpoint alerts | All 5 source types appear in Overview recent feed |

================================================================================
END OF REPORT
Next Analysis Recommended: After xdr-frontend-agent applies fixes — verify gauge
behavior with a live backend session emitting multi-source `fusion_alert` events.
================================================================================
