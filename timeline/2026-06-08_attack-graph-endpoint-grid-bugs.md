================================================================================
IDPS PROJECT ANALYSIS REPORT
================================================================================
Timestamp     : 2026-06-08 00:00:00 UTC
Analyst       : IDPS Project Analyst Agent
Scope         : Bug analysis — Attack Graph node/edge flickering (Bug 1) and
                Endpoint Grid duplicate cards (Bug 2)
Project Phase : Production hardening / reliability pass
Files Reviewed:
  - Cyber Sentinal XDR Frontend/src/components/views/AttackGraphView/useAttackGraphData.ts
  - Cyber Sentinal XDR Frontend/src/components/views/AttackGraphView/AttackGraph.tsx
  - Cyber Sentinal XDR Frontend/src/components/NetworkMonitor.tsx  (lines 406–486)
  - Cyber Sentinal XDR Frontend/src/components/views/EndpointView.tsx (lines 406–409)
  - Backend/backend.py  (lines 5423–5509, 5940–5984)
================================================================================

## EXECUTIVE SUMMARY

Both bugs were confirmed in code. Bug 2 (duplicate endpoint cards) is fully
resolved by the deduplication filter already present at EndpointView.tsx:409.
Bug 1 (attack-graph flickering) is partially mitigated by the `endpointLastSeenRef`
and recency-guard already in useAttackGraphData.ts, but three residual root causes
remain unaddressed: (1) the `endpoint_update` handler still removes nodes
unconditionally on `status === "offline"` emitted by the backend heartbeat, which
fires on a 10-second cycle and can race with a 5-second telemetry cycle; (2) the
`createdAt` timestamp is reset to `Date.now()` on every `endpoint_update`,
shortening the effective TTL window; (3) the secondary `edgeCount` useEffect in
AttackGraph.tsx reheats the D3 simulation to alpha=0.3 on every new edge,
including the harmless "monitors" edge that is re-added on every telemetry cycle
when the `edgeKeySetRef` is not correctly persisted across hot-reload.
Overall project health for these two surfaces: 6/10 — one bug fully fixed, one
requires targeted follow-up.

---

## SECTION 1: CODE QUALITY ASSESSMENT

### 1.1 Strengths

- `useAttackGraphData.ts` correctly uses `nodeIdSetRef` and `edgeKeySetRef` as O(1)
  lookup sets, avoiding O(n) array scans on every socket event.
- Position preservation in `AttackGraph.tsx:206-218` (`posMap` from `simRef.current.nodes()`)
  correctly captures D3-mutated x/y coordinates before creating the new `nodes` memo,
  preventing the position-randomisation problem on state updates.
- The gentle alpha reheat (0.2 on topology change, line 293) rather than a full 1.0
  restart is the correct pattern for incremental updates.
- `edgeKey()` helper enforces a consistent canonical string representation,
  preventing ghost duplicate edges from arriving through different code paths.
- `NetworkMonitor.tsx:414` already implements an upsert-by-`endpoint_id` pattern
  with a recency guard (60-second `last_seen` check before appending new entries).
- `EndpointView.tsx:409` already applies a client-side deduplication filter using
  `arr.findIndex(e => e.endpoint_id === ep.endpoint_id) === idx`.

### 1.2 Issues Found

| Severity | Component | Issue | Recommendation |
|----------|-----------|-------|----------------|
| HIGH | useAttackGraphData.ts:1208 | `endpoint_update` handler removes node immediately on `status === "offline"` with no debounce. Backend heartbeat marks offline at 35s; the frontend drops the node at the exact moment the event arrives, which can coincide with the next 5s ingest cycle if timing is unlucky. | Introduce a `OFFLINE_REMOVAL_DELAY_MS = 8000` setTimeout — only remove the node if no subsequent `endpoint_update` with `status !== "offline"` arrives within the delay window. |
| HIGH | useAttackGraphData.ts:1241 | `createdAt: Date.now()` is written on every `endpoint_update` event (line 1241). This resets the node TTL clock on every 5-second heartbeat, which is semantically correct for liveness but means a node that goes silent will expire at `Date.now() + TTL_of_severity` from the *last heartbeat*, not from when it was first seen. No correctness issue for online nodes, but it means the 60-second TTL cleanup interval can never reclaim endpoint nodes that went offline without emitting an `endpoint_offline` event (e.g. abrupt agent kill). | Do not overwrite `createdAt` if the node already exists. Merge with `existing ? { ...existing, ...epNode, createdAt: existing.createdAt } : epNode`. |
| MEDIUM | AttackGraph.tsx:356-363 | The `edgeCount` useEffect reheats the simulation to `alpha(0.3)` whenever `edgeCount` changes. The "monitors" edge is added per endpoint per telemetry cycle whenever `edgeKeySetRef` is rebuilt (e.g. after `clearGraph()`). If `edgeKeySetRef` loses sync, this fires every 5 seconds. | Add a guard: only reheat if `alpha() < 0.05` (already present) AND the new edge is not a benign "monitors" type. Alternatively track `maliciousEdgeCount` separately and only key the reheat effect on that. |
| MEDIUM | useAttackGraphData.ts:1209 | The offline removal handler does not consult `endpointLastSeenRef` (which is declared at line 312 but never written to). The ref is initialised but the code that was supposed to write to it on each `endpoint_update` is absent — the ref is effectively dead code. | Either write `endpointLastSeenRef.current.set(nid, Date.now())` inside the `endpoint_update` handler (at the start, before the offline guard), and read it in the offline branch to reject removals where `Date.now() - lastSeen < 8000`, or remove the unused ref. |
| LOW | useAttackGraphData.ts:227-235 | `NODE_TTL_MS.LOW` and `NODE_TTL_MS.MEDIUM` are both 5 minutes. The TTL cleanup runs every 60 seconds. A LOW-severity endpoint node created by `fetchTopology()` will expire after 5 minutes and never be re-added unless a new `endpoint_update` arrives, creating a permanent gap in the topology view for idle endpoints. | Either extend LOW/MEDIUM TTL for `type === "endpoint"` nodes, or exclude endpoint nodes (type === "endpoint" or type === "server") from TTL expiration entirely — they are kept alive by the heartbeat loop, not by threat events. |
| LOW | AttackGraph.tsx:226-234 | The `links` memo uses `data.NODES` directly to build `nodeIds` for the dead-link filter, but `nodes` (the D3-position-enriched array) is the value actually passed to the simulation. These should reference the same source of truth. Currently they are consistent because `nodes` and `data.NODES` contain the same IDs, but the double traversal adds unnecessary complexity. | Derive `nodeIds` from the `nodes` memo instead: `const nodeIds = new Set(nodes.map(n => n.id))`. |

---

## SECTION 2: SECURITY VULNERABILITY ANALYSIS

### 2.1 Critical Vulnerabilities

None identified in scope of these two UI/reliability bugs.

### 2.2 High Severity

None directly associated with these bugs.

### 2.3 Medium/Low Severity

| Severity | Description | Impact | Remediation |
|----------|-------------|--------|-------------|
| MEDIUM | `useAttackGraphData.ts` creates a second independent Socket.IO connection (line 674) in addition to the one owned by `NetworkMonitor.tsx`. This means two WebSocket connections are established to the backend per dashboard session, doubling socket resource usage per user. | Increased backend socket handler overhead; potential for event duplication if both sockets receive the same broadcast. | Pass the shared socket from `NetworkMonitor.tsx` down as a prop or via context rather than creating a second `io()` instance inside the hook. |
| LOW | `localStorage.getItem("access_token")` is used inline at the Socket.IO `auth` option (line 679). This is read only at socket-creation time — if the token expires and is silently refreshed by `authAxios`, the socket's auth token goes stale until the component unmounts/remounts. | Expired token on the attack-graph socket will cause a silent auth failure if the backend enforces token validity on socket events. | Use a `socket.auth` dynamic function or disconnect/reconnect the socket after a token refresh event from `AuthContext`. |

---

## SECTION 3: ARCHITECTURE GAP ANALYSIS

| Layer | Component | Status | Notes |
|-------|-----------|--------|-------|
| Network Monitoring | Suricata / Zeek / rule_detector | N/A | Out of scope for this analysis |
| Frontend Graph State | useAttackGraphData.ts | Partial | Position preservation and edge deduplication implemented; offline debounce missing |
| Frontend Endpoint Grid | NetworkMonitor.tsx setEndpoints | Partial | Upsert-by-id correct; recency guard present; see Bug 2 resolution below |
| Frontend Render Guard | EndpointView.tsx grid filter | Implemented | `.filter((ep, idx, arr) => arr.findIndex(...) === idx)` at line 409 |
| Backend Heartbeat | _endpoint_heartbeat_loop | Implemented | 35s stale threshold + session_start guard; emits both endpoint_offline and graph_update_remove |
| Graph Engine TTL | NODE_TTL_MS / 60s cleanup | Partial | MEDIUM/LOW 5-min TTL too short for idle endpoint nodes |
| D3 Simulation Stability | AttackGraph.tsx | Partial | reheat on edgeCount change may fire on benign monitor edges |
| Dead ref | endpointLastSeenRef | Missing | Declared but never written — debounce guard has no data |

---

## SECTION 4: CONFLICTS AND INCOMPATIBILITIES

### 4.1 Bug 1 — Attack Graph Node/Edge Flickering

**Root Cause: CONFIRMED (partial)**

Three distinct contributing mechanisms were identified:

**Mechanism A — `endpoint_update` instant offline removal (PRIMARY)**
File: `useAttackGraphData.ts`, lines 1208-1219

```
if (event.status === "isolated" || event.status === "offline") {
    const nid = `ep-${event.endpoint_id}`;
    setData((prev) => ({
      ...prev,
      NODES: prev.NODES.filter((n) => n.id !== nid),
      EDGES: prev.EDGES.filter(...)
    }));
    nodeIdSetRef.current.delete(nid);
    return;
}
```

The backend heartbeat loop (`_endpoint_heartbeat_loop`, backend.py:5423) runs
every 10 seconds and marks endpoints offline when `last_seen > 35s`. However the
`endpoint_update` emitted by `/endpoint/ingest` at backend.py:5982 always carries
`status: "online"`. The concern is not that the backend emits a stale offline
status in an `endpoint_update` — it does not. The concern is the inverse:
`endpoint_offline` triggers `handleEndpointOffline` at line 1298 which also
filters nodes. The collision between:
  - `endpoint_offline` firing at T=35s (removes node)
  - `endpoint_update` firing at T=5s, T=10s, ... T=30s (adds/updates node)
  - `endpoint_offline` at T=35s racing with `endpoint_update` at T=35s

...means there is a 10-second window (35s-45s) where the backend considers the
endpoint offline but the frontend has just removed the node. If the endpoint
resumes and sends another ingest at T=38s, the backend emits `endpoint_update`
with `status: "online"` and the node reappears — completing the flicker cycle
that operators observe.

**Mechanism B — `createdAt` reset on every update (SECONDARY)**
File: `useAttackGraphData.ts`, line 1241
`createdAt: Date.now()` in `epNode` is always spread onto the existing node
(`existing ? { ...existing, ...epNode } : epNode` at line 1267). This resets
the TTL clock on every heartbeat, which prevents TTL-based cleanup from reclaiming
nodes that went genuinely silent — but has no flickering effect on its own.

**Mechanism C — `endpointLastSeenRef` dead code (TERTIARY)**
File: `useAttackGraphData.ts`, line 312
The ref is declared with the comment "Used to suppress false-positive node removal
during the short telemetry gap" but is never written to. The debounce it was
intended to enable is effectively absent. The comment is misleading documentation.

**Mechanism D — D3 reheat on benign edges**
File: `AttackGraph.tsx`, lines 356-363
The `edgeCount` effect reheats the simulation whenever any edge is added. "monitors"
edges from `fetchTopology()` are non-malicious and stable, but if `edgeKeySetRef`
loses sync (e.g. after `clearGraph()`), the topology re-fetch adds them again,
incrementing `edgeCount` and triggering an alpha(0.3) reheat. This does not cause
node removal but does cause visible layout jitter.

---

### 4.2 Bug 2 — Endpoint Grid Duplicate Cards

**Root Cause: CONFIRMED — and already fixed**

The original root cause was in `NetworkMonitor.tsx` where `setEndpoints` appended
without deduplication. The fix is present at two layers:

**Layer 1 — NetworkMonitor.tsx:412-439 (upsert logic)**
```typescript
const idx = prev.findIndex(e => e.endpoint_id === (data as EndpointInfo).endpoint_id);
if (idx >= 0) {
  const updated = [...prev];
  updated[idx] = { ...updated[idx], ...data, ... };  // merge, preserve fields
  return updated;
}
// recency guard before append
const lastSeen = (data as EndpointInfo).last_seen;
if (lastSeen) {
  const age = (Date.now() - new Date(lastSeen).getTime()) / 1000;
  if (age > 60) return prev;
}
return [data as EndpointInfo, ...prev];
```
This is the primary deduplication point. It correctly finds by `endpoint_id` and
merges-in-place rather than appending.

**Layer 2 — EndpointView.tsx:409 (render-time guard)**
```typescript
.filter((ep, idx, arr) => arr.findIndex(e => e.endpoint_id === ep.endpoint_id) === idx)
```
This is a defensive second layer at render time. It ensures that even if state
somehow contains duplicates (e.g. from a race between the initial `fetchEndpoints()`
REST call and an arriving `endpoint_update` socket event before state settles),
the grid renders each `endpoint_id` exactly once.

**Residual race condition (NOT YET FIXED):**
There is one remaining scenario where duplicates could briefly appear in state
(not in the rendered grid, but in the `endpoints` array):
- `fetchEndpoints()` at NetworkMonitor.tsx:160 fires on mount and returns a list
  of N endpoints via REST.
- Simultaneously, `endpoint_update` socket events arrive for the same endpoints.
- Both paths call `setEndpoints`. If `fetchEndpoints` resolves after some socket
  events have already been processed, the REST response may contain the same
  endpoints that were already added by the socket handler.
- `setEndpoints(res.data?.endpoints ?? [])` at line 163 is a wholesale replacement
  (not a merge), so it overwrites whatever the socket handlers have accumulated.
  This means the REST response is the authoritative initial state, which is correct.
  However if the REST call resolves after 2+ seconds, any socket events that arrived
  in that window and were added to state will be overwritten — endpoints that are
  currently active may momentarily disappear and then reappear in their card.

This is a low-severity cosmetic race, not a security issue. The render-time filter
at EndpointView.tsx:409 prevents duplicate *rendering* in all cases.

---

## SECTION 5: NEXT STEPS AND IMPLEMENTATION ROADMAP

### Immediate Actions (0-2 weeks) — Critical/High fixes

**Fix 1: Implement offline-removal debounce in useAttackGraphData.ts**

Replace the instant node removal in the `endpoint_update` handler (lines 1208-1219)
and the `handleEndpointOffline` handler (lines 1298-1308) with a debounced approach:

```typescript
// At the top of the socket useEffect, alongside nodeIdSetRef:
const offlineDebounceRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());

// In endpoint_update handler, replace the instant-removal block:
if (event.status === "isolated" || event.status === "offline") {
  const nid = `ep-${event.endpoint_id}`;
  // Cancel any existing debounce for this node (a new heartbeat arrived)
  if (offlineDebounceRef.current.has(nid)) return;
  const timer = setTimeout(() => {
    offlineDebounceRef.current.delete(nid);
    setData((prev) => ({
      ...prev,
      NODES: prev.NODES.filter((n) => n.id !== nid),
      EDGES: prev.EDGES.filter(
        (e) => resolveId(e.source) !== nid && resolveId(e.target) !== nid
      ),
    }));
    nodeIdSetRef.current.delete(nid);
  }, 8000); // 8s > 5s ingest interval; gives one ingest cycle to cancel
  offlineDebounceRef.current.set(nid, timer);
  return;
}
// In the non-offline branch: cancel any pending offline debounce
const pendingTimer = offlineDebounceRef.current.get(`ep-${event.endpoint_id}`);
if (pendingTimer) {
  clearTimeout(pendingTimer);
  offlineDebounceRef.current.delete(`ep-${event.endpoint_id}`);
}
```

Apply the same debounce to `handleEndpointOffline`. Clear all timers in the
socket cleanup return function.

**Fix 2: Write to `endpointLastSeenRef` or remove dead code**

Either implement the ref properly:
```typescript
// At start of endpoint_update handler (non-offline path):
endpointLastSeenRef.current.set(`ep-${event.endpoint_id}`, Date.now());
```
Or delete the declaration at line 312 and the comment block — dead code with
misleading comments is a maintenance liability.

**Fix 3: Preserve `createdAt` on endpoint node update**

In the `endpoint_update` handler, change line 1267 from:
```typescript
nodeMap.set(nid, existing ? { ...existing, ...epNode } : epNode);
```
to:
```typescript
nodeMap.set(nid, existing ? { ...existing, ...epNode, createdAt: existing.createdAt } : epNode);
```
This prevents the TTL clock from being reset on every 5-second heartbeat for
nodes that should eventually expire after going silent.

### Short-term (2-6 weeks) — Medium priority improvements

**Fix 4: Exclude endpoint/server nodes from TTL expiry**

In the 60-second TTL cleanup useEffect (lines 341-377), add a guard:
```typescript
for (const node of prev.NODES) {
  // Topology nodes (server hub, endpoint agents) are managed by the heartbeat
  // loop and the endpoint_offline event — never expire them via TTL.
  if (node.type === "server" || node.type === "endpoint") continue;
  const ttl = NODE_TTL_MS[node.severity] ?? NODE_TTL_MS.MEDIUM;
  ...
}
```

**Fix 5: Key D3 reheat only on malicious edge count changes**

In `AttackGraph.tsx`, replace the `edgeCount` effect dependency with a
malicious-only count:
```typescript
const maliciousEdgeCount = links.filter(l => l.malicious).length;
useEffect(() => {
  const sim = simRef.current;
  if (!sim) return;
  if (sim.alpha() < 0.05) {
    sim.alpha(0.3).restart();
  }
}, [nodeIdsKey, maliciousEdgeCount]);
```
This prevents benign "monitors" and "responded_by" edges from causing layout
jitter.

**Fix 6: Deduplicate on fetchEndpoints REST merge**

In `NetworkMonitor.tsx`, change the `setEndpoints` call inside `fetchEndpoints`
from a wholesale replacement to a merge:
```typescript
setEndpoints(prev => {
  const socketMap = new Map(prev.map(e => [e.endpoint_id, e]));
  const merged = (res.data?.endpoints ?? []).map((e: EndpointInfo) => {
    const existing = socketMap.get(e.endpoint_id);
    return existing ? { ...e, ...existing } : e; // socket fields take precedence
  });
  return merged;
});
```

### Medium-term (6-12 weeks) — Architecture enhancements

**Fix 7: Unify Socket.IO connection ownership**

`useAttackGraphData.ts` creates a second Socket.IO connection independent of
the one in `NetworkMonitor.tsx`. Move all socket subscriptions for attack-graph
events into the single socket owned by `NetworkMonitor.tsx` and pass data down
via props or a shared React context. This eliminates the duplicate connection,
reduces backend load, and ensures token refresh is handled in one place.

**Fix 8: Dynamic socket auth token refresh**

When `AuthContext` refreshes the access token, force-reconnect the attack-graph
socket with the new token:
```typescript
socket.auth = { token: localStorage.getItem("access_token") };
socket.disconnect().connect();
```

### Long-term (3-6 months) — Advanced capabilities

- Implement a server-side `graph_update` event that the backend emits on every
  endpoint ingest, carrying a diff payload (new/changed/removed node IDs) rather
  than requiring the frontend to reconstruct topology from individual socket events.
  This moves the source of truth for graph state to the backend's `AttackGraphEngine`
  and eliminates the client-side race conditions entirely.
- Add a graph reconciliation poll (e.g. `/attack-graph/snapshot` every 60s) to
  correct any divergence between frontend state and backend state that may
  accumulate through missed socket events.

---

## SECTION 6: METRICS AND KPIS TO TRACK

| Metric | Current Baseline | Target | Measurement Method |
|--------|-----------------|--------|--------------------|
| Attack graph node flicker rate | Observed every 35-45s per endpoint | 0 flickers/session | Browser console — count `endpoint_offline` events followed by node re-add within 8s |
| Endpoint grid duplicate card occurrences | Fixed at render; residual in state array | 0 duplicates in state | `endpoints.length === new Set(endpoints.map(e=>e.endpoint_id)).size` assertion in React DevTools |
| D3 simulation reheat frequency | On every socket event with new edge | Max 1/min | Track `sim.alpha()` > 0.1 events in browser profiler |
| Socket connection count per session | 2 (NetworkMonitor + AttackGraph) | 1 (unified) | Browser DevTools — Network > WS tab |
| `endpointLastSeenRef` write coverage | 0% (dead code) | 100% of endpoint_update events | Code review + unit test |
| False offline events per hour | Unknown | 0 | Backend log: count `[heartbeat] marking offline` for endpoints that reconnected within 60s |

---

## SECTION 7: FIX ADEQUACY SUMMARY

| Bug | Planned Fix | Status | Completeness | Edge Cases Remaining |
|-----|-------------|--------|-------------|----------------------|
| Bug 1: Graph flickering | upsert by endpoint_id + lastSeen ref debounce | PARTIAL | 40% | Debounce not implemented; ref is dead code; createdAt reset; TTL expires topology nodes |
| Bug 2: Duplicate cards | upsert in NetworkMonitor + render filter | COMPLETE | 95% | Cosmetic race between fetchEndpoints REST and socket events (state-only, not rendered) |

---

## SECTION 8: RISK ASSESSMENT FOR PROPOSED FIXES

| Fix | Regression Risk | Justification |
|-----|----------------|---------------|
| Offline debounce (Fix 1) | LOW | Isolated to `endpoint_update` handler; does not touch detection pipeline; debounce timer is cleared on next live heartbeat |
| Preserve `createdAt` (Fix 3) | NEGLIGIBLE | Purely additive; only affects TTL cleanup which runs every 60s |
| Exclude endpoint nodes from TTL (Fix 4) | LOW | Endpoint nodes are managed by heartbeat loop; TTL exclusion just removes a redundant second expiry path |
| Malicious-only edge reheat (Fix 5) | LOW | Reduces reheat frequency; layout will settle more slowly after benign topology changes, which is acceptable |
| fetchEndpoints merge (Fix 6) | MEDIUM | Merging REST and socket state requires care about field precedence; test with both fast and slow network conditions |
| Socket unification (Fix 7) | HIGH | Architectural change; requires careful prop/context threading and testing of all 13 socket events currently subscribed in useAttackGraphData.ts |

================================================================================
END OF REPORT
Next Analysis Recommended: After Fix 1 (offline debounce) and Fix 3 (createdAt
preservation) are deployed — approximately 2 weeks. Verify with a 30-minute live
monitoring session that no node/edge disappearances occur during normal endpoint
telemetry cycles.
================================================================================
