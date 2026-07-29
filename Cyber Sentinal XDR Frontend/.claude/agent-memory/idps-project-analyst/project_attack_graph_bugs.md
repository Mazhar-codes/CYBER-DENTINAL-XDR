---
name: Attack Graph and Endpoint Grid Bug Analysis
description: Root causes and fix status for Bug 1 (attack-graph flickering) and Bug 2 (duplicate endpoint cards) — analysed 2026-06-08
type: project
---

Two reliability bugs analysed on 2026-06-08.

**Bug 2 (Endpoint Grid duplicates) — RESOLVED**
- `NetworkMonitor.tsx:414` upserts by `endpoint_id` (merge-in-place).
- `EndpointView.tsx:409` has a render-time deduplication filter as a second layer.
- Residual: cosmetic state-only race between `fetchEndpoints()` REST and socket
  events; does not affect rendered output.

**Why:** Each `endpoint_update` socket event was appending a new entry instead of merging.

**Bug 1 (Attack Graph flickering) — PARTIALLY MITIGATED, NOT FULLY FIXED**
Three unresolved issues remain:
1. `useAttackGraphData.ts:1208` removes endpoint nodes instantly on `status === "offline"`.
   No debounce. Backend heartbeat fires every 10s with 35s stale threshold — can race
   with a 5s ingest cycle, causing flicker in the 35-45s window.
2. `endpointLastSeenRef` (line 312) is declared but never written to — dead code.
   The debounce it was meant to enable does not exist.
3. `createdAt` is reset to `Date.now()` on every `endpoint_update`, preventing TTL
   cleanup from reclaiming silently-gone endpoint nodes.
4. Endpoint/server-type nodes should be excluded from the 5-min TTL cleanup — they
   are managed by the heartbeat loop.

**How to apply:** Any work touching `useAttackGraphData.ts` or the attack graph
should implement the 8-second offline-removal debounce, write to `endpointLastSeenRef`,
preserve `createdAt` on merge, and exclude endpoint nodes from TTL expiry.
