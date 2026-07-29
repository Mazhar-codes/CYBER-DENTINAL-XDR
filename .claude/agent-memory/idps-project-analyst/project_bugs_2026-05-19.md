---
name: Runtime Bug Analysis 2026-05-19
description: Root-cause analysis of 4 confirmed bugs: os NameError in isolate_host, endpoint timestamp drift, user behavior metric columns showing dashes, attack graph NaN
type: project
---

4 bugs root-caused via static trace on 2026-05-19.

**Bug 1 — NameError in _server_soar_executor (backend.py line 4839)**
`import os as _os` at line 43 means bare `os.path.*` is unbound. The single
use-site in the `isolate_host` branch was not updated. isolate_host SOAR is
completely broken on server_host.
Fix: replace with `Path(__file__).parent / "isolation_flag.txt"`.

**Why:** Late-stage refactor aliased `os` to `_os` but missed one call site.
**How to apply:** Always check that `os as _os` is consistent throughout the file before closing any SOAR bug.

---

**Bug 2 — Endpoint timestamp drift 73755s (DESKTOP-BTH57BG)**
Timestamp generation in agent.py line 256 is correct and fresh each tick.
Drift is an operational hardware-clock skew on the endpoint — NOT a code bug.
Backend does NOT drop stale payloads (only logs a warning). Scoring is
unaffected; MongoDB documents use server-side `_now()` timestamps.
Fix: `w32tm /resync /force` on DESKTOP-BTH57BG.

**Why:** Nothing to fix in code; resolved by NTP resync on endpoint.
**How to apply:** When drift warnings appear, escalate to endpoint operator rather than modifying code.

---

**Bug 3 — User behavior columns show dashes (backend.py lines 5457–5459)**
`user_anomaly` Socket.IO event uses field names `session_count`, `unusual_hours`,
`remote_sessions`. `UserAnomalyRow` TypeScript interface (types.ts lines 104–106)
and `UserBehaviorView.tsx` render logic (lines 741–772) expect
`concurrent_sessions`, `unusual_hour`, `has_remote_session`.
The `!= null` guards evaluate false → dashes rendered. Score display is
unaffected (uses `anomaly_score` fallback).
Fix: rename 3 keys in `user_anomaly` emit + add `user_score` key.

**Why:** Field names diverged between backend emit and TypeScript interface with no compile-time check.
**How to apply:** When adding new Socket.IO fields, always cross-check against the TypeScript interface in types.ts.

---

**Bug 4 — Attack graph NaN and vanishing nodes**
NaN: `Math.round(NaN)` returns NaN if `attack_graph.py` produces a
`risk_score` of NaN (e.g., 0/0). Guard needed in `backendNodeToGraphNode` line 169:
`isNaN(n.risk_score) ? 0 : Math.round(n.risk_score)`.
meanRisk calculation in AttackGraphView.tsx lines 265–271 already has a
`nodes.length > 0` guard and `?? 0` — NOT the source of NaN.
Vanishing: TTL expiry (CRITICAL 30min, HIGH 15min, MEDIUM/LOW 5min) is
intentional. Looks like a bug on quiet networks with no new events.
snapshot wipe: fetchSnapshot replaces NODES entirely — confirmed, this is the
correct behavior for clearGraph() but does wipe in-flight live nodes on slow
initial loads (race condition, low severity).
backendEdgeToGraphEdge: reads `e.relation` correctly (not `e.type`) — no bug.

**Why:** NaN propagation from Python division, TTL design intent misread as bug.
**How to apply:** Any Python code computing risk_score must guard division by zero.
