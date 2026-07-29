---
name: Attack Replay & Tiered Storage — Gap Analysis 2026-05-10
description: What's built vs. missing for the Attack Reconstruction feature and tiered storage; implementation order and key conflicts
type: project
---

Assessment date: 2026-05-10. Report saved to D:\Cyber Sentinal\timeline\2026-05-10_attack-replay-assessment.md

**Already built (no duplication needed):**
- /endpoint/timeline/{id} REST endpoint + endpoint_timelines collection (50k cap)
- /attack-graph/timeline + /attack-graph/snapshot REST endpoints
- AttackGraphView with GraphControls replay scrubber (replayStep state, 900ms ticker)
- NodeDetailPanel with SHAP / Timeline / Response tabs
- FusionResult.components stored in fused_alerts (per-model scores + weights + contributions)
- shap_explanations tagged with endpoint_id + alert_ts since 2026-05-03
- response_plans stores plan_id, mitre_technique, shap_explanation
- case_notes collection + endpoints (analyst notes per endpoint_id)
- PDF incident report generator (5-section ReportLab)

**Critical conflicts to resolve first:**
1. edge.chain field is never set for live data — attack_graph.py upsert_edge() has no chain_seq counter; only mockData.ts has hardcoded chain values; live replay steps therefore never fire
2. fused_alerts (1k cap) will evict CRITICAL alerts before cold-tier can archive them — need dual-write to uncapped critical_alerts collection
3. ts fields stored as ISO strings — MongoDB TTL indexes require datetime objects; must fix _now() or add secondary datetime field before adding TTL indexes

**Missing HIGH-priority items:**
- GET /replay/{incident_id} unified bundle endpoint (6 data sources correlated by ts window)
- AttackReconstructionView 3-panel layout (left=graph+MITRE, center=ReplayTimeline, right=SHAP+notes)
- ReplayTimeline.tsx — animated step-by-step event log component
- FusionDecisionPanel.tsx — per-model contribution bars + escalation rule labels
- TTL indexes (LOW=7d, MEDIUM=30d, HIGH/CRITICAL=90d+)
- critical_alerts collection (uncapped, 180d TTL)
- chain_seq counter in AttackGraphEngine.upsert_edge()

**Missing MEDIUM-priority items:**
- Process tree data collection (Sysmon EventID 1 PID→PPID adjacency map)
- connection_snapshots collection (raw per-tick connection list for flow replay)
- Evidence Locker (evidence_locker collection + UI tab)
- Cold archive export (GET /archive/export zipped NDJSON)
- Process tree D3 visualization

**Implementation order: fix chain_seq + critical_alerts + TTL → /replay endpoint → 3-panel UI → process tree → evidence locker → cold archive**

**Why:** The /replay endpoint payload contract must be confirmed before frontend build; chain_seq fix must come before any replay UI work or step-based highlighting is permanently mock-only.

**How to apply:** When implementing any part of this feature, start by checking whether chain_seq is flowing in live attack_graph_edges before touching frontend replay logic. Never skip the critical_alerts dual-write when working on fused_alerts persistence. The 3-panel layout reuses existing components (AttackGraph, ResponseModal SHAP, CaseNotesPanel) — do not rebuild them.
