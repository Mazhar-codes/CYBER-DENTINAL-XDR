---
name: Open Issues Audit 2026-05-19 (updated with v2 root-cause analysis)
description: 10 issues total — ThresholdSettings Pydantic gap; PDF executed_at None (str(None) bug); attack graph static nodes (not a bug); user behavior zero columns (OC-SVM vs heuristic schema mismatch); investigation graph SVG only (no D3); edge relation mismatch
type: project
---

ThresholdSettings in backend.py (line 6941) only declares 4 fields — malware_threshold and user_behavior_threshold are absent. Frontend POSTs them but Pydantic strips them silently. No module-level runtime variables exist for these two thresholds.

**Why:** Silent data loss; admin threshold adjustments have zero effect on malware/user detection sensitivity.

**How to apply:** Flag as high-priority fix before any production deployment. Wire new module-level vars _malware_threshold and _user_behavior_threshold into _maybe_emit_malware_fusion_alert() and user score gate.

Other confirmed defects:
- report_generator.py _build_attack_timeline() line 575: plain-string branch assigns _fallback_ts without truncation (32-char ISO string overflows 38mm column). Fix: _truncate(_fallback_ts, 26) and widen col from 38mm to 44mm.
- collect_forensics absent from _ADVISORY_ACTIONS (backend.py) and _build_response_actions._ADVISORY (report_generator.py) but present in _execution_final_status._ADV_SET — 3 sets out of sync.
- MALICIOUS_RELATIONS in useAttackGraphData.ts includes "triggered_alert" but backend snapshot uses "triggered" — all snapshot edges have malicious=false, attack chain replay shows 0 steps.
- DetectionPipelineFlow IS rendered in AttackReconstructionView.tsx (line 1658) but fused_alerts never stores components sub-document — component always renders in degraded mode.
- Audit Log GET /security/events only queries security_events collection; audit_logs (auth events) not fetched on mount — panel appears empty until live audit_event socket fires.
- monitor_persistence stuck pending/failed = privilege issue not code bug; elevation needed for HKLM registry access.

Overall completeness revised: ~97% (down from 99.5%).

## v2 Root-Cause Analysis — 4 Issues (2026-05-19)

**Issue 1 — PDF "Executed At: None" (CONFIRMED BUG):**
`endpoint_commands.executed_at` initialized to Python `None` at insert (backend.py line 6153). `_server_soar_loop` $set only writes `completed_at`, never `executed_at` at top level (lines 4938-4946). `endpoint_command_ack` writes `executed_at` inside nested `ack_result` sub-document (line 5573) not at top level. `report_generator.py` line 886: `exec_result.get("executed_at", exec_result.get("completed_at", "—"))` finds the key (value=None) and returns it; `.get()` does not fall through when key exists. `str(None)` = "None" is printed.
Fix A (report_generator.py line 886): change to `exec_result.get("executed_at") or exec_result.get("completed_at") or "—"`.
Fix B (backend.py ~line 4944 in _server_soar_loop): add `"executed_at": datetime.utcnow().isoformat()` to the $set.

**Issue 2 — Attack graph "static" nodes (NOT A BUG):**
AttackGraph.tsx is SVG-based D3 (not canvas). alphaDecay=0.022 causes natural convergence after ~200 ticks. Drag IS wired: d3.drag() on SVG g.ag-node, rebinds on nodeIdsKey, calls sim.alphaTarget(0.3).restart() on drag start. No fix needed. Optional: lower alphaDecay to 0.003 for slower convergence.

**Issue 3 — User behavior zeros (SCHEMA MISMATCH):**
user_collector.py outputs: current_user, sessions[], session_count. score_session_telemetry() outputs: user_score, anomaly, session_count, current_user, unusual_hours_detected, remote_sessions, flags. No collector/scorer mismatch. Bug is in the frontend: UI table displays OC-SVM column names (login_count, file_access_count) that only the Winlogbeat xdr_runtime pipeline produces. DESKTOP-BTH57BG$ (machine account) correctly scores 0 — not in _SYSTEM_ACCOUNTS set.
Fix: frontend User Behavior table columns → session_count, remote_sessions, unusual_hours_detected. Remove/N/A login_count and file_access_count.

**Issue 4 — Investigation graph SVG only (STRUCTURAL GAP):**
MiniGraph in AttackReconstructionView.tsx lines 212-331 is pure SVG pipeline showing event_type flow stages. Not D3, not interactive. GET /replay/{incident_id} returns no graph node/edge data (no nodes[]/edges[] arrays, no src_ip extraction, no process nodes). Fix: (1) backend /replay assembles graph:{nodes,edges} from endpoint_registry + fusion_alert.src_ip + malware timeline; (2) frontend replaces MiniGraph with existing AttackGraph D3 component. Effort: ~2.5h.
