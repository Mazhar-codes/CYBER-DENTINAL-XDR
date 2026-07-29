---
name: Alignment & Completion Audit 2026-05-16
description: Full-stack alignment audit results — 93% overall; 3 critical gaps found: missing auth/change-password endpoint, URL mismatches in ProfileView, and SOAR action routing gaps
type: project
---

Comprehensive alignment audit completed 2026-05-16. Overall weighted completion: 93% across 18 layers.

**Why:** Systematic check of Socket.IO, REST, TypeScript, SOAR, and auth alignment to identify runtime-breaking gaps before production handoff.

**How to apply:** Use these findings as the priority fix list for the next development session.

## Critical Gaps Confirmed

### 1. Missing POST /auth/change-password (CRITICAL)
- SettingsView.tsx line 426 calls `POST /auth/change-password`
- No such route exists in backend.py or auth/router.py
- Password change is completely broken for all users
- Fix: add endpoint to backend with current_password + new_password Pydantic model, bcrypt verification, session revocation, audit_event emit

### 2. SOAR Action Routing Conflict (HIGH)
- `lock_account`, `scan_filesystem`, `monitor_persistence` are implemented in BOTH executors (command_listener.py AND _server_soar_executor) but are NOT in `_ENDPOINT_VALID_ACTIONS` (lines 3780-3783)
- `scan_filesystem` and `monitor_persistence` are incorrectly in `_ADVISORY_ACTIONS` (lines 3786-3794) — so they are logged as advisory and never forwarded to remote agents
- `lock_account` is in neither frozenset — `/response/execute` silently drops it for remote endpoints
- Fix: move lock_account/scan_filesystem/monitor_persistence INTO `_ENDPOINT_VALID_ACTIONS` and remove scan_filesystem/monitor_persistence from `_ADVISORY_ACTIONS`

### 3. ProfileView URL Mismatches (HIGH)
- ProfileView.tsx line 177: calls `POST /auth/admin/create-user` — backend route is `POST /users/create`
- ProfileView.tsx line 643: calls `GET /case-notes` (no param) — backend route is `GET /case-notes/{endpoint_id}` (requires path param)
- Fix: change URL in ProfileView line 177; for case-notes either add unfiltered backend route or change UI to require endpoint selection first

## Socket.IO Gaps (Low Impact)
- `threat_score` event emitted by /fusion endpoint but no frontend subscriber (gauge works via fusion_alert anyway)
- `command_queued` event emitted by POST /endpoint/command but no frontend subscriber (no optimistic "queued" indicator)

## TypeScript Type Gaps (Non-Breaking)
- `FusionAlert` missing endpoint_id, attack_type, sources, shap_explanation fields
- `EndpointCommand.action` union missing 'unisolate_host'
- `EndpointFusionAlert.shap_explanation` typed as string[] but is array of objects
- `ResponsePlan.status` union missing 'contained' and 'partial' (backend states)
- `AuditEvent.user` vs backend's `user_id` + `username` mismatch

## Per-Layer Scores
Network Detection: 97%, User Behavior: 65%, System Monitor: 95%, Sysmon: 95%,
Malware: 99%, Fusion: 100%, SHAP: 95%, SOAR/Agent: 85%, EDR: 99%,
MongoDB: 99%, Frontend: 97%, Auth: 94%, About/Settings/Profile: 90%,
RBAC: 98%, Startup: 100%, Attack Replay: 93%, PDF Reports: 97%, Response Platform: 82%

## Report Location
D:\Cyber Sentinal\timeline\alignment_completion_report_20260516_204000.md
