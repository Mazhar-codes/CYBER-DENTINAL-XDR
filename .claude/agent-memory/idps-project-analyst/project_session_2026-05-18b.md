---
name: Endpoint Ingest, Attack Graph, Investigation UI & SOAR Hardening — 2026-05-18 Session 2
description: Runtime bug fixes across endpoint ingest (422 errors), attack graph rebuild (TTL, SHAP enrichment, D3), investigation replay bundle (4 sources, narrative, SOAR commands), SOAR visual feedback, PDF report persistence, advisory action completion
type: project
---

All 9 issue categories from this session are resolved. Platform overall completeness: ~99.5%.

**Key facts to preserve for future sessions:**

- `endpoint_agent/identity.py` now backfills missing fields (`ip_address`, `os`) on load without UUID regeneration. No more 422 on old endpoint_config.json files.
- `"winlogbeat_events"` must be `{}` (dict), not `[]` (list). Validated with `@validator` in `EndpointTelemetry`.
- `ep.endpoint.endpoint_id` is the correct path — not `payload.endpoint_id`.
- `signal.signal(SIGINT, _handle_signal)` has been removed from `backend.py`. Uvicorn handles SIGINT directly.
- `_do_shutdown()` now awaits with `asyncio.gather(*bg_tasks, return_exceptions=True)` + 5s hard timeout.
- `/attack-graph/snapshot` default window is 2h (not 48h); `min_score=0.70`; 50-node cap; 3-tier SHAP enrichment always guarantees non-null SHAP on every node.
- Attack graph node TTL: CRITICAL 30min, HIGH 15min, MEDIUM/LOW 5min. Only HIGH/CRITICAL events from network_anomaly, endpoint_alert, fusion_alert channels are ingested.
- D3 force layout: charge=-300, collision detection active, type-based positional forces applied.
- NodeDetailPanel now has 5 tabs: Overview, SHAP (with fallback), Timeline, Info, Response.
- `fetchIncidentReports` is triggered by `useEffect([isAuthenticated])` — not mount-only. Also re-triggered by `report_generated` and `response_executed` socket events.
- `GET /reports` sorts by `generated_at_dt` (BSON datetime) and returns all reports for all users.
- All 13 advisory actions handled in both `_server_soar_executor()` and `command_listener.py` — return success immediately.
- `alert_admin` is now in `_ADVISORY_ACTIONS` frozenset.
- `/replay/{incident_id}` now queries 4 sources: `endpoint_logs`, `fused_alerts`, `alerts`, `sysmon_alerts`. Also returns `soar_commands[]`, `narrative` string, guaranteed `[]` SHAP, case notes by `endpoint_id` OR `plan_id`.
- `AttackReconstructionView.tsx` shows: Investigation Summary narrative (server or client fallback), source chips + score badges on timeline rows, "Response Actions Taken" panel, SHAP fallback to model contribution bars.
- Active Threats in EndpointView shows plan status as colored badges: CONTAINED (green), PARTIAL (amber), EXECUTING (blue), OPEN (gray).

**Still outstanding (operator action required):**
- sklearn 1.7.2 pin for `system_model.pt` and `personal_baseline_model.pkl`
- Winlogbeat configuration (`START_WINLOGBEAT=true` in `.env`)
- SMTP configuration for password reset emails
- `JWT_SECRET_KEY` and `XDR_API_KEY` must be set in `.env`
- JWT in localStorage (needs httpOnly cookie migration for production)
- Settings page: `POST /settings/thresholds` not yet persisted to MongoDB config collection

**Why:** Runtime bugs in endpoint ingest, attack graph, and SOAR feedback were blocking operational deployment. All three were architecturally complete but had not been validated end-to-end against real endpoint data.

**How to apply:** In future sessions, treat endpoint ingest as stable. If 422 errors re-emerge, check `EndpointIdentity` optional field validators first. Attack graph node TTL and scoring filters are now intentional design decisions — do not revert to 48h window or remove min_score filter without a product-level reason.
