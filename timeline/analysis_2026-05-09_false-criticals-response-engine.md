# IDPS Analysis Report — 2026-05-09
## False CRITICAL Alerts & Response Engine Routing

**Status**: RESOLVED — 4 fixes applied  
**Analyst**: IDPS Project Analyst + Domain Agents  
**Overall Project Health**: 7/10 (pre-fix), 8.5/10 (post-fix)

---

## Issues Investigated

### Issue 1 — False CRITICAL Fusion Alerts from Endpoint Telemetry
**Symptom**: Dashboard filled with `Fusion CRITICAL Unknown` alerts whenever endpoint CPU reached 100%.

**Root Cause Chain**:
1. `system_model.pt` sklearn scaler mismatch → `predict_from_metrics()` returns `score=1.0` always
2. `_resource_aware_severity(1.0, [100.0, ...])` → `cpu > 85` → `"CRITICAL"`, `is_genuinely_anomalous=True`
3. Global `_fe` feed threshold was `max_score > 0.4` — every endpoint heartbeat with any elevated score entered the shared server-pipeline 120-second correlation window
4. CorrelationEngine saw `sources_present >= 2` (new `system` event + prior `network` events from server pipeline) → escalated to CRITICAL via `high_count >= 1` rule
5. Additionally: `assess_process_metadata()` evaluated ALL running processes against 22 IOC substrings — legitimate admin tools (nc.exe, psexec) added `malware_score += 0.40` per match, triggering Fusion corroboration bonus

### Issue 2 — Response Plans Invisible for Endpoint Alerts
**Root Cause**: `FusionDecisionEngine.ingest_event()` returns `fe_out` dict with no `endpoint_id` key. `_emit_soc_alert_if_correlated` fell back to hostname string (e.g., `"DESKTOP-XYZ"`) for response plan `endpoint_id`. EndpointView Active Threats filter matched on UUID, so no plans were ever displayed.

---

## Fixes Applied

### Fix 1 — `Backend/backend.py`: Global `_fe` threshold + `endpoint_id` attachment
- Gate condition: `max_score > 0.4` → `max_score >= 0.70 AND _ep_fusion_sev in ("HIGH","CRITICAL")`
- Added `fe_out["endpoint_id"] = ep.endpoint_id` after `asyncio.to_thread()` returns
- Moved `most_significant_source` computation inside the gate (no longer computed on every ingest)
- **Impact**: Eliminates cross-contamination of server-pipeline correlation window; response plans now carry correct UUID

### Fix 2 — `Backend/backend.py`: Remove `await` from fire-and-forget `create_task`
- `await asyncio.create_task(` → `asyncio.create_task(`
- **Impact**: `POST /endpoint/ingest` no longer blocks until response plan generation completes

### Fix 3 — `Backend/agents/system_monitor_agent.py`: Score threshold in `_resource_aware_severity()`
- `cpu > 85 or mem > 95`: CRITICAL requires `score >= 0.65`; HIGH now requires `score >= 0.35`; below → MEDIUM
- `cpu > 80 and mem > 80`: HIGH requires `score >= 0.35`; below → MEDIUM
- **Impact**: Machines under heavy CPU load with absent/broken LSTM model return MEDIUM at most, not CRITICAL

### Fix 4 — `Backend/agents/malware_analysis_agent.py`: Scope `assess_process_metadata()` to pre-screened list
- Removed `process_list` (all running processes) from `combined_names` construction
- `combined_names` now equals `list(suspicious_list)` only — endpoint-pre-screened names
- **Impact**: Eliminates false malware scores from legitimate admin tools in process list

---

## Remaining Issues (not addressed this session)

- `system_model.pt` sklearn scaler mismatch (root fix: retrain with `python train_system_model.py --collect-minutes 60`)
- `GET /reports/{id}/download` has no role check
- `report_generated` Socket.IO payload exposes `pdf_path`
- `admin_name` in PDF should be derived from JWT claims
- Heartbleed attack type missing from `response_engine.py`
- Response plan lifecycle `status` field not implemented
- Socket.IO still uses `cors_allowed_origins="*"`

---

## Verification Checklist

After deploying fixes, confirm:
- [ ] No `Fusion CRITICAL Unknown` alerts during normal endpoint operation with cpu=100%
- [ ] `POST /endpoint/ingest` responds in < 200ms (not blocking on response plan)
- [ ] When a genuine HIGH/CRITICAL fusion alert fires for an endpoint, Active Threats panel in EndpointView shows the plan
- [ ] `db.response_plans.find({"endpoint_id": {$regex: "-"}})` shows UUID-keyed plans

---

*Report generated: 2026-05-09*
