---
name: Cyber Sentinel XDR — Full Architecture
description: Complete target spec: 5 detection layers, fusion engine, full auth/MFA/RBAC layer, MongoDB schema, SOAR-lite, multi-host endpoint agent; tracks what's built vs. outstanding — LAST UPDATED 2026-04-27 session 2 (endpoint_agent package, 6 backend endpoints, EndpointView, 3 MongoDB collections)
type: project
---

Cyber Sentinel XDR is a Windows-based AI-driven XDR/IDPS. As of 2026-04-27 session 2, overall completeness is ~95%. All detection layers code-complete. Auth backend complete; unauthorized access handling system added; siren audio fully rewritten. Standalone multi-host endpoint agent package deployed with full telemetry + SOAR response loop. Socket.IO CORS wildcard remains open.

**Built and functional (confirmed 2026-04-25):**
- `rule_detector.py` — 6 deterministic rules, incremental eve.json read, rotation guard, 2-min recency filter
- `hybrid_detector.py` — 2-gate detection; IsolationForest fallback active; personal_baseline_model.pkl PRESENT but may have sklearn 1.7.2→1.8.0 mismatch (Gate 1 possibly inactive)
- `xdr_runtime.py` — One-Class SVM user behavior inference engine
- `backend.py` — FastAPI + Socket.IO server, full agent wiring, MongoDB, API key auth, Atlas M0 trim; `_latest_scores` dict with 300s TTL; `_get_current_scores()` helper; `_handle_sysmon_telemetry()` wired; `sysmon_active` in monitoring_status
- `user_behavior_agent.py` — async wrapper; 60s interval (config.py default)
- `fusion_engine_agent.py` — 5-step pipeline: weighted base + corroboration bonus (×1.10/×1.20) + 4 escalation rules + reasons + clamp; `contributing_reasons: list[str]` on FusionResult. Weights: net=0.35, user=0.30, sys=0.15, mal=0.20
- `shap_agent.py` — network SHAP active; malware SHAP active; `explain_fusion()` added (pure contribution accounting)
- `malware_analysis_agent.py` — 280-dim EMBER features, LightGBM, pefile extraction
- `system_monitor_agent.py` — DEGRADED MODE but SELF-CALIBRATING: heuristic fallback active; system_model.pt STILL MISSING
- `endpoint_agent.py` — 5 SOAR actions + memory dump; quarantine_file has NO path allowlist (CWE-22)
- `sysmon_behavior_agent.py` — TF-IDF + IsolationForest/XGBoost (GHC dataset); PS forwarder working
- All frontend views wired: NetworkView, AlertsView (SHAP reasons column added), MalwareView, SystemStatusView, SysmonBehaviorView

**Model artifact status (D:\Cyber Sentinal\Backend\) — verified 2026-04-23:**
- PRESENT: malware_model.pkl, malware_scaler.pkl, malware_feature_names.pkl (AUC=0.9803, F1=0.9298)
- PRESENT: network_model_isolation.pkl, network_scaler.pkl, network_features.pkl (IsolationForest fallback)
- PRESENT: network_classifier.pkl + network_label_encoder.pkl (RandomForest, CIC-IDS2017, 99.6% accuracy)
- PRESENT: detector.pkl (Sysmon TF-IDF + IsolationForest, vocab=8524)
- PRESENT: personal_baseline_model.pkl — Gate 1 POSSIBLY INACTIVE due to sklearn mismatch
- MISSING: system_model.pt, system_scaler.pkl, system_metadata.json — run train_system_model.py --collect-minutes 60
- PRESENT: user_model.pkl, user_scaler.pkl (in User Behavior/final_model_backend_only/)

**Auth layer added 2026-04-26 session 2 (Backend/auth/ — 6 files):**
- auth/models.py — RegisterRequest, LoginRequest, TokenResponse, Requires2FAResponse, MFA2FALoginRequest, MFASetupResponse, MFAVerifyRequest, DisableMFARequest, RefreshRequest, UserResponse, user_doc_to_response()
- auth/security.py — bcrypt hashing (12 rounds), JWT HS256 create/decode (access=15min, refresh=7d, temp_2fa=5min), TOTP secret generation, QR code base64 PNG
- auth/rate_limiter.py — sliding-window in-memory rate limiter: 5 attempts/IP/15min
- auth/dependencies.py — get_current_user (Bearer JWT decode + MongoDB lookup + lockout check), require_role(*roles) RBAC factory
- auth/router.py — 10 endpoints: register, login, verify-2fa-login, refresh, logout, logout-all, me, enable-2fa, verify-2fa, disable-2fa; first user=admin; 5-failure lockout; suspicious login detection
- auth/mfa.py — OTPRateLimiter, UsedOTPCache, backup codes, device trust; CONFIRMED WIRED as of 2026-04-26 session 2 (was dead code, now integrated per MFA enterprise upgrade)

**Backend.py auth wiring (2026-04-26 session 2):**
- CORS: ["*"] → ["http://localhost:3000", "http://127.0.0.1:3000"] (HTTP only; Socket.IO still wildcard — OUTSTANDING)
- _require_key_or_jwt dual-auth dependency applied to /predict/network, /predict/user, /fusion, /shap, /system/analyze, /sysmon/status
- JWT_SECRET_KEY startup validation (CRITICAL log on default or <32 chars)
- sessions (10k cap) + audit_logs (50k cap) collections; unique indexes on jti, email, username
- Socket.IO connect() handler fixed: (sid, environ) → (sid, environ, data=None)

**Unauthorized Access Handling System (2026-04-27 — NEW):**
- Global @app.exception_handler(HTTPException): normalizes 401 → {"error":"UNAUTHORIZED","message":"Authentication required","code":401}; 403 → {"error":"FORBIDDEN","message":"Insufficient permissions","code":403}; all other codes pass through; handler is recursion-safe
- _extract_jwt_identity(request) — safe JWT decode, never raises, returns ("anonymous","none") on any error
- _get_client_ip(request) — X-Forwarded-For first, then request.client.host (still unvalidated — outstanding)
- _persist_security_event(doc) — async wrapper around _save("security_events", doc)
- _log_security_event(request, http_code, user_id, role) — builds doc, WARNING log, fire-and-forget asyncio.create_task write; severity: 401=MEDIUM, 403=HIGH
- security_events MongoDB collection: cap=5000, indexes: timestamp DESC, user_id, ip
- GET /security/events endpoint: dual-auth (API key OR admin JWT); limit/skip pagination; clamp 1–500; graceful MongoDB-unavailable fallback

**Frontend auth + unauthorized access files (2026-04-26 session 2 + 2026-04-27):**
- src/types/auth.ts, src/context/AuthContext.tsx
- src/services/authService.ts — axios interceptors (401 silent refresh queue + 403 dispatchAccessDenied); AUTH_BYPASS_PATHS prevents redirect loops
- src/pages/LoginPage.tsx, RegisterPage.tsx, MFASetupPage.tsx
- src/components/ProtectedRoute.tsx — requiredRole prop; AccessDeniedOverlay (2s countdown + glitch lock icon); hasRequiredRole(userRole, required) supports string|string[]
- src/components/AlertSiren.tsx — siren notification bar + vignette; EXIT BUG FIXED (see below)
- src/components/AuditLogPanel.tsx, OTPInput.tsx
- src/components/UnauthorizedBanner.tsx (NEW 2026-04-27) — listens to accessDenied DOM event; slide-in red banner z-index 10000; unauthorized-glitch body class; 2.6s auto-dismiss + 400ms fade-out
- src/utils/sirenAudio.ts (REWRITTEN 2026-04-27) — dual-source: HTMLAudioElement + Web Audio oscillator fallback; enableAudio() gate; _audioEnabled flag; stopSirenInternal(resetEl) unified stop
- src/hooks/useSirenAudio.ts (NEW 2026-04-27) — isPlaying guard prevents duplicate restart; initialises audioEnabled from module singleton
- src/styles/global.css — glitch, redFlash, banner-slide-in, banner-fade-out, access-denied-pulse, access-denied-text-glitch keyframes added
- App.tsx — <UnauthorizedBanner /> at root level; BrowserRouter routing: /login, /register, /dashboard (protected), /setup-2fa

**AlertSiren exit bug — ROOT CAUSE and fix (2026-04-27):**
Bug 1: repeat:Infinity inside Framer Motion animate blocked exit variant from ever running (animation engine never idle).
Bug 2: <> fragment inside AnimatePresence broke per-child keyed tracking — AnimatePresence saw one child (the fragment) not two motion.divs.
Fix: pulse moved to CSS @keyframes siren-vignette-pulse; both motion.divs are direct keyed children of AnimatePresence (key="siren-vignette", key="siren-bar").

**Open security issues (priority order — updated 2026-04-27):**
1. [CRITICAL] Tokens in localStorage (access + refresh) — XSS exfiltration risk (CWE-922)
2. [HIGH] Socket.IO cors_allowed_origins="*" — any origin receives real-time event stream (CWE-346)
3. [HIGH] X-Forwarded-For trusted without proxy validation — rate limiter bypass (CWE-348)
4. [MEDIUM] No forgot-password / change-password endpoint (alert() placeholder in LoginPage)
5. [MEDIUM] TOTP secrets stored plaintext in MongoDB (CWE-312)
6. [MEDIUM] In-memory rate limiter resets on restart (CWE-799)
7. [MEDIUM] OverviewView threat score formula diverges from backend fusion weights
8. [LOW] Access token has no JTI blacklist on logout — 15-min post-logout window

**Endpoint Agent Package (2026-04-27 session 2 — NEW):**
- D:\Cyber Sentinal\endpoint_agent\ — standalone Python package; runs on each monitored Windows host
- agent.py: asyncio runner; _telemetry_loop (5s) + _command_loop (3s) as concurrent tasks; CLI + env-var config (XDR_BACKEND_URL, XDR_API_KEY, XDR_COLLECT_INTERVAL, XDR_COMMAND_INTERVAL); --simulate flag
- identity.py: UUID endpoint_id; persisted to endpoint_config.json; in-process cache
- sender.py: httpx async; 3-attempt exponential backoff (1s/2s/4s); 10s timeout; never raises
- command_listener.py: poll_commands / execute_command / acknowledge_command; 5 actions:
  * kill_process (psutil; PID int() cast; name case-insensitive match)
  * block_ip / unblock_ip (strict IPv4 regex _IP_RE; netsh shell=False; rule: XDR_BLOCK_<ip>)
  * isolate_host (writes isolation_flag.txt; netsh interface "Wi-Fi" disable — NAME HARDCODED)
  * quarantine_file (absolute path validation; shutil.move to quarantine/)
- collectors/: network (psutil net_connections + 22-port suspicious list), system (cpu/mem/disk/procs), user (current user + sessions), malware (heuristic: suspicious proc names + temp-dir paths)
- requirements.txt: httpx>=0.27.0, psutil>=5.9.0

**Six new backend API endpoints (2026-04-27 session 2 — NEW):**
- POST /endpoint/ingest (API key; rate 1/2s per endpoint_id; upserts endpoint_registry; inserts endpoint_logs; background _analyze() → endpoint_alert; emits endpoint_update)
- GET /endpoint/commands/{endpoint_id} (API key; atomic fetch + mark-sent)
- POST /endpoint/command/ack (API key; update status; emit command_result)
- POST /endpoint/command (API key OR JWT admin/analyst; validate action + endpoint; emit command_queued)
- GET /endpoint/list (API key OR JWT; computed online/offline via 30s cutoff)
- GET /endpoint/{endpoint_id} (API key OR JWT; registry + last 20 logs + last 10 commands)
- _endpoint_heartbeat_loop(): every 30s; marks last_seen > 35s as offline; emits endpoint_offline

**Three new MongoDB collections (2026-04-27 session 2 — 17 total):**
- endpoint_logs (cap 10k; idx: endpoint_id, timestamp DESC)
- endpoint_registry (cap 500; unique idx: endpoint_id, last_seen DESC)
- endpoint_commands (cap 2k; idx: endpoint_id, status, created_at DESC)

**EndpointView.tsx (2026-04-27 session 2 — NEW):**
- "endpoints" ViewId added to Sidebar with onlineCount badge
- Three panels: (1) KPI bar + endpoint grid (cards with CPU/MEM progress bars, status dots, critical glow), (2) Endpoint Alerts table (last 20; row click selects endpoint), (3) Response Panel (online-only selector; 5 action buttons; isolate confirm dialog; Command History last 10 with OK/FAIL)
- Types: EndpointInfo, EndpointAlert, EndpointCommand, CommandResult in shared types file
- NetworkMonitor.tsx: 4 Socket.IO subscriptions (endpoint_update, endpoint_alert, endpoint_offline, command_result) + fetchEndpoints() on mount + handleSendCommand() via axios

**EDR Orchestration Layer (2026-05-02 — NEW):**
- response_engine.py: MITRE ATT&CK-mapped response planner; 9 attack type branches; 8 virtual actions (scan_filesystem, monitor_persistence, log_user_session, restrict_access, rate_limit_traffic, lock_account, alert_admin, alert_admin) NOT in _ENDPOINT_VALID_ACTIONS — execution fails HTTP 400 for these plan types
- report_generator.py: ReportLab PDF generator; 5-section layout; _REPORTS_DIR hardcoded to D:\Cyber Sentinal\reports (env var needed); reportlab>=4.0.0 in requirements.txt
- Six new backend endpoints: POST /response/plan, POST /response/execute (analyst+admin only), GET /response/plans, POST /reports/generate (admin only), GET /reports/{id}/download, GET /reports
- Fusion hook: auto-generates response plan on HIGH/CRITICAL severity; create_task pattern so hot path never blocked; emits response_required Socket.IO event
- CRITICAL BUG: /reports/generate fused_alert query has no endpoint_id filter — wrong alert data populates PDFs in multi-host environments
- CRITICAL BUG: response_executed emitted before MongoDB insert success check — command_ids may contain "unavailable" sentinel strings
- ResponseModal.tsx: shapFeatures hardcoded to [] — SHAP chart always empty despite plan.shap_explanation being present
- Two new MongoDB collections: response_plans (cap 2k) + incident_reports (uncapped metadata) = 19 total
- response_executed Socket.IO event NOT subscribed in NetworkMonitor.tsx — Active Threats panel never clears executed plans
- responseRequiredAlert state never cleared — Sidebar badge stays lit after first auto-plan

**Layer completeness (post 2026-05-02):**
- SOAR / Endpoint Agent: 97%; gaps: TLS, Windows Service, Linux iptables, auto-update
- EDR Orchestration: 88% (new layer); gaps: virtual-action execution (-5%), SHAP wiring (-4%), badge clear (-3%)
- MongoDB / Persistence: 99% (19 collections)
- Frontend / SOC Dashboard: 98% (ResponseModal + Active Threats + Incident Reports panels)
- Overall: ~97% (up from 95%)

**CRITICAL ACTIVE BUGS (2026-05-09 — requires immediate fix):**

BUG-A: False CRITICAL fusion alerts from endpoint telemetry (alert storm on busy machines)
- Root cause: global `_fe` buffer (backend.py:3226) is shared between server-pipeline events AND endpoint events. Endpoint's system source (cpu=100% → system_score=1.0) enters the 120-second window that already has server-pipeline network/user events → CorrelationEngine fires 2-source HIGH escalation → CRITICAL.
- The direct FusionEngineAgent.fuse() at line 3139 correctly produces LOW (0.15) for system-only anomaly. The bug is the GLOBAL FE FEED at line 3214-3229 which bypasses the correct score.
- Contributing factors: (1) _resource_aware_severity() returns HIGH for cpu>85% regardless of LSTM score → is_genuinely_anomalous=True; (2) assess_process_metadata() evaluates ALL processes (not just pre-screened suspicious list) → malware_score>0.30 → corroboration bonus fires.
- Fix location: backend.py:3214 — raise threshold from `max_score > 0.4` to `max_score >= 0.70 AND severity in ("HIGH","CRITICAL")` to gate global feed to confirmed threats only.
- Secondary fix: system_monitor_agent.py:768 — require score >= 0.35 before returning HIGH from _resource_aware_severity().
- Tertiary fix: malware_analysis_agent.py:635 — scope combined_names to suspicious_list only, not all processes.

BUG-B: Response plans not visible in EndpointView Active Threats panel
- Root cause: global `_fe` call at backend.py:3226 does NOT attach `endpoint_id` to `fe_out`. FusionDecisionEngine.ingest_event() returns dict with keys {alerts, correlation, final_decision} — no endpoint_id. _emit_soc_alert_if_correlated:2335 falls back to _involved_hosts[0] (hostname string) or "server_host". Response plan stored with endpoint_id=hostname, not UUID.
- EndpointView.tsx:1228 filters by `p.endpoint_id === selectedEndpointId` (UUID). UUID never matches hostname → plans invisible.
- The DIRECT call path at backend.py:3180 correctly passes `"endpoint_id": ep.endpoint_id` — but this path only fires when fusion.should_respond=True (score>=0.70). For system-only anomalies (score=0.15), this path is never reached.
- Fix: after `fe_out = await asyncio.to_thread(_fe.ingest_event, fe_event)` at line 3226, add `fe_out["endpoint_id"] = ep.endpoint_id` before calling _emit_soc_alert_if_correlated.
- Combined with BUG-A fix (raise threshold to 0.70), this means global feed only fires for confirmed HIGH/CRITICAL AND correctly tags plans with UUID.

**Still outstanding (operational):**
- Winlogbeat not writing to C:\XDR_Logs\ — user behavior reads 0 events
- OCEAN features (O,C,E,A,N) hardcoded to 0.0 in xdr_runtime.py
- Flow micro-fragmentation: CIC features computed on micro-flows, not aggregated flows
- system_model.pt still untrained — highest-value next training task; sklearn mismatch causes score=1.0 always
- SHAP not yet implemented for system monitor (LSTM) or Sysmon behavior (TF-IDF token weights)
- Sysmon alert rate-limiting missing — _handle_sysmon_result has no cooldown
- isolate_host hardcodes "Wi-Fi" interface name — configurable NIC name is a pending improvement
- GET /reports/{id}/download has no role check — any authenticated viewer can download forensic PDFs
- report_generated Socket.IO payload exposes pdf_path (absolute filesystem path) — path disclosure
- asyncio.create_task() at backend.py:3179 should be fire-and-forget (remove await)

**Why:** Three root causes drive most open issues: (1) untrained LSTM model (operational gap),
(2) Winlogbeat misconfiguration (highest coverage impact), (3) Socket.IO CORS wildcard (highest
security impact — one-line fix, highest ROI). Endpoint agent adds a fourth: no TLS on agent channel.

**How to apply:** Prioritize Socket.IO CORS fix as the single highest-ROI security change remaining.
When reviewing auth, note that mfa.py is now wired (not dead code). When reviewing siren audio,
remember that enableAudio() MUST be called from an onClick — never from useEffect or Socket.IO handlers.
When reviewing the endpoint agent, note that isolate_host hardcodes "Wi-Fi" — this is a known
limitation and should not be confused with a bug in other network commands.
