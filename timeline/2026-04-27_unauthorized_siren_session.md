# Cyber Sentinel XDR — Session Report: 2026-04-27
## Unauthorized Access Handling, Siren Audio Rewrite, and AlertSiren Exit Bug Fix

**Session Date:** 2026-04-27  
**Analyst:** IDPS Project Analyst Agent  
**Scope:** Backend security event infrastructure, frontend unauthorized-access UX, siren audio dual-source system, AnimatePresence exit animation bug  
**Prior Overall Completeness:** ~91% (as of 2026-04-26)  
**Updated Overall Completeness:** ~93%

---

## 1. Features Implemented

### 1.1 Unauthorized Access Handling System (Backend)

**Files modified:** `D:\Cyber Sentinal\Backend\backend.py`

A global `@app.exception_handler(HTTPException)` decorator now intercepts every 401 and 403 response raised anywhere in the FastAPI application. The handler normalizes the JSON response body into a consistent contract:

- 401 → `{"error": "UNAUTHORIZED", "message": "Authentication required", "code": 401}`
- 403 → `{"error": "FORBIDDEN", "message": "Insufficient permissions", "code": 403}`

All other status codes pass through unchanged, preserving existing behaviour for 404, 422, 503, and other codes. The handler is hardened against infinite recursion: `_extract_jwt_identity()` is wrapped in a bare `try/except`, guaranteeing the handler itself never raises an `HTTPException`.

Four helper functions support the security event pipeline:

- `_extract_jwt_identity(request)` — decodes the Bearer JWT from `Authorization` header; returns `("anonymous", "none")` on any failure, never raises.
- `_get_client_ip(request)` — returns `X-Forwarded-For` first, then `request.client.host`; note this trusts the forwarded header without validation (documented outstanding issue).
- `_persist_security_event(doc)` — thin async wrapper around `_save("security_events", doc)`.
- `_log_security_event(request, http_code, user_id, role)` — builds the event document, emits a `WARNING` to the Python logger, and fires a non-blocking `asyncio.create_task(_persist_security_event(doc))` so the HTTP response is never delayed by database latency.

The `security_events` MongoDB collection was added to `_COLLECTION_CAP` with a 5 000-document cap. Three indexes were added in the startup routine: `timestamp DESC` (for time-range queries), `user_id` (for per-user audit drilldown), and `ip` (for attacker IP grouping).

Severity mapping: 401 responses are logged as `MEDIUM`; 403 responses as `HIGH`. This distinction allows future SOC alert rules to prioritize privilege escalation attempts over ordinary expired-session events.

**New endpoint:** `GET /security/events` (line 1380 in `backend.py`) — returns the last N security events sorted newest-first with `limit`/`skip` pagination. Dual-auth guard: accepted by a valid `X-API-Key` header OR a Bearer JWT whose `role` claim equals `admin`. Input bounds are clamped (limit: 1–500). Returns `{"events": [], "total": 0, "mongo_ok": false}` when MongoDB is unavailable rather than raising a 503.

---

### 1.2 Unauthorized Access Handling System (Frontend)

**Files modified/created:**
- `D:\Cyber Sentinal\Cyber Sentinal XDR Frontend\src\services\authService.ts`
- `D:\Cyber Sentinal\Cyber Sentinal XDR Frontend\src\components\ProtectedRoute.tsx`
- `D:\Cyber Sentinal\Cyber Sentinal XDR Frontend\src\components\UnauthorizedBanner.tsx` (new)
- `D:\Cyber Sentinal\Cyber Sentinal XDR Frontend\src\styles\global.css`
- `D:\Cyber Sentinal\Cyber Sentinal XDR Frontend\src\App.tsx`

The `authAxios` response interceptor in `authService.ts` now handles 403 and 401 distinctly:

- **403 path:** Fires `dispatchAccessDenied()` (dispatches a `new Event('accessDenied')` on `window`), shows a styled `react-hot-toast` error, and redirects to `/dashboard` (stays in the app — access denied should not destroy the session).
- **401 path:** Attempts a silent token refresh via `refreshToken()`. On success, replays the original request with the new token and drains a queue of concurrent requests waiting on the same refresh. On refresh failure, clears tokens, shows a session-expired toast, and redirects to `/login`. An `AUTH_BYPASS_PATHS` list (`/auth/login`, `/auth/register`, `/auth/refresh`, `/auth/verify-2fa-login`) prevents the interceptor from triggering a redirect loop on auth-layer calls.

`ProtectedRoute.tsx` gains a `requiredRole?: string | string[]` prop. When a logged-in user navigates to a route they lack the role for, `AccessDeniedOverlay` renders (full-screen dark background, radial red vignette, glitch lock icon, "ACCESS DENIED" heading, countdown text) while a 2 s `useEffect` fires `navigate('/dashboard', { replace: true })`.

`UnauthorizedBanner.tsx` listens for the `accessDenied` DOM event dispatched by the axios interceptor. On fire it applies `document.body.classList.add('unauthorized-glitch')` for 1.5 s, then renders a fixed red top banner (z-index 10000) with slide-in animation. Auto-dismiss: `exiting` state is set after 2.6 s, triggering a 400 ms CSS fade-out, followed by full unmount at 3.0 s. A manual dismiss button is also provided. The component renders `null` when not visible, adding zero overhead in the idle state.

`App.tsx` mounts `<UnauthorizedBanner />` at the root level above all routes.

`global.css` received six new keyframe blocks: `glitch`, `redFlash`, `banner-slide-in`, `banner-fade-out`, `access-denied-pulse`, `access-denied-text-glitch`.

---

### 1.3 Siren Audio System Rewrite

**Files modified/created:**
- `D:\Cyber Sentinal\Cyber Sentinal XDR Frontend\src\utils\sirenAudio.ts` (rewritten)
- `D:\Cyber Sentinal\Cyber Sentinal XDR Frontend\src\hooks\useSirenAudio.ts` (new)
- `D:\Cyber Sentinal\Cyber Sentinal XDR Frontend\src\components\AlertSiren.tsx`
- `D:\Cyber Sentinal\Cyber Sentinal XDR Frontend\src\components\NetworkMonitor.tsx`

The siren module was redesigned around Chrome/Firefox autoplay policy enforcement. An `AudioContext` created outside a user-gesture handler starts in `"suspended"` state; `ctx.resume()` calls from `useEffect` or Socket.IO callbacks are silently ignored by the browser.

The solution is a two-gate architecture:

1. **`enableAudio()`** — must be called from an `onClick` handler. Sets `_audioEnabled = true`, resumes the `AudioContext` within the user-gesture call stack, and lazily creates the `HTMLAudioElement` pointed at `/Sounds/siren.mp3.wav`.
2. **`startSiren()`** — no-op unless `_audioEnabled` is true. Tries the HTMLAudioElement (primary path); falls back to the Web Audio API oscillator (750 Hz carrier, LFO ±150 Hz at 0.5 Hz producing the 600–900 Hz emergency sweep) if the file fails to load or `play()` is rejected.

`useSirenAudio` is a React hook wrapping the module. It initialises `audioEnabled` from the module singleton (`isAudioEnabled()`) so a re-mounted component reflects the correct state without prompting the user again. The `play()` function has an `isPlaying` guard — if the siren is already running, a second call from a duplicate Socket.IO alert event does not restart or glitch the audio.

`NetworkMonitor.tsx` exposes an "Enable Sound Alerts" amber button in the top control bar. Its `onClick` calls `enableAudio()` from the hook, satisfying the user-gesture requirement. The `audioEnabled` boolean and `onEnableAudio` callback are threaded as props to `AlertSiren`.

---

## 2. Root Cause Analysis — AlertSiren Exit Bug

**Symptom:** The red vignette border and notification bar remained on screen after clicking "ACKNOWLEDGE". The exit animations defined in Framer Motion's `AnimatePresence` were not executing, so the UI elements never unmounted.

**Root Cause — Two compounding bugs:**

**Bug 1 — `repeat: Infinity` inside `animate` blocked `exit`.**
Framer Motion's `AnimatePresence` triggers an element's `exit` variant when the element is removed from the React tree. However, when a component has an infinite `animate` loop (`repeat: Infinity`), the animation engine never finishes its current animation tick, which means the `exit` variant is never scheduled to run. The vignette's pulsing red opacity loop (`animate={{ opacity: [0.3, 0.7, 0.3] }}` with `repeat: Infinity`) was the blocker.

**Bug 2 — React fragment inside `AnimatePresence` broke per-child keying.**
`AnimatePresence` identifies its children by React `key` props to know which child is entering or exiting. When children are wrapped in a `<>` fragment, React sees one child (the fragment), not the individual `motion.div`s inside it. The fragment has no `key`, so `AnimatePresence` cannot track the individual elements and does not call their exit callbacks.

**Fix Applied:**
- The infinite pulsing was moved out of Framer Motion entirely and into a CSS `@keyframes siren-vignette-pulse` rule injected via a `<style>` tag. Framer Motion now only handles `initial → animate` (enter) and `exit` (leave), both of which are discrete non-looping transitions. This allows `exit` to run immediately when `isActive` becomes `false`.
- The `<>` fragment wrapper was removed. Both `motion.div` elements (`key="siren-vignette"` and `key="siren-bar"`) are now direct children of `AnimatePresence`, giving each its own tracked lifecycle.

---

## 3. Implementation Status Per Layer (2026-04-27)

| Layer | Status | Notes |
|-------|--------|-------|
| Network Detection | 90% | Rule detector + RandomForest classifier fully operational |
| User Behavior | 55% | OC-SVM model works; Winlogbeat not configured |
| System Monitor | 68% | Resource-aware severity added; score=1.0 bug mitigated (retrain recommended) |
| Sysmon Behavior | 70% | File-based reader + PS forwarder working |
| Malware Detection | 98% | 3-tier labels, trusted-path whitelist, ransomware correlation gate |
| Fusion Engine | 100% | Multi-source requirements, confirmed-malware gates |
| SHAP Explainability | 80% | Network + malware; system/sysmon not yet |
| SOAR / Endpoint Agent | 92% | Label-gated quarantine/isolate |
| MongoDB / Persistence | 98% | 16 collections; `security_events` with 3 indexes added this session |
| Frontend / SOC Dashboard | 96% | UnauthorizedBanner, AccessDeniedOverlay, dual-source siren, exit bug fixed |
| Authentication & AuthZ | 97% | Global exception handler, security_events pipeline; forgot-password outstanding |

**Overall: ~93%**

---

## 4. Remaining Outstanding Issues

### Bugs (must fix before production)
- `system_model.pt` always returns score=1.0 due to sklearn 1.7.2 vs 1.8.0 scaler mismatch. Mitigated by `_resource_aware_severity`; root fix: pin sklearn or retrain.
- `personal_baseline_model.pkl` may have the same sklearn mismatch — verify Gate 1 pass-through rate.
- Dual Sysmon source risk: if Winlogbeat is active alongside the PS forwarder, events are processed twice. Needs a mutual-exclusion flag.
- `OverviewView.tsx` threat score uses client-side formula `net×0.6 + user×0.4` instead of subscribing to the `fusion_alert` Socket.IO event.

### Auth Layer
- Forgot-password flow (`/auth/forgot-password` + `/auth/reset-password` + email delivery) not implemented.
- JWT stored in localStorage — XSS-exfiltration risk; migrate to `httpOnly` cookies for production.
- In-memory rate limiter resets on server restart — use Redis or MongoDB-backed counters for production.
- Socket.IO `cors_allowed_origins` is still `"*"` — restrict to `["http://localhost:3000"]`.
- `X-Forwarded-For` header is trusted without validation — safe behind a reverse proxy, but exposed if the backend faces the internet directly.

### Configuration
- `JWT_SECRET_KEY` and `XDR_API_KEY` must be set in `.env`; server logs CRITICAL warning when defaults are in use.
- Winlogbeat not configured for security event log → `C:\XDR_Logs\` (user behavior reads 0 events).
- OCEAN personality features hardcoded to 0.0 — needs `POST /users/ocean` endpoint + `user_profiles` collection.

### Lower Priority
- Flow micro-fragmentation: CIC feature extraction needs micro-flow grouping before computation.
- SHAP not implemented for LSTM system monitor or Sysmon TF-IDF tokens.
- `_handle_sysmon_result` has no rate-limit cooldown; EventID 3 flooding can produce hundreds of socket emissions per minute.

---

## 5. Next Recommended Steps

1. **Fix Socket.IO CORS wildcard** — change `cors_allowed_origins="*"` to `["http://localhost:3000", "http://127.0.0.1:3000"]` in the `socketio.AsyncServer` constructor. One-line change, critical security gap.
2. **Fix `OverviewView.tsx` threat score** — subscribe to `fusion_alert` Socket.IO event and display `threat_score × 100` instead of the client-side formula.
3. **Retrain `system_model.pt`** — `python train_system_model.py --collect-minutes 60` with the correct sklearn version pinned in venv. Eliminates the score=1.0 false positives entirely.
4. **Implement forgot-password flow** — add `/auth/forgot-password` and `/auth/reset-password` endpoints; integrate an SMTP provider (e.g. SendGrid) or a one-time token stored in MongoDB.
5. **Add Sysmon alert rate-limiting** — add a cooldown dict in `_handle_sysmon_result` mirroring the 30 s cooldown already applied to system anomalies.
6. **SHAP for system monitor** — gradient-based attribution (e.g. `captum` for PyTorch) or simple feature contribution deltas for the LSTM Autoencoder.
7. **Migrate JWT to httpOnly cookies** — eliminates the primary XSS attack surface; requires CSRF token handling on mutation endpoints.
