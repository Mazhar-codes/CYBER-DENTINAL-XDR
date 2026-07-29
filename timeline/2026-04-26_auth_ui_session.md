================================================================================
IDPS PROJECT ANALYSIS REPORT
================================================================================
Timestamp     : 2026-04-26 18:00:00 UTC
Analyst       : IDPS Project Analyst Agent
Scope         : Authentication & Authorization System (session 2) — Backend auth
                package (6 files), backend.py integration, config.py additions,
                12 new frontend files, 3 modified frontend files; 3 bug fixes
                resolved during development
Project Phase : Phase 4 — Production Hardening & Security Layer Integration
================================================================================

## EXECUTIVE SUMMARY

Today's session delivered a complete authentication and authorization layer for
Cyber Sentinel XDR, transforming the system from an entirely unauthenticated API
into a production-grade security stack with JWT-based session management, bcrypt
password hashing, TOTP multi-factor authentication, IP-aware rate limiting, RBAC
(admin/analyst/viewer), cryptographic refresh-token rotation, full audit logging
to MongoDB, and real-time audit event streaming to the SOC dashboard. These
changes eliminate the most critical pre-production blocker: every sensitive API
endpoint was previously callable by any actor with network access to port 8000.
Three bugs discovered during the session — FastAPI 422 validation error rendering
crash, Socket.IO connect() TypeError, and login form collapsing while typing —
were resolved before the session closed.

Overall project health score: 8.1/10 (up from 7.4/10 in the prior session).
The remaining gap to 10/10 is the 2FA URL mismatch between frontend and backend,
in-memory rate limiter loss on restart, localStorage token storage exposure risk,
Socket.IO CORS wildcard bypass, unimplemented password-reset flow, and outstanding
pre-existing gaps (Winlogbeat, sklearn scaler mismatch, OCEAN features).

================================================================================

## SECTION 1: CODE QUALITY ASSESSMENT

### 1.1 Strengths

- auth/router.py is cleanly decomposed across 10 endpoints with no mixed concerns.
  Each endpoint handles exactly one action; shared logic (audit writes, session
  document construction, suspicious-login detection) is extracted into private
  helpers (_write_audit, _create_session_doc, _detect_suspicious_login).

- auth/security.py uses lazy import wrappers (_require_jose, _require_bcrypt,
  _require_pyotp, _require_qrcode) that raise clear RuntimeError with pip install
  instructions rather than opaque ImportError at call time. This is the correct
  pattern for optional dependency groups.

- Timing oracle prevention in the login path is correctly implemented: when the
  email is not found, a dummy bcrypt hash is computed at the same cost factor
  (rounds=settings.bcrypt_rounds) before returning 401, preventing response-time
  enumeration of registered addresses.

- bcrypt 72-byte truncation is explicitly handled in hash_password() and
  verify_password() with .encode("utf-8")[:72], which is the correct treatment
  of bcrypt's hard limit. Without this, passwords longer than 72 bytes silently
  compare equal to their 72-byte prefix (CWE-916 variant).

- Refresh token rotation is correctly implemented: old session is deactivated
  before new session is inserted, not after. Hash-mismatch on refresh
  immediately revokes the session, which is the right response to a potential
  stolen-token replay attempt.

- TOTP provisioning correctly separates two_factor_secret storage (stored during
  enable-2fa) from two_factor_enabled activation (set only after verify-2fa
  confirms the device), preventing the scenario where a user saves a QR code but
  never completes enrollment yet the system treats them as 2FA-protected.

- The dual-auth dependency (_require_key_or_jwt) is well-scoped: endpoints called
  by the endpoint agent use _require_key; endpoints called by SOC dashboard users
  use _require_key_or_jwt; the separation is intentional and correctly reflects
  the two different caller populations.

- authService.ts refresh queue pattern (isRefreshing flag + refreshQueue array) is
  the correct approach for handling concurrent 401s without issuing multiple
  parallel refresh requests. Callbacks are drained via processRefreshQueue after
  the new token is obtained.

- AuthContext.tsx hydration sequence (access token → getMe → fallback to
  refresh → getMe → clear) correctly handles both warm sessions and expired
  access tokens on page load without requiring a full re-login.

### 1.2 Issues Found

| Severity | Component | Issue | Recommendation |
|----------|-----------|-------|----------------|
| CRITICAL | authService.ts L152-162 | MFA management URLs do not match backend. Frontend calls /auth/2fa/enable, /auth/2fa/verify-setup, /auth/2fa/disable. Backend exposes /auth/enable-2fa, /auth/verify-2fa, /auth/disable-2fa. All three MFA management functions will return 404. | Fix: change to /auth/enable-2fa, /auth/verify-2fa, /auth/disable-2fa |
| CRITICAL | authService.ts L116 | verify2FA() (login step) calls POST /auth/verify-2fa. Backend endpoint is POST /auth/verify-2fa-login. 2FA login will always fail with 404. | Fix: change URL to /auth/verify-2fa-login |
| HIGH | backend.py L425 | Socket.IO server is initialized with cors_allowed_origins="*" while HTTP CORS is correctly restricted to localhost:3000. Any origin can establish a Socket.IO connection and receive real-time telemetry, alert, and audit_event emissions without authentication. | Set cors_allowed_origins=["http://localhost:3000","http://127.0.0.1:3000"] to match HTTP CORS policy |
| HIGH | authService.ts L79-80 | Both access_token and refresh_token are stored in localStorage. A single XSS vector anywhere in the React app can exfiltrate both tokens. The refresh token has a 7-day lifetime; compromise is persistent. | Migrate access_token to memory (React state) and refresh_token to an HttpOnly Secure cookie. This is the standard mitigation (Auth0, Okta, and OAuth RFC 6819 all recommend it) |
| HIGH | auth/rate_limiter.py | In-memory rate limiter resets on every uvicorn worker restart. Under --workers >1 or any rolling restart, an attacker can simply wait for or force a restart to clear their lockout. Also provides no protection across multiple uvicorn worker processes sharing the same port. | Replace with Redis-backed limiter (redis-py + asyncio) for production. Acceptable to keep for development but must be flagged as pre-production gap |
| HIGH | auth/router.py L255 | During dummy hash for timing protection, hash_password is called with the full bcrypt rounds setting (12). This correctly prevents timing oracle but introduces a 200-400ms delay on every "user not found" response, which under load causes thread-pool exhaustion. Bcrypt at 12 rounds takes ~250ms per hash. | Use bcrypt.checkpw against a pre-computed sentinel hash stored at startup rather than computing a fresh hash per request. See hash_password call in login() on user-not-found path |
| MEDIUM | auth/models.py L94 | LoginRequest allows password field max_length=128. RegisterRequest also allows 128. bcrypt truncates at 72 bytes (UTF-8). A user who sets a password longer than 72 chars will be silently authenticated by any prefix of the same 72 bytes. The 72-byte truncation in security.py is correct but users are unaware of this constraint. | Add max_length=72 to password fields in both request models, or document the effective password limit prominently |
| MEDIUM | auth/dependencies.py L164-177 | X-Forwarded-For is trusted blindly as a string from the request header. If the backend is ever placed behind a reverse proxy that passes a client-supplied X-Forwarded-For without stripping/prepending, an attacker can supply a spoofed IP to bypass the rate limiter. | Only trust X-Forwarded-For when the connection originates from a known trusted proxy IP. Add TRUSTED_PROXIES list to config.py |
| MEDIUM | auth/router.py L100-113 | _write_audit emits the audit event to Socket.IO with from backend import sio inside an async helper. This circular import pattern (backend.py imports auth/router.py at line 705 which imports backend.py at runtime) works by relying on the module being fully initialized by the time audit events fire. It is fragile: any import ordering change during startup could cause AttributeError. | Pass sio as a module-level singleton reference to the auth router at registration time rather than importing it inside the function |
| MEDIUM | auth/router.py | No /auth/forgot-password or /auth/reset-password endpoint exists. Users who lose their credentials have no self-service recovery path. | Implement email-based OTP reset or admin-forced password reset endpoint |
| MEDIUM | auth/router.py | No /auth/change-password endpoint exists for authenticated users to update their own password. | Add POST /auth/change-password requiring current_password + new_password |
| LOW | auth/security.py L233-243 | QR code uses ERROR_CORRECT_L (lowest error correction). For security-sensitive enrollment where a scan failure could lock a user out of their account, ERROR_CORRECT_M or ERROR_CORRECT_Q is preferred. | Change to qrcode.constants.ERROR_CORRECT_M |
| LOW | auth/router.py L794 | /auth/audit-log endpoint has limit capped at 500 but no time-range filtering. Retrieving 500 entries in a capped 50k collection on every AuditLogPanel refresh is acceptable but will degrade as the collection fills. | Add start_time and end_time query parameters for range-bounded queries |

================================================================================

## SECTION 2: SECURITY VULNERABILITY ANALYSIS

### 2.1 Critical Vulnerabilities

**VULN-AUTH-001: 2FA Login Endpoint URL Mismatch (CWE-706)**
- Description: authService.ts L116 calls POST /auth/verify-2fa for the login
  2FA step. The backend endpoint is POST /auth/verify-2fa-login. Every user with
  2FA enabled will receive a 404 after entering their OTP, making 2FA functionally
  broken as a second factor for login. This is a de-facto authentication bypass
  for 2FA-protected accounts: users who enable 2FA will be unable to log in at all.
- Impact: Complete 2FA lockout for any user who enables the feature. Depending on
  how the frontend handles the 404 error, it may also silently succeed (if the
  error is swallowed), meaning the 2FA second-factor check is never actually
  executed.
- CWE: CWE-706 (Use of Incorrectly-Resolved Name or Reference)
- Remediation: In authService.ts, change the verify2FA function URL from
  '/auth/verify-2fa' to '/auth/verify-2fa-login'.

**VULN-AUTH-002: MFA Management Endpoints All Return 404 (CWE-706)**
- Description: authService.ts calls /auth/2fa/enable, /auth/2fa/verify-setup, and
  /auth/2fa/disable. Backend exposes /auth/enable-2fa, /auth/verify-2fa, and
  /auth/disable-2fa. None of the three MFA management operations are reachable
  from the frontend.
- Impact: Users cannot enable, verify, or disable 2FA through the UI. The
  MFASetupPage.tsx is entirely non-functional. This makes the TOTP infrastructure
  built in this session unreachable via the normal UI flow.
- CWE: CWE-706
- Remediation: In authService.ts update three function URLs:
  enable2FA: /auth/2fa/enable → /auth/enable-2fa
  verify2FASetup: /auth/2fa/verify-setup → /auth/verify-2fa
  disable2FA: /auth/2fa/disable → /auth/disable-2fa

### 2.2 High Severity

**VULN-AUTH-003: Tokens Stored in localStorage (CWE-922)**
- Description: Both access_token (15 min) and refresh_token (7 days) are stored
  in localStorage via storeTokens() in authService.ts. Any JavaScript executing
  in the page context — including injected third-party scripts, npm supply-chain
  compromises, or XSS — can read both tokens via document.localStorage. The
  refresh token's 7-day lifetime means a single XSS exploitation yields persistent
  access even after the access token expires.
- Impact: Persistent session hijacking. An attacker exfiltrating the refresh token
  can silently obtain new access tokens for up to 7 days, invisible to the victim.
- CWE: CWE-922 (Insecure Storage of Sensitive Information), OWASP A02:2021
- Remediation: Store access_token in React memory (useState/Context) only. Store
  refresh_token in an HttpOnly Secure SameSite=Strict cookie set by the backend
  on login. The backend /auth/refresh endpoint reads from the cookie rather than
  the request body. This eliminates all JavaScript access to the refresh token.

**VULN-AUTH-004: Socket.IO CORS Wildcard (CWE-346)**
- Description: socketio.AsyncServer is initialized with cors_allowed_origins="*"
  at backend.py L425. The HTTP FastAPI middleware correctly restricts CORS to
  localhost:3000, but Socket.IO uses its own CORS handling independent of FastAPI
  middleware. The wildcard permits any origin to establish a WebSocket connection
  and receive the full real-time event stream including network_anomaly, system_anomaly,
  malware_alert, user_anomaly, fusion_alert, and audit_event emissions.
- Impact: Any web page a SOC operator visits while the backend is running can
  silently subscribe to real-time security event feeds, exfiltrating live threat
  intelligence and operator audit trails.
- CWE: CWE-346 (Origin Validation Error), OWASP A05:2021
- Remediation: Change backend.py L425 to:
  cors_allowed_origins=["http://localhost:3000", "http://127.0.0.1:3000"]

**VULN-AUTH-005: In-Memory Rate Limiter Not Persistent (CWE-799)**
- Description: LoginRateLimiter stores attempt timestamps in a Python dict that
  is process-local and reset on every uvicorn restart. Under development with
  --reload, every code change resets all rate limit counters. An attacker who can
  trigger a backend restart (e.g., via a malformed request that causes an unhandled
  exception) gets a clean rate limit slate.
- Impact: Brute-force attacks can circumvent the 5-attempt/15-minute window by
  forcing restarts between attack waves.
- CWE: CWE-799 (Improper Control of Interaction Frequency)
- Remediation: Use Redis (asyncio-redis or redis-py with async support) for
  rate limit state. The counter key is f"login_ratelimit:{ip}" with TTL=900s.
  For development without Redis, current behavior is acceptable but must be
  documented as a known gap.

**VULN-AUTH-006: X-Forwarded-For Spoofing Risk (CWE-348)**
- Description: get_request_ip() in auth/dependencies.py trusts the first value
  of X-Forwarded-For without verifying the connection originates from a trusted
  proxy. If the backend is exposed directly (no reverse proxy) or placed behind
  a proxy that does not strip client-supplied headers, an attacker can set
  X-Forwarded-For: 1.2.3.4 to present any IP to the rate limiter, bypassing
  per-IP lockouts entirely.
- Impact: Rate limiter and suspicious-login detection can be defeated by any
  client with HTTP header control.
- CWE: CWE-348 (Use of Less Trusted Source)
- Remediation: Add TRUSTED_PROXY_IPS setting (default: ["127.0.0.1"]). In
  get_request_ip(), only use X-Forwarded-For when request.client.host is in
  TRUSTED_PROXY_IPS.

### 2.3 Medium/Low Severity

**VULN-AUTH-007: No TOTP Replay Protection (CWE-294)**
- Description: verify_totp() in auth/security.py uses pyotp with valid_window=1
  (accepts codes from the previous 30s step, current step, and next 30s step).
  There is no used-OTP cache. The same TOTP code can be replayed within its
  validity window (~90 seconds) to authenticate multiple times.
- Impact: Network packet replay or shoulder-surfing within the 90-second window
  bypasses 2FA protection.
- CWE: CWE-294 (Authentication Bypass by Capture-replay)
- Remediation: Maintain a Redis set or MongoDB collection of recently used JTIs
  from temp_token values. On successful verify-2fa-login, record the temp_token
  JTI. Reject duplicate uses within the token's 5-minute expiry.

**VULN-AUTH-008: TOTP Secret Stored Unencrypted in MongoDB (CWE-312)**
- Description: two_factor_secret is stored as a plaintext BASE32 string in the
  users collection (auth/models.py document shape, written in auth/router.py
  enable_2fa()). If the MongoDB instance is compromised, all TOTP secrets are
  exposed, allowing an attacker to generate valid OTPs for every 2FA-enabled user.
- Impact: Complete 2FA bypass for all users on database compromise.
- CWE: CWE-312 (Cleartext Storage of Sensitive Information)
- Remediation: Encrypt the TOTP secret with AES-256-GCM using a key derived from
  settings.jwt_secret_key before storing. Decrypt at verify time. This is an
  application-layer encryption pattern appropriate when dedicated secrets management
  (HSM, KMS) is not available.

**VULN-AUTH-009: JWT Algorithm Confusion Risk (CWE-327)**
- Description: HS256 is hardcoded in security.py but algorithms=[algorithm] is
  passed as a list to jwt.decode(). The python-jose library's decode() accepts
  the algorithms list but does not enforce algorithm pinning by default in all
  versions. If the JWT_ALGORITHM config value is changed to RS256, the existing
  HS256-signed tokens would be accepted until they expire.
- Impact: Low immediate risk; becomes relevant during key rotation or algorithm
  migration.
- CWE: CWE-327 (Use of Broken or Risky Cryptographic Algorithm)
- Remediation: Pin to algorithms=["HS256"] explicitly in decode_token() rather
  than passing the configurable algorithm string. Algorithm changes should require
  explicit code changes, not config changes.

**VULN-AUTH-010: Two-Factor Secret Not Cleared on Password Reset (informational)**
- Description: When /auth/disable-2fa is called, two_factor_secret is set to None
  and two_factor_enabled is set to False. However, there is no password reset
  endpoint yet. When one is added, it must also invalidate all sessions and
  optionally reset 2FA, otherwise a password reset does not fully recover from
  account compromise.
- Impact: Post-password-reset account access if attacker retains a valid session.
- Remediation: Any future /auth/forgot-password flow must call logout-all and
  optionally invalidate 2FA configuration.

================================================================================

## SECTION 3: ARCHITECTURE GAP ANALYSIS

Layer-by-layer assessment of all system components following today's changes.

| Layer | Component | Status | Notes |
|-------|-----------|--------|-------|
| Authentication | JWT access tokens (HS256, 15 min) | Implemented | HS256 with configurable secret; CRITICAL log on default key |
| Authentication | JWT refresh tokens (HS256, 7 days) | Implemented | Bcrypt-hashed before storage; rotation on every refresh call |
| Authentication | bcrypt password hashing (12 rounds) | Implemented | 72-byte truncation correctly handled |
| Authentication | Account lockout (5 failures, 15 min) | Implemented | Applied at login; checked on every authenticated request |
| Authentication | TOTP multi-factor authentication | Partial | Backend fully implemented; frontend URL mismatch makes it unreachable (VULN-AUTH-001, VULN-AUTH-002) |
| Authentication | Refresh token HttpOnly cookie | Missing | Tokens in localStorage (VULN-AUTH-003) |
| Authentication | Password reset / forgot-password | Missing | No endpoint exists; no email transport wired |
| Authentication | Change-password for authenticated users | Missing | No /auth/change-password endpoint |
| Authorization | RBAC (admin/analyst/viewer) | Implemented | require_role() factory; admin bypasses all checks |
| Authorization | First-user-is-admin provisioning | Implemented | user_count==0 check in /auth/register |
| Authorization | Dual-auth (_require_key_or_jwt) | Implemented | Endpoint agent uses API key; SOC users use JWT |
| Rate Limiting | Per-IP sliding window (5/15min) | Partial | In-memory only; resets on restart (VULN-AUTH-005) |
| Audit Logging | Immutable audit trail in MongoDB | Implemented | 50k cap; all auth actions written with user/IP/status |
| Audit Logging | Real-time Socket.IO audit stream | Implemented | audit_event emission; AuditLogPanel in frontend |
| Audit Logging | Suspicious login detection | Implemented | New IP or device from last active session flagged |
| Session Management | Session documents in MongoDB | Implemented | jti-indexed; is_active flag; logout/logout-all |
| Session Management | Refresh token rotation | Implemented | Old session deactivated before new session created |
| Session Management | TOTP replay protection | Missing | Same OTP reusable within 90s window (VULN-AUTH-007) |
| Frontend Auth | LoginPage with 2FA step | Implemented | Glassmorphism UI; inline OTP; Framer Motion animations |
| Frontend Auth | RegisterPage with password strength | Implemented | 4-level strength bar; per-field real-time validation |
| Frontend Auth | MFASetupPage | Partial | Page exists; all 3 API calls use wrong URLs (404) |
| Frontend Auth | ProtectedRoute redirect | Implemented | Preserves intended destination in location.state |
| Frontend Auth | AuthContext hydration | Implemented | access token → getMe → refresh fallback on mount |
| Frontend Auth | Silent refresh on 401 | Implemented | Queue pattern for concurrent 401s |
| Frontend UX | AlertSiren (full-screen vignette) | Implemented | Web Audio API siren; ACKNOWLEDGE button |
| Frontend UX | AuditLogPanel (live feed) | Implemented | audit_event Socket.IO; success/failure filter |
| Frontend UX | OTPInput (6-cell auto-advance) | Implemented | Neon glow; auto-advance on digit entry |
| CORS | FastAPI HTTP middleware | Implemented | Restricted to localhost:3000 |
| CORS | Socket.IO origin | Missing | Wildcard (*) — any origin can subscribe (VULN-AUTH-004) |
| Network Detection | Rule detector + RandomForest | Implemented | 99.6% accuracy; CIC-IDS2017 |
| User Behavior | OC-SVM inference | Partial | Model runs; Winlogbeat not configured (0 events) |
| System Monitor | LSTM Autoencoder | Partial | Score=1.0 bug (sklearn mismatch); resource-aware severity mitigates |
| Sysmon Behavior | TF-IDF + XGBoost | Implemented | PS forwarder active; file-based reader available |
| Malware Detection | LightGBM EMBER | Implemented | AUC=0.9803; 3-tier labels; trusted-path whitelist |
| Fusion Engine | Weighted threat score | Implemented | 5-source weights; ransomware correlation gate |
| SHAP | Network + malware | Partial | System/Sysmon not yet covered |
| SOAR | Endpoint agent actions | Implemented | Label-gated quarantine/isolate |
| MongoDB | All collections + indexes | Implemented | 12 collections; sessions + audit_logs added this session |
| Frontend SOC | Network, Malware, Sysmon views | Implemented | Layout correct; accurate status indicators |
| Frontend SOC | OverviewView threat score | Partial | Client-side formula diverges from backend fusion weights |

================================================================================

## SECTION 4: CONFLICTS AND INCOMPATIBILITIES

### 4.1 Endpoint URL Mismatch — Frontend vs. Backend (BLOCKING)

Root cause: authService.ts was written with a different URL convention
(/auth/2fa/{action}) than the router.py convention (/auth/{action}-2fa).
This is a pure naming inconsistency introduced during parallel development of
backend and frontend.

Affected functions and required fixes:

  verify2FA() — login step
    Current:  POST /auth/verify-2fa
    Correct:  POST /auth/verify-2fa-login

  enable2FA()
    Current:  POST /auth/2fa/enable
    Correct:  POST /auth/enable-2fa

  verify2FASetup()
    Current:  POST /auth/2fa/verify-setup
    Correct:  POST /auth/verify-2fa

  disable2FA()
    Current:  POST /auth/2fa/disable
    Correct:  POST /auth/disable-2fa

Resolution: Apply all four URL fixes to authService.ts in a single commit.
No backend changes required; the backend endpoints are correctly defined.

### 4.2 Socket.IO CORS vs. HTTP CORS Inconsistency

Root cause: FastAPI CORSMiddleware and socketio.AsyncServer maintain separate
CORS configurations. The developer correctly restricted FastAPI CORS but missed
the socketio parameter.

Resolution: Set cors_allowed_origins=["http://localhost:3000",
"http://127.0.0.1:3000"] in the AsyncServer constructor at backend.py L425.

### 4.3 OverviewView Threat Score Formula Divergence (Pre-existing)

Root cause: OverviewView.tsx computes threat score client-side as net*0.6 +
user*0.4. Backend fusion uses net=0.35, user=0.30, sys=0.15, mal=0.20. This
was flagged in the previous session and remains unresolved.

Resolution: Subscribe OverviewView to the fusion_alert Socket.IO event and
display threat_score*100 from the fusion result directly.

### 4.4 /predict/malware Endpoint Not Protected by Dual-Auth (Inconsistency)

Root cause: backend.py applies _require_key_or_jwt to /predict/network, /predict/user,
/fusion, /shap, /system/analyze, /sysmon/status — but /predict/malware and
/scan/malware still use _require_key only. SOC dashboard users with JWT cannot
call these endpoints directly from the browser (they have no API key).

Resolution: Apply _require_key_or_jwt to /predict/malware and /scan/malware
consistent with the other inference endpoints.

### 4.5 bcrypt Dummy-Hash Performance Issue on Unknown Email

Root cause: hash_password(dummy, rounds=12) is called on every login attempt
where the email is not found (timing oracle prevention). At 12 bcrypt rounds,
each call takes ~200-400ms on modern hardware. Under concurrent login attempts
against non-existent emails (e.g., user enumeration scan), the asyncio event
loop is blocked for this duration because bcrypt is CPU-bound and not offloaded
to a thread pool.

Resolution: At backend startup, compute a module-level DUMMY_HASH =
hash_password("startup-sentinel-never-used"). In the user-not-found path,
call bcrypt.checkpw(payload.password.encode()[:72], DUMMY_HASH.encode())
instead of computing a fresh hash. Constant-time comparison is maintained;
event loop blocking is eliminated.

================================================================================

## SECTION 5: NEXT STEPS AND IMPLEMENTATION ROADMAP

### Immediate Actions (0-2 weeks) — Critical Fixes

1. Fix authService.ts 2FA URL mismatches (VULN-AUTH-001, VULN-AUTH-002)
   Fix all four endpoint URLs in authService.ts as listed in Section 4.1.
   This is a single-file change, zero backend impact. Unblocks all MFA flows
   and the 2FA login step for users who have already enabled 2FA.

2. Fix Socket.IO CORS wildcard (VULN-AUTH-004)
   backend.py L425: change cors_allowed_origins="*" to
   cors_allowed_origins=["http://localhost:3000", "http://127.0.0.1:3000"].
   One-line change; prevents unauthorized real-time event subscription.

3. Fix /predict/malware and /scan/malware auth gap (Section 4.4)
   Change both endpoints from _require_key to _require_key_or_jwt.
   Ensures dashboard users can trigger malware scans without an API key.

4. Fix bcrypt dummy-hash event loop blocking (Section 4.5)
   Compute DUMMY_HASH at module startup. Replace hash_password call with
   bcrypt.checkpw against DUMMY_HASH in the user-not-found login path.

5. Fix OverviewView threat score divergence (Section 4.3, pre-existing)
   Subscribe to fusion_alert Socket.IO event in OverviewView; display
   event.threat_score*100 instead of the client-computed formula.

6. Retrain system_model.pt to fix score=1.0 bug (pre-existing CRITICAL)
   pip install scikit-learn==1.7.2 in venv OR run:
   python Backend/train_system_model.py --collect-minutes 60
   The resource-aware severity mitigates false CRITICALs but the root
   cause is an sklearn scaler version mismatch that must be corrected.

### Short-term (2-6 weeks) — High Priority

7. Migrate tokens from localStorage to memory + HttpOnly cookie (VULN-AUTH-003)
   Requires backend change: /auth/login and /auth/refresh set refresh_token as
   HttpOnly Secure SameSite=Strict cookie in the HTTP response in addition to
   (or instead of) returning it in the JSON body. Frontend: store only
   access_token in React AuthContext memory; remove localStorage writes for
   refresh_token.

8. Add TOTP replay protection (VULN-AUTH-007)
   Track used temp_token JTIs in a MongoDB temp_used_tokens collection with TTL
   index (auto-delete after 5 minutes). On /auth/verify-2fa-login, check JTI
   was not already used; on success, insert the JTI.

9. Implement /auth/forgot-password and /auth/reset-password (Medium, unimplemented)
   Design: POST /auth/forgot-password accepts email, generates a short-lived
   (15 min) signed reset token, sends via email (SMTP settings in config.py).
   POST /auth/reset-password accepts token + new_password, verifies token,
   updates password hash, calls logout-all, writes audit entry.
   Dependency: configure SMTP credentials in .env.

10. Encrypt TOTP secrets at rest (VULN-AUTH-008)
    Add AES-256-GCM encryption of two_factor_secret before MongoDB write.
    Key derived from settings.jwt_secret_key via HKDF-SHA256. Decrypt at
    verify time. Migration script needed for any existing users.

11. Harden X-Forwarded-For IP extraction (VULN-AUTH-006)
    Add TRUSTED_PROXIES=["127.0.0.1"] to config.py. In get_request_ip(),
    only use X-Forwarded-For when connection.host is in TRUSTED_PROXIES.

12. Configure Winlogbeat for user behavior inference (pre-existing, operational)
    Set START_WINLOGBEAT=true in .env. Configure Winlogbeat output to
    C:\XDR_Logs\. Until done, the OC-SVM user behavior model receives 0 events
    and user behavior scores are always 0.0.

### Medium-term (6-12 weeks) — Architecture Enhancements

13. Replace in-memory rate limiter with Redis-backed implementation (VULN-AUTH-005)
    Add redis[asyncio] to requirements.txt. Implement RedisRateLimiter class
    with same interface as LoginRateLimiter. Feature-flag via RATE_LIMITER=redis
    env var; fall back to in-memory when Redis is unavailable.

14. Implement /auth/change-password for authenticated users
    POST /auth/change-password: requires current_password + new_password.
    Verify current password with bcrypt, apply strength validation, update hash,
    revoke all other sessions (logout-all excluding current JTI).

15. Add SHAP explainability for system monitor and Sysmon layers (pre-existing)
    System: gradient-based attribution on LSTM Autoencoder reconstruction error.
    Sysmon: TF-IDF token weight contribution as feature importance proxy.

16. Fix Sysmon dual-source deduplication (pre-existing)
    Add mutual-exclusion flag: if Winlogbeat is active, disable PS forwarder.
    Check on startup which log source is live and set exclusive mode.

17. Add /auth/admin/users endpoint for user management
    Admin-only: list all users, update roles, force-unlock, force-logout-all.
    Required for any real SOC deployment where the first admin needs to manage
    analyst accounts.

18. Wire OCEAN personality features to a real data source
    Add POST /users/ocean endpoint (admin-only) + user_profiles MongoDB collection.
    Source: HR system export, self-assessment form, or behavioral inference.
    Until wired, the user behavior model always scores with O=C=E=A=N=0.0.

### Long-term (3-6 months) — Advanced Capabilities

19. Implement role-differentiated SOC views
    Analyst role: read access to all detection views; no admin panels.
    Viewer role: summary dashboards only; no raw alert data.
    Admin role: full access including audit log, user management, system config.
    Currently all authenticated users see the same dashboard regardless of role.

20. API rate limiting beyond auth endpoints
    Extend rate limiting to /predict/network, /fusion, and /scan/malware.
    Prevents resource exhaustion attacks via heavy ML inference requests.

21. Certificate-pinned mTLS for endpoint agent communication
    /ingest and /commands are API-key authenticated but transmitted over plain
    HTTP. For production deployments with remote endpoints, require TLS with
    a pinned backend certificate to prevent MITM interception of telemetry.

22. Session activity timeout
    Currently sessions expire only on explicit logout or refresh token expiry.
    Add last_active timestamp to session documents; expire sessions inactive
    for >8 hours via a background cleanup task.

================================================================================

## SECTION 6: UPDATED PROJECT COMPLETION TABLE

| Layer | Previous % | Current % | Status | Key Change |
|-------|-----------|-----------|--------|------------|
| Network Detection | 90% | 90% | Stable | No changes this session |
| User Behavior | 55% | 55% | Stable | Winlogbeat still not configured |
| System Monitor | 68% | 68% | Stable | sklearn mismatch still unresolved |
| Sysmon Behavior | 70% | 70% | Stable | No changes this session |
| Malware Detection | 98% | 98% | Stable | No changes this session |
| Fusion Engine | 100% | 100% | Stable | No changes this session |
| SHAP Explainability | 80% | 80% | Stable | No changes this session |
| SOAR / Endpoint Agent | 92% | 92% | Stable | No changes this session |
| MongoDB / Persistence | 96% | 98% | Improved | sessions + audit_logs collections added |
| Frontend / SOC Dashboard | 90% | 93% | Improved | Auth pages, AlertSiren, AuditLogPanel, OTPInput |
| Authentication & Authorization | 0% | 78% | NEW | Full backend; 2FA URLs broken in frontend |
| API Security / CORS | 20% | 65% | Improved | JWT dual-auth; CORS restricted; Socket.IO still * |

**Overall project completeness: ~87% → ~91%**

The 4% gain reflects the completed auth backend (full credit) offset by the
frontend 2FA URL mismatch (partial deduction from the new auth layer score).
Resolving the 4 URL fixes in authService.ts would bring auth to ~92% and
overall to ~92%.

================================================================================

## SECTION 7: METRICS AND KPIs TO TRACK

### Authentication Layer Health
- Login success rate vs. failure rate per hour (alert if failure rate > 20%)
- Accounts currently locked (query: users.locked_until > now())
- Rate-limit events per IP per hour (from audit_logs collection, action=429)
- Active sessions per user (sessions.is_active=true grouped by user_id)
- 2FA adoption rate (users.two_factor_enabled=true / total users)

### Security Posture Indicators
- Suspicious login events per day (audit_logs.action=suspicious_login_new_device)
- Failed MFA attempts per day (audit_logs.action=mfa_failed)
- Token refresh frequency vs. expected (anomaly if refresh rate > 1/minute/user)
- Audit log write failures per hour (logged at WARNING level in router.py)

### IDPS Detection Effectiveness (unchanged from prior sessions)
- Network: alerts per hour by attack type; false positive rate
- User behavior: anomaly events per day; proportion with Winlogbeat events > 0
- System: CRITICAL events per hour; is_genuinely_anomalous ratio
- Malware: scan volume, malicious/suspicious/benign ratio, trusted-path hit rate
- Fusion: HIGH+CRITICAL alerts per hour; SOAR actions triggered vs. acknowledged

================================================================================
END OF REPORT
Session    : 2026-04-26 session 2 — Authentication & Authorization System
Next Review: After authService.ts URL fixes are applied and 2FA flows are
             validated end-to-end. Recommend running full auth integration test
             suite covering: register, login (no 2FA), login (2FA), refresh,
             logout, logout-all, enable-2fa, verify-2fa, disable-2fa, and
             all RBAC-protected endpoints before any wider deployment.
================================================================================
