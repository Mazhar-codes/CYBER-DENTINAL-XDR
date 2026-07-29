================================================================================
IDPS PROJECT ANALYSIS REPORT — AUTH/MFA SECURITY ASSESSMENT
================================================================================
Timestamp     : 2026-04-26 18:00:00 UTC
Analyst       : IDPS Project Analyst Agent
Scope         : Full security and code-quality assessment of the MFA/2FA
                authentication subsystem — Backend/auth/ (6 files) and
                Frontend auth layer (authService.ts, AuthContext.tsx,
                LoginPage.tsx, MFASetupPage.tsx, auth.ts)
Project Phase : Post-implementation hardening — auth layer at 88% completeness
================================================================================

## EXECUTIVE SUMMARY

The Cyber Sentinel XDR authentication layer has a well-structured skeleton: JWT
token pairs, bcrypt-12 password hashing, TOTP enrollment, account lockout, RBAC,
and an audit trail are all correctly implemented at the protocol level.  However,
a critical integration gap undermines the entire MFA subsystem: `auth/mfa.py`
contains production-ready OTP replay prevention, OTP rate limiting, backup codes,
and device-trust token utilities — none of which are imported or called from
`auth/router.py`.  The TOTP gate is therefore trivially bypassable by code reuse
within a 30-second window and is undefended against brute-force enumeration of
the 10^6 six-digit space.  Additionally, both token stores live in localStorage
(XSS-accessible), Socket.IO accepts connections from any origin, and the
X-Forwarded-For trust is unvalidated.  Overall auth security score: **5.5/10** —
strong fundamentals, critical runtime wiring missing.

================================================================================
## SECTION 1: CODE QUALITY ASSESSMENT
================================================================================

### 1.1 Strengths

- router.py is well-organised with clear section headers and consistent
  dependency injection patterns throughout all 10 endpoints.
- security.py uses lazy imports with actionable error messages, isolating
  optional dependency failures from application startup.
- rate_limiter.py implements a correct asyncio.Lock-guarded sliding window;
  monotonic timestamps avoid wall-clock drift issues.
- models.py applies field-level Pydantic validators (password strength regex,
  email type, min/max length constraints) — input is sanitised before any
  business logic runs.
- `_write_audit` is non-blocking by design: exceptions are swallowed so audit
  failures never block authentication responses.
- bcrypt truncation at 72 bytes (the bcrypt hard limit) is explicitly handled in
  both hash_password and verify_password — prevents silent truncation bugs.
- Refresh token rotation uses bcrypt hash comparison against stored hash, not
  plaintext comparison — correct token binding implementation.
- Timing oracle prevention on user-not-found path (dummy hash_password call,
  router.py line 255) is correctly implemented.
- Audit log emits over Socket.IO with non-serialisable `_id` stripped before
  emission (router.py lines 108-111) — correct serialisation pattern.

### 1.2 Issues Found

| Severity | Component | Issue | Recommendation |
|----------|-----------|-------|----------------|
| CRITICAL | auth/router.py | mfa.py module (OTP replay prevention + OTP rate limiter) never imported or called; all 4 enterprise MFA controls are dead code | Wire otp_used_cache and otp_rate_limiter into verify-2fa-login, verify-2fa, disable-2fa endpoints |
| CRITICAL | authService.ts line 79,80 | access_token and refresh_token stored in localStorage — accessible to any JavaScript executing on the page | Migrate to httpOnly SameSite=Strict cookies via backend Set-Cookie |
| HIGH | backend.py line 425 | Socket.IO server created with cors_allowed_origins="*" — any browser can subscribe to the live threat feed | Set cors_allowed_origins=["http://localhost:3000","http://127.0.0.1:3000"] matching HTTP CORS policy |
| HIGH | auth/dependencies.py line 171-174 | X-Forwarded-For header trusted blindly without validation — header is attacker-controlled in direct deployments | Implement configurable TRUSTED_PROXIES allowlist before reading XFF |
| HIGH | router.py (all OTP endpoints) | No OTP-specific rate limiting on /verify-2fa-login, /verify-2fa, /disable-2fa — otp_rate_limiter exists in mfa.py but is never called | Import and call otp_rate_limiter.check(user_id) at the top of each OTP handler |
| HIGH | router.py verify_2fa_login (line 419) | No OTP replay prevention — same TOTP code accepted multiple times within 30s window + valid_window=1 extends exposure to 90s | Import otp_used_cache; check before verifying; mark_used after success |
| MEDIUM | router.py / router.py enable-2fa | No backup codes generated or returned during 2FA enrollment — generate_backup_codes() exists in mfa.py but is never called | Call generate_backup_codes() in enable-2fa handler; store hashes in user document; surface plaintext to user once |
| MEDIUM | router.py | No device trust mechanism — device_token helpers exist in mfa.py but are never integrated | Implement trusted_devices list in user document; issue device token on first verified login; skip OTP for 30 days |
| MEDIUM | router.py login (line 351) | last_login_ip field not stored — UserDocument comment in models.py references it but the update_one on line 352 only sets last_login (datetime) | Add "last_login_ip": ip to the $set payload on successful login and after 2FA verification |
| MEDIUM | LoginPage.tsx line 362 | Forgot-password link triggers alert() placeholder — no backend endpoint exists | Implement /auth/forgot-password + /auth/reset-password with HMAC-signed time-limited tokens delivered by email |
| MEDIUM | rate_limiter.py line 89 | In-memory rate limiter state is lost on process restart — bypassed by simply restarting the backend | Back with MongoDB counter or Redis for production deployments |
| LOW | auth/router.py audit_log endpoint (line 803) | No pagination beyond hard limit=500 — large audit logs could cause memory spikes | Add cursor-based pagination using MongoDB _id as cursor |
| LOW | security.py verify_totp (line 220-221) | Exception swallowed and returns False — incorrect TOTP secret format would silently fail instead of alerting | Log the exception at WARNING level before returning False |
| LOW | router.py sessions endpoint (line 766) | Admin sessions list has no pagination (hard limit 200, no cursor) | Add skip/limit query params and index on {user_id, is_active, login_time} |

================================================================================
## SECTION 2: SECURITY VULNERABILITY ANALYSIS
================================================================================

### 2.1 Critical Vulnerabilities

---
**[CRIT-01] OTP Replay Attack — TOTP Code Reuse Within Window**

Description: `verify_totp()` uses `valid_window=1`, meaning any code is valid
for up to 90 seconds (previous + current + next 30-second step). Within this
window, the exact same code can be submitted any number of times. The
`UsedOTPCache` class in `mfa.py` (with a correct 90-second TTL) exists precisely
to prevent this, but is never imported or called.

Impact: An attacker who intercepts a legitimate OTP (shoulder-surfing, network
sniff on non-TLS path, phishing replica) can replay it repeatedly within the 90s
window to authenticate as the victim without their knowledge.

Affected lines:
  - auth/security.py:212-222 (verify_totp — no used-code tracking)
  - auth/router.py:419 (verify_2fa_login — no replay check before call)
  - auth/router.py:701 (verify_2fa — no replay check before call)
  - auth/router.py:745 (disable_2fa — no replay check before call)
  - auth/mfa.py:26-58 (UsedOTPCache — implemented but dead)

CWE: CWE-294 (Authentication Bypass by Capture-replay)

Remediation:
```python
# At top of router.py — add to imports:
from auth.mfa import otp_used_cache, otp_rate_limiter

# In verify_2fa_login, before verify_totp():
if await otp_used_cache.is_used(user_id, payload.otp_code):
    raise HTTPException(status_code=401, detail="OTP already used — wait for next code")
# After successful verify_totp():
await otp_used_cache.mark_used(user_id, payload.otp_code)
```

---
**[CRIT-02] No OTP Rate Limiting — Brute-Force of 6-Digit Code Space**

Description: The `/auth/verify-2fa-login` endpoint has no rate limiting
whatsoever. An attacker holding a valid `temp_token` (issued by /login after
correct password) can enumerate all 1,000,000 possible 6-digit TOTP codes without
restriction. The `OTPRateLimiter` class (max 5 attempts per user per 5 minutes)
exists in `mfa.py` and is correctly implemented but is never imported or called.

Impact: Full bypass of 2FA. With network latency of ~10ms per request, full
keyspace exhaustion takes ~2.8 hours. Given TOTP's 30-second window, the attacker
only needs to find one valid code before the user's next legitimate login attempt.
This makes 2FA provide near-zero additional security against a network-positioned
attacker.

Affected lines:
  - auth/router.py:372-457 (verify_2fa_login — no rate limit applied)
  - auth/mfa.py:65-94 (OTPRateLimiter — implemented but dead)

CWE: CWE-307 (Improper Restriction of Excessive Authentication Attempts)

Remediation:
```python
# In verify_2fa_login, after decoding temp_payload and extracting user_id:
await otp_rate_limiter.check(user_id)  # raises 429 after 5 failures
# After successful verification:
await otp_rate_limiter.reset(user_id)
```

---
**[CRIT-03] JWT Tokens in localStorage — XSS Exfiltration**

Description: `authService.ts` stores both `access_token` and `refresh_token` in
`localStorage` (lines 79-80). Any JavaScript executing in the page context — from
a stored XSS payload in alert descriptions, SHAP reason strings, or any injected
third-party script — can read both tokens and exfiltrate them with a single
`localStorage.getItem()` call.

Impact: A successful XSS attack yields a persistent session (7-day refresh
token) that survives password changes until the refresh token's natural expiry.
In a SOC dashboard context, an operator's session could be hijacked and used to
read live threat feeds, modify response actions, or execute SOAR commands.

Affected lines:
  - authService.ts:79 (localStorage.setItem('access_token', ...))
  - authService.ts:80 (localStorage.setItem('refresh_token', ...))
  - AuthContext.tsx:38 (localStorage.getItem('access_token'))
  - AuthContext.tsx:49 (localStorage.getItem('refresh_token'))

CWE: CWE-922 (Insecure Storage of Sensitive Information), CWE-79 (XSS)

Remediation: Migrate tokens to `httpOnly; SameSite=Strict; Secure` cookies set
by the backend. The frontend no longer touches tokens — the cookie is sent
automatically. This requires backend changes to `/auth/login`,
`/auth/verify-2fa-login`, `/auth/refresh`, and `/auth/logout` to
`Set-Cookie` / `Delete-Cookie` instead of returning tokens in body. The axios
interceptor in authService.ts becomes unnecessary.

### 2.2 High Severity

---
**[HIGH-01] Socket.IO CORS Wildcard — Live Threat Feed Exposed to Any Origin**

Description: `backend.py` line 425:
```python
sio = socketio.AsyncServer(async_mode="asgi", cors_allowed_origins="*", ...)
```
While the HTTP FastAPI layer correctly restricts CORS to localhost:3000
(lines 694-699), the Socket.IO ASGI layer has a separate CORS policy that
permits any browser origin to subscribe to WebSocket events including
`network_anomaly`, `system_anomaly`, `malware_alert`, `fusion_alert`,
`audit_event`, and `user_anomaly` — all of which contain sensitive threat
intelligence.

Impact: Any webpage the SOC operator visits could silently open a WebSocket
connection to localhost:8000 and receive the full real-time threat feed. This is
a cross-origin information disclosure that bypasses the HTTP CORS fix already
applied to the REST layer.

Remediation: Match Socket.IO CORS to HTTP CORS policy:
```python
sio = socketio.AsyncServer(
    async_mode="asgi",
    cors_allowed_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    logger=False,
)
```

---
**[HIGH-02] Unvalidated X-Forwarded-For — Rate Limiter IP Bypass**

Description: `dependencies.py` lines 171-174 read the first value from
`X-Forwarded-For` without any proxy allowlist validation. An attacker connecting
directly (no reverse proxy) can forge this header to any value, assigning
themselves a different IP per request and bypassing both the IP-based login rate
limiter and the account lockout correlation logic.

Impact: Full bypass of the login rate limiter (5 attempts/IP/15 min) by rotating
the forged X-Forwarded-For value on each request. Account lockout remains
effective (it is keyed by user document, not IP), but brute-force speed is
limited only by bcrypt cost (12 rounds ≈ 200ms/attempt).

CWE: CWE-348 (Use of Less Trusted Source for IP Address)

Remediation:
```python
TRUSTED_PROXY_CIDRS = settings.trusted_proxy_cidrs  # e.g. ["127.0.0.1/32"]

def get_request_ip(request: Request) -> str:
    client_ip = request.client.host if request.client else "unknown"
    if _is_trusted_proxy(client_ip, TRUSTED_PROXY_CIDRS):
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
    return client_ip
```

---
**[HIGH-03] No Backup Codes — Account Lockout on Authenticator Loss**

Description: `mfa.py` lines 104-138 implement `generate_backup_codes()` and
`verify_and_consume_backup_code()` — cryptographically sound (SHA-256 hashed,
one-time use, XXXX-XXXX format). These are never called from any endpoint.

Impact: If a SOC operator loses their phone (or the authenticator app is wiped),
they have no recovery path. The admin must manually intervene in MongoDB to reset
`two_factor_enabled` and `two_factor_secret` — an out-of-band operational
procedure with no audit trail.

Remediation: During `/auth/enable-2fa`, call `generate_backup_codes(10)`, store
SHA-256 hashes in `user["backup_codes"]` as `[{"hash": str, "used": false}]`,
and return plaintext codes once in the response. Add `/auth/verify-2fa-login`
fallback path accepting a backup code. Add `/auth/regenerate-backup-codes`
endpoint (requires active TOTP to prevent misuse).

---
**[HIGH-04] last_login_ip Not Persisted**

Description: The `UserDocument` schema comment in `models.py` (lines 28-34)
implies a `last_login_ip` field, and suspicious login detection compares IPs
against the most recent session. However, the `$set` calls in `verify_2fa_login`
(router.py line 449) and the non-2FA login path (router.py line 352) only set
`last_login` (datetime), not `last_login_ip`. The suspicious login detection
therefore relies solely on the sessions collection, which works, but the user
document's own IP history is missing — making `/auth/me` responses incomplete for
audit dashboards.

Remediation: Add `"last_login_ip": ip` to the `$set` dict on both successful
login code paths (lines 352 and 449 of router.py).

### 2.3 Medium/Low Severity

---
**[MED-01] No Device Trust — Every Login Requires OTP**

Description: `mfa.py` implements `generate_device_token()` and
`hash_device_token()` for a "trust this device for 30 days" flow, but these are
never integrated. Every login from an already-verified device requires a fresh OTP.

Impact: Operator friction reduces compliance — repeated OTP prompts from known
workstations encourage workarounds (disabling 2FA, shared accounts). Not a direct
security regression, but degrades the usability/security balance.

CWE: Not applicable (usability gap, not a vulnerability).

---
**[MED-02] Forgot-Password is alert() Placeholder**

Description: `LoginPage.tsx` line 362-363:
```tsx
onClick={() => alert('Password reset coming soon')}
```
No backend endpoint exists for password reset. This means the only recovery path
for a forgotten password is direct MongoDB manipulation by an admin.

Impact: For production deployments this is an operational gap. More critically,
there is no mechanism to validate that the requester owns the account email before
resetting, so any admin-level manual reset carries insider threat risk with no
audit trail.

Remediation: Implement `/auth/forgot-password` (accepts email, generates
HMAC-SHA256 signed token with 15-minute expiry, sends via SMTP) and
`/auth/reset-password` (validates token, accepts new password, invalidates all
sessions). Store token hash in MongoDB `password_reset_tokens` collection with TTL
index.

---
**[MED-03] In-Memory Rate Limiter Resets on Process Restart**

Description: `login_rate_limiter` (rate_limiter.py line 89) and `otp_rate_limiter`
(mfa.py line 94) are module-level singletons stored in process memory. A Uvicorn
restart (e.g., from --reload, crash, or deliberate kill) clears all rate limit
state.

Impact: An attacker can bypass rate limiting by triggering a backend restart
(e.g., via an unauthenticated endpoint that causes an unhandled exception) between
brute-force bursts.

Remediation: Back the rate limiter with MongoDB (TTL-indexed `rate_limit_attempts`
collection) or Redis. For MongoDB approach, each attempt document:
`{ip, endpoint, timestamp, _id}` with a TTL index on `timestamp` of 15 minutes.

---
**[MED-04] TOTP Secret Stored Plaintext in MongoDB**

Description: `user["two_factor_secret"]` is the raw BASE32 TOTP secret stored
unencrypted in the `users` collection. The comment in `models.py` line 33 reads
"store encrypted at rest" — this is an unimplemented recommendation, not a
current behaviour.

Impact: If the MongoDB database is compromised (no encryption at rest, leaked
backup, or misconfigured Atlas ACL), the attacker gains every user's TOTP secret
and can pre-generate future codes — fully defeating 2FA retrospectively.

CWE: CWE-312 (Cleartext Storage of Sensitive Information)

Remediation: Encrypt the secret with AES-256-GCM using a key derived from
`settings.jwt_secret_key` via HKDF before storing. Decrypt only in memory during
TOTP verification. The `cryptography` library provides `Fernet` (AES-128-CBC) or
the lower-level `hazmat` primitives for AES-GCM.

---
**[LOW-01] QR Code Error Correction Level is L (Lowest)**

Description: `security.py` line 232: `error_correction=qrcode.constants.ERROR_CORRECT_L`
Level L corrects only 7% of damaged codewords. On a small phone screen with a
protective case, partial QR obstruction causes scan failure.

Remediation: Use `ERROR_CORRECT_M` (15%) — minimal performance cost, significantly
better real-world scan reliability.

---
**[LOW-02] Temp 2FA Token JTI Not Tracked — Unlimited Single-Use Tokens**

Description: `create_temp_2fa_token` (security.py lines 153-170) embeds a UUID4
`jti` but `verify_2fa_login` (router.py line 392-401) does not store or revoke
used temp tokens. A valid 5-minute temp token can be submitted to
`/verify-2fa-login` multiple times with different OTP codes until one succeeds
(i.e., the brute-force window is the token's 5-minute lifetime, not the OTP's
30-second window).

Impact: When combined with [CRIT-02] (no OTP rate limiting), the temp token's
5-minute lifetime gives an attacker 5 minutes of unthrottled OTP enumeration —
approximately 30,000 requests at 10ms latency.

Remediation: After successful OTP verification, store the temp token's `jti` in a
`used_temp_tokens` MongoDB collection with a 5-minute TTL index. Reject any
`/verify-2fa-login` request whose temp token `jti` is already in that collection.

---
**[LOW-03] Email Address Exposed in Contact Us Link**

Description: `LoginPage.tsx` line 501:
```tsx
{ label: 'Contact Us', href: 'mailto:annashabib02283@gmail.com' }
```
A personal email address is hardcoded in the login page footer — publicly visible
to any user who views the page source.

Impact: Low direct security risk, but exposes a personal identifier in a
production security product. This email could be targeted for phishing or
social engineering.

Remediation: Replace with a team alias or organisation email. Move configuration
to an environment variable: `process.env.REACT_APP_SUPPORT_EMAIL`.

---
**[LOW-04] Access Token Has No JTI Blacklist**

Description: On `/auth/logout`, only the session (refresh token) is invalidated.
The access token (15-minute lifetime) continues to be accepted by
`get_current_user` for the remainder of its TTL after logout. This is by design in
many JWT implementations, but in a SOC tool where sessions may be revoked due to
suspected compromise, a 15-minute post-logout window is meaningful.

Impact: An attacker who steals an access token (e.g., via XSS before token
migration to cookies) retains authenticated access for up to 15 minutes after the
legitimate user logs out.

Remediation: Maintain a `revoked_access_tokens` MongoDB collection (TTL=15 min)
storing `jti` values of logged-out tokens. Check this set in `get_current_user`
before returning the user document. Cost: one additional MongoDB read per
authenticated request.

================================================================================
## SECTION 3: ARCHITECTURE GAP ANALYSIS — AUTH LAYER
================================================================================

| Component | Status | Notes |
|-----------|--------|-------|
| Password hashing (bcrypt-12) | Implemented | Correctly implemented with 72-byte truncation |
| JWT access tokens (15 min, HS256) | Implemented | JTI injected; type="access" enforced |
| JWT refresh tokens (7 day) | Implemented | Rotation on use; bcrypt hash stored |
| Account lockout (5 attempts / 15 min) | Implemented | Persisted in MongoDB user doc |
| Login rate limiting (IP / 15 min) | Implemented | In-memory; resets on restart |
| RBAC (admin / analyst / viewer) | Implemented | Admin bypasses all role checks |
| TOTP enrollment (/enable-2fa + /verify-2fa) | Implemented | Secret stored provisionally until confirmed |
| TOTP login gate (temp_token pattern) | Implemented | 5-minute temp token; type="2fa_pending" enforced |
| Audit log (MongoDB + Socket.IO) | Implemented | Non-blocking; strips non-serialisable _id |
| Suspicious login detection | Implemented | Compares IP+UA against last active session |
| OTP Replay Prevention | DEAD CODE | UsedOTPCache in mfa.py — NOT wired to router |
| OTP Rate Limiting | DEAD CODE | OTPRateLimiter in mfa.py — NOT wired to router |
| Backup Codes | DEAD CODE | generate_backup_codes in mfa.py — NOT wired |
| Device Trust | DEAD CODE | generate_device_token in mfa.py — NOT wired |
| last_login_ip storage | Missing | Field not set in user doc on login |
| Temp token JTI blacklisting | Missing | Used temp tokens not tracked |
| Access token JTI blacklist on logout | Missing | 15-min post-logout window |
| TOTP secret encryption at rest | Missing | Plaintext in MongoDB (models.py comment notes gap) |
| Forgot-password / reset flow | Missing | alert() placeholder in frontend |
| Token storage hardening | Missing | localStorage used; httpOnly cookies not implemented |
| Socket.IO CORS restriction | Missing | cors_allowed_origins="*" at backend.py:425 |
| Proxy-validated X-Forwarded-For | Missing | XFF trusted blindly |
| Rate limiter persistence | Missing | In-memory; lost on restart |

================================================================================
## SECTION 4: CONFLICTS AND INCOMPATIBILITIES
================================================================================

**[CONFLICT-01] mfa.py Exists But Is Entirely Disconnected**

Root Cause: `auth/mfa.py` was created as a supporting module but the import
was never added to `router.py`. The `__init__.py` for the `auth` package (line 1)
is a single comment with no re-exports, so nothing auto-imports `mfa.py`.

Evidence:
  - `grep -r "from auth.mfa\|import mfa\|otp_used_cache\|otp_rate_limiter" Backend/` → zero matches outside mfa.py itself
  - router.py imports: `from auth.rate_limiter import login_rate_limiter` (login only) — OTP limiter never imported

Resolution: Add two import lines to router.py and three call sites as described in
CRIT-01 and CRIT-02 remediations. No structural changes needed — the API is
already correct.

---
**[CONFLICT-02] HTTP CORS Restricted but Socket.IO CORS Wildcard**

Root Cause: `CORSMiddleware` is applied to the `FastAPI` app object (backend.py
line 693) with origin allowlist. The `socketio.AsyncServer` is created at line 425
— before `app` exists — with `cors_allowed_origins="*"`. The Socket.IO ASGI layer
wraps the FastAPI app but has its own independent CORS policy.

Evidence:
  - backend.py:425 — `cors_allowed_origins="*"`
  - backend.py:694-699 — HTTP CORS correctly restricted

Resolution: Pass the same origin list to `socketio.AsyncServer`. One-line fix.

---
**[CONFLICT-03] TOTP valid_window=1 Without Replay Prevention**

Root Cause: `valid_window=1` in `security.py:219` is appropriate for clock skew
tolerance when paired with replay prevention. Without `UsedOTPCache`, it instead
extends the attack window from 30s to 90s. These two design choices conflict.

Resolution: Wire `otp_used_cache` — then `valid_window=1` is correct and safe.

================================================================================
## SECTION 5: NEXT STEPS AND IMPLEMENTATION ROADMAP
================================================================================

### Immediate Actions (0-2 weeks) — CRITICAL / Must Fix Before Any Production Use

**P0-01: Wire mfa.py into router.py (resolves CRIT-01 + CRIT-02 simultaneously)**

In `auth/router.py`, add at top of imports:
```python
from auth.mfa import otp_used_cache, otp_rate_limiter
```

In `verify_2fa_login` (around line 418), insert before `verify_totp()`:
```python
await otp_rate_limiter.check(user_id)
if await otp_used_cache.is_used(user_id, payload.otp_code):
    await _write_audit(db, user["username"], "mfa_replay_blocked", ip, False)
    raise HTTPException(status_code=401, detail="OTP already used — wait for next code")
```
After successful `verify_totp()`:
```python
await otp_used_cache.mark_used(user_id, payload.otp_code)
await otp_rate_limiter.reset(user_id)
```

Apply the same pattern to `verify_2fa` (line 701) and `disable_2fa` (line 745).
Estimated effort: 1 developer-hour.

**P0-02: Fix Socket.IO CORS (resolves HIGH-01)**

`backend.py` line 425 — change `cors_allowed_origins="*"` to:
```python
cors_allowed_origins=["http://localhost:3000", "http://127.0.0.1:3000"]
```
One-line fix. Estimated effort: 5 minutes.

**P0-03: Store last_login_ip (resolves HIGH-04)**

In `router.py` line 352 (non-2FA login) and line 449 (verify_2fa_login), add
`"last_login_ip": ip` to the `$set` dict alongside `"last_login": now`.
Estimated effort: 15 minutes.

**P0-04: Block Temp Token JTI Reuse (resolves LOW-02)**

Create MongoDB TTL collection `used_temp_tokens` with index `{jti: 1}` and TTL 5
minutes on `expires_at`. In `verify_2fa_login`, after decoding temp_payload:
```python
jti = temp_payload.get("jti")
if db["used_temp_tokens"].find_one({"jti": jti}):
    raise HTTPException(status_code=401, detail="Token already used")
```
After issuing full tokens:
```python
db["used_temp_tokens"].insert_one({
    "jti": jti,
    "expires_at": datetime.now(timezone.utc) + timedelta(minutes=5)
})
```
Estimated effort: 30 minutes.

### Short-term (2-6 weeks) — HIGH Priority

**P1-01: Wire Backup Codes into 2FA Enrollment (resolves HIGH-03)**

Modify `/auth/enable-2fa` to call `generate_backup_codes(10)`, compute hashes via
`hash_backup_code()`, store as `user["backup_codes"]`, and include plaintext codes
in `MFASetupResponse`. Modify `MFASetupPage.tsx` to display codes in a copy-able
panel with a "I have saved these codes" confirmation gate. Add
`/auth/verify-2fa-login` fallback branch that calls `verify_and_consume_backup_code()`.

**P1-02: Validate X-Forwarded-For (resolves HIGH-02)**

Add `TRUSTED_PROXY_IPS` list to `config.py` (default: `["127.0.0.1"]`).
Modify `get_request_ip()` in `dependencies.py` to only read XFF when the direct
client IP is in the trusted list. This is a 15-line change.

**P1-03: Encrypt TOTP Secret at Rest (resolves MED-04)**

Add `settings.totp_encryption_key` (derived from JWT secret via HKDF or a
dedicated env var). Wrap TOTP secret in Fernet encryption before MongoDB storage.
Decrypt in `verify_2fa_login`, `verify_2fa`, `disable_2fa`. Migration script
needed for existing user documents.

**P1-04: Implement Forgot-Password Flow (resolves MED-02)**

Backend: `/auth/forgot-password` generates `secrets.token_urlsafe(32)`, stores
SHA-256 hash + expiry in `password_reset_tokens` collection, sends email via
`aiosmtplib`. `/auth/reset-password` validates token, calls `hash_password()`,
updates user, invalidates all sessions. Frontend: Replace `alert()` with a modal
form collecting the email address.

### Medium-term (6-12 weeks) — Architecture Enhancements

**P2-01: Migrate Tokens to httpOnly Cookies (resolves CRIT-03)**

This is the highest-impact remaining item and requires coordinated backend +
frontend changes:

Backend: Modify login/verify-2fa-login/refresh to `Set-Cookie` instead of JSON
body. Add `SameSite=Strict; HttpOnly; Secure; Path=/auth` attributes. Modify
logout to `Delete-Cookie`.

Frontend: Remove all `localStorage.getItem/setItem` for tokens. Remove the
Authorization header interceptor (browser sends cookie automatically). The
`AuthContext` hydration on mount simply calls `GET /auth/me` (cookie-authenticated).

This change breaks the existing axios interceptor pattern — the refresh flow must
be replaced with a `/auth/refresh` call that the backend handles cookie-to-cookie.

**P2-02: MongoDB-Backed Rate Limiting (resolves MED-03)**

Replace the in-memory `LoginRateLimiter` and `OTPRateLimiter` with a shared
MongoDB-backed implementation. Use a TTL index on `{timestamp: 1}` with TTL of
the window duration. Index on `{key: 1, endpoint: 1}` for fast lookups.

**P2-03: Device Trust Implementation (resolves MED-01)**

After successful 2FA verification, issue a `device_token` (from `mfa.py`) and
set it as a long-lived `httpOnly` cookie named `x-device-trust`. Store the hash
in `user["trusted_devices"]` with expiry. On subsequent logins from the same
device, if the device token is valid, skip OTP. Include device management UI
in the SOC dashboard settings.

**P2-04: Access Token JTI Blacklist (resolves LOW-04)**

MongoDB collection `revoked_tokens` with TTL index (15 min). On logout, store
the access token's JTI. In `get_current_user`, add one MongoDB lookup against
this collection. Consider a Bloom filter for high-throughput deployments.

### Long-term (3-6 months) — Advanced Capabilities

- Hardware security key support (FIDO2/WebAuthn) via `webauthn` Python library
  as a 2FA alternative to TOTP — phishing-resistant by design
- Adaptive MFA: risk-score-based OTP prompting (skip OTP for low-risk logins,
  require OTP + IP validation for high-risk fusion scores above threshold)
- SIEM integration: forward `audit_logs` entries to external SIEM via Kafka or
  syslog-ng for retention beyond MongoDB collection caps
- Certificate-based mutual TLS for endpoint agent ↔ backend authentication,
  replacing the shared API key

================================================================================
## SECTION 6: METRICS AND KPIs TO TRACK
================================================================================

| Metric | Target | Collection Method |
|--------|--------|-------------------|
| OTP replay attempts blocked/day | Baseline then trend | audit_logs action="mfa_replay_blocked" |
| OTP brute-force attempts blocked/day | 0 after P0-01 | otp_rate_limiter 429 responses |
| Failed 2FA attempts per user per week | Alert if >10 | audit_logs action="mfa_failed" |
| Temp token JTI reuse attempts | 0 | used_temp_tokens collision count |
| Rate limiter bypass attempts (XFF forge) | Alert on sudden IP diversity | Detect >10 unique XFF IPs per user in 1 hour |
| Suspicious login detections per week | Trend monitoring | audit_logs action="suspicious_login_new_device" |
| Account lockout events per day | Alert if >5 unique users | audit_logs action="login_blocked" |
| Socket.IO connection origins | 100% localhost only after fix | Monitor engineio access log |
| Backup code consumption rate | <5% of 2FA users/month | Track used=true in backup_codes array |
| Session duration vs. expected TTL | Alert on outliers | sessions.login_time vs. last refresh time |

================================================================================
END OF REPORT
Next Analysis Recommended: After P0 items are implemented (est. 2026-05-03) —
  verify OTP replay and rate-limit controls with integration tests before
  any external network exposure of the backend.
================================================================================
