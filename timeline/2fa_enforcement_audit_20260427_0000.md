# 2FA Enforcement Audit Report
**Date:** 2026-04-27  
**Scope:** Full MFA enforcement investigation — backend token issuance, refresh bypass, frontend state  
**Verdict:** 3 vulnerabilities found and fixed. 2FA enforcement is now complete.

---

## Executive Summary

The user observed what appeared to be a successful login without OTP. The code audit revealed **three distinct issues** — one that broke 2FA login entirely (CRITICAL), one that allowed indefinite bypass via old refresh tokens (HIGH), and one that explained the user's observation (MEDIUM). All three have been fixed.

---

## Token Issuance Map

| Endpoint | Issues JWT? | OTP Required? | Status |
|---|---|---|---|
| `POST /auth/login` (no 2FA) | Yes | N/A | SAFE |
| `POST /auth/login` (2FA + trusted device) | Yes | Via prior device-token OTP | SAFE |
| `POST /auth/login` (2FA, no device) | No — temp_token only | — | SAFE |
| `POST /auth/verify-2fa-login` | Yes | Yes (TOTP + replay + rate limit + JTI) | FIXED (was broken) |
| `POST /auth/refresh` | Yes | No check (BYPASS) | FIXED |
| `POST /auth/register` | No | — | SAFE |

---

## Vulnerabilities Found

### CRITICAL — `verify_2fa_login` issued 403 after valid OTP

**File:** `Backend/auth/router.py` — `verify_2fa_login()` line ~587  
**Root cause:** `_issue_tokens_and_session()` was called without `otp_verified=True`. The fail-safe guard we added (`if user.get("two_factor_enabled") and not otp_verified: raise 403`) then fired on every successful 2FA verification, making 2FA login completely broken — a 403 was returned to the user after entering a valid OTP.  
**Impact:** 2FA-enabled users could never complete login. The bypass was impossible but so was legitimate login.  
**Fix:** Added `otp_verified=True` to the `_issue_tokens_and_session()` call in `verify_2fa_login`. Added `[AUTH] OTP verified` debug log at this point.

---

### HIGH — Refresh token bypass (pre-2FA sessions)

**File:** `Backend/auth/router.py` — `refresh_token_endpoint()` (~line 628)  
**Root cause:** `/auth/refresh` called `create_access_token()` directly, bypassing `_issue_tokens_and_session()` and its 2FA guard entirely. An old refresh token from a session created before 2FA was enabled could be used indefinitely to get new access tokens without ever completing OTP.  
**Attack scenario:**  
1. User registers → gets refresh_token (no 2FA)  
2. User enables 2FA  
3. Old refresh_token still valid → calls `/auth/refresh` → new access_token without OTP  
4. Repeats until refresh_token expires (7 days)  
**Fix (3 parts):**  
1. Added `otp_verified: bool` field to session documents in `_create_session_doc()`  
2. `_issue_tokens_and_session()` now passes `otp_verified` through to the session doc  
3. `/auth/refresh` checks: `if user.two_factor_enabled and not session.otp_verified → 401`  
4. New rotated session carries forward `otp_verified` from old session  
5. `POST /auth/verify-2fa` (activation) now revokes all active sessions immediately, eliminating any pre-2FA sessions from MongoDB

---

### MEDIUM — Stale localStorage token (root cause of user's observation)

**File:** `Frontend/src/services/authService.ts` — `login()` function  
**Root cause:** `login()` did not clear old tokens before POSTing to `/auth/login`. `AuthContext.hydrate()` runs on every page load and calls `getMe()` with whatever `access_token` is in localStorage. If the token is still valid (within 15 min), the user is marked as `isAuthenticated=true` and sees the dashboard — without going through the login page at all. This is why the user saw "login succeeded without OTP" — they were never on the login page; the old token auto-authenticated them.  
**Fix:** Added `clearTokens()` at the top of `login()` in `authService.ts`. Old tokens are now wiped before any login attempt.

---

## MFASetupPage Fix

`MFASetupPage.tsx` previously called `navigate('/dashboard')` after activating 2FA. Since activation now revokes all sessions server-side, the current access token becomes un-refreshable (next refresh attempt hits the 2FA check and returns 401). Rather than waiting for this to fail silently, `MFASetupPage` now:
1. Calls `clearTokens()` immediately on success
2. Navigates to `/login` with a toast: "2FA enabled! Please log in again with your authenticator."

---

## Verified — Correct Before Fix

| Component | Check | Result |
|---|---|---|
| `dependencies.py:75` | Rejects `type != "access"` tokens | CORRECT — temp tokens cannot access protected routes |
| `LoginPage.tsx` | Shows OTP form when `requires2FA=true`, no bypass | CORRECT |
| `AuthContext.tsx` | `isAuthenticated` only true after `getMe()` succeeds | CORRECT |
| `ProtectedRoute.tsx` | Shows spinner during `isLoading`, redirects to `/login` when not authenticated | CORRECT |
| `App.tsx` | No routing bypass to `/dashboard` without `ProtectedRoute` | CORRECT |
| OTP replay prevention | `UsedOTPCache` called in `verify_2fa_login` | CORRECT |
| OTP rate limiting | `OTPRateLimiter` called in `verify_2fa_login` | CORRECT |
| Temp token single-use | `UsedJTICache` called in `verify_2fa_login` | CORRECT |
| Device trust bypass | Requires valid SHA-256-hashed device token from prior OTP session | CORRECT |

---

## Files Modified

| File | Change |
|---|---|
| `Backend/auth/router.py` | `_create_session_doc` + `otp_verified` field; `_issue_tokens_and_session` passes it through; `verify_2fa_login` uses `otp_verified=True`; `refresh` blocks unverified sessions; `verify_2fa` revokes pre-2FA sessions; `GET /auth/test-mfa-enforcement` added |
| `Frontend/src/services/authService.ts` | `login()` calls `clearTokens()` before POST |
| `Frontend/src/pages/MFASetupPage.tsx` | After activation: `clearTokens()` + navigate to `/login` |

---

## Status: 2FA Enforcement Complete

All token issuance paths now require OTP when `two_factor_enabled=True`. The fail-safe guard in `_issue_tokens_and_session` provides defence-in-depth: even if a future code change attempts to bypass OTP, the guard will block it with a 403 and log a SECURITY VIOLATION error.
