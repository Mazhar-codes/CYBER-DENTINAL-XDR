import axios, { AxiosError, InternalAxiosRequestConfig } from 'axios';
import toast from 'react-hot-toast';
import {
  BackupCodesResponse,
  TokenResponse,
  TrustedDevice,
  UserResponse,
  MFASetupResponse,
  LoginResponse,
} from '../types/auth';

import { BACKEND_URL } from '../config';

/** Auth-related paths that must never trigger the 401 redirect loop */
const AUTH_BYPASS_PATHS = [
  '/auth/login',
  '/auth/register',
  '/auth/refresh',
  '/auth/verify-2fa-login',
  '/auth/forgot-password',
  '/auth/reset-password',
  '/auth/recovery/request-mfa',
  '/auth/recovery/check',
];

function isAuthBypassPath(url: string | undefined): boolean {
  if (!url) return false;
  return AUTH_BYPASS_PATHS.some((p) => url.includes(p));
}

/**
 * Demo Mode has no real backend session, so every authenticated call the
 * dashboard makes on mount will legitimately 401/403. Without this check the
 * interceptor below would immediately bounce the user back out to
 * /startup or /dashboard-reload, defeating the whole point of the bypass —
 * see AuthContext.tsx's `enterDemoMode()` / `isDemoModeActive()`.
 */
function isDemoMode(): boolean {
  return localStorage.getItem('xdr_demo_mode') === '1';
}

/** Dispatch the global DOM event that UnauthorizedBanner listens to */
function dispatchAccessDenied(): void {
  window.dispatchEvent(new Event('accessDenied'));
}

const DEVICE_TOKEN_KEY = 'xdr_device_token';

// ── Token helpers ────────────────────────────────────────────────────────────
export function storeTokens(tokens: TokenResponse): void {
  localStorage.setItem('access_token', tokens.access_token);
  localStorage.setItem('refresh_token', tokens.refresh_token);
  if (tokens.device_token) {
    localStorage.setItem(DEVICE_TOKEN_KEY, tokens.device_token);
  }
}

export function clearTokens(): void {
  localStorage.removeItem('access_token');
  localStorage.removeItem('refresh_token');
  // Intentionally keep device_token so trusted-device bypass survives logout/re-login
}

export function getAccessToken(): string | null {
  return localStorage.getItem('access_token');
}

export function getDeviceToken(): string | null {
  return localStorage.getItem(DEVICE_TOKEN_KEY);
}

export function clearDeviceToken(): void {
  localStorage.removeItem(DEVICE_TOKEN_KEY);
}

// ── Axios instance with auth interceptors ────────────────────────────────────
export const authAxios = axios.create({ baseURL: BACKEND_URL });

// Attach Bearer token + Device-Token header to every request
authAxios.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const token = localStorage.getItem('access_token');
  if (token && config.headers) {
    config.headers['Authorization'] = `Bearer ${token}`;
  } else if (isDemoMode() && config.headers) {
    // Demo Mode has no real JWT (no real login occurred). The backend's dual-auth
    // dependency (_require_key_or_jwt) accepts a valid X-API-Key as a full
    // equivalent to a JWT, so this keeps every real feature — endpoint list,
    // reports, response actions, live models — working exactly as normal while
    // only the login screen itself is skipped. Key is only ever attached
    // client-side while demo mode is active; never used for a real session.
    const demoApiKey = process.env.REACT_APP_XDR_API_KEY;
    if (demoApiKey) {
      config.headers['X-API-Key'] = demoApiKey;
    }
  }
  const deviceToken = getDeviceToken();
  if (deviceToken && config.headers) {
    config.headers['X-Device-Token'] = deviceToken;
  }
  return config;
});

let isRefreshing = false;
let refreshQueue: Array<(token: string) => void> = [];

function processRefreshQueue(token: string): void {
  refreshQueue.forEach((cb) => cb(token));
  refreshQueue = [];
}

// Response interceptor — handles 401 (token refresh + session expiry) and 403 (access denied)
authAxios.interceptors.response.use(
  (res) => res,
  async (error: AxiosError) => {
    const original = error.config as InternalAxiosRequestConfig & { _retry?: boolean };
    const status = error.response?.status;
    const requestUrl = original?.url;

    // Demo Mode: let every panel handle the failed call on its own (empty/error
    // state) instead of yanking the user out of the dashboard.
    if (isDemoMode()) {
      return Promise.reject(error);
    }

    // ── 403 Forbidden ────────────────────────────────────────────────────────
    if (status === 403 && !isAuthBypassPath(requestUrl)) {
      toast.error('Access Denied — insufficient permissions', {
        id: 'access-denied',
        icon: '🚫',
        style: {
          background: 'rgba(30,0,10,0.97)',
          color: '#ff6688',
          border: '1px solid rgba(255,0,68,0.4)',
          fontFamily: "'Fira Code', monospace",
          fontSize: '12px',
        },
        duration: 4000,
      });
      dispatchAccessDenied();
      // Redirect to dashboard (stay in app, access denied should not log user out)
      if (window.location.pathname !== '/dashboard') {
        window.location.href = '/dashboard';
      }
      return Promise.reject(error);
    }

    // ── 401 Unauthorized ─────────────────────────────────────────────────────
    if (status === 401 && !isAuthBypassPath(requestUrl) && !original._retry) {
      original._retry = true;
      const storedRefreshToken = localStorage.getItem('refresh_token');

      // No refresh token at all — session is dead
      if (!storedRefreshToken) {
        clearTokens();
        localStorage.removeItem('user');
        toast.error('Session expired. Please log in again.', {
          id: 'session-expired',
          icon: '🔒',
          style: {
            background: 'rgba(10,20,40,0.97)',
            color: '#e0f4ff',
            border: '1px solid rgba(255,170,0,0.4)',
            fontFamily: "'Fira Code', monospace",
            fontSize: '12px',
          },
          duration: 4000,
        });
        window.location.href = '/startup';
        return Promise.reject(error);
      }

      // Another request is already refreshing — queue this one
      if (isRefreshing) {
        return new Promise<string>((resolve) => {
          refreshQueue.push(resolve);
        }).then((newToken) => {
          if (original.headers) {
            original.headers['Authorization'] = `Bearer ${newToken}`;
          }
          return authAxios(original);
        });
      }

      // Attempt silent token refresh
      isRefreshing = true;
      try {
        const tokens = await refreshToken(storedRefreshToken);
        storeTokens(tokens);
        processRefreshQueue(tokens.access_token);
        if (original.headers) {
          original.headers['Authorization'] = `Bearer ${tokens.access_token}`;
        }
        return authAxios(original);
      } catch {
        // Refresh itself failed — session is fully expired
        clearTokens();
        localStorage.removeItem('user');
        toast.error('Session expired. Please log in again.', {
          id: 'session-expired',
          icon: '🔒',
          style: {
            background: 'rgba(10,20,40,0.97)',
            color: '#e0f4ff',
            border: '1px solid rgba(255,170,0,0.4)',
            fontFamily: "'Fira Code', monospace",
            fontSize: '12px',
          },
          duration: 4000,
        });
        window.location.href = '/startup';
        return Promise.reject(error);
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(error);
  }
);

// ── Auth API calls ────────────────────────────────────────────────────────────
export async function register(
  username: string,
  email: string,
  password: string
): Promise<void> {
  await authAxios.post('/auth/register', { username, email, password });
}

export async function login(
  email: string,
  password: string
): Promise<TokenResponse | LoginResponse> {
  // Clear any stale tokens before attempting login.
  // Without this, a leftover access_token in localStorage would cause AuthContext.hydrate()
  // to call getMe() on the next page load and mark the user as authenticated without OTP.
  clearTokens();
  const res = await authAxios.post<TokenResponse | LoginResponse>('/auth/login', {
    email,
    password,
  });
  return res.data;
}

export async function verify2FA(
  temp_token: string,
  otp_code: string,
): Promise<TokenResponse> {
  const body = { temp_token, otp_code };
  console.log('[XDR-Auth] POST /auth/verify-2fa-login', { temp_token: '***', otp_code });
  const res = await authAxios.post<TokenResponse>('/auth/verify-2fa-login', body);
  return res.data;
}

export async function verify2FAWithBackupCode(
  temp_token: string,
  backup_code: string
): Promise<TokenResponse> {
  const body = { temp_token, backup_code };
  console.log('[XDR-Auth] POST /auth/verify-2fa-login (backup code)', { temp_token: '***' });
  const res = await authAxios.post<TokenResponse>('/auth/verify-2fa-login', body);
  return res.data;
}

export async function refreshToken(refresh_token: string): Promise<TokenResponse> {
  const res = await axios.post<TokenResponse>(`${BACKEND_URL}/auth/refresh`, {
    refresh_token,
  });
  return res.data;
}

export async function logout(): Promise<void> {
  try {
    await authAxios.post('/auth/logout');
  } catch {
    // Network error is acceptable — backend may be unreachable; proceed with local cleanup
  } finally {
    clearTokens();
  }
}

export async function logoutAll(): Promise<void> {
  try {
    await authAxios.post('/auth/logout-all');
  } finally {
    clearTokens();
  }
}

export async function getMe(): Promise<UserResponse> {
  const res = await authAxios.get<UserResponse>('/auth/me');
  return res.data;
}

export async function enable2FA(): Promise<MFASetupResponse> {
  const res = await authAxios.post<MFASetupResponse>('/auth/enable-2fa');
  return res.data;
}

export async function verify2FASetup(otp_code: string): Promise<void> {
  await authAxios.post('/auth/verify-2fa', { otp_code });
}

export async function disable2FA(otp_code: string): Promise<void> {
  await authAxios.post('/auth/disable-2fa', { otp_code });
}

export async function regenerateBackupCodes(): Promise<BackupCodesResponse> {
  const res = await authAxios.post<BackupCodesResponse>('/auth/backup-codes');
  return res.data;
}

export async function listTrustedDevices(): Promise<TrustedDevice[]> {
  const res = await authAxios.get<TrustedDevice[]>('/auth/trusted-devices');
  return res.data;
}

export async function revokeTrustedDevice(deviceId: string): Promise<void> {
  await authAxios.delete(`/auth/trusted-devices/${deviceId}`);
}

export async function revokeAllTrustedDevices(): Promise<void> {
  await authAxios.delete('/auth/trusted-devices');
  clearDeviceToken();
}

// ── Credential Recovery ───────────────────────────────────────────────────────

export async function forgotPassword(
  email: string
): Promise<{ message: string; dev_token?: string }> {
  const res = await authAxios.post<{ message: string; dev_token?: string }>(
    '/auth/forgot-password',
    { email }
  );
  return res.data;
}

export async function resetPassword(
  token: string,
  new_password: string,
  mfa_code?: string,
  backup_code?: string
): Promise<{ message: string }> {
  const body: Record<string, string> = { token, new_password };
  if (mfa_code) body.mfa_code = mfa_code;
  if (backup_code) body.backup_code = backup_code;
  const res = await authAxios.post<{ message: string }>('/auth/reset-password', body);
  return res.data;
}

export async function requestMFARecovery(
  email: string,
  reason: string
): Promise<{ message: string; request_id: string }> {
  const res = await authAxios.post<{ message: string; request_id: string }>(
    '/auth/recovery/request-mfa',
    { email, reason }
  );
  return res.data;
}

export async function getPendingMFARecoveryRequests(): Promise<any[]> {
  const res = await authAxios.get<any>('/auth/recovery/pending');
  return Array.isArray(res.data) ? res.data : (res.data?.requests ?? []);
}

export async function approveMFARecovery(
  requestId: string,
  action: 'approve' | 'deny'
): Promise<{ message: string }> {
  const res = await authAxios.post<{ message: string }>(
    `/auth/recovery/approve/${requestId}`,
    { action }
  );
  return res.data;
}

export async function generateBackupCodes(): Promise<{ codes: string[] }> {
  // Backend route is POST /auth/backup-codes (no /generate suffix)
  const res = await authAxios.post<{ codes: string[] }>('/auth/backup-codes');
  return res.data;
}

export async function getBackupCodesStatus(): Promise<{ remaining: number }> {
  const res = await authAxios.get<{ remaining: number }>('/auth/backup-codes/status');
  return res.data;
}

export async function checkRecoveryToken(
  token: string
): Promise<{ valid: boolean; requires_mfa: boolean }> {
  // Use plain axios (no auth header needed — public endpoint)
  const res = await axios.get<{ valid: boolean; requires_mfa: boolean }>(
    `${BACKEND_URL}/auth/recovery/check`,
    { params: { token } }
  );
  return res.data;
}
