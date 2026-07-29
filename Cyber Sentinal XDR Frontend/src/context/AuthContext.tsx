import React, {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  ReactNode,
} from 'react';
import {
  getMe,
  login as loginApi,
  logout as logoutApi,
  storeTokens,
  clearTokens,
  refreshToken,
} from '../services/authService';
import { UserResponse, TokenResponse } from '../types/auth';

/**
 * Demo Mode — a purely client-side login bypass for offline/no-backend demos.
 * No real token is ever issued; `isDemoMode` is a flag the axios interceptor
 * in authService.ts also reads so it doesn't bounce the user back to /login
 * when demo-mode API calls inevitably 401/403 against a real backend.
 */
const DEMO_MODE_KEY = 'xdr_demo_mode';

const DEMO_USER: UserResponse = {
  id: 'demo-user',
  username: 'Demo User',
  email: 'demo@cybersentinel.local',
  role: 'admin',
  two_factor_enabled: false,
  created_at: new Date().toISOString(),
  last_login: new Date().toISOString(),
};

export function isDemoModeActive(): boolean {
  return localStorage.getItem(DEMO_MODE_KEY) === '1';
}

interface AuthContextType {
  user: UserResponse | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  isDemoMode: boolean;
  /** Always returns requires2FA: true with a tempToken. requiresSetup is true on first login (no TOTP yet). */
  login(email: string, password: string): Promise<{
    requires2FA: boolean;
    tempToken?: string;
    requiresSetup?: boolean;
    secret?: string;
    qrCodeBase64?: string;
    backupCodes?: string[];
  }>;
  /**
   * Called after a successful POST /auth/verify-2fa-login.
   * Stores the tokens in localStorage AND updates the in-memory user state so
   * ProtectedRoute sees isAuthenticated=true immediately without a page reload.
   */
  completeMFALogin(tokens: TokenResponse): Promise<void>;
  logout(): Promise<void>;
  refreshUser(): Promise<void>;
  /** Client-only bypass — skips real login/MFA entirely, no backend call. */
  enterDemoMode(): void;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<UserResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isDemoMode, setIsDemoMode] = useState(false);

  // On mount: hydrate from stored token.
  // Order of operations:
  //   0. If demo mode was previously activated, short-circuit straight to the
  //      synthetic demo user — no network calls, no real token required.
  //   1. If no access_token, attempt a silent refresh first (avoids a guaranteed 401 from /auth/me).
  //   2. Only call /auth/me once we have a valid (possibly freshly-issued) access token.
  //   3. If both fail, treat as unauthenticated — no error toast, no redirect.
  useEffect(() => {
    const hydrate = async () => {
      if (isDemoModeActive()) {
        setIsDemoMode(true);
        setUser(DEMO_USER);
        setIsLoading(false);
        return;
      }

      let accessToken = localStorage.getItem('access_token');

      if (!accessToken) {
        // No access token — try silent refresh before giving up.
        const storedRefresh = localStorage.getItem('refresh_token');
        if (!storedRefresh) {
          // Nothing to work with — unauthenticated state, stay quiet.
          setIsLoading(false);
          return;
        }
        try {
          const tokens = await refreshToken(storedRefresh);
          storeTokens(tokens);
          accessToken = tokens.access_token;
        } catch {
          // Refresh token is expired or invalid — clear stale tokens silently.
          clearTokens();
          setIsLoading(false);
          return;
        }
      }

      // At this point we have a valid access token (original or freshly refreshed).
      try {
        const me = await getMe();
        setUser(me);
      } catch {
        // Access token rejected (e.g. server restarted, key rotated) — try one refresh.
        const storedRefresh = localStorage.getItem('refresh_token');
        if (storedRefresh) {
          try {
            const tokens = await refreshToken(storedRefresh);
            storeTokens(tokens);
            const me = await getMe();
            setUser(me);
          } catch {
            clearTokens();
          }
        } else {
          clearTokens();
        }
      } finally {
        setIsLoading(false);
      }
    };
    hydrate();
  }, []);

  const login = useCallback(
    async (email: string, password: string) => {
      const result = await loginApi(email, password);
      // Login always returns a 2FA challenge — tokens are never issued directly
      if ('requires_2fa' in result && result.requires_2fa) {
        return {
          requires2FA: true,
          tempToken: result.temp_token,
          requiresSetup: result.requires_setup,
          secret: result.secret,
          qrCodeBase64: result.qr_code_base64,
          backupCodes: result.backup_codes,
        };
      }
      // Fallback (should not occur with mandatory MFA backend)
      const tokens = result as TokenResponse;
      storeTokens(tokens);
      const me = await getMe();
      setUser(me);
      return { requires2FA: false };
    },
    []
  );

  const completeMFALogin = useCallback(async (tokens: TokenResponse) => {
    // 1. Persist tokens to localStorage so all axios calls and future hydrations work.
    storeTokens(tokens);
    // 2. Fetch the full user profile so isAuthenticated flips to true synchronously
    //    from React's perspective before navigate() renders ProtectedRoute.
    try {
      const me = await getMe();
      setUser(me);
    } catch {
      // Extremely unlikely — we just received fresh tokens from the backend.
      // Clear to avoid a stale-token loop.
      clearTokens();
    }
  }, []);

  const enterDemoMode = useCallback(() => {
    localStorage.setItem(DEMO_MODE_KEY, '1');
    setIsDemoMode(true);
    setUser(DEMO_USER);
    setIsLoading(false);
  }, []);

  const logout = useCallback(async () => {
    const wasDemoMode = isDemoModeActive();
    localStorage.removeItem(DEMO_MODE_KEY);
    setIsDemoMode(false);
    if (wasDemoMode) {
      // Demo mode never held a real session — nothing to tell the backend.
      setUser(null);
      return;
    }
    try {
      await logoutApi();
    } catch {
      // Backend may be offline; local cleanup still runs
    } finally {
      setUser(null);
      clearTokens();
    }
  }, []);

  const refreshUser = useCallback(async () => {
    try {
      const me = await getMe();
      setUser(me);
    } catch {
      // silent
    }
  }, []);

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: user !== null,
        isLoading,
        isDemoMode,
        login,
        completeMFALogin,
        logout,
        refreshUser,
        enterDemoMode,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextType {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
