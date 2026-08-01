import React, { useState, useRef, useEffect, useCallback } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { toast } from 'react-hot-toast';
import { useAuth } from '../context/AuthContext';
import { verify2FA, verify2FAWithBackupCode } from '../services/authService';
import OTPInput from '../components/OTPInput';
import DualOrbitLoader from '../components/shared/DualOrbitLoader';

interface LocationState {
  from?: { pathname: string };
}

type LoginStep = 'credentials' | 'otp' | 'setup';

// ── Error classification ──────────────────────────────────────────────────────

type ErrorCategory =
  | 'WRONG_CODE'
  | 'REPLAY_BLOCKED'
  | 'SESSION_EXPIRED'
  | 'ACCOUNT_LOCKED'
  | 'RATE_LIMITED'
  | 'SETUP_REQUIRED'
  | 'VALIDATION';

type ErrorAction = 'shake' | 'redirect-credentials' | 'lockout-countdown' | 'restart-flow';

interface AuthErrorState {
  category: ErrorCategory;
  message: string;
  subtext?: string;
  action: ErrorAction;
  lockoutMinutes?: number;
}

/** Extract a plain string from any axios/fetch error shape */
function getRawDetail(err: unknown): { detail: string; status?: number } {
  if (err && typeof err === 'object') {
    const axiosErr = err as {
      response?: { status?: number; data?: { detail?: unknown } };
      message?: string;
    };
    const status = axiosErr.response?.status;
    const raw = axiosErr.response?.data?.detail;

    if (typeof raw === 'string') return { detail: raw, status };

    if (Array.isArray(raw)) {
      const joined = raw
        .map((d) => {
          if (d && typeof d === 'object' && 'msg' in d) {
            return String((d as { msg: unknown }).msg).replace(/^Value error,\s*/i, '');
          }
          return String(d);
        })
        .join(' · ');
      return { detail: joined, status };
    }

    if (axiosErr.message) return { detail: axiosErr.message, status };
  }
  if (err instanceof Error) return { detail: err.message };
  return { detail: 'Authentication failed' };
}

/** Extract lockout minutes from a backend "locked until HH:MM:SS" or "locked for N minutes" string */
function extractLockoutMinutes(detail: string): number {
  // "locked until 2026-04-26T15:32:00" or "Try again in 14 minutes"
  const minMatch = detail.match(/(\d+)\s*minute/i);
  if (minMatch) return parseInt(minMatch[1], 10);
  // "locked until <ISO timestamp>"
  const untilMatch = detail.match(/locked until\s+(.+)/i);
  if (untilMatch) {
    const lockUntil = new Date(untilMatch[1].trim());
    if (!isNaN(lockUntil.getTime())) {
      const diffMs = lockUntil.getTime() - Date.now();
      return Math.max(1, Math.ceil(diffMs / 60_000));
    }
  }
  return 15; // fallback
}

/** Extract remaining attempts from "N attempt(s) remaining" */
function extractRemainingAttempts(detail: string): number | null {
  const m = detail.match(/(\d+)\s+attempt/i);
  return m ? parseInt(m[1], 10) : null;
}

function classifyAuthError(err: unknown): AuthErrorState {
  const { detail, status } = getRawDetail(err);
  const d = detail.toLowerCase();

  // Rate limiting — 429 or explicit message
  if (status === 429 || d.includes('rate limit') || d.includes('too many')) {
    return {
      category: 'RATE_LIMITED',
      message: 'Too Many Attempts',
      subtext: 'Your request has been throttled. Please wait before trying again.',
      action: 'lockout-countdown',
      lockoutMinutes: extractLockoutMinutes(detail) || 5,
    };
  }

  // Already locked (403 with "locked until")
  if (status === 403 && d.includes('locked until')) {
    return {
      category: 'ACCOUNT_LOCKED',
      message: 'Account Temporarily Locked',
      subtext: detail,
      action: 'lockout-countdown',
      lockoutMinutes: extractLockoutMinutes(detail),
    };
  }

  // Account just became locked
  if (d.includes('account is now locked')) {
    return {
      category: 'ACCOUNT_LOCKED',
      message: 'Account Locked',
      subtext: 'Too many failed attempts. Your account is temporarily locked.',
      action: 'lockout-countdown',
      lockoutMinutes: extractLockoutMinutes(detail),
    };
  }

  // Temp token already used — session expired
  if (d.includes('already been used. please log in') || d.includes('invalid temp token')) {
    return {
      category: 'SESSION_EXPIRED',
      message: 'Session Expired',
      subtext: 'Your authentication session has expired. Please start over.',
      action: 'redirect-credentials',
    };
  }

  // TOTP replay block
  if (d.includes('already been used. wait') || d.includes('already been used — wait')) {
    return {
      category: 'REPLAY_BLOCKED',
      message: 'Code Already Used',
      subtext: 'This OTP was already consumed. Wait for the next 30-second window.',
      action: 'shake',
    };
  }

  // Wrong OTP code (also covers expired codes — valid_window=0 means only the
  // current 30-second window is accepted, so a code that just rolled over fails here)
  if (d.includes('invalid otp') || d.includes('invalid code') || d.includes('wrong code')) {
    return {
      category: 'WRONG_CODE',
      message: 'Invalid Code',
      subtext: 'The code you entered does not match or has expired. Enter the code currently shown in your authenticator app.',
      action: 'shake',
    };
  }

  // 2FA secret not found
  if (d.includes('2fa secret not found') || d.includes('2fa not set up')) {
    return {
      category: 'SETUP_REQUIRED',
      message: 'Setup Required',
      subtext: 'Two-factor authentication is not configured for this account.',
      action: 'restart-flow',
    };
  }

  // Wrong credentials with remaining attempts
  if (d.includes('invalid email or password') || d.includes('remaining')) {
    return {
      category: 'WRONG_CODE',
      message: 'Authentication Failed',
      subtext: detail,
      action: 'shake',
    };
  }

  // Generic validation / anything else
  return {
    category: 'VALIDATION',
    message: 'Authentication Error',
    subtext: detail,
    action: 'shake',
  };
}

// ── ErrorPanel component ──────────────────────────────────────────────────────

interface ErrorPanelProps {
  error: AuthErrorState;
  onDismiss: () => void;
  onRestart?: () => void;
}

function ErrorPanel({ error, onDismiss, onRestart }: ErrorPanelProps) {
  const [secondsLeft, setSecondsLeft] = useState<number>(
    (error.lockoutMinutes ?? 0) * 60
  );

  useEffect(() => {
    if (error.action !== 'lockout-countdown') return;
    const initialSecs = (error.lockoutMinutes ?? 5) * 60;
    setSecondsLeft(initialSecs);
    const id = setInterval(() => {
      setSecondsLeft((s) => {
        if (s <= 1) { clearInterval(id); return 0; }
        return s - 1;
      });
    }, 1000);
    return () => clearInterval(id);
  }, [error.action, error.lockoutMinutes]);

  const mins = Math.floor(secondsLeft / 60);
  const secs = secondsLeft % 60;
  const countdownStr = `${mins}m ${String(secs).padStart(2, '0')}s`;

  const isAmber =
    error.category === 'ACCOUNT_LOCKED' || error.category === 'RATE_LIMITED';

  const panelColor = isAmber ? '#f59e0b' : '#ff4466';
  const panelBg = isAmber ? 'rgba(245,158,11,0.08)' : 'rgba(255,30,60,0.08)';
  const panelBorder = isAmber
    ? '1px solid rgba(245,158,11,0.35)'
    : '1px solid rgba(255,30,60,0.35)';
  const panelShadow = isAmber
    ? '0 0 16px rgba(245,158,11,0.12)'
    : '0 0 16px rgba(255,30,60,0.12)';

  const Icon = () => {
    switch (error.category) {
      case 'WRONG_CODE':
        return (
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={panelColor} strokeWidth="2.5">
            <circle cx="12" cy="12" r="10" />
            <line x1="15" y1="9" x2="9" y2="15" />
            <line x1="9" y1="9" x2="15" y2="15" />
          </svg>
        );
      case 'SESSION_EXPIRED':
        return (
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={panelColor} strokeWidth="2.5">
            <circle cx="12" cy="12" r="10" />
            <polyline points="12 6 12 12 16 14" />
          </svg>
        );
      case 'REPLAY_BLOCKED':
        return (
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={panelColor} strokeWidth="2.5">
            <polyline points="1 4 1 10 7 10" />
            <path d="M3.51 15a9 9 0 102.13-9.36L1 10" />
            <line x1="12" y1="8" x2="12" y2="12" />
            <line x1="12" y1="16" x2="12.01" y2="16" />
          </svg>
        );
      case 'ACCOUNT_LOCKED':
        return (
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={panelColor} strokeWidth="2.5">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
            <path d="M7 11V7a5 5 0 0110 0v4" />
          </svg>
        );
      case 'RATE_LIMITED':
        return (
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={panelColor} strokeWidth="2.5">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            <line x1="12" y1="8" x2="12" y2="12" />
            <line x1="12" y1="16" x2="12.01" y2="16" />
          </svg>
        );
      case 'SETUP_REQUIRED':
        return (
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={panelColor} strokeWidth="2.5">
            <circle cx="12" cy="12" r="3" />
            <path d="M19.07 4.93a10 10 0 010 14.14M4.93 4.93a10 10 0 000 14.14" />
          </svg>
        );
      default:
        return (
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={panelColor} strokeWidth="2.5">
            <circle cx="12" cy="12" r="10" />
            <line x1="12" y1="8" x2="12" y2="12" />
            <line x1="12" y1="16" x2="12.01" y2="16" />
          </svg>
        );
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: -8, scale: 0.97 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      exit={{ opacity: 0, y: -8, scale: 0.97 }}
      transition={{ duration: 0.2, ease: 'easeOut' }}
      style={{
        position: 'relative',
        background: panelBg,
        border: panelBorder,
        borderRadius: 10,
        boxShadow: panelShadow,
        padding: '12px 14px',
        marginTop: 8,
      }}
    >
      {/* Dismiss button */}
      <button
        type="button"
        onClick={onDismiss}
        aria-label="Dismiss error"
        style={{
          position: 'absolute',
          top: 8,
          right: 8,
          background: 'none',
          border: 'none',
          cursor: 'pointer',
          color: panelColor,
          opacity: 0.6,
          padding: 2,
          lineHeight: 1,
          display: 'flex',
          alignItems: 'center',
        }}
      >
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
          <line x1="18" y1="6" x2="6" y2="18" />
          <line x1="6" y1="6" x2="18" y2="18" />
        </svg>
      </button>

      {/* Header row */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, paddingRight: 20 }}>
        <Icon />
        <span
          style={{
            color: panelColor,
            fontWeight: 700,
            fontSize: 13,
            fontFamily: "'Fira Code', monospace",
            letterSpacing: 1,
          }}
        >
          {error.message}
        </span>
      </div>

      {/* Subtext */}
      {error.subtext && (
        <p
          style={{
            color: 'rgba(224,244,255,0.7)',
            fontSize: 11,
            margin: '6px 0 0',
            fontFamily: "'Fira Code', monospace",
            lineHeight: 1.5,
            paddingRight: 20,
          }}
        >
          {error.subtext}
        </p>
      )}

      {/* Countdown for lockout/rate-limit */}
      {error.action === 'lockout-countdown' && secondsLeft > 0 && (
        <div
          style={{
            marginTop: 8,
            display: 'inline-flex',
            alignItems: 'center',
            gap: 6,
            background: isAmber ? 'rgba(245,158,11,0.1)' : 'rgba(255,30,60,0.1)',
            border: panelBorder,
            borderRadius: 20,
            padding: '3px 10px',
          }}
        >
          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke={panelColor} strokeWidth="2.5">
            <circle cx="12" cy="12" r="10" />
            <polyline points="12 6 12 12 16 14" />
          </svg>
          <span
            style={{
              color: panelColor,
              fontSize: 11,
              fontFamily: "'Fira Code', monospace",
              letterSpacing: 1,
            }}
          >
            Try again in {countdownStr}
          </span>
        </div>
      )}
      {error.action === 'lockout-countdown' && secondsLeft === 0 && (
        <p style={{ color: '#00d4ff', fontSize: 11, margin: '8px 0 0', fontFamily: "'Fira Code', monospace" }}>
          You may try again now.
        </p>
      )}

      {/* Restart flow button for SETUP_REQUIRED */}
      {error.action === 'restart-flow' && onRestart && (
        <button
          type="button"
          onClick={onRestart}
          style={{
            marginTop: 10,
            padding: '6px 14px',
            borderRadius: 6,
            border: `1px solid ${panelColor}`,
            background: 'transparent',
            color: panelColor,
            fontSize: 11,
            fontWeight: 700,
            fontFamily: "'Fira Code', monospace",
            letterSpacing: 1,
            cursor: 'pointer',
            textTransform: 'uppercase',
          }}
        >
          Restart Login
        </button>
      )}
    </motion.div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function LoginPage({ overlay = false }: { overlay?: boolean } = {}) {
  const navigate = useNavigate();
  const location = useLocation();
  const { login, completeMFALogin, isAuthenticated, isLoading } = useAuth();
  const from = (location.state as LocationState)?.from?.pathname ?? '/dashboard';

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [shake, setShake] = useState(false);

  // Step machine: credentials → otp | setup
  const [step, setStep] = useState<LoginStep>('credentials');
  const [tempToken, setTempToken] = useState('');
  const [otp, setOtp] = useState('');
  const [otpLoading, setOtpLoading] = useState(false);
  const [useBackupCode, setUseBackupCode] = useState(false);
  const [backupCode, setBackupCode] = useState('');

  // Setup step state (first-time TOTP enrollment)
  const [setupQrBase64, setSetupQrBase64] = useState('');
  const [setupSecret, setSetupSecret] = useState('');
  const [setupBackupCodes, setSetupBackupCodes] = useState<string[]>([]);
  const [backupCopied, setBackupCopied] = useState(false);
  const [backupAcknowledged, setBackupAcknowledged] = useState(false);

  // 30-second TOTP countdown (synced to the real TOTP window)
  const [countdown, setCountdown] = useState(30);

  // Hover-to-expand card state
  const [expanded, setExpanded] = useState(false);

  // Password visibility toggle
  const [showPwd, setShowPwd] = useState(false);

  // Login success flash state (green checkmark before redirect)
  const [loginSuccess, setLoginSuccess] = useState(false);

  // Structured error state
  const [authError, setAuthError] = useState<AuthErrorState | null>(null);

  // Remaining attempts amber counter (credentials step only)
  const [remainingAttempts, setRemainingAttempts] = useState<number | null>(null);

  // Particle canvas
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animRef = useRef<number>(0);

  // Card expands on hover, while submitting, mid-flow, or when fields have content.
  // Default state is collapsed (logo only) — hover reveals the form.
  const isExpanded =
    expanded ||
    step !== 'credentials' ||
    loading ||
    email !== '' ||
    password !== '';

  // Only redirect once hydration is complete. Without the isLoading guard,
  // this fires while isAuthenticated is transiently false during hydration,
  // which can leave authenticated users stuck on the login page.
  useEffect(() => {
    if (!isLoading && isAuthenticated) navigate(from, { replace: true });
  }, [isLoading, isAuthenticated, navigate, from]);

  // Sync countdown with actual TOTP 30-second window
  useEffect(() => {
    if (step !== 'otp' && step !== 'setup') return;
    const tick = () => {
      const rem = 30 - (Math.floor(Date.now() / 1000) % 30);
      setCountdown(rem);
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [step]);

  // Particle animation
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let W = canvas.width = window.innerWidth;
    let H = canvas.height = window.innerHeight;

    const handleResize = () => {
      W = canvas.width = window.innerWidth;
      H = canvas.height = window.innerHeight;
    };
    window.addEventListener('resize', handleResize);

    const COLS = Math.ceil(W / 40) + 1;
    const ROWS = Math.ceil(H / 40) + 1;

    interface Particle { x: number; y: number; vy: number; opacity: number; size: number; }
    const particles: Particle[] = Array.from({ length: 40 }, () => ({
      x: Math.random() * W,
      y: Math.random() * H,
      vy: 0.2 + Math.random() * 0.4,
      opacity: 0.1 + Math.random() * 0.5,
      size: 1 + Math.random() * 2,
    }));

    let t = 0;
    function draw() {
      if (!ctx) return;
      ctx.clearRect(0, 0, W, H);

      // Dark background
      ctx.fillStyle = '#050b18';
      ctx.fillRect(0, 0, W, H);

      // Grid
      ctx.strokeStyle = 'rgba(0,212,255,0.06)';
      ctx.lineWidth = 1;
      for (let c = 0; c < COLS; c++) {
        ctx.beginPath();
        ctx.moveTo(c * 40, 0);
        ctx.lineTo(c * 40, H);
        ctx.stroke();
      }
      for (let r = 0; r < ROWS; r++) {
        ctx.beginPath();
        ctx.moveTo(0, r * 40);
        ctx.lineTo(W, r * 40);
        ctx.stroke();
      }

      // Floating dots
      particles.forEach((p) => {
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(0,212,255,${p.opacity * (0.6 + 0.4 * Math.sin(t * 0.02 + p.x))})`;
        ctx.fill();
        p.y -= p.vy;
        if (p.y < -10) { p.y = H + 10; p.x = Math.random() * W; }
      });

      t++;
      animRef.current = requestAnimationFrame(draw);
    }
    draw();
    return () => {
      cancelAnimationFrame(animRef.current);
      window.removeEventListener('resize', handleResize);
    };
  }, []);

  const triggerShake = () => {
    setShake(true);
    setTimeout(() => setShake(false), 400);
  };

  const clearError = useCallback(() => {
    setAuthError(null);
  }, []);

  const handleAuthError = useCallback(
    (err: unknown) => {
      const classified = classifyAuthError(err);
      setAuthError(classified);
      toast.error(classified.message, { style: toastErrorStyle });

      if (classified.action === 'shake') {
        triggerShake();
      }

      if (classified.action === 'redirect-credentials') {
        // Show error for 2.5 s, then auto-reset to credentials step
        setTimeout(() => {
          setAuthError(null);
          setStep('credentials');
          setOtp('');
          setBackupCode('');
          setUseBackupCode(false);
          setTempToken('');
        }, 2500);
      }

      // Extract remaining attempts for credentials step amber hint
      if (classified.category === 'WRONG_CODE' && classified.subtext) {
        const rem = extractRemainingAttempts(classified.subtext);
        setRemainingAttempts(rem);
      } else {
        setRemainingAttempts(null);
      }
    },
    [] // eslint-disable-line react-hooks/exhaustive-deps
  );

  const handleRestartFlow = useCallback(() => {
    setAuthError(null);
    setStep('credentials');
    setOtp('');
    setBackupCode('');
    setUseBackupCode(false);
    setTempToken('');
    setSetupQrBase64('');
    setSetupSecret('');
    setSetupBackupCodes([]);
    setBackupAcknowledged(false);
    setRemainingAttempts(null);
  }, []);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password) {
      triggerShake();
      setAuthError({
        category: 'VALIDATION',
        message: 'Fields Required',
        subtext: 'Email and password are required.',
        action: 'shake',
      });
      return;
    }
    setLoading(true);
    setAuthError(null);
    setRemainingAttempts(null);
    try {
      const result = await login(email, password);
      if (result.requires2FA && result.tempToken) {
        setTempToken(result.tempToken);
        if (result.requiresSetup) {
          // First-time TOTP enrollment — show QR code + backup codes
          setSetupQrBase64(result.qrCodeBase64 ?? '');
          setSetupSecret(result.secret ?? '');
          setSetupBackupCodes(result.backupCodes ?? []);
          setStep('setup');
          toast('Set up your authenticator app to continue', { icon: '🔐', style: toastInfoStyle });
        } else {
          setStep('otp');
          toast('Enter the 6-digit code from your authenticator app', { icon: '🔐', style: toastInfoStyle });
        }
      }
    } catch (err: unknown) {
      handleAuthError(err);
    } finally {
      setLoading(false);
    }
  };

  const handleOTPVerify = async (e: React.FormEvent) => {
    e.preventDefault();

    if (useBackupCode) {
      const normalised = backupCode.trim();
      if (normalised.length < 6) {
        setAuthError({
          category: 'VALIDATION',
          message: 'Backup Code Required',
          subtext: 'Please enter your backup code.',
          action: 'shake',
        });
        triggerShake();
        return;
      }
      setOtpLoading(true);
      setAuthError(null);
      if (process.env.NODE_ENV === 'development') {
        console.log('[XDR-Auth] Sending backup code verify:', { temp_token: tempToken ? '***' : 'MISSING', backup_code: normalised });
      }
      try {
        const tokens = await verify2FAWithBackupCode(tempToken, normalised);
        // completeMFALogin stores tokens AND fetches /auth/me so that
        // isAuthenticated is true before navigate() renders ProtectedRoute.
        await completeMFALogin(tokens);
        setLoginSuccess(true);
        setTimeout(() => { navigate(from, { replace: true }); }, 800);
      } catch (err: unknown) {
        if (process.env.NODE_ENV === 'development') {
          console.error('[XDR-Auth] Backup code verify failed:', err);
        }
        handleAuthError(err);
        setBackupCode('');
      } finally {
        setOtpLoading(false);
      }
      return;
    }

    if (otp.length < 6) {
      setAuthError({
        category: 'VALIDATION',
        message: 'Code Incomplete',
        subtext: 'Enter all 6 digits from your authenticator app.',
        action: 'shake',
      });
      triggerShake();
      return;
    }
    setOtpLoading(true);
    setAuthError(null);
    if (process.env.NODE_ENV === 'development') {
      console.log('[XDR-Auth] Sending OTP verify:', { temp_token: tempToken ? '***' : 'MISSING', otp_code: otp, otp_length: otp.length });
    }
    try {
      const tokens = await verify2FA(tempToken, otp);
      // completeMFALogin stores tokens AND fetches /auth/me so that
      // isAuthenticated is true before navigate() renders ProtectedRoute.
      await completeMFALogin(tokens);
      setLoginSuccess(true);
      setTimeout(() => { navigate(from, { replace: true }); }, 800);
    } catch (err: unknown) {
      if (process.env.NODE_ENV === 'development') {
        console.error('[XDR-Auth] OTP verify failed:', err);
      }
      handleAuthError(err);
      setOtp('');
    } finally {
      setOtpLoading(false);
    }
  };

  const handleSetupVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (setupBackupCodes.length > 0 && !backupAcknowledged) {
      setAuthError({
        category: 'VALIDATION',
        message: 'Backup Codes Not Saved',
        subtext: 'Save your backup codes and check the box to continue.',
        action: 'shake',
      });
      triggerShake();
      return;
    }
    if (otp.length < 6) {
      setAuthError({
        category: 'VALIDATION',
        message: 'Code Incomplete',
        subtext: 'Enter the 6-digit code from your authenticator app.',
        action: 'shake',
      });
      triggerShake();
      return;
    }
    setOtpLoading(true);
    setAuthError(null);
    if (process.env.NODE_ENV === 'development') {
      console.log('[XDR-Auth] Sending setup OTP verify:', { temp_token: tempToken ? '***' : 'MISSING', otp_code: otp, otp_length: otp.length });
    }
    try {
      const tokens = await verify2FA(tempToken, otp);
      // completeMFALogin stores tokens AND fetches /auth/me so that
      // isAuthenticated is true before navigate() renders ProtectedRoute.
      await completeMFALogin(tokens);
      setLoginSuccess(true);
      setTimeout(() => { navigate(from, { replace: true }); }, 800);
    } catch (err: unknown) {
      if (process.env.NODE_ENV === 'development') {
        console.error('[XDR-Auth] Setup OTP verify failed:', err);
      }
      handleAuthError(err);
      setOtp('');
    } finally {
      setOtpLoading(false);
    }
  };

  const copyBackupCodes = () => {
    navigator.clipboard.writeText(setupBackupCodes.join('\n')).then(() => {
      setBackupCopied(true);
      setTimeout(() => setBackupCopied(false), 2500);
      toast.success('Backup codes copied', { style: toastSuccessStyle });
    });
  };

  // While hydration is in progress, render a minimal spinner.
  // This prevents the collapsed card from flashing before we know whether
  // the user is authenticated (in which case we redirect) or not
  // (in which case we show the fully-expanded form).
  if (isLoading) {
    return (
      <div
        style={{
          minHeight: '100vh',
          // In overlay mode the iframe cinematic is behind us — transparent bg
          // so we don't cover it with a solid dark screen during hydration.
          background: overlay ? 'transparent' : '#050b18',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}
      >
        <DualOrbitLoader size={64} label="Authenticating..." />
      </div>
    );
  }

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        position: 'relative',
        overflow: 'hidden',
        background: overlay ? 'transparent' : '#050b18',
      }}
    >
      {/* Particle canvas background — hidden in overlay/cinematic mode */}
      {!overlay && <canvas ref={canvasRef} style={{ position: 'fixed', inset: 0, zIndex: 0 }} />}

      {/* Corner decorations */}
      <CornerDecoration position="top-left" />
      <CornerDecoration position="top-right" />
      <CornerDecoration position="bottom-left" />
      <CornerDecoration position="bottom-right" />

      {/* Demo Mode bypass — client-only, skips login/MFA/backend entirely.
          Not rendered here in overlay mode: StartupScreen mounts its own
          top-level copy so it's clickable immediately, unaffected by the
          overlay's pointerEvents:'none' wrapper and not gated behind
          scrolling to the last cinematic scene. */}

      {/* Auth card — layout-animated, hover to expand */}
      <motion.div
        layout
        initial={{ y: 40, opacity: 0, scale: 0.96 }}
        animate={{ y: 0, opacity: 1, scale: 1 }}
        transition={{ type: 'spring', stiffness: 260, damping: 28 }}
        onHoverStart={() => setExpanded(true)}
        onHoverEnd={() => setExpanded(false)}
        className="scan-line-container"
        style={{
          pointerEvents: 'auto',
          position: 'relative',
          zIndex: 10,
          width: '100%',
          maxWidth: 420,
          margin: '24px',
          background: 'rgba(0,20,40,0.82)',
          backdropFilter: 'blur(20px)',
          WebkitBackdropFilter: 'blur(20px)',
          border: authError ? '1px solid rgba(255,30,60,0.55)' : '1px solid rgba(0,212,255,0.3)',
          borderRadius: 16,
          boxShadow: authError
            ? '0 0 30px rgba(255,30,60,0.25), 0 0 80px rgba(120,0,20,0.4), inset 0 1px 0 rgba(255,30,60,0.12)'
            : '0 0 30px rgba(0,212,255,0.15), 0 0 80px rgba(0,50,100,0.4), inset 0 1px 0 rgba(0,212,255,0.1)',
          padding: '40px 36px',
          overflow: 'hidden',
        }}
      >
        {/* Logo — always visible */}
        <div style={{ textAlign: 'center', marginBottom: isExpanded ? 32 : 16 }}>
          <motion.div
            animate={{ boxShadow: ['0 0 16px rgba(0,212,255,0.4)', '0 0 36px rgba(0,212,255,0.75)', '0 0 16px rgba(0,212,255,0.4)'] }}
            transition={{ duration: 2, repeat: Infinity }}
            style={{
              width: 90,
              height: 90,
              borderRadius: 18,
              background: '#070c18',
              border: '1px solid rgba(0,212,255,0.35)',
              overflow: 'hidden',
              margin: '0 auto 16px',
            }}
          >
            <img
              src="/logo.jpg"
              alt="Cyber Sentinel XDR"
              style={{ width: '100%', height: '100%', objectFit: 'cover', display: 'block' }}
            />
          </motion.div>
          <h1
            className="neon-text"
            style={{
              margin: 0,
              fontSize: 20,
              fontWeight: 900,
              letterSpacing: 3,
              textTransform: 'uppercase',
              fontFamily: "'Fira Code', monospace",
            }}
          >
            CYBER SENTINEL XDR
          </h1>
          <p
            style={{
              margin: '6px 0 0',
              fontSize: 10,
              letterSpacing: 4,
              color: '#6b8fa3',
              textTransform: 'uppercase',
              fontWeight: 600,
            }}
          >
            Security Operations Center
          </p>

        </div>

        {/* Login success flash overlay */}
        <AnimatePresence>
          {loginSuccess && (
            <motion.div
              key="success-flash"
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.3, ease: 'easeOut' }}
              style={{
                position: 'absolute',
                inset: 0,
                borderRadius: 16,
                background: 'rgba(0,255,136,0.08)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexDirection: 'column',
                gap: 12,
                zIndex: 20,
                backdropFilter: 'blur(4px)',
              }}
            >
              <motion.div
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                transition={{ type: 'spring', stiffness: 300, damping: 20, delay: 0.1 }}
                style={{
                  width: 64,
                  height: 64,
                  borderRadius: '50%',
                  background: 'rgba(0,255,136,0.15)',
                  border: '2px solid #00ff88',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  boxShadow: '0 0 24px rgba(0,255,136,0.4)',
                }}
              >
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#00ff88" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="20 6 9 17 4 12" />
                </svg>
              </motion.div>
              <span style={{ color: '#00ff88', fontWeight: 800, fontSize: 13, letterSpacing: 2, fontFamily: "'Fira Code', monospace", textTransform: 'uppercase' }}>
                Access Granted
              </span>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Form + footer block — only shown when isExpanded */}
        <AnimatePresence>
          {isExpanded && (
            <motion.div
              key="form-block"
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              transition={{ duration: 0.22 }}
            >
              <AnimatePresence mode="wait">
                {step === 'credentials' && (
                  /* ── Step 1: Credentials ──────────────────────────────────── */
                  <motion.form
                    key="login-form"
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: 20 }}
                    transition={{ duration: 0.2 }}
                    className={shake ? 'field-error' : ''}
                    onSubmit={handleLogin}
                    style={{ display: 'flex', flexDirection: 'column', gap: 16 }}
                  >
                    <div>
                      <label style={labelStyle}>Email</label>
                      <input
                        type="email"
                        value={email}
                        onChange={(e) => { setEmail(e.target.value); clearError(); setRemainingAttempts(null); }}
                        placeholder="operator@sentinel.local"
                        autoComplete="email"
                        className="xdr-input"
                        style={inputStyle}
                        onFocus={(e) => Object.assign(e.target.style, inputFocusStyle)}
                        onBlur={(e) => Object.assign(e.target.style, inputStyle)}
                      />
                    </div>

                    <div>
                      <label style={labelStyle}>Password</label>
                      <div style={{ position: 'relative' }}>
                        <input
                          type={showPwd ? 'text' : 'password'}
                          value={password}
                          onChange={(e) => { setPassword(e.target.value); clearError(); setRemainingAttempts(null); }}
                          placeholder="••••••••••••"
                          autoComplete="current-password"
                          className="xdr-input"
                          style={{ ...inputStyle, paddingRight: '40px' }}
                          onFocus={(e) => Object.assign(e.target.style, { ...inputFocusStyle, paddingRight: '40px' })}
                          onBlur={(e) => Object.assign(e.target.style, { ...inputStyle, paddingRight: '40px' })}
                        />
                        <button
                          type="button"
                          onClick={() => setShowPwd(p => !p)}
                          style={{ position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', padding: 0, color: '#6b8fa3', lineHeight: 1 }}
                          aria-label={showPwd ? 'Hide password' : 'Show password'}
                        >
                          {showPwd ? (
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                              <path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94"/>
                              <path d="M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19"/>
                              <line x1="1" y1="1" x2="23" y2="23"/>
                            </svg>
                          ) : (
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                              <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                              <circle cx="12" cy="12" r="3"/>
                            </svg>
                          )}
                        </button>
                      </div>
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: -6 }}>
                      <span
                        style={{ color: '#6b8fa3', fontSize: 11, cursor: 'pointer', letterSpacing: 0.5, fontFamily: "'Fira Code', monospace", transition: 'color 0.2s' }}
                        onClick={() => navigate('/forgot-password')}
                        onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.color = '#00d4ff'; }}
                        onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.color = '#6b8fa3'; }}
                      >
                        Forgot password?
                      </span>
                      <span
                        style={{ color: '#6b8fa3', fontSize: 11, cursor: 'pointer', letterSpacing: 0.5, fontFamily: "'Fira Code', monospace", transition: 'color 0.2s' }}
                        onClick={() => navigate('/mfa-recovery')}
                        onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.color = '#ffaa00'; }}
                        onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.color = '#6b8fa3'; }}
                      >
                        Lost MFA device?
                      </span>
                    </div>

                    {/* Inline error panel for credentials step */}
                    <AnimatePresence>
                      {authError && step === 'credentials' && (
                        <ErrorPanel
                          key="creds-error"
                          error={authError}
                          onDismiss={clearError}
                          onRestart={handleRestartFlow}
                        />
                      )}
                    </AnimatePresence>

                    {/* Amber remaining-attempts hint */}
                    <AnimatePresence>
                      {remainingAttempts !== null && (
                        <motion.p
                          key="remaining-hint"
                          initial={{ opacity: 0, y: -4 }}
                          animate={{ opacity: 1, y: 0 }}
                          exit={{ opacity: 0, y: -4 }}
                          transition={{ duration: 0.18 }}
                          style={{
                            margin: 0,
                            color: '#f59e0b',
                            fontSize: 11,
                            fontFamily: "'Fira Code', monospace",
                            textAlign: 'center',
                            letterSpacing: 0.5,
                          }}
                        >
                          {remainingAttempts} attempt{remainingAttempts !== 1 ? 's' : ''} remaining before lockout
                        </motion.p>
                      )}
                    </AnimatePresence>

                    <motion.button whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }} type="submit" disabled={loading}
                      className="xdr-btn"
                      style={{ marginTop: 8, padding: '12px 24px', borderRadius: 8, border: 'none', background: loading ? 'rgba(0,50,80,0.5)' : 'linear-gradient(135deg, #00d4ff 0%, #0066ff 100%)', color: loading ? '#6b8fa3' : '#050b18', fontWeight: 900, fontSize: 13, letterSpacing: 2, textTransform: 'uppercase', cursor: loading ? 'not-allowed' : 'pointer', boxShadow: loading ? 'none' : '0 0 20px rgba(0,212,255,0.4)', transition: 'all 0.2s', fontFamily: "'Fira Code', monospace" }}>
                      {loading ? 'Authenticating...' : 'Authenticate'}
                    </motion.button>

                    <div style={{ textAlign: 'center', marginTop: 12 }}>
                      <span style={{ color: '#6b8fa3', fontSize: 11 }}>First-time setup on a new database? </span>
                      <Link to="/register" style={{ color: '#00d4ff', fontSize: 11, fontWeight: 700, textDecoration: 'none' }}>Create the admin account</Link>
                    </div>
                  </motion.form>
                )}

                {step === 'otp' && (
                  /* ── Step 2: OTP verification ─────────────────────────────── */
                  <motion.form
                    key="otp-form"
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -20 }}
                    transition={{ duration: 0.2 }}
                    className={shake ? 'field-error' : ''}
                    onSubmit={handleOTPVerify}
                    style={{ display: 'flex', flexDirection: 'column', gap: 16, alignItems: 'center', width: '100%' }}
                  >
                    <div style={{ textAlign: 'center' }}>
                      <span style={{ fontSize: 32 }}>🔐</span>
                      <p style={{ color: '#e0f4ff', fontWeight: 700, fontSize: 14, margin: '8px 0 4px', letterSpacing: 1 }}>
                        Two-Factor Authentication
                      </p>
                      <p style={{ color: '#6b8fa3', fontSize: 12, margin: '0 0 8px' }}>
                        {useBackupCode ? 'Enter one of your backup codes' : 'Enter the 6-digit code from your authenticator app'}
                      </p>
                      {!useBackupCode && (
                        <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6, background: 'rgba(0,212,255,0.06)', border: '1px solid rgba(0,212,255,0.15)', borderRadius: 20, padding: '3px 12px' }}>
                          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke={countdown <= 5 ? '#ff6688' : '#00d4ff'} strokeWidth="2.5">
                            <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
                          </svg>
                          <span style={{ fontSize: 11, fontFamily: "'Fira Code', monospace", color: countdown <= 5 ? '#ff6688' : '#6b8fa3', letterSpacing: 1 }}>
                            {countdown}s
                          </span>
                        </div>
                      )}
                    </div>

                    {useBackupCode ? (
                      <input
                        type="text"
                        value={backupCode}
                        onChange={(e) => { setBackupCode(e.target.value.toUpperCase()); clearError(); }}
                        placeholder="XXXX-XXXX"
                        autoComplete="off"
                        style={{ ...inputStyle, width: '100%', textAlign: 'center', letterSpacing: 4, fontSize: 16 }}
                        onFocus={(e) => Object.assign(e.target.style, { ...inputFocusStyle, textAlign: 'center', letterSpacing: 4, fontSize: 16 })}
                        onBlur={(e) => Object.assign(e.target.style, { ...inputStyle, textAlign: 'center', letterSpacing: 4, fontSize: 16 })}
                      />
                    ) : (
                      <div onChange={() => clearError()} style={{ width: '100%', display: 'flex', justifyContent: 'center' }}>
                        <OTPInput value={otp} onChange={(v) => { setOtp(v); clearError(); }} disabled={otpLoading} />
                      </div>
                    )}

                    {/* Inline error panel for OTP step */}
                    <AnimatePresence>
                      {authError && step === 'otp' && (
                        <div style={{ width: '100%' }}>
                          <ErrorPanel
                            key="otp-error"
                            error={authError}
                            onDismiss={clearError}
                            onRestart={handleRestartFlow}
                          />
                        </div>
                      )}
                    </AnimatePresence>

                    <motion.button whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }} type="submit"
                      disabled={otpLoading || (!useBackupCode && otp.length < 6) || (useBackupCode && backupCode.trim().length < 6)}
                      style={{ width: '100%', padding: '12px 24px', borderRadius: 8, border: 'none', background: (otpLoading || (!useBackupCode && otp.length < 6) || (useBackupCode && backupCode.trim().length < 6)) ? 'rgba(0,50,80,0.5)' : 'linear-gradient(135deg, #00d4ff 0%, #0066ff 100%)', color: (otpLoading || (!useBackupCode && otp.length < 6) || (useBackupCode && backupCode.trim().length < 6)) ? '#6b8fa3' : '#050b18', fontWeight: 900, fontSize: 13, letterSpacing: 2, textTransform: 'uppercase', cursor: 'pointer', fontFamily: "'Fira Code', monospace", boxShadow: (!otpLoading && ((!useBackupCode && otp.length === 6) || (useBackupCode && backupCode.trim().length >= 6))) ? '0 0 20px rgba(0,212,255,0.4)' : 'none' }}>
                      {otpLoading ? 'Verifying...' : 'Verify Code'}
                    </motion.button>

                    <button type="button" onClick={() => { setUseBackupCode(b => !b); setOtp(''); setBackupCode(''); clearError(); }}
                      style={{ background: 'none', border: 'none', color: '#00d4ff', fontSize: 11, cursor: 'pointer', fontFamily: "'Fira Code', monospace", letterSpacing: 0.5 }}>
                      {useBackupCode ? 'Use authenticator app instead' : 'Use backup code instead'}
                    </button>
                    <button type="button" onClick={() => { setStep('credentials'); setOtp(''); setBackupCode(''); setUseBackupCode(false); clearError(); }}
                      style={{ background: 'none', border: 'none', color: '#6b8fa3', fontSize: 11, cursor: 'pointer', textDecoration: 'underline' }}>
                      Back to login
                    </button>
                  </motion.form>
                )}

                {step === 'setup' && (
                  /* ── Step 3: First-time TOTP enrollment ───────────────────── */
                  <motion.form
                    key="setup-form"
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -20 }}
                    transition={{ duration: 0.2 }}
                    onSubmit={handleSetupVerify}
                    style={{ display: 'flex', flexDirection: 'column', gap: 14 }}
                  >
                    <div style={{ textAlign: 'center' }}>
                      <img src="/logo.jpg" alt="Cyber Sentinel XDR" style={{ width: 44, height: 44, borderRadius: 10, objectFit: 'cover', border: '1px solid rgba(0,212,255,0.3)', marginBottom: 6 }} />
                      <p style={{ color: '#00d4ff', fontWeight: 700, fontSize: 13, margin: '6px 0 2px', letterSpacing: 2, textTransform: 'uppercase', fontFamily: "'Fira Code', monospace" }}>
                        MFA Setup Required
                      </p>
                      <p style={{ color: '#6b8fa3', fontSize: 11, margin: '0 0 6px' }}>
                        Scan the QR code in your authenticator app
                      </p>
                    </div>

                    {/* QR Code */}
                    {setupQrBase64 && (
                      <div style={{ display: 'flex', justifyContent: 'center', padding: 12, background: '#ffffff', borderRadius: 10, width: 'fit-content', margin: '0 auto', boxShadow: '0 0 16px rgba(0,212,255,0.2)' }}>
                        <img src={`data:image/png;base64,${setupQrBase64}`} alt="QR Code" style={{ width: 140, height: 140, display: 'block' }} />
                      </div>
                    )}

                    {/* Manual secret */}
                    {setupSecret && (
                      <div>
                        <p style={{ color: '#475569', fontSize: 10, margin: '0 0 4px', letterSpacing: 1, textTransform: 'uppercase', fontFamily: "'Fira Code', monospace" }}>Or enter manually</p>
                        <div style={{ background: 'rgba(0,0,0,0.4)', border: '1px solid rgba(0,212,255,0.2)', borderRadius: 6, padding: '8px 12px', fontFamily: "'Fira Code', monospace", fontSize: 12, color: '#00d4ff', letterSpacing: 2, wordBreak: 'break-all', userSelect: 'all', textAlign: 'center' }}>
                          {setupSecret.match(/.{1,4}/g)?.join(' ')}
                        </div>
                      </div>
                    )}

                    {/* Backup codes */}
                    {setupBackupCodes.length > 0 && (
                      <div style={{ background: 'rgba(0,0,0,0.4)', border: '1px solid rgba(245,158,11,0.3)', borderRadius: 8, padding: '10px 12px' }}>
                        <p style={{ color: '#f59e0b', fontSize: 10, margin: '0 0 8px', fontWeight: 700, letterSpacing: 0.5 }}>
                          SAVE THESE BACKUP CODES — shown only once
                        </p>
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '3px 12px', marginBottom: 8 }}>
                          {setupBackupCodes.map((c, i) => (
                            <span key={i} style={{ fontFamily: "'Fira Code', monospace", fontSize: 11, color: '#e2e8f0', letterSpacing: 1 }}>{c}</span>
                          ))}
                        </div>
                        <button type="button" onClick={copyBackupCodes}
                          style={{ width: '100%', padding: '6px', borderRadius: 5, border: '1px solid rgba(245,158,11,0.4)', background: backupCopied ? 'rgba(16,185,129,0.15)' : 'rgba(245,158,11,0.08)', color: backupCopied ? '#10b981' : '#f59e0b', fontSize: 10, fontWeight: 700, letterSpacing: 1, cursor: 'pointer', fontFamily: "'Fira Code', monospace", marginBottom: 8 }}>
                          {backupCopied ? 'COPIED!' : 'COPY ALL CODES'}
                        </button>
                        <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
                          <input type="checkbox" checked={backupAcknowledged} onChange={(e) => setBackupAcknowledged(e.target.checked)}
                            style={{ accentColor: '#00d4ff', width: 13, height: 13, cursor: 'pointer' }} />
                          <span style={{ color: '#94a3b8', fontSize: 10, fontFamily: "'Fira Code', monospace" }}>
                            I have saved these codes securely
                          </span>
                        </label>
                      </div>
                    )}

                    {/* OTP confirmation */}
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, marginBottom: 8 }}>
                        <p style={{ color: '#6b8fa3', fontSize: 11, margin: 0 }}>
                          Enter the 6-digit code shown in your app
                        </p>
                        <div style={{ display: 'inline-flex', alignItems: 'center', gap: 4, background: 'rgba(0,212,255,0.06)', border: '1px solid rgba(0,212,255,0.15)', borderRadius: 20, padding: '2px 8px' }}>
                          <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke={countdown <= 5 ? '#ff6688' : '#00d4ff'} strokeWidth="2.5">
                            <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
                          </svg>
                          <span style={{ fontSize: 10, fontFamily: "'Fira Code', monospace", color: countdown <= 5 ? '#ff6688' : '#6b8fa3', letterSpacing: 1 }}>
                            {countdown}s
                          </span>
                        </div>
                      </div>
                      <OTPInput value={otp} onChange={(v) => { setOtp(v); clearError(); }} disabled={otpLoading} />
                    </div>

                    {/* Inline error panel for setup step */}
                    <AnimatePresence>
                      {authError && step === 'setup' && (
                        <ErrorPanel
                          key="setup-error"
                          error={authError}
                          onDismiss={clearError}
                          onRestart={handleRestartFlow}
                        />
                      )}
                    </AnimatePresence>

                    <motion.button whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }} type="submit"
                      disabled={otpLoading || otp.length < 6 || (setupBackupCodes.length > 0 && !backupAcknowledged)}
                      style={{ padding: '12px 24px', borderRadius: 8, border: 'none', background: (otpLoading || otp.length < 6 || (setupBackupCodes.length > 0 && !backupAcknowledged)) ? 'rgba(0,50,80,0.5)' : 'linear-gradient(135deg, #00d4ff 0%, #0066ff 100%)', color: (otpLoading || otp.length < 6 || (setupBackupCodes.length > 0 && !backupAcknowledged)) ? '#6b8fa3' : '#050b18', fontWeight: 900, fontSize: 13, letterSpacing: 2, textTransform: 'uppercase', cursor: 'pointer', fontFamily: "'Fira Code', monospace", boxShadow: (!otpLoading && otp.length === 6) ? '0 0 20px rgba(0,212,255,0.4)' : 'none' }}>
                      {otpLoading ? 'Activating...' : 'Activate 2FA & Sign In'}
                    </motion.button>

                    <button type="button" onClick={() => { setStep('credentials'); setOtp(''); setSetupQrBase64(''); setSetupSecret(''); setSetupBackupCodes([]); setBackupAcknowledged(false); clearError(); }}
                      style={{ background: 'none', border: 'none', color: '#6b8fa3', fontSize: 11, cursor: 'pointer', textDecoration: 'underline', textAlign: 'center' }}>
                      Back to login
                    </button>
                  </motion.form>
                )}
              </AnimatePresence>

              {/* ── Footer ────────────────────────────────────────────────────── */}
              <div style={{
                marginTop: 'auto',
                padding: '20px 0 8px',
                textAlign: 'center',
                borderTop: '1px solid rgba(99,102,241,0.1)',
                paddingTop: 16,
              }}>
                {/* Trust badges row */}
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, marginBottom: 10 }}>
                  {['TLS 1.3', 'FIPS 140-2', 'ZERO TRUST'].map((badge) => (
                    <span
                      key={badge}
                      style={{
                        fontSize: 10,
                        color: '#a5b4fc',
                        letterSpacing: 0.8,
                        fontWeight: 700,
                        fontFamily: "'Fira Code', monospace",
                        textTransform: 'uppercase',
                        border: '1px solid rgba(99,102,241,0.5)',
                        background: 'rgba(99,102,241,0.1)',
                        borderRadius: 4,
                        padding: '2px 8px',
                      }}
                    >
                      {badge}
                    </span>
                  ))}
                </div>

                {/* Nav links row */}
                <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 0, marginBottom: 8 }}>
                  {[
                    { label: '▶ Intro', to: '/startup' },
                    { label: 'Contact Us', to: '/contact-us' },
                    { label: 'Help', to: '/help' },
                    { label: 'Privacy Policy', to: '/privacy-policy' },
                  ].map(({ label, to }, i) => (
                    <React.Fragment key={label}>
                      {i > 0 && (
                        <span style={{ color: '#334155', fontSize: 11, margin: '0 6px', userSelect: 'none' }}>|</span>
                      )}
                      <Link
                        to={to}
                        style={{
                          color: label === '▶ Intro' ? '#6366f1' : '#64748b',
                          fontSize: 11,
                          textDecoration: 'none',
                          fontFamily: "'Fira Code', monospace",
                          letterSpacing: 0.5,
                          transition: 'color 0.2s ease',
                        }}
                        onMouseEnter={e => ((e.currentTarget as HTMLElement).style.color = label === '▶ Intro' ? '#a5b4fc' : '#94a3b8')}
                        onMouseLeave={e => ((e.currentTarget as HTMLElement).style.color = label === '▶ Intro' ? '#6366f1' : '#64748b')}
                      >
                        {label}
                      </Link>
                    </React.Fragment>
                  ))}
                </div>

                {/* Copyright */}
                <p style={{
                  margin: 0,
                  textAlign: 'center',
                  fontSize: 11,
                  color: '#475569',
                  letterSpacing: 0.5,
                  fontFamily: "'Fira Code', monospace",
                }}>
                  <span style={{ color: '#6366f1', fontWeight: 600 }}>v1.0.0</span>
                  {' '}&nbsp;|&nbsp;{' '}
                  &copy; 2026 Cyber Sentinel XDR. All rights reserved.
                </p>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>
    </div>
  );
}

// ── Decorative corner brackets ───────────────────────────────────────────────
function CornerDecoration({ position }: { position: 'top-left' | 'top-right' | 'bottom-left' | 'bottom-right' }) {
  const size = 60;
  const thickness = 2;
  const color = 'rgba(0,212,255,0.3)';
  const style: React.CSSProperties = {
    position: 'fixed',
    width: size,
    height: size,
    zIndex: 5,
    ...(position.includes('top') ? { top: 20 } : { bottom: 20 }),
    ...(position.includes('left') ? { left: 20 } : { right: 20 }),
    borderTop: position.includes('top') ? `${thickness}px solid ${color}` : 'none',
    borderBottom: position.includes('bottom') ? `${thickness}px solid ${color}` : 'none',
    borderLeft: position.includes('left') ? `${thickness}px solid ${color}` : 'none',
    borderRight: position.includes('right') ? `${thickness}px solid ${color}` : 'none',
    pointerEvents: 'none',
  };
  return <div style={style} />;
}

// ── Styles ───────────────────────────────────────────────────────────────────
const labelStyle: React.CSSProperties = {
  display: 'block',
  fontSize: 10,
  fontWeight: 700,
  color: '#6b8fa3',
  letterSpacing: 1.5,
  textTransform: 'uppercase',
  marginBottom: 6,
  fontFamily: "'Fira Code', monospace",
};

const inputStyle: React.CSSProperties = {
  width: '100%',
  padding: '11px 14px',
  background: 'rgba(0,10,25,0.8)',
  border: '1px solid rgba(0,212,255,0.2)',
  borderRadius: 8,
  color: '#e0f4ff',
  fontSize: 14,
  fontFamily: "'Fira Code', monospace",
  outline: 'none',
  transition: 'all 0.2s',
  boxSizing: 'border-box',
};

const inputFocusStyle: React.CSSProperties = {
  ...inputStyle,
  border: '1px solid rgba(0,212,255,0.7)',
  boxShadow: '0 0 12px rgba(0,212,255,0.2)',
  background: 'rgba(0,20,40,0.9)',
};

const toastErrorStyle = {
  background: '#1a0010',
  color: '#ff6688',
  border: '1px solid rgba(255,51,102,0.4)',
  fontSize: '13px',
};

const toastSuccessStyle = {
  background: '#001a10',
  color: '#00ff88',
  border: '1px solid rgba(0,255,136,0.3)',
  fontSize: '13px',
};

const toastInfoStyle = {
  background: '#001030',
  color: '#00d4ff',
  border: '1px solid rgba(0,212,255,0.3)',
  fontSize: '13px',
};
