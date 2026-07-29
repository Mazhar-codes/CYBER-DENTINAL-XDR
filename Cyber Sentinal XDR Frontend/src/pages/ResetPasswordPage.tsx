// ResetPasswordPage.tsx
// Account recovery — step 2: verify MFA → set new password → success timeline.

import React, { useState, useRef, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { toast } from 'react-hot-toast';
import { resetPassword, checkRecoveryToken } from '../services/authService';
import OTPInput from '../components/OTPInput';
import SecurityRecoveryTimeline, { TimelineEvent } from '../components/SecurityRecoveryTimeline';

// ── Toast styles ─────────────────────────────────────────────────────────────
const toastErrStyle = {
  background: '#1a0010',
  color: '#ff6688',
  border: '1px solid rgba(255,51,102,0.4)',
  fontSize: '13px',
  fontFamily: "'Fira Code', monospace",
};
const toastSuccessStyle = {
  background: '#001a10',
  color: '#00ff88',
  border: '1px solid rgba(0,255,136,0.3)',
  fontSize: '13px',
  fontFamily: "'Fira Code', monospace",
};

// ── Password strength (mirrors RegisterPage) ─────────────────────────────────
type PwdStrength = 0 | 1 | 2 | 3 | 4;

function pwdStrength(pw: string): PwdStrength {
  if (!pw) return 0;
  let s = 0;
  if (pw.length >= 8) s++;
  if (pw.length >= 12) s++;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) s++;
  if (/[0-9]/.test(pw)) s++;
  if (/[^A-Za-z0-9]/.test(pw)) s++;
  return Math.min(4, s) as PwdStrength;
}

const STRENGTH_LABELS: Record<PwdStrength, string> = { 0: '', 1: 'Weak', 2: 'Fair', 3: 'Good', 4: 'Strong' };
const STRENGTH_COLORS: Record<PwdStrength, string> = {
  0: 'transparent', 1: '#ff3366', 2: '#ffaa00', 3: '#00d4ff', 4: '#00ff88',
};
const STRENGTH_WIDTHS: Record<PwdStrength, string> = {
  0: '0%', 1: '25%', 2: '50%', 3: '75%', 4: '100%',
};

// ── Requirement checklist ─────────────────────────────────────────────────────
interface Req { label: string; met: boolean; }
function buildReqs(pw: string): Req[] {
  return [
    { label: '12+ characters', met: pw.length >= 12 },
    { label: 'Uppercase letter', met: /[A-Z]/.test(pw) },
    { label: 'Lowercase letter', met: /[a-z]/.test(pw) },
    { label: 'Number', met: /[0-9]/.test(pw) },
    { label: 'Special character', met: /[^A-Za-z0-9]/.test(pw) },
  ];
}

// ── Canvas particle background ────────────────────────────────────────────────
function useParticleCanvas(ref: React.RefObject<HTMLCanvasElement | null>) {
  const animRef = useRef<number>(0);
  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    let W = (canvas.width = window.innerWidth);
    let H = (canvas.height = window.innerHeight);
    const onResize = () => { W = canvas.width = window.innerWidth; H = canvas.height = window.innerHeight; };
    window.addEventListener('resize', onResize);
    interface P { x: number; y: number; vy: number; opacity: number; size: number; }
    const pts: P[] = Array.from({ length: 40 }, () => ({
      x: Math.random() * W, y: Math.random() * H,
      vy: 0.2 + Math.random() * 0.4,
      opacity: 0.1 + Math.random() * 0.5,
      size: 1 + Math.random() * 2,
    }));
    let t = 0;
    function draw() {
      if (!ctx) return;
      ctx.fillStyle = '#050b18'; ctx.fillRect(0, 0, W, H);
      ctx.strokeStyle = 'rgba(0,212,255,0.06)'; ctx.lineWidth = 1;
      for (let c = 0; c <= Math.ceil(W / 40); c++) { ctx.beginPath(); ctx.moveTo(c * 40, 0); ctx.lineTo(c * 40, H); ctx.stroke(); }
      for (let r = 0; r <= Math.ceil(H / 40); r++) { ctx.beginPath(); ctx.moveTo(0, r * 40); ctx.lineTo(W, r * 40); ctx.stroke(); }
      pts.forEach((p) => {
        ctx.beginPath(); ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(0,212,255,${p.opacity * (0.6 + 0.4 * Math.sin(t * 0.02 + p.x))})`; ctx.fill();
        p.y -= p.vy; if (p.y < -10) { p.y = H + 10; p.x = Math.random() * W; }
      });
      t++; animRef.current = requestAnimationFrame(draw);
    }
    draw();
    return () => { cancelAnimationFrame(animRef.current); window.removeEventListener('resize', onResize); };
  }, [ref]);
}

// ── Corner decorations ────────────────────────────────────────────────────────
function Corner({ pos }: { pos: 'tl' | 'tr' | 'bl' | 'br' }) {
  const clr = 'rgba(0,212,255,0.28)';
  const s: React.CSSProperties = {
    position: 'fixed', width: 56, height: 56, zIndex: 5, pointerEvents: 'none',
    ...(pos.includes('t') ? { top: 20 } : { bottom: 20 }),
    ...(pos.includes('l') ? { left: 20 } : { right: 20 }),
    borderTop: pos.includes('t') ? `2px solid ${clr}` : 'none',
    borderBottom: pos.includes('b') ? `2px solid ${clr}` : 'none',
    borderLeft: pos.includes('l') ? `2px solid ${clr}` : 'none',
    borderRight: pos.includes('r') ? `2px solid ${clr}` : 'none',
  };
  return <div style={s} />;
}

// ── Step progress indicator ───────────────────────────────────────────────────
function StepIndicator({ current, total }: { current: number; total: number }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 0, marginBottom: 28 }}>
      {Array.from({ length: total }, (_, i) => {
        const done = i < current;
        const active = i === current;
        return (
          <React.Fragment key={i}>
            <motion.div
              animate={{
                background: done
                  ? '#00ff88'
                  : active
                  ? '#00d4ff'
                  : 'rgba(51,65,85,0.6)',
                boxShadow: active ? '0 0 10px rgba(0,212,255,0.6)' : 'none',
              }}
              transition={{ duration: 0.35 }}
              style={{
                width: 28,
                height: 28,
                borderRadius: '50%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                border: `2px solid ${done ? '#00ff88' : active ? '#00d4ff' : '#334155'}`,
                fontSize: 11,
                fontWeight: 700,
                fontFamily: "'Fira Code', monospace",
                color: done || active ? '#050b18' : '#475569',
                flexShrink: 0,
              }}
            >
              {done ? (
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#050b18" strokeWidth="3">
                  <polyline points="20 6 9 17 4 12" />
                </svg>
              ) : (
                i + 1
              )}
            </motion.div>
            {i < total - 1 && (
              <motion.div
                animate={{ background: done ? '#00ff88' : 'rgba(51,65,85,0.4)' }}
                transition={{ duration: 0.35 }}
                style={{ width: 36, height: 2, borderRadius: 1 }}
              />
            )}
          </React.Fragment>
        );
      })}
    </div>
  );
}

// ── Shared input style helper ─────────────────────────────────────────────────
function inp(hasError = false): React.CSSProperties {
  return {
    width: '100%',
    padding: '11px 14px',
    background: 'rgba(0,10,25,0.8)',
    border: `1px solid ${hasError ? 'rgba(255,51,102,0.6)' : 'rgba(0,212,255,0.2)'}`,
    borderRadius: 8,
    color: '#e0f4ff',
    fontSize: 14,
    fontFamily: "'Fira Code', monospace",
    outline: 'none',
    transition: 'all 0.2s',
    boxSizing: 'border-box',
    boxShadow: hasError ? '0 0 8px rgba(255,51,102,0.15)' : 'none',
  };
}

function applyFocus(el: HTMLInputElement) {
  el.style.border = '1px solid rgba(0,212,255,0.7)';
  el.style.boxShadow = '0 0 12px rgba(0,212,255,0.2)';
  el.style.background = 'rgba(0,20,40,0.9)';
}
function removeFocus(el: HTMLInputElement, hasError = false) {
  el.style.border = hasError ? '1px solid rgba(255,51,102,0.6)' : '1px solid rgba(0,212,255,0.2)';
  el.style.boxShadow = hasError ? '0 0 8px rgba(255,51,102,0.15)' : 'none';
  el.style.background = 'rgba(0,10,25,0.8)';
}

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

// ── Main component ────────────────────────────────────────────────────────────
type ResetStep = 0 | 1 | 2; // 0=MFA, 1=new password, 2=complete

export default function ResetPasswordPage() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const token = params.get('token') ?? '';

  const canvasRef = useRef<HTMLCanvasElement>(null);
  useParticleCanvas(canvasRef);

  const [step, setStep] = useState<ResetStep>(0);
  const [loading, setLoading] = useState(false);
  const [shake, setShake] = useState(false);

  // Step 0: MFA
  const [otp, setOtp] = useState('');
  const [useBackup, setUseBackup] = useState(false);
  const [backupCode, setBackupCode] = useState('');
  const [mfaError, setMfaError] = useState('');

  // Step 1: New password
  const [newPwd, setNewPwd] = useState('');
  const [confirmPwd, setConfirmPwd] = useState('');
  const [pwdError, setPwdError] = useState('');
  const [confirmError, setConfirmError] = useState('');
  const [showNewPwd, setShowNewPwd] = useState(false);
  const [showConfirmPwd, setShowConfirmPwd] = useState(false);

  // Step 2: collected MFA code for final API call
  const [resolvedMfaCode, setResolvedMfaCode] = useState('');
  const [resolvedBackupCode, setResolvedBackupCode] = useState('');

  // MFA requirement check (resolved on mount via GET /auth/recovery/check)
  const [mfaCheckDone, setMfaCheckDone] = useState(false);
  const [tokenValid, setTokenValid] = useState(true);
  const [accountRequiresMfa, setAccountRequiresMfa] = useState(true); // default true (safe)

  const strength = pwdStrength(newPwd);
  const reqs = buildReqs(newPwd);
  const completedAt = new Date().toLocaleTimeString();

  const triggerShake = () => { setShake(true); setTimeout(() => setShake(false), 400); };

  useEffect(() => {
    if (!token) return;
    checkRecoveryToken(token)
      .then((result) => {
        setTokenValid(result.valid);
        setAccountRequiresMfa(result.requires_mfa);
        // If token is valid and MFA is NOT required, skip directly to step 1
        if (result.valid && !result.requires_mfa) {
          setStep(1);
        }
      })
      .catch(() => {
        // On error, stay on step 0 (safer default — user can still try)
      })
      .finally(() => {
        setMfaCheckDone(true);
      });
  }, [token]); // eslint-disable-line react-hooks/exhaustive-deps

  if (!token) {
    return (
      <div
        style={{
          minHeight: '100vh',
          background: '#050b18',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}
      >
        <div
          style={{
            textAlign: 'center',
            background: 'rgba(0,20,40,0.84)',
            border: '1px solid rgba(255,51,102,0.4)',
            borderRadius: 14,
            padding: '40px 36px',
            maxWidth: 380,
          }}
        >
          <p style={{ color: '#ff6688', fontFamily: "'Fira Code', monospace", fontSize: 14, fontWeight: 700 }}>
            Invalid Recovery Link
          </p>
          <p style={{ color: '#6b8fa3', fontSize: 12, margin: '10px 0 20px', fontFamily: "'Fira Code', monospace" }}>
            This link is missing a token. Please request a new recovery email.
          </p>
          <button
            onClick={() => navigate('/forgot-password')}
            style={{
              padding: '10px 24px',
              borderRadius: 8,
              border: 'none',
              background: 'linear-gradient(135deg, #00d4ff, #0066ff)',
              color: '#050b18',
              fontWeight: 900,
              fontSize: 12,
              letterSpacing: 1.5,
              cursor: 'pointer',
              fontFamily: "'Fira Code', monospace",
            }}
          >
            Request New Link
          </button>
        </div>
      </div>
    );
  }

  // ── Step 0 submit: MFA verification ─────────────────────────────────────────
  const handleMFANext = (e: React.FormEvent) => {
    e.preventDefault();
    if (useBackup) {
      if (backupCode.trim().length < 6) {
        setMfaError('Enter your backup code');
        triggerShake();
        return;
      }
      setResolvedBackupCode(backupCode.trim());
    } else {
      if (otp.length < 6) {
        setMfaError('Enter all 6 digits from your authenticator app');
        triggerShake();
        return;
      }
      setResolvedMfaCode(otp);
    }
    setMfaError('');
    setStep(1);
  };

  // ── Step 1 submit: new password → call API ───────────────────────────────────
  const handlePasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    let valid = true;
    if (strength < 2) {
      setPwdError('Password too weak — at least Fair strength required');
      valid = false;
    } else {
      setPwdError('');
    }
    if (newPwd !== confirmPwd) {
      setConfirmError('Passwords do not match');
      valid = false;
    } else {
      setConfirmError('');
    }
    if (!valid) { triggerShake(); return; }

    setLoading(true);
    try {
      await resetPassword(
        token,
        newPwd,
        resolvedMfaCode || undefined,
        resolvedBackupCode || undefined
      );
      toast.success('Password updated — all sessions revoked', { style: toastSuccessStyle });
      setStep(2);
    } catch (err: unknown) {
      const msg = extractMsg(err);
      toast.error(msg, { style: toastErrStyle });
      triggerShake();
      // If MFA-related error, drop back to step 0
      if (msg.toLowerCase().includes('mfa') || msg.toLowerCase().includes('token') || msg.toLowerCase().includes('otp')) {
        setStep(0);
        setOtp('');
        setBackupCode('');
        setResolvedMfaCode('');
        setResolvedBackupCode('');
      }
    } finally {
      setLoading(false);
    }
  };

  // ── Recovery timeline events ─────────────────────────────────────────────────
  const timelineEvents: TimelineEvent[] = [
    { time: '', label: 'Recovery requested', status: 'completed', severity: 'info' },
    { time: '', label: 'Identity verified via MFA', status: 'completed', severity: 'info' },
    { time: '', label: 'New password set', status: 'completed', severity: 'info' },
    { time: '', label: 'All sessions revoked', status: 'completed', severity: 'info' },
    { time: completedAt, label: 'Security event logged', status: 'completed', severity: 'info' },
  ];

  const stepLabels = ['Identity Verification', 'New Password', 'Recovery Complete'];

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        position: 'relative',
        overflow: 'hidden',
        background: '#050b18',
        padding: '24px',
      }}
    >
      <canvas ref={canvasRef} style={{ position: 'fixed', inset: 0, zIndex: 0 }} />
      <Corner pos="tl" />
      <Corner pos="tr" />
      <Corner pos="bl" />
      <Corner pos="br" />

      <motion.div
        layout
        initial={{ y: 40, opacity: 0, scale: 0.96 }}
        animate={{ y: 0, opacity: 1, scale: 1 }}
        transition={{ type: 'spring', stiffness: 260, damping: 28 }}
        className="scan-line-container"
        style={{
          position: 'relative',
          zIndex: 10,
          width: '100%',
          maxWidth: 460,
          background: 'rgba(0,20,40,0.84)',
          backdropFilter: 'blur(20px)',
          WebkitBackdropFilter: 'blur(20px)',
          border: '1px solid rgba(0,212,255,0.3)',
          borderRadius: 16,
          boxShadow:
            '0 0 30px rgba(0,212,255,0.15), 0 0 80px rgba(0,50,100,0.4), inset 0 1px 0 rgba(0,212,255,0.1)',
          padding: '40px 36px',
          overflow: 'hidden',
        }}
      >
        {/* Header */}
        <div style={{ textAlign: 'center', marginBottom: 24 }}>
          <motion.div
            animate={{ boxShadow: ['0 0 16px rgba(0,212,255,0.4)', '0 0 32px rgba(0,212,255,0.7)', '0 0 16px rgba(0,212,255,0.4)'] }}
            transition={{ duration: 2, repeat: Infinity }}
            style={{
              width: 56,
              height: 56,
              borderRadius: 14,
              background: 'linear-gradient(135deg, rgba(0,212,255,0.2), rgba(0,80,180,0.3))',
              border: '1px solid rgba(0,212,255,0.4)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: 26,
              margin: '0 auto 14px',
            }}
          >
            🔑
          </motion.div>
          <h1
            className="neon-text"
            style={{
              margin: 0,
              fontSize: 17,
              fontWeight: 900,
              letterSpacing: 3,
              textTransform: 'uppercase',
              fontFamily: "'Fira Code', monospace",
            }}
          >
            Reset Password
          </h1>
          <p
            style={{
              margin: '6px 0 0',
              fontSize: 10,
              letterSpacing: 4,
              color: '#6b8fa3',
              textTransform: 'uppercase',
            }}
          >
            {stepLabels[step]}
          </p>
        </div>

        {!mfaCheckDone && token ? (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '48px 0', gap: 12 }}>
            <motion.div
              animate={{ rotate: 360 }}
              transition={{ duration: 0.9, repeat: Infinity, ease: 'linear' }}
              style={{ fontSize: 22, color: '#00d4ff' }}
            >
              ⟳
            </motion.div>
            <span style={{ color: '#6b8fa3', fontSize: 13, fontFamily: "'Fira Code', monospace" }}>
              Verifying recovery link...
            </span>
          </div>
        ) : (
          <>
        {/* Token-expired banner — shown when check resolves as invalid */}
        {!tokenValid && (
          <div style={{
            background: 'rgba(255,51,102,0.07)',
            border: '1px solid rgba(255,51,102,0.3)',
            borderRadius: 8,
            padding: '10px 14px',
            marginBottom: 18,
            display: 'flex',
            gap: 8,
            alignItems: 'flex-start',
          }}>
            <span style={{ color: '#ff6688', fontSize: 13 }}>✕</span>
            <p style={{ margin: 0, color: '#ff6688', fontSize: 11, fontFamily: "'Fira Code', monospace", lineHeight: 1.6 }}>
              This recovery link has expired or is invalid. Please request a new one.
            </p>
          </div>
        )}
        {/* Step progress */}
        <StepIndicator current={step} total={3} />

        <AnimatePresence mode="wait">
          {/* ── Step 0: MFA ─────────────────────────────────────────────────── */}
          {step === 0 && (
            <motion.form
              key="step-mfa"
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 20 }}
              transition={{ duration: 0.22 }}
              className={shake ? 'field-error' : ''}
              onSubmit={handleMFANext}
              style={{ display: 'flex', flexDirection: 'column', gap: 18, alignItems: 'center', width: '100%' }}
            >
              <div style={{ textAlign: 'center', width: '100%' }}>
                <p style={{ color: '#6b8fa3', fontSize: 12, margin: '0 0 18px', fontFamily: "'Fira Code', monospace", lineHeight: 1.7 }}>
                  {useBackup
                    ? 'Enter one of your saved backup codes to verify your identity.'
                    : 'Enter the 6-digit code from your authenticator app to verify your identity.'}
                </p>
              </div>

              {useBackup ? (
                <div style={{ width: '100%' }}>
                  <label style={labelStyle}>Backup Code</label>
                  <input
                    type="text"
                    value={backupCode}
                    onChange={(e) => { setBackupCode(e.target.value.toUpperCase()); setMfaError(''); }}
                    placeholder="XXXX-XXXX"
                    autoComplete="off"
                    style={{ ...inp(!!mfaError), textAlign: 'center', letterSpacing: 4, fontSize: 16 }}
                    onFocus={(e) => applyFocus(e.target)}
                    onBlur={(e) => removeFocus(e.target, !!mfaError)}
                  />
                </div>
              ) : (
                <div style={{ width: '100%', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8 }}>
                  <OTPInput value={otp} onChange={(v) => { setOtp(v); setMfaError(''); }} />
                </div>
              )}

              <AnimatePresence>
                {mfaError && (
                  <motion.p
                    initial={{ opacity: 0, y: -6 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0 }}
                    style={{
                      margin: 0,
                      fontSize: 12,
                      color: '#ff6688',
                      fontFamily: "'Fira Code', monospace",
                      textAlign: 'center',
                    }}
                  >
                    {mfaError}
                  </motion.p>
                )}
              </AnimatePresence>

              <motion.button
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                type="submit"
                disabled={useBackup ? backupCode.trim().length < 6 : otp.length < 6}
                style={{
                  width: '100%',
                  padding: '12px 24px',
                  borderRadius: 8,
                  border: 'none',
                  background:
                    (useBackup ? backupCode.trim().length >= 6 : otp.length === 6)
                      ? 'linear-gradient(135deg, #00d4ff 0%, #0066ff 100%)'
                      : 'rgba(0,50,80,0.5)',
                  color:
                    (useBackup ? backupCode.trim().length >= 6 : otp.length === 6)
                      ? '#050b18'
                      : '#6b8fa3',
                  fontWeight: 900,
                  fontSize: 13,
                  letterSpacing: 2,
                  textTransform: 'uppercase',
                  cursor: 'pointer',
                  fontFamily: "'Fira Code', monospace",
                  boxShadow:
                    (useBackup ? backupCode.trim().length >= 6 : otp.length === 6)
                      ? '0 0 20px rgba(0,212,255,0.4)'
                      : 'none',
                }}
              >
                Verify Identity
              </motion.button>

              <button
                type="button"
                onClick={() => { setUseBackup((b) => !b); setOtp(''); setBackupCode(''); setMfaError(''); }}
                style={{
                  background: 'none',
                  border: 'none',
                  color: '#00d4ff',
                  fontSize: 11,
                  cursor: 'pointer',
                  fontFamily: "'Fira Code', monospace",
                }}
              >
                {useBackup ? 'Use authenticator app instead' : 'Use backup code instead'}
              </button>
              <button
                type="button"
                onClick={() => navigate('/forgot-password')}
                style={{
                  background: 'none',
                  border: 'none',
                  color: '#6b8fa3',
                  fontSize: 11,
                  cursor: 'pointer',
                  textDecoration: 'underline',
                }}
              >
                Back — request new link
              </button>
            </motion.form>
          )}

          {/* ── Step 1: New password ─────────────────────────────────────────── */}
          {step === 1 && (
            <motion.form
              key="step-password"
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              transition={{ duration: 0.22 }}
              className={shake ? 'field-error' : ''}
              onSubmit={handlePasswordSubmit}
              style={{ display: 'flex', flexDirection: 'column', gap: 16 }}
            >
              {/* No-MFA info banner */}
              {!accountRequiresMfa && (
                <div style={{
                  background: 'rgba(0,255,136,0.06)',
                  border: '1px solid rgba(0,255,136,0.2)',
                  borderRadius: 8,
                  padding: '10px 14px',
                  marginBottom: 18,
                  display: 'flex',
                  gap: 8,
                  alignItems: 'flex-start',
                }}>
                  <span style={{ color: '#00ff88', fontSize: 13 }}>✓</span>
                  <p style={{ margin: 0, color: '#00ff88', fontSize: 11, fontFamily: "'Fira Code', monospace", lineHeight: 1.6 }}>
                    No MFA configured on this account. Proceed directly to set your new password.
                  </p>
                </div>
              )}
              {/* New password */}
              <div>
                <label style={{ ...labelStyle, color: pwdError ? '#ff6688' : '#6b8fa3' }}>
                  New Password
                </label>
                <div style={{ position: 'relative' }}>
                  <input
                    type={showNewPwd ? 'text' : 'password'}
                    value={newPwd}
                    onChange={(e) => { setNewPwd(e.target.value); setPwdError(''); }}
                    placeholder="••••••••••••"
                    autoComplete="new-password"
                    style={{ ...inp(!!pwdError), paddingRight: 40 }}
                    onFocus={(e) => applyFocus(e.target)}
                    onBlur={(e) => removeFocus(e.target, !!pwdError)}
                  />
                  <button
                    type="button"
                    onClick={() => setShowNewPwd((p) => !p)}
                    style={{ position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: '#6b8fa3', padding: 0 }}
                  >
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      {showNewPwd ? (
                        <>
                          <path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94" />
                          <path d="M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19" />
                          <line x1="1" y1="1" x2="23" y2="23" />
                        </>
                      ) : (
                        <>
                          <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                          <circle cx="12" cy="12" r="3" />
                        </>
                      )}
                    </svg>
                  </button>
                </div>
                {/* Strength bar */}
                {newPwd && (
                  <div style={{ marginTop: 8 }}>
                    <div style={{ height: 3, background: 'rgba(255,255,255,0.05)', borderRadius: 3, overflow: 'hidden' }}>
                      <motion.div
                        initial={{ width: '0%' }}
                        animate={{ width: STRENGTH_WIDTHS[strength] }}
                        transition={{ duration: 0.3 }}
                        style={{ height: '100%', background: STRENGTH_COLORS[strength], borderRadius: 3 }}
                      />
                    </div>
                    <span style={{ fontSize: 10, color: STRENGTH_COLORS[strength], fontWeight: 700, letterSpacing: 1, marginTop: 4, display: 'block' }}>
                      {STRENGTH_LABELS[strength]}
                    </span>
                  </div>
                )}
                {pwdError && (
                  <motion.p initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }} style={{ margin: '4px 0 0', fontSize: 11, color: '#ff6688', fontFamily: "'Fira Code', monospace" }}>
                    {pwdError}
                  </motion.p>
                )}
              </div>

              {/* Requirements checklist */}
              {newPwd && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  style={{
                    background: 'rgba(0,10,30,0.5)',
                    border: '1px solid rgba(0,212,255,0.1)',
                    borderRadius: 8,
                    padding: '10px 14px',
                  }}
                >
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                    {reqs.map((r) => (
                      <div key={r.label} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke={r.met ? '#00ff88' : '#334155'} strokeWidth="2.5">
                          {r.met ? <polyline points="20 6 9 17 4 12" /> : <circle cx="12" cy="12" r="10" />}
                        </svg>
                        <span style={{ fontSize: 11, color: r.met ? '#94a3b8' : '#475569', fontFamily: "'Fira Code', monospace" }}>
                          {r.label}
                        </span>
                      </div>
                    ))}
                  </div>
                </motion.div>
              )}

              {/* Confirm password */}
              <div>
                <label style={{ ...labelStyle, color: confirmError ? '#ff6688' : '#6b8fa3' }}>
                  Confirm Password
                </label>
                <div style={{ position: 'relative' }}>
                  <input
                    type={showConfirmPwd ? 'text' : 'password'}
                    value={confirmPwd}
                    onChange={(e) => { setConfirmPwd(e.target.value); setConfirmError(''); }}
                    placeholder="••••••••••••"
                    autoComplete="new-password"
                    style={{ ...inp(!!confirmError), paddingRight: 40 }}
                    onFocus={(e) => applyFocus(e.target)}
                    onBlur={(e) => removeFocus(e.target, !!confirmError)}
                  />
                  <button
                    type="button"
                    onClick={() => setShowConfirmPwd((p) => !p)}
                    style={{ position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: '#6b8fa3', padding: 0 }}
                  >
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      {showConfirmPwd ? (
                        <>
                          <path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94" />
                          <path d="M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19" />
                          <line x1="1" y1="1" x2="23" y2="23" />
                        </>
                      ) : (
                        <>
                          <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                          <circle cx="12" cy="12" r="3" />
                        </>
                      )}
                    </svg>
                  </button>
                </div>
                {confirmError && (
                  <motion.p initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }} style={{ margin: '4px 0 0', fontSize: 11, color: '#ff6688', fontFamily: "'Fira Code', monospace" }}>
                    {confirmError}
                  </motion.p>
                )}
              </div>

              <motion.button
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                type="submit"
                disabled={loading || strength < 2 || newPwd !== confirmPwd}
                style={{
                  marginTop: 4,
                  padding: '12px 24px',
                  borderRadius: 8,
                  border: 'none',
                  background:
                    !loading && strength >= 2 && newPwd === confirmPwd && confirmPwd.length > 0
                      ? 'linear-gradient(135deg, #00d4ff 0%, #0066ff 100%)'
                      : 'rgba(0,50,80,0.5)',
                  color:
                    !loading && strength >= 2 && newPwd === confirmPwd && confirmPwd.length > 0
                      ? '#050b18'
                      : '#6b8fa3',
                  fontWeight: 900,
                  fontSize: 13,
                  letterSpacing: 2,
                  textTransform: 'uppercase',
                  cursor: loading ? 'not-allowed' : 'pointer',
                  fontFamily: "'Fira Code', monospace",
                  boxShadow:
                    !loading && strength >= 2 && newPwd === confirmPwd && confirmPwd.length > 0
                      ? '0 0 20px rgba(0,212,255,0.4)'
                      : 'none',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: 8,
                }}
              >
                {loading && (
                  <motion.span
                    animate={{ rotate: 360 }}
                    transition={{ duration: 0.9, repeat: Infinity, ease: 'linear' }}
                    style={{ display: 'inline-block', fontSize: 14 }}
                  >
                    ⟳
                  </motion.span>
                )}
                {loading ? 'Updating...' : 'Set New Password'}
              </motion.button>
            </motion.form>
          )}

          {/* ── Step 2: Recovery complete ────────────────────────────────────── */}
          {step === 2 && (
            <motion.div
              key="step-complete"
              initial={{ opacity: 0, scale: 0.94 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.35 }}
              style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 22 }}
            >
              {/* Green checkmark */}
              <motion.div
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                transition={{ type: 'spring', stiffness: 280, damping: 22, delay: 0.1 }}
                style={{
                  width: 72,
                  height: 72,
                  borderRadius: '50%',
                  background: 'rgba(0,255,136,0.12)',
                  border: '2px solid rgba(0,255,136,0.7)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  boxShadow: '0 0 32px rgba(0,255,136,0.35)',
                }}
              >
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#00ff88" strokeWidth="2.5">
                  <polyline points="20 6 9 17 4 12" />
                </svg>
              </motion.div>

              <div style={{ textAlign: 'center' }}>
                <p
                  style={{
                    margin: '0 0 6px',
                    fontFamily: "'Fira Code', monospace",
                    fontSize: 15,
                    fontWeight: 700,
                    color: '#00ff88',
                    letterSpacing: 1,
                  }}
                >
                  Password Updated Successfully
                </p>
                <p style={{ margin: 0, fontSize: 11, color: '#94a3b8', fontFamily: "'Fira Code', monospace", lineHeight: 1.7 }}>
                  All active sessions have been revoked for security.
                </p>
              </div>

              {/* Recovery timeline */}
              <div style={{ width: '100%' }}>
                <SecurityRecoveryTimeline
                  title="Security Recovery Timeline"
                  events={timelineEvents}
                />
              </div>

              <motion.button
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                onClick={() => navigate('/login')}
                style={{
                  width: '100%',
                  padding: '12px 24px',
                  borderRadius: 8,
                  border: 'none',
                  background: 'linear-gradient(135deg, #00ff88 0%, #00d4ff 100%)',
                  color: '#050b18',
                  fontWeight: 900,
                  fontSize: 13,
                  letterSpacing: 2,
                  textTransform: 'uppercase',
                  cursor: 'pointer',
                  fontFamily: "'Fira Code', monospace",
                  boxShadow: '0 0 20px rgba(0,255,136,0.4)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: 8,
                }}
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                  <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                  <path d="M7 11V7a5 5 0 0110 0v4" />
                </svg>
                Secure Login
              </motion.button>
            </motion.div>
          )}
        </AnimatePresence>
          </>
        )}
      </motion.div>
    </div>
  );
}

function extractMsg(err: unknown): string {
  if (err && typeof err === 'object' && 'response' in err) {
    const e = err as { response?: { data?: { detail?: unknown; message?: unknown } } };
    const d = e.response?.data?.detail;
    const m = e.response?.data?.message;
    if (typeof d === 'string') return d;
    if (Array.isArray(d)) {
      return d.map((x) => (typeof x === 'object' && x && 'msg' in x ? String((x as { msg: unknown }).msg) : String(x))).join(' · ');
    }
    if (typeof m === 'string' && m !== 'Authentication required') return m;
  }
  if (err instanceof Error) return err.message;
  return 'Password reset failed';
}
