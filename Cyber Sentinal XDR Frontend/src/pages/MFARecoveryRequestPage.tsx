// MFARecoveryRequestPage.tsx
// For users locked out of their authenticator app — submit a recovery request to the administrator.

import React, { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { toast } from 'react-hot-toast';
import { requestMFARecovery } from '../services/authService';

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

// ── Input helpers ─────────────────────────────────────────────────────────────
const inputBase: React.CSSProperties = {
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

function applyFocus(el: HTMLElement) {
  (el as HTMLElement).style.border = '1px solid rgba(0,212,255,0.7)';
  (el as HTMLElement).style.boxShadow = '0 0 12px rgba(0,212,255,0.2)';
  (el as HTMLElement).style.background = 'rgba(0,20,40,0.9)';
}
function removeFocus(el: HTMLElement, hasErr = false) {
  (el as HTMLElement).style.border = hasErr ? '1px solid rgba(255,51,102,0.6)' : '1px solid rgba(0,212,255,0.2)';
  (el as HTMLElement).style.boxShadow = hasErr ? '0 0 8px rgba(255,51,102,0.15)' : 'none';
  (el as HTMLElement).style.background = 'rgba(0,10,25,0.8)';
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

// ── Canvas particles ─────────────────────────────────────────────────────────
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
      ctx.strokeStyle = 'rgba(255,100,0,0.05)'; ctx.lineWidth = 1;
      for (let c = 0; c <= Math.ceil(W / 40); c++) { ctx.beginPath(); ctx.moveTo(c * 40, 0); ctx.lineTo(c * 40, H); ctx.stroke(); }
      for (let r = 0; r <= Math.ceil(H / 40); r++) { ctx.beginPath(); ctx.moveTo(0, r * 40); ctx.lineTo(W, r * 40); ctx.stroke(); }
      pts.forEach((p) => {
        ctx.beginPath(); ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(255,100,0,${p.opacity * (0.4 + 0.3 * Math.sin(t * 0.015 + p.x))})`; ctx.fill();
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
  const clr = 'rgba(255,100,0,0.3)';
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

// ── Animated broken lock icon ─────────────────────────────────────────────────
function BrokenLockIcon() {
  return (
    <motion.div
      animate={{
        boxShadow: [
          '0 0 16px rgba(255,100,0,0.3)',
          '0 0 36px rgba(255,68,68,0.6)',
          '0 0 16px rgba(255,100,0,0.3)',
        ],
      }}
      transition={{ duration: 2.2, repeat: Infinity }}
      style={{
        width: 72,
        height: 72,
        borderRadius: 18,
        background: 'linear-gradient(135deg, rgba(255,80,0,0.18) 0%, rgba(180,0,0,0.28) 100%)',
        border: '1px solid rgba(255,100,0,0.5)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        margin: '0 auto 18px',
        position: 'relative',
      }}
    >
      {/* Lock body */}
      <svg width="36" height="36" viewBox="0 0 24 24" fill="none" strokeWidth="1.8">
        <rect x="3" y="11" width="18" height="11" rx="2" ry="2" stroke="#ff6644" />
        {/* Broken shackle — left side only */}
        <motion.path
          d="M7 11V7a5 5 0 018-4"
          stroke="#ff4444"
          strokeLinecap="round"
          animate={{ opacity: [1, 0.4, 1] }}
          transition={{ duration: 1.6, repeat: Infinity }}
        />
        {/* Broken chain gap hint */}
        <motion.line
          x1="15"
          y1="3"
          x2="17"
          y2="1"
          stroke="#ffaa00"
          strokeWidth="2"
          strokeLinecap="round"
          animate={{ opacity: [0, 1, 0] }}
          transition={{ duration: 1.6, repeat: Infinity, delay: 0.3 }}
        />
        {/* Keyhole */}
        <circle cx="12" cy="16" r="1.5" fill="#ff6644" />
        <line x1="12" y1="17.5" x2="12" y2="20" stroke="#ff6644" strokeWidth="1.5" strokeLinecap="round" />
      </svg>
    </motion.div>
  );
}

// ── Hourglass icon for pending state ─────────────────────────────────────────
function HourglassIcon() {
  return (
    <motion.div
      animate={{ rotate: [0, 0, 180, 180, 0] }}
      transition={{ duration: 3, repeat: Infinity, times: [0, 0.4, 0.5, 0.9, 1] }}
      style={{
        width: 64,
        height: 64,
        borderRadius: '50%',
        background: 'rgba(255,170,0,0.1)',
        border: '2px solid rgba(255,170,0,0.5)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        boxShadow: '0 0 24px rgba(255,170,0,0.3)',
      }}
    >
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#ffaa00" strokeWidth="2">
        <path d="M5 22h14" />
        <path d="M5 2h14" />
        <path d="M17 22v-4.172a2 2 0 00-.586-1.414L12 12l-4.414 4.414A2 2 0 007 17.828V22" />
        <path d="M7 2v4.172a2 2 0 00.586 1.414L12 12l4.414-4.414A2 2 0 0017 6.172V2" />
      </svg>
    </motion.div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
export default function MFARecoveryRequestPage() {
  const navigate = useNavigate();
  const canvasRef = useRef<HTMLCanvasElement>(null);
  useParticleCanvas(canvasRef);

  const [email, setEmail] = useState('');
  const [reason, setReason] = useState('');
  const [emailError, setEmailError] = useState('');
  const [reasonError, setReasonError] = useState('');
  const [loading, setLoading] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [requestId, setRequestId] = useState('');
  const [shake, setShake] = useState(false);

  const triggerShake = () => { setShake(true); setTimeout(() => setShake(false), 400); };

  const validate = () => {
    let valid = true;
    if (!email.trim() || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
      setEmailError('Enter a valid email address');
      valid = false;
    } else {
      setEmailError('');
    }
    if (!reason.trim() || reason.trim().length < 20) {
      setReasonError('Please provide at least 20 characters explaining your situation');
      valid = false;
    } else {
      setReasonError('');
    }
    return valid;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!validate()) { triggerShake(); return; }
    setLoading(true);
    try {
      const resp = await requestMFARecovery(email.trim(), reason.trim());
      setRequestId(resp.request_id);
      setSubmitted(true);
      toast.success('Recovery request submitted', { style: toastSuccessStyle });
    } catch (err: unknown) {
      const msg = extractMsg(err);
      toast.error(msg, { style: toastErrStyle });
      triggerShake();
    } finally {
      setLoading(false);
    }
  };

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
          border: '1px solid rgba(255,80,0,0.3)',
          borderRadius: 16,
          boxShadow:
            '0 0 30px rgba(255,80,0,0.15), 0 0 80px rgba(100,20,0,0.4), inset 0 1px 0 rgba(255,80,0,0.08)',
          padding: '40px 36px',
          overflow: 'hidden',
        }}
      >
        {/* Header */}
        <div style={{ textAlign: 'center', marginBottom: 24 }}>
          <BrokenLockIcon />
          <h1
            style={{
              margin: 0,
              fontSize: 17,
              fontWeight: 900,
              letterSpacing: 3,
              textTransform: 'uppercase',
              fontFamily: "'Fira Code', monospace",
              color: '#ff6644',
              textShadow: '0 0 12px rgba(255,100,0,0.5)',
            }}
          >
            MFA Recovery Request
          </h1>
          <p
            style={{
              margin: '6px 0 0',
              fontSize: 10,
              letterSpacing: 3,
              color: '#6b8fa3',
              textTransform: 'uppercase',
            }}
          >
            Submit a request to your system administrator
          </p>
        </div>

        <AnimatePresence mode="wait">
          {!submitted ? (
            /* ── Request form ─────────────────────────────────────────────── */
            <motion.form
              key="request-form"
              initial={{ opacity: 0, x: -16 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 16 }}
              transition={{ duration: 0.22 }}
              className={shake ? 'field-error' : ''}
              onSubmit={handleSubmit}
              style={{ display: 'flex', flexDirection: 'column', gap: 16 }}
            >
              {/* Info banner */}
              <div
                style={{
                  background: 'rgba(255,80,0,0.06)',
                  border: '1px solid rgba(255,80,0,0.25)',
                  borderRadius: 8,
                  padding: '10px 14px',
                  display: 'flex',
                  gap: 10,
                  alignItems: 'flex-start',
                }}
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#ff6644" strokeWidth="2.5" style={{ flexShrink: 0, marginTop: 1 }}>
                  <circle cx="12" cy="12" r="10" />
                  <line x1="12" y1="8" x2="12" y2="12" />
                  <line x1="12" y1="16" x2="12.01" y2="16" />
                </svg>
                <p style={{ margin: 0, fontSize: 11, color: '#ff8866', fontFamily: "'Fira Code', monospace", lineHeight: 1.6 }}>
                  Your request will be reviewed by a system administrator. You will be contacted via email once approved.
                </p>
              </div>

              {/* Email */}
              <div>
                <label style={{ ...labelStyle, color: emailError ? '#ff6688' : '#6b8fa3' }}>
                  Registered Email
                </label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => { setEmail(e.target.value); setEmailError(''); }}
                  placeholder="operator@sentinel.local"
                  autoComplete="email"
                  style={{
                    ...inputBase,
                    border: emailError ? '1px solid rgba(255,51,102,0.6)' : '1px solid rgba(0,212,255,0.2)',
                    boxShadow: emailError ? '0 0 8px rgba(255,51,102,0.15)' : 'none',
                  }}
                  onFocus={(e) => applyFocus(e.target)}
                  onBlur={(e) => removeFocus(e.target, !!emailError)}
                />
                <AnimatePresence>
                  {emailError && (
                    <motion.p
                      initial={{ opacity: 0, y: -4 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0 }}
                      style={{ margin: '4px 0 0', fontSize: 11, color: '#ff6688', fontFamily: "'Fira Code', monospace" }}
                    >
                      {emailError}
                    </motion.p>
                  )}
                </AnimatePresence>
              </div>

              {/* Reason */}
              <div>
                <label style={{ ...labelStyle, color: reasonError ? '#ff6688' : '#6b8fa3' }}>
                  Reason / Explanation
                </label>
                <textarea
                  value={reason}
                  onChange={(e) => { setReason(e.target.value); setReasonError(''); }}
                  placeholder="Explain why you lost access to your authenticator app (e.g., lost phone, factory reset, etc.)..."
                  rows={4}
                  style={{
                    ...inputBase,
                    resize: 'vertical',
                    minHeight: 90,
                    border: reasonError ? '1px solid rgba(255,51,102,0.6)' : '1px solid rgba(0,212,255,0.2)',
                    boxShadow: reasonError ? '0 0 8px rgba(255,51,102,0.15)' : 'none',
                  } as React.CSSProperties}
                  onFocus={(e) => applyFocus(e.target)}
                  onBlur={(e) => removeFocus(e.target, !!reasonError)}
                />
                <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 4 }}>
                  <AnimatePresence>
                    {reasonError && (
                      <motion.p
                        initial={{ opacity: 0, y: -4 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0 }}
                        style={{ margin: 0, fontSize: 11, color: '#ff6688', fontFamily: "'Fira Code', monospace" }}
                      >
                        {reasonError}
                      </motion.p>
                    )}
                  </AnimatePresence>
                  <span
                    style={{
                      fontSize: 10,
                      color: reason.length < 20 ? '#475569' : '#6b8fa3',
                      fontFamily: "'Fira Code', monospace",
                      marginLeft: 'auto',
                    }}
                  >
                    {reason.length} / 20 min
                  </span>
                </div>
              </div>

              <motion.button
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                type="submit"
                disabled={loading}
                style={{
                  marginTop: 4,
                  padding: '12px 24px',
                  borderRadius: 8,
                  border: 'none',
                  background: loading
                    ? 'rgba(80,30,0,0.5)'
                    : 'linear-gradient(135deg, #ff6644 0%, #cc3300 100%)',
                  color: loading ? '#6b8fa3' : '#fff',
                  fontWeight: 900,
                  fontSize: 13,
                  letterSpacing: 2,
                  textTransform: 'uppercase',
                  cursor: loading ? 'not-allowed' : 'pointer',
                  boxShadow: loading ? 'none' : '0 0 20px rgba(255,100,0,0.4)',
                  fontFamily: "'Fira Code', monospace",
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
                {loading ? 'Submitting Request...' : 'Submit Recovery Request'}
              </motion.button>

              <button
                type="button"
                onClick={() => navigate('/login')}
                style={{
                  background: 'none',
                  border: 'none',
                  color: '#6b8fa3',
                  fontSize: 11,
                  cursor: 'pointer',
                  fontFamily: "'Fira Code', monospace",
                  padding: 0,
                  textAlign: 'center',
                  textDecoration: 'underline',
                }}
              >
                Return to Login
              </button>
            </motion.form>
          ) : (
            /* ── Submitted / pending state ────────────────────────────────── */
            <motion.div
              key="pending-state"
              initial={{ opacity: 0, scale: 0.94 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.32 }}
              style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 22 }}
            >
              <HourglassIcon />

              <div style={{ textAlign: 'center' }}>
                <p
                  style={{
                    margin: '0 0 6px',
                    fontFamily: "'Fira Code', monospace",
                    fontSize: 14,
                    fontWeight: 700,
                    color: '#ffaa00',
                    letterSpacing: 1,
                  }}
                >
                  Request Submitted
                </p>
                <p
                  style={{
                    margin: 0,
                    fontSize: 12,
                    color: '#94a3b8',
                    fontFamily: "'Fira Code', monospace",
                    lineHeight: 1.7,
                  }}
                >
                  Your administrator will review this request. You will be notified via email.
                </p>
              </div>

              {/* Request ID code block */}
              <div style={{ width: '100%' }}>
                <p
                  style={{
                    margin: '0 0 8px',
                    fontSize: 9,
                    fontWeight: 700,
                    color: '#475569',
                    letterSpacing: 2,
                    textTransform: 'uppercase',
                    fontFamily: "'Fira Code', monospace",
                  }}
                >
                  Request ID
                </p>
                <div
                  style={{
                    background: 'rgba(0,0,0,0.5)',
                    border: '1px solid rgba(255,170,0,0.3)',
                    borderRadius: 8,
                    padding: '12px 16px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: 12,
                  }}
                >
                  <code
                    style={{
                      fontFamily: "'Fira Code', monospace",
                      fontSize: 14,
                      color: '#ffaa00',
                      fontWeight: 700,
                      letterSpacing: 2,
                    }}
                  >
                    #{requestId || 'PENDING'}
                  </code>
                  <button
                    type="button"
                    onClick={() => {
                      navigator.clipboard.writeText(requestId);
                      toast.success('Request ID copied', { style: toastSuccessStyle });
                    }}
                    style={{
                      background: 'rgba(255,170,0,0.08)',
                      border: '1px solid rgba(255,170,0,0.3)',
                      borderRadius: 6,
                      padding: '4px 10px',
                      color: '#ffaa00',
                      fontSize: 10,
                      fontWeight: 700,
                      fontFamily: "'Fira Code', monospace",
                      cursor: 'pointer',
                      letterSpacing: 1,
                    }}
                  >
                    Copy
                  </button>
                </div>
              </div>

              {/* Status timeline */}
              <div
                style={{
                  width: '100%',
                  background: 'rgba(0,10,30,0.6)',
                  border: '1px solid rgba(255,170,0,0.15)',
                  borderRadius: 10,
                  padding: '16px 18px',
                }}
              >
                {[
                  { label: 'Request received', done: true },
                  { label: 'Pending administrator review', done: false, active: true },
                  { label: 'Email notification sent', done: false },
                  { label: 'MFA reset and re-enrolment', done: false },
                ].map((item, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: i < 3 ? 12 : 0 }}>
                    <div
                      style={{
                        width: 18,
                        height: 18,
                        borderRadius: '50%',
                        background: item.done
                          ? 'rgba(0,255,136,0.15)'
                          : item.active
                          ? 'rgba(255,170,0,0.1)'
                          : 'transparent',
                        border: `2px solid ${item.done ? '#00ff88' : item.active ? '#ffaa00' : '#334155'}`,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        flexShrink: 0,
                      }}
                    >
                      {item.done && (
                        <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="#00ff88" strokeWidth="3">
                          <polyline points="20 6 9 17 4 12" />
                        </svg>
                      )}
                      {item.active && (
                        <motion.div
                          animate={{ scale: [0.5, 1, 0.5] }}
                          transition={{ duration: 1.4, repeat: Infinity }}
                          style={{ width: 7, height: 7, borderRadius: '50%', background: '#ffaa00' }}
                        />
                      )}
                    </div>
                    <span
                      style={{
                        fontFamily: "'Fira Code', monospace",
                        fontSize: 12,
                        color: item.done ? '#94a3b8' : item.active ? '#ffaa00' : '#334155',
                        fontWeight: item.active ? 700 : 400,
                      }}
                    >
                      {item.label}
                    </span>
                  </div>
                ))}
              </div>

              <button
                type="button"
                onClick={() => navigate('/login')}
                style={{
                  background: 'none',
                  border: 'none',
                  color: '#6b8fa3',
                  fontSize: 12,
                  cursor: 'pointer',
                  fontFamily: "'Fira Code', monospace",
                  textDecoration: 'underline',
                  letterSpacing: 0.5,
                }}
                onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.color = '#00d4ff'; }}
                onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.color = '#6b8fa3'; }}
              >
                Return to Login
              </button>
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>
    </div>
  );
}

function extractMsg(err: unknown): string {
  if (err && typeof err === 'object' && 'response' in err) {
    const e = err as { response?: { data?: { detail?: unknown } } };
    const d = e.response?.data?.detail;
    if (typeof d === 'string') return d;
  }
  if (err instanceof Error) return err.message;
  return 'Request failed';
}
