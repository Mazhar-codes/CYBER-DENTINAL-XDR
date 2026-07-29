// ForgotPasswordPage.tsx
// Account recovery — step 1: user submits their email; backend dispatches a single-use token.

import React, { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { toast } from 'react-hot-toast';
import { forgotPassword } from '../services/authService';

// ── shared toast styles ──────────────────────────────────────────────────────
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

// ── shared input styles ──────────────────────────────────────────────────────
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

// ── Canvas particle background ───────────────────────────────────────────────
function useParticleCanvas(canvasRef: React.RefObject<HTMLCanvasElement | null>) {
  const animRef = useRef<number>(0);
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    let W = (canvas.width = window.innerWidth);
    let H = (canvas.height = window.innerHeight);
    const onResize = () => {
      W = canvas.width = window.innerWidth;
      H = canvas.height = window.innerHeight;
    };
    window.addEventListener('resize', onResize);
    interface P { x: number; y: number; vy: number; opacity: number; size: number; }
    const pts: P[] = Array.from({ length: 40 }, () => ({
      x: Math.random() * W,
      y: Math.random() * H,
      vy: 0.2 + Math.random() * 0.4,
      opacity: 0.1 + Math.random() * 0.5,
      size: 1 + Math.random() * 2,
    }));
    let t = 0;
    function draw() {
      if (!ctx) return;
      ctx.fillStyle = '#050b18';
      ctx.fillRect(0, 0, W, H);
      ctx.strokeStyle = 'rgba(0,212,255,0.06)';
      ctx.lineWidth = 1;
      for (let c = 0; c <= Math.ceil(W / 40); c++) {
        ctx.beginPath(); ctx.moveTo(c * 40, 0); ctx.lineTo(c * 40, H); ctx.stroke();
      }
      for (let r = 0; r <= Math.ceil(H / 40); r++) {
        ctx.beginPath(); ctx.moveTo(0, r * 40); ctx.lineTo(W, r * 40); ctx.stroke();
      }
      pts.forEach((p) => {
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
      window.removeEventListener('resize', onResize);
    };
  }, [canvasRef]);
}

// ── Animated shield icon ─────────────────────────────────────────────────────
function ShieldIcon() {
  return (
    <motion.div
      animate={{
        boxShadow: [
          '0 0 16px rgba(0,212,255,0.4)',
          '0 0 36px rgba(0,212,255,0.8)',
          '0 0 16px rgba(0,212,255,0.4)',
        ],
      }}
      transition={{ duration: 2.4, repeat: Infinity }}
      style={{
        width: 72,
        height: 72,
        borderRadius: 18,
        background: 'linear-gradient(135deg, rgba(0,212,255,0.18) 0%, rgba(0,80,180,0.28) 100%)',
        border: '1px solid rgba(0,212,255,0.45)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        margin: '0 auto 18px',
      }}
    >
      <motion.svg
        width="36"
        height="36"
        viewBox="0 0 24 24"
        fill="none"
        stroke="#00d4ff"
        strokeWidth="1.8"
        animate={{ opacity: [0.8, 1, 0.8] }}
        transition={{ duration: 2.4, repeat: Infinity }}
      >
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        <polyline points="9 12 11 14 15 10" />
      </motion.svg>
    </motion.div>
  );
}

// ── Corner decorations ────────────────────────────────────────────────────────
function Corner({ pos }: { pos: 'tl' | 'tr' | 'bl' | 'br' }) {
  const size = 56;
  const clr = 'rgba(0,212,255,0.28)';
  const s: React.CSSProperties = {
    position: 'fixed',
    width: size,
    height: size,
    zIndex: 5,
    pointerEvents: 'none',
    ...(pos.includes('t') ? { top: 20 } : { bottom: 20 }),
    ...(pos.includes('l') ? { left: 20 } : { right: 20 }),
    borderTop: pos.includes('t') ? `2px solid ${clr}` : 'none',
    borderBottom: pos.includes('b') ? `2px solid ${clr}` : 'none',
    borderLeft: pos.includes('l') ? `2px solid ${clr}` : 'none',
    borderRight: pos.includes('r') ? `2px solid ${clr}` : 'none',
  };
  return <div style={s} />;
}

// ── Main component ────────────────────────────────────────────────────────────
export default function ForgotPasswordPage() {
  const navigate = useNavigate();
  const canvasRef = useRef<HTMLCanvasElement>(null);
  useParticleCanvas(canvasRef);

  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState('');
  const [devToken, setDevToken] = useState<string | null>(null);
  const [devPanelOpen, setDevPanelOpen] = useState(false);

  const isDev = process.env.NODE_ENV === 'development';

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim() || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
      setError('Enter a valid email address');
      return;
    }
    setError('');
    setLoading(true);
    try {
      const resp = await forgotPassword(email.trim());
      if (isDev && resp.dev_token) {
        setDevToken(resp.dev_token);
      }
      setSubmitted(true);
      toast.success('Recovery email dispatched', { style: toastSuccessStyle });
    } catch (err: unknown) {
      // Always show success state regardless — prevents email enumeration
      setSubmitted(true);
      if (isDev) {
        const msg = extractMsg(err);
        toast.error(`[DEV] ${msg}`, { style: toastErrStyle });
      }
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
          maxWidth: 440,
          margin: '24px',
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
        <div style={{ textAlign: 'center', marginBottom: 28 }}>
          <ShieldIcon />
          <h1
            className="neon-text"
            style={{
              margin: 0,
              fontSize: 18,
              fontWeight: 900,
              letterSpacing: 3,
              textTransform: 'uppercase',
              fontFamily: "'Fira Code', monospace",
            }}
          >
            Account Recovery
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
            XDR Security Console
          </p>
        </div>

        {/* Warning banner */}
        <div
          style={{
            background: 'rgba(255,170,0,0.07)',
            border: '1px solid rgba(255,170,0,0.3)',
            borderRadius: 8,
            padding: '10px 14px',
            marginBottom: 24,
            display: 'flex',
            gap: 10,
            alignItems: 'flex-start',
          }}
        >
          <svg
            width="14"
            height="14"
            viewBox="0 0 24 24"
            fill="none"
            stroke="#ffaa00"
            strokeWidth="2.5"
            style={{ flexShrink: 0, marginTop: 1 }}
          >
            <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
            <line x1="12" y1="9" x2="12" y2="13" />
            <line x1="12" y1="17" x2="12.01" y2="17" />
          </svg>
          <p
            style={{
              margin: 0,
              fontSize: 11,
              color: '#ffaa00',
              fontFamily: "'Fira Code', monospace",
              lineHeight: 1.6,
            }}
          >
            This system controls critical security infrastructure. Identity
            verification required.
          </p>
        </div>

        <AnimatePresence mode="wait">
          {!submitted ? (
            /* ── Step 1: Email form ─────────────────────────────────────────── */
            <motion.form
              key="email-form"
              initial={{ opacity: 0, x: -16 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 16 }}
              transition={{ duration: 0.22 }}
              onSubmit={handleSubmit}
              style={{ display: 'flex', flexDirection: 'column', gap: 16 }}
            >
              <div>
                <label
                  style={{
                    display: 'block',
                    fontSize: 10,
                    fontWeight: 700,
                    color: error ? '#ff6688' : '#6b8fa3',
                    letterSpacing: 1.5,
                    textTransform: 'uppercase',
                    marginBottom: 6,
                    fontFamily: "'Fira Code', monospace",
                  }}
                >
                  Registered Email
                </label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => { setEmail(e.target.value); setError(''); }}
                  placeholder="operator@sentinel.local"
                  autoComplete="email"
                  style={{
                    ...inputBase,
                    border: error
                      ? '1px solid rgba(255,51,102,0.6)'
                      : '1px solid rgba(0,212,255,0.2)',
                    boxShadow: error ? '0 0 8px rgba(255,51,102,0.15)' : 'none',
                  }}
                  onFocus={(e) => {
                    e.target.style.border = '1px solid rgba(0,212,255,0.7)';
                    e.target.style.boxShadow = '0 0 12px rgba(0,212,255,0.2)';
                    e.target.style.background = 'rgba(0,20,40,0.9)';
                  }}
                  onBlur={(e) => {
                    e.target.style.border = error
                      ? '1px solid rgba(255,51,102,0.6)'
                      : '1px solid rgba(0,212,255,0.2)';
                    e.target.style.boxShadow = error ? '0 0 8px rgba(255,51,102,0.15)' : 'none';
                    e.target.style.background = 'rgba(0,10,25,0.8)';
                  }}
                />
                <AnimatePresence>
                  {error && (
                    <motion.p
                      initial={{ opacity: 0, y: -4 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -4 }}
                      style={{
                        margin: '4px 0 0',
                        fontSize: 11,
                        color: '#ff6688',
                        fontFamily: "'Fira Code', monospace",
                      }}
                    >
                      {error}
                    </motion.p>
                  )}
                </AnimatePresence>
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
                    ? 'rgba(0,50,80,0.5)'
                    : 'linear-gradient(135deg, #00d4ff 0%, #0066ff 100%)',
                  color: loading ? '#6b8fa3' : '#050b18',
                  fontWeight: 900,
                  fontSize: 13,
                  letterSpacing: 2,
                  textTransform: 'uppercase',
                  cursor: loading ? 'not-allowed' : 'pointer',
                  boxShadow: loading ? 'none' : '0 0 20px rgba(0,212,255,0.4)',
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
                {loading ? 'Dispatching...' : 'Send Recovery Link'}
              </motion.button>

              {/* Links row */}
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  marginTop: 4,
                }}
              >
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
                  }}
                  onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.color = '#00d4ff'; }}
                  onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.color = '#6b8fa3'; }}
                >
                  Return to Login
                </button>
                <button
                  type="button"
                  onClick={() => navigate('/mfa-recovery')}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: '#6b8fa3',
                    fontSize: 11,
                    cursor: 'pointer',
                    fontFamily: "'Fira Code', monospace",
                    padding: 0,
                  }}
                  onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.color = '#ffaa00'; }}
                  onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.color = '#6b8fa3'; }}
                >
                  Lost MFA device?
                </button>
              </div>
            </motion.form>
          ) : (
            /* ── Success state ──────────────────────────────────────────────── */
            <motion.div
              key="success-state"
              initial={{ opacity: 0, scale: 0.94 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.3 }}
              style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 20 }}
            >
              {/* Animated checkmark */}
              <motion.div
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                transition={{ type: 'spring', stiffness: 280, damping: 22, delay: 0.1 }}
                style={{
                  width: 64,
                  height: 64,
                  borderRadius: '50%',
                  background: 'rgba(0,255,136,0.12)',
                  border: '2px solid rgba(0,255,136,0.6)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  boxShadow: '0 0 24px rgba(0,255,136,0.3)',
                }}
              >
                <svg
                  width="28"
                  height="28"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="#00ff88"
                  strokeWidth="2.5"
                >
                  <polyline points="20 6 9 17 4 12" />
                </svg>
              </motion.div>

              <div style={{ textAlign: 'center' }}>
                <p
                  style={{
                    margin: '0 0 8px',
                    fontFamily: "'Fira Code', monospace",
                    fontSize: 14,
                    fontWeight: 700,
                    color: '#00ff88',
                    letterSpacing: 1,
                  }}
                >
                  Recovery Instructions Dispatched
                </p>
                <p
                  style={{
                    margin: 0,
                    fontSize: 12,
                    color: '#94a3b8',
                    fontFamily: "'Fira Code', monospace",
                    lineHeight: 1.7,
                    maxWidth: 320,
                  }}
                >
                  If that email exists in this system, recovery instructions have been sent. Check your inbox.
                </p>
              </div>

              {/* DEV MODE collapsible panel */}
              {isDev && devToken && (
                <div
                  style={{
                    width: '100%',
                    background: 'rgba(255,170,0,0.06)',
                    border: '1px solid rgba(255,170,0,0.3)',
                    borderRadius: 10,
                  }}
                >
                  <button
                    type="button"
                    onClick={() => setDevPanelOpen((o) => !o)}
                    style={{
                      width: '100%',
                      background: 'none',
                      border: 'none',
                      padding: '10px 14px',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                    }}
                  >
                    <span
                      style={{
                        fontFamily: "'Fira Code', monospace",
                        fontSize: 10,
                        fontWeight: 700,
                        color: '#ffaa00',
                        letterSpacing: 1.5,
                        textTransform: 'uppercase',
                      }}
                    >
                      DEV MODE — Raw Token
                    </span>
                    <svg
                      width="12"
                      height="12"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="#ffaa00"
                      strokeWidth="2.5"
                      style={{
                        transform: devPanelOpen ? 'rotate(180deg)' : 'none',
                        transition: 'transform 0.2s',
                      }}
                    >
                      <polyline points="6 9 12 15 18 9" />
                    </svg>
                  </button>
                  <AnimatePresence>
                    {devPanelOpen && (
                      <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ duration: 0.2 }}
                        style={{ overflow: 'hidden' }}
                      >
                        <div style={{ padding: '0 14px 12px' }}>
                          <code
                            style={{
                              display: 'block',
                              fontFamily: "'Fira Code', monospace",
                              fontSize: 11,
                              color: '#ffaa00',
                              wordBreak: 'break-all',
                              lineHeight: 1.5,
                              background: 'rgba(0,0,0,0.3)',
                              borderRadius: 6,
                              padding: '8px 10px',
                            }}
                          >
                            {devToken}
                          </code>
                          <button
                            type="button"
                            onClick={() => navigate(`/reset-password?token=${devToken}`)}
                            style={{
                              marginTop: 8,
                              width: '100%',
                              padding: '7px',
                              borderRadius: 6,
                              border: '1px solid rgba(255,170,0,0.4)',
                              background: 'rgba(255,170,0,0.08)',
                              color: '#ffaa00',
                              fontSize: 10,
                              fontWeight: 700,
                              letterSpacing: 1,
                              cursor: 'pointer',
                              fontFamily: "'Fira Code', monospace",
                              textTransform: 'uppercase',
                            }}
                          >
                            Open Reset Page with this Token
                          </button>
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              )}

              <button
                type="button"
                onClick={() => navigate('/login')}
                style={{
                  background: 'none',
                  border: 'none',
                  color: '#00d4ff',
                  fontSize: 12,
                  cursor: 'pointer',
                  fontFamily: "'Fira Code', monospace",
                  textDecoration: 'underline',
                  letterSpacing: 0.5,
                }}
              >
                Return to Login
              </button>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Security badges */}
        <div
          style={{
            marginTop: 28,
            borderTop: '1px solid rgba(0,212,255,0.08)',
            paddingTop: 14,
            display: 'flex',
            justifyContent: 'center',
            gap: 8,
            flexWrap: 'wrap',
          }}
        >
          {['MFA Required', 'Single-Use Token', '10 Min Expiry'].map((badge, i) => (
            <React.Fragment key={badge}>
              {i > 0 && (
                <span style={{ color: '#1e3a4a', fontSize: 9, alignSelf: 'center' }}>•</span>
              )}
              <span
                style={{
                  fontSize: 8,
                  color: '#334155',
                  letterSpacing: 1.5,
                  fontWeight: 700,
                  fontFamily: "'Fira Code', monospace",
                  textTransform: 'uppercase',
                }}
              >
                {badge}
              </span>
            </React.Fragment>
          ))}
        </div>
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
  return 'Request failed';
}
