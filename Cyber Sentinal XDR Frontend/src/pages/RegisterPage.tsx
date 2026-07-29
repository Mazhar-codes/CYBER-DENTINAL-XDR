import React, { useState, useRef, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { toast } from 'react-hot-toast';
import { register } from '../services/authService';

type PasswordStrength = 0 | 1 | 2 | 3 | 4;

function getPasswordStrength(pw: string): PasswordStrength {
  if (!pw) return 0;
  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 12) score++;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  return Math.min(4, score) as PasswordStrength;
}

const STRENGTH_LABELS: Record<PasswordStrength, string> = {
  0: '',
  1: 'Weak',
  2: 'Fair',
  3: 'Good',
  4: 'Strong',
};

const STRENGTH_COLORS: Record<PasswordStrength, string> = {
  0: 'transparent',
  1: '#ff3366',
  2: '#ffaa00',
  3: '#00d4ff',
  4: '#00ff88',
};

const STRENGTH_WIDTHS: Record<PasswordStrength, string> = {
  0: '0%',
  1: '25%',
  2: '50%',
  3: '75%',
  4: '100%',
};

interface FieldState {
  value: string;
  touched: boolean;
  error: string;
}

function useField(initial = ''): [FieldState, (v: string) => void, (err: string) => void, () => void] {
  const [state, setState] = useState<FieldState>({ value: initial, touched: false, error: '' });
  const set = (v: string) => setState((s) => ({ ...s, value: v, touched: true, error: '' }));
  const setError = (err: string) => setState((s) => ({ ...s, error: err }));
  const touch = () => setState((s) => ({ ...s, touched: true }));
  return [state, set, setError, touch];
}

export default function RegisterPage() {
  const navigate = useNavigate();
  const [username, setUsername, setUsernameError] = useField();
  const [email, setEmail, setEmailError] = useField();
  const [password, setPassword, setPasswordError] = useField();
  const [confirm, setConfirm, setConfirmError] = useField();
  const [loading, setLoading] = useState(false);
  const [shake, setShake] = useState(false);

  const strength = getPasswordStrength(password.value);

  // Particle canvas
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animRef = useRef<number>(0);
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    let W = (canvas.width = window.innerWidth);
    let H = (canvas.height = window.innerHeight);
    const onResize = () => { W = canvas.width = window.innerWidth; H = canvas.height = window.innerHeight; };
    window.addEventListener('resize', onResize);
    interface P { x: number; y: number; vy: number; opacity: number; size: number; }
    const pts: P[] = Array.from({ length: 35 }, () => ({ x: Math.random() * W, y: Math.random() * H, vy: 0.2 + Math.random() * 0.4, opacity: 0.1 + Math.random() * 0.4, size: 1 + Math.random() * 2 }));
    let t = 0;
    function draw() {
      if (!ctx) return;
      ctx.fillStyle = '#050b18'; ctx.fillRect(0, 0, W, H);
      ctx.strokeStyle = 'rgba(0,212,255,0.05)'; ctx.lineWidth = 1;
      for (let c = 0; c <= Math.ceil(W / 40); c++) { ctx.beginPath(); ctx.moveTo(c * 40, 0); ctx.lineTo(c * 40, H); ctx.stroke(); }
      for (let r = 0; r <= Math.ceil(H / 40); r++) { ctx.beginPath(); ctx.moveTo(0, r * 40); ctx.lineTo(W, r * 40); ctx.stroke(); }
      pts.forEach((p) => { ctx.beginPath(); ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2); ctx.fillStyle = `rgba(0,212,255,${p.opacity * (0.6 + 0.4 * Math.sin(t * 0.02 + p.x))})`; ctx.fill(); p.y -= p.vy; if (p.y < -10) { p.y = H + 10; p.x = Math.random() * W; } });
      t++; animRef.current = requestAnimationFrame(draw);
    }
    draw();
    return () => { cancelAnimationFrame(animRef.current); window.removeEventListener('resize', onResize); };
  }, []);

  const validate = (): boolean => {
    let valid = true;
    if (!username.value || username.value.length < 3) { setUsernameError('Username must be at least 3 characters'); valid = false; }
    if (!email.value || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.value)) { setEmailError('Invalid email address'); valid = false; }
    if (!password.value || strength < 2) { setPasswordError('Password too weak (at least Fair)'); valid = false; }
    if (password.value !== confirm.value) { setConfirmError('Passwords do not match'); valid = false; }
    return valid;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!validate()) { setShake(true); setTimeout(() => setShake(false), 400); return; }
    setLoading(true);
    try {
      await register(username.value, email.value, password.value);
      toast.success('Account created — please log in', { style: { background: '#001a10', color: '#00ff88', border: '1px solid rgba(0,255,136,0.3)' } });
      navigate('/login');
    } catch (err: unknown) {
      setShake(true); setTimeout(() => setShake(false), 400);
      const msg = getMsg(err);
      toast.error(msg, { style: { background: '#1a0010', color: '#ff6688', border: '1px solid rgba(255,51,102,0.4)' } });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', position: 'relative', overflow: 'hidden', background: '#050b18' }}>
      <canvas ref={canvasRef} style={{ position: 'fixed', inset: 0, zIndex: 0 }} />

      <motion.div
        initial={{ y: 40, opacity: 0, scale: 0.96 }}
        animate={{ y: 0, opacity: 1, scale: 1 }}
        transition={{ type: 'spring', stiffness: 200, damping: 22 }}
        className={`scan-line-container${shake ? ' field-error' : ''}`}
        style={{
          position: 'relative', zIndex: 10, width: '100%', maxWidth: 440, margin: '24px',
          background: 'rgba(0,20,40,0.82)', backdropFilter: 'blur(20px)', WebkitBackdropFilter: 'blur(20px)',
          border: '1px solid rgba(0,212,255,0.3)', borderRadius: 16,
          boxShadow: '0 0 30px rgba(0,212,255,0.15), 0 0 80px rgba(0,50,100,0.4), inset 0 1px 0 rgba(0,212,255,0.1)',
          padding: '36px 36px',
        }}
      >
        {/* Logo */}
        <div style={{ textAlign: 'center', marginBottom: 28 }}>
          <div style={{ fontSize: 32, marginBottom: 10 }}>🛡️</div>
          <h1 className="neon-text" style={{ margin: 0, fontSize: 18, fontWeight: 900, letterSpacing: 3, textTransform: 'uppercase', fontFamily: "'Fira Code', monospace" }}>
            Request Access
          </h1>
          <p style={{ margin: '6px 0 0', fontSize: 10, letterSpacing: 3, color: '#6b8fa3', textTransform: 'uppercase' }}>Cyber Sentinel XDR — Operator Registration</p>
        </div>

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <FieldGroup label="Username" error={username.error}>
            <input type="text" value={username.value} onChange={(e) => setUsername(e.target.value)} placeholder="operator_name" autoComplete="username" style={inputStyle(!!username.error)} onFocus={(e) => applyFocus(e.target)} onBlur={(e) => removeFocus(e.target)} />
          </FieldGroup>

          <FieldGroup label="Email" error={email.error}>
            <input type="email" value={email.value} onChange={(e) => setEmail(e.target.value)} placeholder="operator@sentinel.local" autoComplete="email" style={inputStyle(!!email.error)} onFocus={(e) => applyFocus(e.target)} onBlur={(e) => removeFocus(e.target)} />
          </FieldGroup>

          <FieldGroup label="Password" error={password.error}>
            <input type="password" value={password.value} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••••••" autoComplete="new-password" style={inputStyle(!!password.error)} onFocus={(e) => applyFocus(e.target)} onBlur={(e) => removeFocus(e.target)} />
            {/* Strength bar */}
            {password.value && (
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
          </FieldGroup>

          <FieldGroup label="Confirm Password" error={confirm.error}>
            <input type="password" value={confirm.value} onChange={(e) => setConfirm(e.target.value)} placeholder="••••••••••••" autoComplete="new-password" style={inputStyle(!!confirm.error)} onFocus={(e) => applyFocus(e.target)} onBlur={(e) => removeFocus(e.target)} />
          </FieldGroup>

          <motion.button
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
            type="submit"
            disabled={loading}
            style={{
              marginTop: 8, padding: '12px 24px', borderRadius: 8, border: 'none',
              background: loading ? 'rgba(0,50,80,0.5)' : 'linear-gradient(135deg, #00d4ff 0%, #0066ff 100%)',
              color: loading ? '#6b8fa3' : '#050b18',
              fontWeight: 900, fontSize: 13, letterSpacing: 2, textTransform: 'uppercase',
              cursor: loading ? 'not-allowed' : 'pointer',
              boxShadow: loading ? 'none' : '0 0 20px rgba(0,212,255,0.4)',
              fontFamily: "'Fira Code', monospace",
            }}
          >
            {loading ? 'Creating Account...' : 'Create Account'}
          </motion.button>

          <div style={{ textAlign: 'center', marginTop: 4 }}>
            <span style={{ color: '#6b8fa3', fontSize: 12 }}>Already have access? </span>
            <Link to="/login" style={{ color: '#00d4ff', fontSize: 12, fontWeight: 700, textDecoration: 'none' }}>Sign In</Link>
          </div>
        </form>
      </motion.div>
    </div>
  );
}

function FieldGroup({ label, error, children }: { label: string; error: string; children: React.ReactNode }) {
  return (
    <div>
      <label style={{ display: 'block', fontSize: 10, fontWeight: 700, color: error ? '#ff6688' : '#6b8fa3', letterSpacing: 1.5, textTransform: 'uppercase', marginBottom: 6, fontFamily: "'Fira Code', monospace" }}>
        {label}
      </label>
      {children}
      {error && (
        <motion.p
          initial={{ opacity: 0, y: -4 }}
          animate={{ opacity: 1, y: 0 }}
          style={{ margin: '4px 0 0', fontSize: 11, color: '#ff6688' }}
        >
          {error}
        </motion.p>
      )}
    </div>
  );
}

function inputStyle(hasError: boolean): React.CSSProperties {
  return {
    width: '100%', padding: '11px 14px',
    background: 'rgba(0,10,25,0.8)',
    border: `1px solid ${hasError ? 'rgba(255,51,102,0.6)' : 'rgba(0,212,255,0.2)'}`,
    borderRadius: 8, color: '#e0f4ff', fontSize: 14,
    fontFamily: "'Fira Code', monospace", outline: 'none',
    transition: 'all 0.2s', boxSizing: 'border-box' as const,
    boxShadow: hasError ? '0 0 8px rgba(255,51,102,0.15)' : 'none',
  };
}

function applyFocus(el: HTMLInputElement) {
  el.style.border = '1px solid rgba(0,212,255,0.7)';
  el.style.boxShadow = '0 0 12px rgba(0,212,255,0.2)';
  el.style.background = 'rgba(0,20,40,0.9)';
}

function removeFocus(el: HTMLInputElement) {
  el.style.border = '1px solid rgba(0,212,255,0.2)';
  el.style.boxShadow = 'none';
  el.style.background = 'rgba(0,10,25,0.8)';
}

function getMsg(err: unknown): string {
  if (err && typeof err === 'object' && 'response' in err) {
    const e = err as { response?: { data?: { detail?: unknown } } };
    const detail = e.response?.data?.detail;
    if (typeof detail === 'string') return detail;
    // FastAPI 422: detail is an array of {loc, msg, type, ...} objects
    if (Array.isArray(detail)) {
      return detail
        .map((d) => {
          if (d && typeof d === 'object' && 'msg' in d) {
            // Pydantic v2 prepends "Value error, " to field_validator messages
            return String((d as { msg: unknown }).msg).replace(/^Value error,\s*/i, '');
          }
          return String(d);
        })
        .join(' · ');
    }
    return 'Registration failed';
  }
  if (err instanceof Error) return err.message;
  return 'Registration failed';
}
