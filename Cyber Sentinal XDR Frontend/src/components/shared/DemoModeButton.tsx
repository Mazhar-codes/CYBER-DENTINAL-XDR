import React from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';

/**
 * Small "?" bypass icon — skips login/MFA entirely and drops straight into
 * /dashboard via AuthContext.enterDemoMode(). Purely client-side; no backend
 * call is made. Rendered both on the plain /login route and inside the
 * cinematic StartupScreen overlay so it's reachable from the very first
 * frame, regardless of which one the user happens to land on.
 */
export default function DemoModeButton() {
  const navigate = useNavigate();
  const { enterDemoMode } = useAuth();

  return (
    <button
      type="button"
      title="Demo Mode — skip login and open the dashboard"
      onClick={() => {
        enterDemoMode();
        navigate('/dashboard', { replace: true });
      }}
      style={{
        position: 'fixed',
        left: 20,
        bottom: 20,
        zIndex: 10001,
        pointerEvents: 'auto',
        width: 32,
        height: 32,
        borderRadius: '50%',
        border: '1px solid rgba(0,212,255,0.25)',
        background: 'rgba(0,20,40,0.65)',
        color: '#3d5a70',
        fontFamily: "'Fira Code', monospace",
        fontSize: 14,
        fontWeight: 700,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        cursor: 'pointer',
        backdropFilter: 'blur(6px)',
        transition: 'color 0.2s, border-color 0.2s, background 0.2s',
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.color = '#22d3ee';
        e.currentTarget.style.borderColor = 'rgba(0,212,255,0.6)';
        e.currentTarget.style.background = 'rgba(0,20,40,0.9)';
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.color = '#3d5a70';
        e.currentTarget.style.borderColor = 'rgba(0,212,255,0.25)';
        e.currentTarget.style.background = 'rgba(0,20,40,0.65)';
      }}
    >
      ?
    </button>
  );
}
