import React, { useEffect, useState } from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import DualOrbitLoader from './shared/DualOrbitLoader';

interface ProtectedRouteProps {
  children: React.ReactElement;
  /** Role name or array of names allowed to access this route */
  requiredRole?: string | string[];
}

/** Returns true if the user's role satisfies the required role constraint */
function hasRequiredRole(
  userRole: string | undefined,
  required: string | string[] | undefined
): boolean {
  if (!required) return true;
  if (!userRole) return false;
  const allowed = Array.isArray(required) ? required : [required];
  return allowed.includes(userRole);
}

// ── Loading screen ─────────────────────────────────────────────────────────────
function AuthLoader() {
  return (
    <div
      style={{
        minHeight: '100vh',
        background: 'var(--bg-primary, #050b18)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
      }}
    >
      <DualOrbitLoader size={64} label="Authenticating..." />
    </div>
  );
}

// ── Access Denied overlay ──────────────────────────────────────────────────────
function AccessDeniedOverlay() {
  return (
    <div
      style={{
        minHeight: '100vh',
        background: '#050b18',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        flexDirection: 'column',
        gap: 24,
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      {/* Radial red vignette */}
      <div
        style={{
          position: 'absolute',
          inset: 0,
          background:
            'radial-gradient(ellipse at 50% 50%, transparent 30%, rgba(255,0,44,0.35) 100%)',
          pointerEvents: 'none',
          animation: 'vignette-pulse 0.8s ease-in-out infinite',
        }}
      />

      {/* Lock icon */}
      <div
        style={{
          fontSize: 64,
          filter: 'drop-shadow(0 0 20px rgba(255,0,68,0.8))',
          animation: 'glitch 0.2s ease-in-out infinite',
        }}
      >
        🔒
      </div>

      {/* ACCESS DENIED text */}
      <div
        className="access-denied-text"
        style={{
          color: '#ff0044',
          fontWeight: 900,
          fontSize: 28,
          fontFamily: "'Fira Code', monospace",
          textShadow:
            '0 0 10px rgba(255,0,68,0.9), 0 0 30px rgba(255,0,68,0.5)',
        }}
      >
        ACCESS DENIED
      </div>

      <div
        style={{
          color: '#ff6688',
          fontSize: 13,
          fontFamily: "'Fira Code', monospace",
          letterSpacing: 2,
          textTransform: 'uppercase',
          opacity: 0.8,
        }}
      >
        Insufficient permissions for this resource
      </div>

      <div
        className="access-denied-animate"
        style={{
          border: '1px solid rgba(255,0,68,0.4)',
          borderRadius: 8,
          padding: '8px 24px',
          color: '#6b8fa3',
          fontSize: 11,
          fontFamily: 'monospace',
          letterSpacing: 1,
        }}
      >
        Redirecting to dashboard...
      </div>

      <style>{`
        @keyframes vignette-pulse {
          0%, 100% { opacity: 0.5; }
          50%       { opacity: 1; }
        }
      `}</style>
    </div>
  );
}

// ── ProtectedRoute ─────────────────────────────────────────────────────────────
export default function ProtectedRoute({
  children,
  requiredRole,
}: ProtectedRouteProps) {
  const { isAuthenticated, isLoading, user } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const [showDenied, setShowDenied] = useState(false);

  // If role check fails, show the access denied animation for 2 s then redirect
  useEffect(() => {
    if (!isLoading && isAuthenticated && requiredRole) {
      if (!hasRequiredRole(user?.role, requiredRole)) {
        setShowDenied(true);
        const timer = setTimeout(() => {
          navigate('/dashboard', { replace: true });
        }, 2000);
        return () => clearTimeout(timer);
      }
    }
  }, [isLoading, isAuthenticated, user, requiredRole, navigate]);

  if (isLoading) {
    return <AuthLoader />;
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // Role check failed — show overlay (redirect fires via useEffect above)
  if (requiredRole && !hasRequiredRole(user?.role, requiredRole)) {
    return <AccessDeniedOverlay />;
  }

  // Role check passed (or no role required) but useEffect briefly set showDenied — reset it
  if (showDenied) {
    setShowDenied(false);
  }

  return children;
}
