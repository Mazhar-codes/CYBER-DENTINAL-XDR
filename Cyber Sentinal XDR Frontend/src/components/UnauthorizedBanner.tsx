import React, { useState, useEffect, useCallback, useRef } from 'react';

/**
 * UnauthorizedBanner
 *
 * Listens for the custom DOM event `accessDenied` (dispatched by the axios
 * 403 interceptor in authService.ts).  When fired it renders a full-width red
 * banner at the top of the viewport that auto-dismisses after 3 seconds and
 * applies the .unauthorized-glitch CSS class to document.body for 1.5 s.
 */

interface BannerState {
  visible: boolean;
  exiting: boolean;
}

export default function UnauthorizedBanner() {
  const [banner, setBanner] = useState<BannerState>({ visible: false, exiting: false });
  const dismissTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const exitTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const clearTimers = () => {
    if (dismissTimer.current) clearTimeout(dismissTimer.current);
    if (exitTimer.current) clearTimeout(exitTimer.current);
  };

  const showBanner = useCallback(() => {
    // Apply body glitch class for 1.5 s
    document.body.classList.add('unauthorized-glitch');
    setTimeout(() => {
      document.body.classList.remove('unauthorized-glitch');
    }, 1500);

    // Show banner
    clearTimers();
    setBanner({ visible: true, exiting: false });

    // Start fade-out at 2.6 s, fully unmount at 3 s
    dismissTimer.current = setTimeout(() => {
      setBanner({ visible: true, exiting: true });
      exitTimer.current = setTimeout(() => {
        setBanner({ visible: false, exiting: false });
      }, 400);
    }, 2600);
  }, []);

  useEffect(() => {
    window.addEventListener('accessDenied', showBanner);
    return () => {
      window.removeEventListener('accessDenied', showBanner);
      clearTimers();
      document.body.classList.remove('unauthorized-glitch');
    };
  }, [showBanner]);

  if (!banner.visible) return null;

  return (
    <div
      role="alert"
      aria-live="assertive"
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        zIndex: 10000,
        display: 'flex',
        alignItems: 'center',
        gap: 14,
        padding: '0 24px',
        height: 52,
        background:
          'linear-gradient(90deg, #1a0005 0%, #3d0010 40%, #1a0005 100%)',
        borderBottom: '2px solid #ff0044',
        boxShadow:
          '0 0 30px rgba(255,0,68,0.6), 0 4px 40px rgba(255,0,0,0.4)',
        animation: banner.exiting
          ? 'banner-fade-out 0.4s ease-out forwards'
          : 'banner-slide-in 0.3s cubic-bezier(0.22, 1, 0.36, 1) forwards',
      }}
    >
      {/* Icon */}
      <span
        style={{
          fontSize: 18,
          flexShrink: 0,
          filter: 'drop-shadow(0 0 6px rgba(255,0,68,0.9))',
        }}
      >
        🚫
      </span>

      {/* Dot indicator */}
      <div
        style={{
          width: 8,
          height: 8,
          borderRadius: '50%',
          background: '#ff0044',
          flexShrink: 0,
          boxShadow: '0 0 8px rgba(255,0,68,0.9)',
          animation: 'pulse-border 0.6s ease-in-out infinite',
        }}
      />

      {/* Message text */}
      <span
        className="access-denied-text"
        style={{
          color: '#ff6688',
          fontWeight: 900,
          fontSize: 12,
          letterSpacing: 4,
          textTransform: 'uppercase',
          fontFamily: "'Fira Code', monospace",
          textShadow:
            '0 0 8px rgba(255,0,68,0.9), 0 0 20px rgba(255,0,68,0.5)',
          flex: 1,
        }}
      >
        Unauthorized Access Attempt Blocked
      </span>

      {/* Right side: timestamp */}
      <span
        style={{
          color: '#6b8fa3',
          fontSize: 10,
          fontFamily: 'monospace',
          flexShrink: 0,
          letterSpacing: 1,
        }}
      >
        {new Date().toLocaleTimeString('en-GB', {
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
        })}
      </span>

      {/* Dismiss button */}
      <button
        onClick={() => {
          clearTimers();
          setBanner({ visible: true, exiting: true });
          exitTimer.current = setTimeout(
            () => setBanner({ visible: false, exiting: false }),
            400
          );
        }}
        aria-label="Dismiss unauthorized access banner"
        style={{
          background: 'transparent',
          border: '1px solid rgba(255,0,68,0.5)',
          borderRadius: 4,
          color: '#ff6688',
          fontSize: 16,
          lineHeight: 1,
          padding: '2px 8px',
          cursor: 'pointer',
          fontFamily: 'monospace',
          flexShrink: 0,
          transition: 'border-color 0.15s, box-shadow 0.15s',
        }}
        onMouseEnter={(e) => {
          (e.currentTarget as HTMLButtonElement).style.borderColor =
            '#ff0044';
          (e.currentTarget as HTMLButtonElement).style.boxShadow =
            '0 0 8px rgba(255,0,68,0.6)';
        }}
        onMouseLeave={(e) => {
          (e.currentTarget as HTMLButtonElement).style.borderColor =
            'rgba(255,0,68,0.5)';
          (e.currentTarget as HTMLButtonElement).style.boxShadow = 'none';
        }}
      >
        ×
      </button>
    </div>
  );
}
