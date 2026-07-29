import React, { useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useSirenAudio } from '../hooks/useSirenAudio';

interface AlertSirenProps {
  isActive: boolean;
  severity: 'HIGH' | 'CRITICAL';
  timestamp?: string;
  onAcknowledge: () => void;
  /** Whether the user has clicked "Enable Sound Alerts" in the top bar. */
  audioEnabled: boolean;
  /** Called when the user clicks the in-banner mute/enable button. */
  onEnableAudio: () => void;
}

export default function AlertSiren({
  isActive,
  severity,
  timestamp,
  onAcknowledge,
  audioEnabled,
  onEnableAudio,
}: AlertSirenProps) {
  const { play, stop, isPlaying } = useSirenAudio();

  // Start audio when alert becomes active AND user has enabled sound.
  // Guard against restarting when already playing.
  useEffect(() => {
    if (isActive && audioEnabled && !isPlaying) {
      play();
    }
  }, [isActive, audioEnabled]); // eslint-disable-line react-hooks/exhaustive-deps

  // Stop audio when the alert is dismissed.
  useEffect(() => {
    if (!isActive) {
      stop();
    }
  }, [isActive]); // eslint-disable-line react-hooks/exhaustive-deps

  // Clean up on unmount.
  useEffect(() => {
    return () => { stop(); };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const handleAcknowledge = () => {
    stop();
    onAcknowledge();
  };

  const isCritical = severity === 'CRITICAL';

  return (
    <>
      <style>{`
        @keyframes siren-vignette-pulse {
          0%, 100% { opacity: 0.3; }
          50%       { opacity: ${isCritical ? 0.7 : 0.5}; }
        }
      `}</style>
      <AnimatePresence>
          {/* Full-screen red vignette — enter/exit via framer-motion, pulse via CSS */}
          {isActive && <motion.div
            key="siren-vignette"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.35 }}
            style={{
              position: 'fixed',
              inset: 0,
              background: `radial-gradient(ellipse at 50% 50%, transparent 40%, ${
                isCritical ? 'rgba(255,0,44,0.55)' : 'rgba(255,50,50,0.40)'
              } 100%)`,
              pointerEvents: 'none',
              zIndex: 9990,
              animation: 'siren-vignette-pulse 0.8s ease-in-out infinite',
            }}
          />}

          {/* Notification bar — anchored below the 56px app top bar to avoid colliding
              with Start/Stop Monitoring buttons. The entry animation (y -80→0) still
              looks like a slide-in from above because at top:56 the banner starts
              at viewport-y ≈ -24, i.e. above the top bar and off-screen. */}
          {isActive && <motion.div
            key="siren-bar"
            initial={{ y: -80, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            exit={{ y: -80, opacity: 0 }}
            transition={{ type: 'spring', stiffness: 300, damping: 25 }}
            style={{
              position: 'fixed',
              top: 56,
              left: 0,
              right: 0,
              zIndex: 9999,
              background: isCritical
                ? 'linear-gradient(90deg, #1a0010 0%, #3d0020 50%, #1a0010 100%)'
                : 'linear-gradient(90deg, #1a000a 0%, #3d0015 50%, #1a000a 100%)',
              borderBottom: `2px solid ${isCritical ? '#ff0044' : '#ff3366'}`,
              boxShadow: isCritical
                ? '0 4px 40px rgba(255,0,68,0.6)'
                : '0 4px 30px rgba(255,51,102,0.4)',
              padding: '0 24px',
              height: 56,
              display: 'flex',
              alignItems: 'center',
              gap: 16,
            }}
          >
            {/* Pulsing icon */}
            <motion.span
              animate={{ scale: [1, 1.3, 1], opacity: [1, 0.6, 1] }}
              transition={{ duration: 0.6, repeat: Infinity }}
              style={{ fontSize: 22, flexShrink: 0 }}
            >
              &#128680;
            </motion.span>

            {/* Message */}
            <div style={{ flex: 1, minWidth: 0 }}>
              <span
                style={{
                  color: isCritical ? '#ff6688' : '#ff8899',
                  fontWeight: 900,
                  fontSize: 13,
                  letterSpacing: 2,
                  textTransform: 'uppercase',
                  fontFamily: "'Fira Code', monospace",
                }}
              >
                {isCritical ? 'CRITICAL' : 'HIGH'} THREAT DETECTED
              </span>
              {timestamp && (
                <span
                  style={{
                    color: '#6b8fa3',
                    fontSize: 11,
                    marginLeft: 16,
                    fontFamily: 'monospace',
                  }}
                >
                  &mdash; {timestamp}
                </span>
              )}
            </div>

            {/* Muted indicator — shown only when sound is not yet enabled */}
            {!audioEnabled && (
              <motion.button
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                onClick={onEnableAudio}
                title="Click to enable siren audio"
                style={{
                  padding: '6px 12px',
                  background: 'rgba(255,200,0,0.08)',
                  border: '1px solid rgba(255,200,0,0.35)',
                  borderRadius: 6,
                  color: '#ffc800',
                  fontWeight: 700,
                  fontSize: 11,
                  letterSpacing: 1,
                  textTransform: 'uppercase',
                  cursor: 'pointer',
                  fontFamily: "'Fira Code', monospace",
                  flexShrink: 0,
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                }}
              >
                <span style={{ fontSize: 13 }}>&#128263;</span>
                Enable Sound
              </motion.button>
            )}

            {/* Acknowledge button */}
            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              onClick={handleAcknowledge}
              style={{
                padding: '8px 20px',
                background: 'transparent',
                border: `2px solid ${isCritical ? '#ff0044' : '#ff3366'}`,
                borderRadius: 6,
                color: isCritical ? '#ff6688' : '#ff8899',
                fontWeight: 800,
                fontSize: 11,
                letterSpacing: 1.5,
                textTransform: 'uppercase',
                cursor: 'pointer',
                fontFamily: "'Fira Code', monospace",
                boxShadow: isCritical
                  ? '0 0 12px rgba(255,0,68,0.5)'
                  : '0 0 10px rgba(255,51,102,0.4)',
                transition: 'box-shadow 0.2s',
                flexShrink: 0,
              }}
            >
              ACKNOWLEDGE
            </motion.button>
          </motion.div>}
    </AnimatePresence>
    </>
  );
}
