import React, { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import LoginPage from '../pages/LoginPage';
import DemoModeButton from './shared/DemoModeButton';

/**
 * StartupScreen — cinematic iframe intro.
 *
 * Primary mechanism: the iframe posts { type: 'at-last-scene' } when Lenis
 * scroll progress ≥ 88%, and { type: 'left-last-scene' } when it drops back.
 *
 * Fallback mechanism: a 150ms poll reads iframe.contentWindow.__lenis.progress
 * directly (same-origin). This guarantees the login overlay appears even if
 * the postMessage is missed (e.g. after a page refresh where the iframe script
 * reloads from cache and fires before the parent's listener is registered).
 */
const LAST_SCENE_THRESHOLD = 0.88;

const StartupScreen: React.FC = () => {
  const [atLastScene, setAtLastScene] = useState(false);

  // Mark the startup as seen so subsequent visits go directly to /login
  useEffect(() => {
    sessionStorage.setItem('xdr_startup_seen', '1');
  }, []);

  // Primary: postMessage from iframe
  useEffect(() => {
    const handler = (e: MessageEvent) => {
      if (!e.data || typeof e.data !== 'object') return;
      if (e.data.type === 'at-last-scene') {
        setAtLastScene(true);
      } else if (e.data.type === 'left-last-scene') {
        setAtLastScene(false);
      }
    };
    window.addEventListener('message', handler);
    return () => window.removeEventListener('message', handler);
  }, []);

  // Fallback: the iframe's Lenis RAF writes `window.parent.__cinematicProgress`
  // on every frame (same-origin direct property assignment — no postMessage
  // overhead, no serialisation, no timing race).  Poll our own window to read
  // it every 100 ms.  This guarantees detection even when postMessage is missed.
  useEffect(() => {
    const id = setInterval(() => {
      const p: number = (window as any).__cinematicProgress ?? 0;
      setAtLastScene(p >= LAST_SCENE_THRESHOLD);
    }, 100);
    return () => clearInterval(id);
  }, []);

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 9999,
        background: '#02060e',
      }}
    >
      {/* Cinematic intro iframe — always mounted, always running */}
      <iframe
        src="/Startup/index.html"
        style={{ width: '100%', height: '100%', border: 'none' }}
        title="Cyber Sentinel XDR Intro"
      />

      {/* Demo Mode bypass — mounted here at the top level (not inside the
          pointerEvents:'none' overlay below) so it's clickable from the very
          first frame, without waiting for the user to scroll to the last
          cinematic scene. */}
      <DemoModeButton />

      {/*
       * Real LoginPage overlaid on the cinematic background.
       *
       * pointerEvents:'none' on the wrapper lets scroll events reach the
       * iframe so Lenis responds to scroll-back.
       *
       * AnimatePresence gives a smooth 350ms fade-out when the user scrolls
       * back up (left-last-scene → atLastScene=false → exit animation runs).
       */}
      <AnimatePresence>
        {atLastScene && (
          <motion.div
            key="login-overlay"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.35, ease: 'easeInOut' }}
            style={{
              position: 'absolute',
              inset: 0,
              zIndex: 10,
              pointerEvents: 'none',   // ← scroll passes through to iframe
            }}
          >
            <LoginPage overlay />
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default StartupScreen;
