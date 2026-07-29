/**
 * useSirenAudio — React hook that wraps the sirenAudio module.
 *
 * WHY enableAudio() MUST be called from a click handler:
 * Chrome (≥66) and Firefox enforce the Web Audio API autoplay policy. An
 * AudioContext starts in the "suspended" state and can only transition to
 * "running" as a direct result of a user-gesture event handler (click,
 * keydown, touchstart, etc.).  Calling ctx.resume() from a useEffect, a
 * Socket.IO message handler, or a setTimeout is silently ignored by the
 * browser — the context remains suspended and no audio is produced.
 *
 * Wire `enableAudio` to an onClick prop. All subsequent `play()` calls
 * (triggered by socket events) will work correctly.
 *
 * Usage:
 *   const { audioEnabled, enableAudio, play, stop, isPlaying } = useSirenAudio();
 *
 *   // In top bar:
 *   <button onClick={enableAudio}>Enable Sound Alerts</button>
 *
 *   // In siren component:
 *   useEffect(() => { if (active && audioEnabled) play(); }, [active]);
 */

import { useState, useCallback } from 'react';
import {
  enableAudio as _enableAudio,
  disableAudio as _disableAudio,
  isAudioEnabled,
  startSiren,
  stopSiren,
} from '../utils/sirenAudio';

const STORAGE_KEY = 'xdr_sound_enabled';

export interface SirenAudioControls {
  /** True once the user has clicked the "Enable Sound Alerts" button. */
  audioEnabled: boolean;
  /**
   * Call this directly from an onClick handler.
   * Unlocks the AudioContext per browser autoplay policy.
   * Also persists preference to localStorage.
   */
  enableAudio: () => void;
  /**
   * Disable audio: stops the siren and sets audioEnabled to false.
   * Persists the disabled preference to localStorage.
   */
  disableAudio: () => void;
  /**
   * Start the siren. No-op when audioEnabled is false.
   * Safe to call when already playing — will not restart.
   */
  play: () => void;
  /** Stop the siren and reset playback position. */
  stop: () => void;
  /** True while the siren is playing. */
  isPlaying: boolean;
}

export function useSirenAudio(): SirenAudioControls {
  // Initialise from module state so the hook reflects reality on re-mount.
  // Also check localStorage: if the user previously enabled audio, reflect that
  // in the UI label (though AudioContext still needs a new user gesture on page reload).
  const [audioEnabled, setAudioEnabled] = useState<boolean>(() => {
    // If the module already has audio enabled (same page session), use that.
    if (isAudioEnabled()) return true;
    // Otherwise fall back to stored preference for the UI toggle label only.
    return localStorage.getItem(STORAGE_KEY) === 'true';
  });
  const [isPlaying, setIsPlaying] = useState<boolean>(false);

  const enableAudio = useCallback(() => {
    _enableAudio();
    setAudioEnabled(true);
    localStorage.setItem(STORAGE_KEY, 'true');
  }, []);

  const disableAudio = useCallback(() => {
    _disableAudio();
    setAudioEnabled(false);
    setIsPlaying(false);
    localStorage.setItem(STORAGE_KEY, 'false');
  }, []);

  const play = useCallback(() => {
    if (!isAudioEnabled()) {
      if (process.env.NODE_ENV === 'development') {
        console.warn('[useSirenAudio] play() called before enableAudio() — ignoring.');
      }
      return;
    }
    // Guard: do not restart if already playing
    if (isPlaying) return;
    startSiren();
    setIsPlaying(true);
  }, [isPlaying]);

  const stop = useCallback(() => {
    stopSiren();
    setIsPlaying(false);
  }, []);

  return { audioEnabled, enableAudio, disableAudio, play, stop, isPlaying };
}
