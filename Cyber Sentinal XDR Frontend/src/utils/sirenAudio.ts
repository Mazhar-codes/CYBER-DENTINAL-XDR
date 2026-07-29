/**
 * Siren Audio — dual-source system for Cyber Sentinel XDR
 *
 * WHY enableAudio() MUST be called from a click handler:
 * Chrome (≥66) and Firefox enforce the Web Audio API autoplay policy: an
 * AudioContext starts in "suspended" state and can only be resumed (or
 * created in "running" state) as a direct result of a user-gesture event
 * handler (click, keydown, touchstart, etc.).  A useEffect callback, a
 * Socket.IO message handler, or a setTimeout are NOT user gestures.
 * Calling ctx.resume() from those paths is silently ignored by the browser.
 *
 * Solution: expose enableAudio() which MUST be wired to an onClick.
 * startSiren() is a no-op until enableAudio() has been called at least once.
 *
 * Audio source priority:
 *   1. HTMLAudioElement → /Sounds/siren.mp3.wav  (real WAV file present in public/)
 *   2. Web Audio API oscillator  (fallback when file fails to load or decode)
 */

// ── Module-level singletons ────────────────────────────────────────────────────

let audioCtx: AudioContext | null = null;
let oscillator: OscillatorNode | null = null;
let lfoOscillator: OscillatorNode | null = null;
let gainNode: GainNode | null = null;

/** Set to true only after the user clicks "Enable Sound Alerts". */
let _audioEnabled = false;

/** Single HTMLAudioElement instance — never recreated after first load. */
let _sirenEl: HTMLAudioElement | null = null;

/** True once the MP3/WAV file has confirmed it can be decoded and played. */
let _fileReady = false;

/** True while the HTMLAudioElement is the active playback path. */
let _usingFile = false;

// ── Internal helpers ────────────────────────────────────────────────────────────

function getAudioContext(): AudioContext {
  if (!audioCtx || audioCtx.state === 'closed') {
    audioCtx = new AudioContext();
  }
  return audioCtx;
}

/**
 * Lazily create the HTMLAudioElement and attempt to preload the siren file.
 * Called once during enableAudio() so the load request is tied to a user click.
 */
function initFileAudio(): void {
  if (_sirenEl) return;

  const el = new Audio('/Sounds/siren.mp3.wav');
  el.loop = true;
  el.volume = 0.75;
  el.preload = 'auto';

  el.addEventListener('canplaythrough', () => {
    _fileReady = true;
    if (process.env.NODE_ENV === 'development') {
      console.info('[Siren] Audio file ready: /Sounds/siren.mp3.wav');
    }
  }, { once: true });

  el.addEventListener('error', () => {
    _fileReady = false;
    if (process.env.NODE_ENV === 'development') {
      console.warn('[Siren] Audio file failed to load — will use Web Audio API synthesizer.');
    }
  }, { once: true });

  _sirenEl = el;
}

// ── Web Audio oscillator helpers ───────────────────────────────────────────────

function startOscillator(): void {
  stopOscillator();
  try {
    const ctx = getAudioContext();
    if (ctx.state === 'suspended') {
      // resume() is safe here only if we're in the call-chain of enableAudio()
      ctx.resume();
    }

    gainNode = ctx.createGain();
    gainNode.gain.setValueAtTime(0, ctx.currentTime);
    gainNode.gain.linearRampToValueAtTime(0.18, ctx.currentTime + 0.1);
    gainNode.connect(ctx.destination);

    // Main carrier — sine wave centred at 750 Hz
    oscillator = ctx.createOscillator();
    oscillator.type = 'sine';
    oscillator.frequency.setValueAtTime(750, ctx.currentTime);

    // LFO — modulates carrier ±150 Hz at 0.5 Hz → 600–900 Hz sweep over 2 s
    lfoOscillator = ctx.createOscillator();
    lfoOscillator.type = 'sine';
    lfoOscillator.frequency.setValueAtTime(0.5, ctx.currentTime);

    const lfoGain = ctx.createGain();
    lfoGain.gain.setValueAtTime(150, ctx.currentTime);

    lfoOscillator.connect(lfoGain);
    lfoGain.connect(oscillator.frequency);
    oscillator.connect(gainNode);

    oscillator.start();
    lfoOscillator.start();
  } catch (err) {
    if (process.env.NODE_ENV === 'development') {
      console.warn('[Siren] Web Audio API error:', err);
    }
  }
}

function stopOscillator(): void {
  try {
    if (gainNode && audioCtx) {
      gainNode.gain.linearRampToValueAtTime(0, audioCtx.currentTime + 0.1);
    }
    // Delay stop slightly so the gain fade-out completes
    const osc = oscillator;
    const lfo = lfoOscillator;
    setTimeout(() => {
      try { osc?.stop(); } catch { /* already stopped */ }
      try { lfo?.stop(); } catch { /* already stopped */ }
    }, 150);
  } catch {
    // ignore
  }
  oscillator = null;
  lfoOscillator = null;
  gainNode = null;
}

// ── Public API ─────────────────────────────────────────────────────────────────

/**
 * enableAudio() — MUST be called directly from an onClick handler.
 * This is the user-gesture gate required by browser autoplay policy.
 * Safe to call multiple times; subsequent calls are no-ops.
 */
export function enableAudio(): void {
  if (_audioEnabled) return;
  _audioEnabled = true;

  // Resume (or create) the AudioContext inside the user-gesture call stack
  try {
    const ctx = getAudioContext();
    if (ctx.state === 'suspended') {
      ctx.resume().catch(() => { /* ignore */ });
    }
  } catch {
    // ignore
  }

  // Preload the audio file (also triggered by the user click)
  initFileAudio();

  if (process.env.NODE_ENV === 'development') {
    console.info('[Siren] Audio enabled by user gesture.');
  }
}

/** Returns true once the user has clicked "Enable Sound Alerts". */
export function isAudioEnabled(): boolean {
  return _audioEnabled;
}

/**
 * disableAudio() — stops any active siren and prevents future automatic playback.
 * The next call to enableAudio() from a user gesture will re-enable it.
 */
export function disableAudio(): void {
  stopSirenInternal(true);
  _audioEnabled = false;
  if (process.env.NODE_ENV === 'development') {
    console.info('[Siren] Audio disabled by user.');
  }
}

/**
 * startSiren() — starts siren audio.
 * No-op if enableAudio() has not been called.
 * Tries HTMLAudioElement first; falls back to Web Audio oscillator.
 */
export function startSiren(): void {
  if (!_audioEnabled) {
    if (process.env.NODE_ENV === 'development') {
      console.warn('[Siren] startSiren() called before enableAudio() — ignoring (autoplay policy).');
    }
    return;
  }

  // Stop any currently running audio before starting again
  stopSirenInternal(false);

  if (_fileReady && _sirenEl) {
    // Primary path: HTMLAudioElement
    _sirenEl.currentTime = 0;
    _sirenEl.play().then(() => {
      _usingFile = true;
    }).catch((err: Error) => {
      // NotAllowedError: browser blocked playback — fall back to oscillator
      _usingFile = false;
      if (process.env.NODE_ENV === 'development') {
        console.warn('[Siren] HTMLAudioElement.play() rejected:', err.message, '— falling back to oscillator.');
      }
      startOscillator();
    });
  } else {
    // Fallback path: Web Audio API synthesizer
    _usingFile = false;
    startOscillator();
  }
}

/**
 * stopSiren() — stops siren audio and resets playback position.
 */
export function stopSiren(): void {
  stopSirenInternal(true);
}

function stopSirenInternal(resetEl: boolean): void {
  if (_usingFile && _sirenEl) {
    try {
      _sirenEl.pause();
      if (resetEl) _sirenEl.currentTime = 0;
    } catch {
      // ignore
    }
    _usingFile = false;
  } else {
    stopOscillator();
  }
}
