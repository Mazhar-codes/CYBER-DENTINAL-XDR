/* global React, ReactDOM, framerMotion, Lenis */

// ── Issue 1 fix: disable browser scroll restoration and force scroll to top ──
// Must run synchronously before React mounts so Lenis always starts at 0.
if ('scrollRestoration' in history) history.scrollRestoration = 'manual';
window.scrollTo(0, 0);

const { useEffect, useRef, useState, useMemo, useCallback, memo } = React;
const { motion: _fm, useScroll, useTransform, useMotionValue, useSpring, AnimatePresence, useMotionValueEvent } = window.Motion || window.framerMotion || {};
// Fallback: if framer-motion CDN fails, render plain divs so the app doesn't crash
function _mFallback(tag) {
  return function MotionEl(_ref) {
    var children = _ref.children, animate = _ref.animate, initial = _ref.initial, exit = _ref.exit, transition = _ref.transition, whileHover = _ref.whileHover, whileTap = _ref.whileTap, layout = _ref.layout, rest = Object.assign({}, _ref);
    delete rest.animate; delete rest.initial; delete rest.exit; delete rest.transition;
    delete rest.whileHover; delete rest.whileTap; delete rest.layout; delete rest.children;
    return React.createElement(tag, rest, children);
  };
}
const motion = _fm || { div: _mFallback('div'), span: _mFallback('span') };

// =================================================================
// AUDIO BUS
// =================================================================
const audioBus = (() => {
  let ctx = null, master = null, ambientGain = null;
  let ambient = null;
  function ensure() {
    if (ctx) return;
    ctx = new (window.AudioContext || window.webkitAudioContext)();
    master = ctx.createGain(); master.gain.value = 0.22; master.connect(ctx.destination);
  }
  function startAmbient() {
    ensure();
    if (ambient) return;
    const o1 = ctx.createOscillator(); o1.type = 'sine'; o1.frequency.value = 60;
    const o2 = ctx.createOscillator(); o2.type = 'sine'; o2.frequency.value = 92;
    const o3 = ctx.createOscillator(); o3.type = 'triangle'; o3.frequency.value = 220;
    const lfo = ctx.createOscillator(); lfo.frequency.value = 0.18;
    const lfoG = ctx.createGain(); lfoG.gain.value = 16;
    lfo.connect(lfoG).connect(o3.frequency);
    const g = ctx.createGain(); g.gain.value = 0;
    o1.connect(g); o2.connect(g); o3.connect(g);
    g.connect(master);
    o1.start(); o2.start(); o3.start(); lfo.start();
    g.gain.linearRampToValueAtTime(0.55, ctx.currentTime + 1.4);
    ambient = { o1, o2, o3, lfo }; ambientGain = g;
  }
  function fadeAmbient(target = 0, dur = 1.4) {
    if (!ambientGain) return;
    ambientGain.gain.linearRampToValueAtTime(target, ctx.currentTime + dur);
  }
  function tick() {
    if (!ctx) return;
    const o = ctx.createOscillator(); o.type = 'square';
    o.frequency.value = 880 + Math.random() * 120;
    const g = ctx.createGain(); g.gain.value = 0;
    o.connect(g); g.connect(master);
    g.gain.linearRampToValueAtTime(0.04, ctx.currentTime + 0.005);
    g.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.06);
    o.start(); o.stop(ctx.currentTime + 0.07);
  }
  function alert() {
    if (!ctx) return;
    const o = ctx.createOscillator(); o.type = 'sawtooth'; o.frequency.value = 220;
    const g = ctx.createGain(); g.gain.value = 0;
    o.connect(g); g.connect(master);
    g.gain.linearRampToValueAtTime(0.28, ctx.currentTime + 0.02);
    o.frequency.linearRampToValueAtTime(880, ctx.currentTime + 0.4);
    g.gain.linearRampToValueAtTime(0, ctx.currentTime + 0.7);
    o.start(); o.stop(ctx.currentTime + 0.75);
  }
  function whoosh() {
    if (!ctx) return;
    const o = ctx.createOscillator(); o.type = 'sawtooth';
    o.frequency.value = 90;
    const f = ctx.createBiquadFilter(); f.type = 'bandpass'; f.frequency.value = 800; f.Q.value = 4;
    const g = ctx.createGain(); g.gain.value = 0;
    o.connect(f); f.connect(g); g.connect(master);
    g.gain.linearRampToValueAtTime(0.18, ctx.currentTime + 0.04);
    f.frequency.linearRampToValueAtTime(2400, ctx.currentTime + 0.45);
    g.gain.linearRampToValueAtTime(0, ctx.currentTime + 0.5);
    o.start(); o.stop(ctx.currentTime + 0.55);
  }
  return {
    enable: () => ensure(),
    startAmbient, fadeAmbient, tick, alert, whoosh,
    isOn: () => !!ctx,
  };
})();

// =================================================================
// SCROLL CONTEXT (Lenis-backed)
// =================================================================
// targetScrollRef is written by the Lenis RAF on every frame and read
// by the App-level lerp RAF loop.  Separating the two loops means React
// state updates happen at a controlled cadence (lerp loop) rather than
// on every raw scroll event, which eliminates the stutter / snap.
const _targetScrollRef = { p: 0, v: 0 };

function useLenisScroll() {
  useEffect(() => {
    // Issue 1 fix: guarantee we start at the very top even after a
    // browser refresh that would otherwise restore the scroll position.
    window.scrollTo(0, 0);

    const lenis = new Lenis({
      // lerp: 0.18 — converges in ~280ms (3× faster than 0.08).
      // Eliminates the "stuck at scene boundary" feel without sacrificing
      // the smooth deceleration that makes the cinematic feel premium.
      lerp: 0.18,
      smoothWheel: true,
      smoothTouch: false,
      wheelMultiplier: 1.0,
      touchMultiplier: 1.4,
    });
    let lastP = 0, lastT = performance.now();
    let rafId;
    function raf(t) {
      lenis.raf(t);
      const now = performance.now();
      const dt = Math.max(1, now - lastT) / 1000;
      const p = lenis.progress;
      const v = (p - lastP) / dt;
      lastT = now; lastP = p;
      // Write raw Lenis progress into the shared ref — no React setState here.
      _targetScrollRef.p = p;
      _targetScrollRef.v = v;
      // Write to parent window directly (same-origin) so StartupScreen can
      // poll this without relying on postMessage timing.  This is the raw
      // Lenis value — NOT the double-lerped newP — so it reflects the user's
      // actual scroll position immediately.
      if (window.parent && window.parent !== window) {
        window.parent.__cinematicProgress = p;
      }
      rafId = requestAnimationFrame(raf);
    }
    rafId = requestAnimationFrame(raf);
    window.__lenis = lenis;
    return () => {
      cancelAnimationFrame(rafId);
      lenis.destroy();
      window.__lenis = null;
    };
  }, []);
}

// =================================================================
// HUD CHROME
// =================================================================
function HudChrome() {
  // Minimal chrome — corner brackets only. All status / uplink / sector / EPS
  // labels removed for a quieter, more cinematic frame.
  return (
    <>
      <div className="hud hud-corner tl"></div>
      <div className="hud hud-corner tr"></div>
      <div className="hud hud-corner bl"></div>
      <div className="hud hud-corner br"></div>
    </>
  );
}

// =================================================================
// PROGRESS RAIL (right side)
// =================================================================
const SCENE_NAMES = ['BOOT', 'WATCH', 'FUSION', 'RESPONSE', 'MATRIX', 'CORE', 'SHIELD', 'ACCESS'];
const SCENE_FULL = [
  'XDR BOOT SEQUENCE',
  'GLOBAL THREAT MAP',
  'AI FUSION ENGINE',
  'LIVE THREAT RESPONSE',
  'GLOBAL THREAT MATRIX',
  'AI CORRELATION CORE',
  'AUTONOMOUS RESPONSE',
  'SECURE ACCESS PORTAL',
];
const SCENE_DESC = [
  'Initializing kernel · neural mesh activation · holographic uplink.',
  'Endpoint mesh online — 1,204 sensors streaming live telemetry into the fusion core.',
  'Multi-domain correlation engine — network · users · system · malware fused into one signal.',
  'Simulated intrusion · automated SOAR containment · neutralized in seconds.',
  'Worldwide threat intelligence streaming across continents in real time.',
  'Network · user · system · malware signals merging into one explainable verdict.',
  'A containment shockwave cleanses infected geometry into trusted topology.',
  'Identity verified · MFA shield armed · transferring control to operator.',
];

const RANGES_FALLBACK = [
  [0.00,0.12],[0.12,0.24],[0.24,0.38],[0.38,0.50],
  [0.50,0.65],[0.65,0.78],[0.78,0.90],[0.90,1.00],
];

function ProgressRail({ progress }) {
  const RANGES = (window.cinFx && window.cinFx.RANGES) || RANGES_FALLBACK;
  return (
    <div className="rail">
      {SCENE_NAMES.map((nm, i) => {
        const [a, b] = RANGES[i];
        const p = Math.max(0, Math.min(1, (progress - a) / (b - a)));
        const active = progress >= a - 0.02 && progress < b + 0.02;
        return (
          <div
            key={i}
            className={`step ${active ? 'active' : ''}`}
            onClick={() => {
              const target = (a + 0.001) * (document.documentElement.scrollHeight - window.innerHeight);
              if (window.__lenis) window.__lenis.scrollTo(target, { duration: 1.6 });
            }}
          >
            <span className="ix">0{i+1}</span>
            <span className="bar" style={{'--p': p}}></span>
            <span>{nm}</span>
          </div>
        );
      })}
    </div>
  );
}

// =================================================================
// SCENE 1 — BOOT
// =================================================================
const BOOT_LINES = [
  ['cy', '> initializing CYBER SENTINEL XDR core...'],
  ['ok', '[ ✓ ] kernel modules loaded'],
  ['ok', '[ ✓ ] mfa subsystem online'],
  ['ok', '[ ✓ ] endpoint sensor mesh ready'],
  ['cy', '> linking AI fusion engine...'],
  ['dim', '        - network domain ............ <span class="ok">OK</span>'],
  ['dim', '        - user behavior ............. <span class="ok">OK</span>'],
  ['dim', '        - system / sysmon ........... <span class="ok">OK</span>'],
  ['dim', '        - malware analysis .......... <span class="ok">OK</span>'],
  ['ok', '[ ✓ ] SHAP explainability primed'],
  ['ok', '[ ✓ ] SOAR response engine armed'],
  ['warn', '[ ! ] siren array on standby'],
  ['cy', '> establishing secure tunnel...'],
  ['ok', '[ ✓ ] TLS 1.3 / X25519 / AES-256-GCM'],
  ['cy', '> fetching live threat intelligence ▌'],
];

function SceneBoot({ active, local }) {
  const opacity = useMemo(() => {
    if (active < 0.02) return 0;
    return active;
  }, [active]);

  return (
    <motion.div
      className="scene"
      style={{ opacity, pointerEvents: 'none' }}
      animate={{ opacity }}
      transition={{ duration: 0.2 }}
    >
      {/* Title with depth parallax */}
      <motion.div
        className="title-group"
        style={{
          x: '-50%',
          y: '-50%',
          z: 0,
          opacity: Math.min(1, active * 1.4),
        }}
        animate={{
          scale: 1 + local * 0.4,
          filter: `blur(${local * 8}px)`,
        }}
        transition={{ duration: 0 }}
      >
        <div className="title-eyebrow">EXTENDED · DETECTION · RESPONSE</div>
        <div className="title-main">CYBER SENTINEL</div>
        <div className="title-divider"></div>
      </motion.div>
    </motion.div>
  );
}

const BootLog = memo(function BootLog({ active }) {
  const [n, setN] = useState(0);
  const ref = useRef(null);
  useEffect(() => {
    if (!active) return;
    if (n >= BOOT_LINES.length) return;
    const id = setTimeout(() => {
      setN((x) => x + 1);
      audioBus.tick();
    }, 200 + Math.random() * 140);
    return () => clearTimeout(id);
  }, [n, active]);
  useEffect(() => { if (ref.current) ref.current.scrollTop = ref.current.scrollHeight; }, [n]);
  return (
    <div ref={ref} style={{maxHeight: '46vh', overflow: 'hidden'}}>
      {BOOT_LINES.slice(0, n).map((l, i) => (
        <div key={i} className={'ln ' + l[0]} dangerouslySetInnerHTML={{__html: l[1]}} />
      ))}
    </div>
  );
});

// =================================================================
// SCENE 2 — CYBERSPACE
// =================================================================
function SceneWatch({ active, local, velocity }) {
  return (
    <motion.div className="scene" style={{ opacity: active }}>
      <motion.div
        className="metric-card"
        style={{
          top: '24%', left: '7%',
          opacity: Math.min(1, active * 1.4),
          transform: `translateY(${(1 - active) * 14}px)`,
        }}
      >
        <div className="lbl">EVENTS / SEC</div>
        <div className="val">12,847<span className="u">EPS</span></div>
        <div className="sub">▲ 4.6% over 60s</div>
      </motion.div>
      <motion.div
        className="metric-card grn"
        style={{
          top: '40%', left: '7%',
          opacity: Math.min(1, (active - 0.1) * 1.6),
          transform: `translateY(${(1 - active) * 18}px)`,
        }}
      >
        <div className="lbl">ENDPOINTS WATCHED</div>
        <div className="val">1,204<span className="u">NODES</span></div>
        <div className="sub">14 sensor shards · all online</div>
      </motion.div>
      <motion.div
        className="metric-card"
        style={{
          bottom: '28%', right: '7%',
          opacity: Math.min(1, (active - 0.1) * 1.6),
          transform: `translateY(${(1 - active) * 18}px)`,
        }}
      >
        <div className="lbl">CORRELATION LATENCY</div>
        <div className="val">0.42<span className="u">MS</span></div>
        <div className="sub">p99 fused decision time</div>
      </motion.div>
      <motion.div
        className="metric-card am"
        style={{
          bottom: '12%', right: '7%',
          opacity: Math.min(1, (active - 0.2) * 1.6),
          transform: `translateY(${(1 - active) * 22}px)`,
        }}
      >
        <div className="lbl">THREAT VELOCITY</div>
        <div className="val">{(0.6 + Math.abs(velocity) * 8).toFixed(2)}<span className="u">×</span></div>
        <div className="sub">live · gesture-reactive</div>
      </motion.div>

      <div className="radar" style={{opacity: 0.6 * active, transform: `translate(-50%,-50%) scale(${0.9 + local * 0.2})`}}>
        <div className="sweep"></div>
      </div>
    </motion.div>
  );
}

// =================================================================
// SCENE 3 — FUSION
// =================================================================
function SceneFusion({ active, local }) {
  const featRows = [
    ['lateral.move',     0.82],
    ['priv.escalation',  0.74],
    ['suspicious.dns',   0.61],
    ['credential.dump',  0.48],
    ['anomaly.beacon',   0.39],
  ];
  return (
    <motion.div className="scene" style={{ opacity: active }}>
      <motion.div className="fusion-label ne" style={{ top: '16%', left: '7%', opacity: Math.min(1, active*1.3), transform: `translate(${(active-1)*40}px, 0)` }}>
        <span>NETWORK FLOWS</span>
        <span className="num">412.6 GB/s</span>
        <span style={{fontSize:9, color:'var(--fg-muted)'}}>9,844 ACTIVE STREAMS</span>
      </motion.div>
      <motion.div className="fusion-label ub" style={{ top: '16%', right: '7%', textAlign:'right', alignItems:'flex-end', opacity: Math.min(1, (active-0.05)*1.4), transform: `translate(${(1-active)*40}px, 0)` }}>
        <span>USER BEHAVIOR</span>
        <span className="num">9,842 SESS</span>
        <span style={{fontSize:9, color:'var(--fg-muted)'}}>UEBA SCORING ONLINE</span>
      </motion.div>
      <motion.div className="fusion-label sy" style={{ bottom: '20%', left: '7%', opacity: Math.min(1, (active-0.1)*1.5), transform: `translate(${(active-1)*40}px, 0)` }}>
        <span>SYSTEM / SYSMON</span>
        <span className="num">2.1 M EVT/s</span>
        <span style={{fontSize:9, color:'var(--fg-muted)'}}>14 K HOSTS · KERNEL TAPS</span>
      </motion.div>
      <motion.div className="fusion-label mw" style={{ bottom: '20%', right: '7%', textAlign:'right', alignItems:'flex-end', opacity: Math.min(1, (active-0.15)*1.6), transform: `translate(${(1-active)*40}px, 0)` }}>
        <span>MALWARE ANALYSIS</span>
        <span className="num">218 SAMPLES</span>
        <span style={{fontSize:9, color:'var(--fg-muted)'}}>SANDBOX QUEUE 2.3 s</span>
      </motion.div>

      <motion.div
        className="fusion-readout"
        style={{ opacity: Math.min(1, (active-0.2)*1.8) }}
      >
        <span className="chip">FUSION CORE <b>ACTIVE</b></span>
        <span className="chip">SHAP <b>EXPLAINABLE</b></span>
        <span className="chip">SEVERITY <b>NOMINAL</b></span>
      </motion.div>

      <motion.div
        className="shap-hud"
        style={{ opacity: Math.min(1, (active-0.3)*2.0) }}
      >
        <div className="ttl">▶ SHAP — TOP CONTRIBUTING SIGNALS</div>
        {featRows.map(([k, v]) => (
          <div key={k} className="row">
            <div className="lab">{k}</div>
            <div className="b" style={{'--w': `${(v * 100).toFixed(1)}%`}}></div>
            <div className="v">{(v * 100).toFixed(1)}</div>
          </div>
        ))}
      </motion.div>
    </motion.div>
  );
}

// =================================================================
// SCENE 4 — THREAT RESPONSE
// =================================================================
function SceneResponse({ active, local }) {
  // local 0..1 within scene
  // 0.0–0.2  detection
  // 0.2–0.5  spread / red flash
  // 0.5–0.7  SOAR engaged (amber)
  // 0.7–1.0  neutralized (green)

  let banner = null;
  let bannerCls = '';
  let flashColor = null;

  if (local < 0.2) {
    banner = { main: 'THREAT DETECTED', sub: 'MULTI-STAGE INTRUSION · CORRELATION CONFIRMED' };
    bannerCls = '';
    flashColor = `rgba(220,38,38,${(0.2 - local) * 2 + 0.4})`;
  } else if (local < 0.5) {
    banner = { main: 'LATERAL MOVEMENT', sub: 'T1486 · T1021.001 · APT PATTERN' };
    bannerCls = '';
    flashColor = `rgba(220,38,38,${0.35 + Math.sin(local*30)*0.15})`;
  } else if (local < 0.72) {
    banner = { main: 'SOAR ENGAGED', sub: 'AUTOMATED CONTAINMENT IN PROGRESS' };
    bannerCls = 'am';
    flashColor = `rgba(255,180,0,${0.18 + Math.sin(local*20)*0.08})`;
  } else {
    banner = { main: 'THREAT NEUTRALIZED', sub: 'ALL ENDPOINTS SECURE' };
    bannerCls = 'gr';
    flashColor = `rgba(34,197,94,${(local - 0.72) * 1.2})`;
  }

  // tell engine the network phase
  useEffect(() => {
    if (!window.cinFx_phase) return;
    if (active < 0.05) { window.cinFx_phase('reset'); return; }
    if (local < 0.05) window.cinFx_phase('attack-start', true);
    else if (local > 0.5 && local < 0.55) window.cinFx_phase('isolate', true);
    else if (local > 0.7) window.cinFx_phase('secure');
  }, [Math.floor(local * 30), active < 0.05]);

  // siren on entry
  const playedRef = useRef(false);
  useEffect(() => {
    if (active > 0.1 && !playedRef.current) { playedRef.current = true; audioBus.alert(); window.cinFx?.triggerShake(14); }
    if (active < 0.05) playedRef.current = false;
  }, [active]);

  // events feed
  const events = useMemo(() => {
    const all = [
      [0.05, 'crit', '00:01.04', 'Suspicious process spawn — endpoint 0x4F-A3', 'CRITICAL'],
      [0.18, 'crit', '00:01.62', 'Lateral movement — 4 hosts at risk',           'ALERT'],
      [0.34, 'warn', '00:03.18', 'Fusion engine: T1486 + T1021.001 → APT',         'AI'],
      [0.50, 'warn', '00:04.21', 'Isolating endpoint 0x4F-A3 — kill switch armed', 'SOAR'],
      [0.62, 'warn', '00:05.04', 'IP 198.51.100.77 blocked at perimeter',          'BLOCK'],
      [0.78, 'ok',   '00:06.40', 'Containment verified — system nominal',          'OK'],
    ];
    return all.filter((e) => local >= e[0]);
  }, [Math.floor(local * 50)]);

  return (
    <motion.div className="scene" style={{ opacity: active }}>
      <div className="flash-overlay" style={{ background: `radial-gradient(ellipse at center, ${flashColor}, transparent 60%)`, opacity: 1 }} />

      <motion.div
        className={`alert-banner ${bannerCls}`}
        style={{
          opacity: Math.min(1, active*1.4),
          letterSpacing: `${12 - Math.sin(local*10)*2}px`,
        }}
      >
        <span className="main">{banner.main}</span>
        <span className="sub">{banner.sub}</span>
      </motion.div>

      <motion.div className="event-feed" style={{ opacity: Math.min(1, active * 1.2) }}>
        {events.slice(-5).map((e, i) => (
          <div key={i} className={`event ${e[1] === 'ok' ? 'ok' : e[1] === 'warn' ? 'warn' : ''}`}>
            <span className="t">{e[2]}</span>
            <span className="m">{e[3]}</span>
            <span className="badge">{e[4]}</span>
          </div>
        ))}
      </motion.div>

      <motion.div className="severity-meter" style={{ opacity: Math.min(1, active*1.3) }}>
        <div className="lbl">▶ FUSION SEVERITY</div>
        <div className="scale">
          {Array.from({length: 10}).map((_, i) => {
            const onCount = local < 0.5 ? Math.ceil(local * 2 * 10) : (local < 0.72 ? 9 - Math.floor((local-0.5)*40) : 1);
            return <span key={i} className={i < onCount ? 'on' : ''}></span>;
          })}
        </div>
        <div className="val">{local < 0.5 ? 'CRITICAL' : local < 0.72 ? 'CONTAINED' : 'NOMINAL'}</div>
      </motion.div>
    </motion.div>
  );
}

// =================================================================
// CHAPTER CAPTION
// =================================================================
function Chapter({ idx, sub }) {
  // Plain DOM (CSS handles entrance). Avoids a framer-motion 11
  // false-positive key warning emitted from motion.div internals.
  return (
    <div className="chapter" data-idx={idx}>
      <div className="ix">SCENE {String(idx + 1).padStart(2, '0')} / 05</div>
      <div className="nm">{SCENE_FULL[idx]}</div>
      <div className="desc">{SCENE_DESC[idx]}</div>
    </div>
  );
}

// =================================================================

// =================================================================
// MAIN APP
// =================================================================
const TWEAK_DEFAULTS = /*EDITMODE-BEGIN*/{
  "accent": "cyan",
  "speed": 1,
  "intensity": 1,
  "audio": false
}/*EDITMODE-END*/;

function App() {
  const [progress, setProgress] = useState(0);
  const [velocity, setVelocity] = useState(0);
  const canvasRef = useRef(null);
  const threeCanvasRef = useRef(null);
  const [audioOn, setAudioOn] = useState(false);
  const [cursor, setCursor] = useState({ x: 0, y: 0 });

  useEffect(() => {
    if (canvasRef.current && window.cinFx) window.cinFx.setCanvas(canvasRef.current);
    if (threeCanvasRef.current && window.threeStage) {
      window.threeStage.mount(threeCanvasRef.current);
    }
  }, []);

  // cursor tracking — feed normalized -1..1 to both engines for parallax
  useEffect(() => {
    function onMove(e) {
      const nx = (e.clientX / window.innerWidth) * 2 - 1;
      const ny = -((e.clientY / window.innerHeight) * 2 - 1);
      setCursor({ x: nx, y: ny });
      if (window.threeStage) window.threeStage.setCursor(nx, ny);
    }
    window.addEventListener('mousemove', onMove);
    window.addEventListener('pointermove', onMove);
    return () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('pointermove', onMove);
    };
  }, []);

  // ── Issue 2 fix: lerp loop ────────────────────────────────────────
  // currentLerpRef tracks the smoothed progress/velocity values.
  // A single RAF loop lerps toward the Lenis raw values (_targetScrollRef)
  // and writes to React state only when the value shifts meaningfully,
  // giving a fluid "catch-up" feel without React re-rendering every RAF tick.
  const currentLerpRef = useRef({ p: 0, v: 0 });
  const lastScenePhaseRef = useRef(null);

  useLenisScroll(); // no callback — drives _targetScrollRef instead

  useEffect(() => {
    const LERP_FACTOR = 0.10; // app-level smooth; Lenis lerp:0.18 handles primary smoothing
    const MIN_DELTA   = 0.0005; // only trigger setState when value shifts by this much
    let rafId;

    function lerpFrame() {
      const cur = currentLerpRef.current;
      const tgt = _targetScrollRef;

      const newP = cur.p + (tgt.p - cur.p) * LERP_FACTOR;
      const newV = cur.v + (tgt.v - cur.v) * LERP_FACTOR;
      cur.p = newP;
      cur.v = newV;

      // Feed engines on every frame (they smooth internally too)
      if (window.cinFx) {
        window.cinFx.setProgress(newP);
        window.cinFx.setVelocity(newV);
      }
      if (window.threeStage) {
        window.threeStage.setProgress(newP);
        window.threeStage.setVelocity(newV);
      }

      // Batch React state update — only when progress moves enough
      setProgress((prev) => Math.abs(prev - newP) > MIN_DELTA ? newP : prev);
      setVelocity((prev) => Math.abs(prev - newV) > 0.002 ? newV : prev);

      // Notify parent frame when entering / leaving the last scene
      const phase = newP >= 0.88 ? 'last' : 'earlier';
      if (phase !== lastScenePhaseRef.current) {
        lastScenePhaseRef.current = phase;
        if (window.parent && window.parent !== window) {
          window.parent.postMessage(
            { type: phase === 'last' ? 'at-last-scene' : 'left-last-scene' },
            '*'
          );
        }
      }

      rafId = requestAnimationFrame(lerpFrame);
    }

    rafId = requestAnimationFrame(lerpFrame);
    return () => cancelAnimationFrame(rafId);
  }, []); // mount-only — no deps; refs are stable

  const RANGES = (window.cinFx && window.cinFx.RANGES) || RANGES_FALLBACK;
  const sceneIdx = useMemo(() => {
    for (let i = 0; i < RANGES.length; i++) {
      if (progress < RANGES[i][1]) return i;
    }
    return RANGES.length - 1;
  }, [progress]);

  const local = useMemo(() => {
    const [a, b] = RANGES[sceneIdx];
    return Math.max(0, Math.min(1, (progress - a) / (b - a)));
  }, [progress, sceneIdx]);

  const sceneOp = (i) => window.cinFx ? window.cinFx.sceneOpacity(i) : (i === sceneIdx ? 1 : 0);

  const toggleAudio = useCallback(() => {
    setAudioOn((on) => {
      const next = !on;
      if (next) { audioBus.enable(); audioBus.startAmbient(); }
      else { audioBus.fadeAmbient(0); }
      return next;
    });
  }, []);

  // Minimal label for scenes 5/6/7 (3D)
  const minimalLabel = (idx) => {
    if (idx === 4) return 'THREAT INTELLIGENCE';
    if (idx === 5) return 'FUSION ENGINE';
    if (idx === 6) return 'CONTAINMENT ACTIVE';
    return null;
  };

  return (
    <div className="scroll-track">
      {/* sticky stage */}
      <div className="stage" data-screen-label="Cinematic v2">
        <div className="grid-bg" style={{
          backgroundPosition: `${progress * 200}px ${progress * 80}px`,
          opacity: 0.6 + Math.abs(velocity) * 1.5,
        }}></div>

        {/* 2D canvas FX (scenes 1-4 + final portal) */}
        <canvas className="fx" ref={canvasRef} />
        {/* 3D WebGL stage (scenes 5-7) */}
        <canvas className="fx3d" ref={threeCanvasRef} />

        <HudChrome />

        {/* render all scenes; opacity engine cross-fades */}
        <SceneBoot     active={sceneOp(0)} local={sceneIdx===0?local:0} />
        <SceneWatch    active={sceneOp(1)} local={sceneIdx===1?local:0} velocity={velocity} />
        <SceneFusion   active={sceneOp(2)} local={sceneIdx===2?local:0} />
        <SceneResponse active={sceneOp(3)} local={sceneIdx===3?local:0} />
        {/* 3D scenes 4/5/6 have only minimal floating text overlays */}
        <Scene3DLabel  active={sceneOp(4)} text="THREAT INTELLIGENCE" />
        <Scene3DLabel  active={sceneOp(5)} text="FUSION ENGINE" />
        <Scene3DLabel  active={sceneOp(6)} text="CONTAINMENT ACTIVE" />

        {/* Top-right fixed actions */}
        <div className="top-actions">
          <button className="btn-glass" onClick={() => {
            const h = document.documentElement.scrollHeight - window.innerHeight;
            window.__lenis && window.__lenis.scrollTo(h * 0.92, { duration: 1.8 });
          }}>SKIP TO LOGIN ›</button>
        </div>

        {/* scroll hint only in scene 0 */}
        {sceneIdx === 0 && local < 0.6 && (
          <motion.div
            className="scroll-hint"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
          >
            <div>SCROLL TO ENTER</div>
            <div className="arrow"></div>
          </motion.div>
        )}

        <div className="vignette"></div>
        <div className="grain"></div>
      </div>
    </div>
  );
}

// =================================================================
// MINIMAL 3D LABEL (overlay for WebGL scenes)
// =================================================================
function Scene3DLabel({ active, text }) {
  if (active < 0.05) return null;
  return (
    <div className="scene-label" style={{ opacity: Math.min(1, active * 1.4) }}>
      <span className="scene-label-eye">▶ ACTIVE</span>
      <span className="scene-label-main">{text}</span>
      <span className="scene-label-line"></span>
    </div>
  );
}

// =================================================================
// TWEAKS PANEL
// =================================================================
function CinematicTweaks() {
  const [t, setTweak] = window.useTweaks(TWEAK_DEFAULTS);

  useEffect(() => {
    const map = {
      cyan:[0,212,255], blue:[59,130,246], violet:[168,85,247], green:[34,255,144], pink:[236,72,153]
    };
    const rgb = map[t.accent] || map.cyan;
    if (window.cinFx) window.cinFx.setAccent(rgb);
    if (window.threeStage) window.threeStage.setAccent(rgb);
    document.documentElement.style.setProperty('--cy', `rgb(${rgb.join(',')})`);
  }, [t.accent]);

  return (
    <window.TweaksPanel title="Cinematic">
      <window.TweakSection label="Accent">
        <window.TweakSelect
          label="Color signature"
          value={t.accent}
          onChange={(v) => setTweak('accent', v)}
          options={[
            { value: 'cyan', label: 'Cyan' },
            { value: 'blue', label: 'Blue' },
            { value: 'violet', label: 'Violet' },
            { value: 'green', label: 'Green' },
            { value: 'pink', label: 'Pink' },
          ]}
        />
      </window.TweakSection>
      <window.TweakSection label="Navigation">
        <window.TweakButton label="↑ Top" onClick={() => window.__lenis && window.__lenis.scrollTo(0, { duration: 1.6 })}/>
        <window.TweakButton label="⏭ Login" onClick={() => {
          const h = document.documentElement.scrollHeight - window.innerHeight;
          window.__lenis && window.__lenis.scrollTo(h * 0.86, { duration: 1.6 });
        }}/>
      </window.TweakSection>
    </window.TweaksPanel>
  );
}

// =================================================================
// MOUNT
// =================================================================
const root = ReactDOM.createRoot(document.getElementById('app'));
root.render(<App />);

window.addEventListener('load', () => {
  setTimeout(() => {
    const host = document.getElementById('tweaks-host');
    if (host && window.TweaksPanel) ReactDOM.createRoot(host).render(<CinematicTweaks />);
  }, 100);
});
