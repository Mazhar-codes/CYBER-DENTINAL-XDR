/* ============================================================
   CYBER SENTINEL XDR — Canvas FX Engine (v2)
   Vanilla canvas drawing driven by external scroll progress.
   Exposed: window.cinFx.setProgress(p), .setVelocity(v), .setAccent(),
            .setPaused(), .setIntensity(), .triggerShake(), .setCanvas()
   ============================================================ */
(function () {
  'use strict';

  const TAU = Math.PI * 2;
  const rand = (a, b) => a + Math.random() * (b - a);
  const lerp = (a, b, t) => a + (b - a) * t;
  const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
  const smoothstep = (e0, e1, x) => {
    const t = clamp((x - e0) / (e1 - e0), 0, 1);
    return t * t * (3 - 2 * t);
  };

  const state = {
    canvas: null, ctx: null, W: 0, H: 0, DPR: 1,
    p: 0,            // scroll progress 0..1
    pSmooth: 0,      // smoothed
    v: 0,            // velocity (signed)
    vAbs: 0,
    accent: [0, 212, 255],
    intensity: 1,
    paused: false,
    shake: 0,
    t: 0,
  };

  function resize() {
    if (!state.canvas) return;
    state.DPR = Math.min(window.devicePixelRatio || 1, 2);
    state.W = window.innerWidth;
    state.H = window.innerHeight;
    state.canvas.style.width = state.W + 'px';
    state.canvas.style.height = state.H + 'px';
    state.canvas.width = state.W * state.DPR;
    state.canvas.height = state.H * state.DPR;
    state.ctx.setTransform(state.DPR, 0, 0, state.DPR, 0, 0);
  }
  window.addEventListener('resize', resize);

  // ====== Stars ======
  const stars = Array.from({ length: 220 }, () => ({
    x: Math.random(), y: Math.random(),
    z: Math.random() * 0.85 + 0.15,
    base: Math.random() * 0.4 + 0.2,
  }));

  function drawStars(opacity) {
    const { ctx, W, H, v } = state;
    for (const s of stars) {
      // parallax with scroll
      const px = (s.x + state.pSmooth * (1 - s.z) * 0.6) % 1;
      const py = (s.y + state.pSmooth * (1 - s.z) * 0.1) % 1;
      const r = s.z * 1.6;
      const a = (s.base + s.z * 0.4) * opacity;
      ctx.fillStyle = `rgba(150,210,255,${a})`;
      ctx.fillRect(px * W, py * H, r, r);
      // streaks under fast scroll
      if (state.vAbs > 0.4) {
        const len = Math.min(40, state.vAbs * 80) * (1 - s.z);
        ctx.strokeStyle = `rgba(150,210,255,${a * 0.4})`;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(px * W, py * H);
        ctx.lineTo(px * W + Math.sign(v) * len, py * H);
        ctx.stroke();
      }
    }
  }

  // ====== Globe (Scene 1) ======
  const globePts = [];
  for (let i = 0; i < 320; i++) {
    const phi = Math.acos(1 - 2 * Math.random());
    const theta = TAU * Math.random();
    globePts.push({
      x: Math.sin(phi) * Math.cos(theta),
      y: Math.sin(phi) * Math.sin(theta),
      z: Math.cos(phi),
      pulse: Math.random(),
    });
  }
  const globeArcs = [];
  function newGlobeArc() {
    const a = (Math.random() * globePts.length) | 0;
    let b = (Math.random() * globePts.length) | 0;
    if (b === a) b = (b + 1) % globePts.length;
    globeArcs.push({ a, b, t: 0, life: rand(1.4, 2.6) });
  }
  for (let i = 0; i < 8; i++) newGlobeArc();

  function drawGlobe(cx, cy, R, opacity, gestureRot) {
    const { ctx } = state;
    // gestureRot is added to base rotation
    const t = state.t * 0.18 + gestureRot;
    const tilt = 0.32;
    const cT = Math.cos(tilt), sT = Math.sin(tilt);

    const proj = (p) => {
      const x = Math.cos(t) * p.x + Math.sin(t) * p.z;
      const z1 = -Math.sin(t) * p.x + Math.cos(t) * p.z;
      const y = cT * p.y - sT * z1;
      const z = sT * p.y + cT * z1;
      return { x, y, z, pulse: p.pulse };
    };

    const ac = state.accent;
    const accent = (a) => `rgba(${ac[0]},${ac[1]},${ac[2]},${a})`;

    // outer rings
    for (let i = 0; i < 3; i++) {
      ctx.strokeStyle = accent(0.18 * opacity * (1 - i * 0.3));
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.arc(cx, cy, R * (1 + i * -0.22), 0, TAU);
      ctx.stroke();
    }

    // wireframe (lat/long)
    ctx.strokeStyle = accent(0.16 * opacity);
    for (let lat = -60; lat <= 60; lat += 20) {
      const phi = (lat * Math.PI) / 180;
      ctx.beginPath();
      let started = false;
      for (let lon = 0; lon <= 360; lon += 4) {
        const th = (lon * Math.PI) / 180;
        const px = Math.cos(phi) * Math.cos(th + t);
        const pz = Math.cos(phi) * Math.sin(th + t);
        const py = Math.sin(phi);
        const yy = cT * py - sT * pz;
        const zz = sT * py + cT * pz;
        if (zz < -0.05) { started = false; continue; }
        if (!started) { ctx.moveTo(cx + px * R, cy + yy * R); started = true; }
        else ctx.lineTo(cx + px * R, cy + yy * R);
      }
      ctx.stroke();
    }
    for (let lon = 0; lon < 360; lon += 24) {
      ctx.beginPath();
      let started = false;
      for (let lat = -90; lat <= 90; lat += 4) {
        const phi = (lat * Math.PI) / 180;
        const th = (lon * Math.PI) / 180;
        const px = Math.cos(phi) * Math.cos(th + t);
        const pz = Math.cos(phi) * Math.sin(th + t);
        const py = Math.sin(phi);
        const yy = cT * py - sT * pz;
        const zz = sT * py + cT * pz;
        if (zz < -0.05) { started = false; continue; }
        if (!started) { ctx.moveTo(cx + px * R, cy + yy * R); started = true; }
        else ctx.lineTo(cx + px * R, cy + yy * R);
      }
      ctx.stroke();
    }

    // points
    const projected = globePts.map(proj);
    for (const p of projected) {
      if (p.z < -0.2) continue;
      const x = cx + p.x * R, y = cy + p.y * R;
      const a = (p.z + 1) / 2;
      const pulse = 0.6 + 0.4 * Math.sin(state.t * 2 + p.pulse * 10);
      ctx.fillStyle = accent(a * 0.95 * opacity * pulse);
      ctx.beginPath();
      ctx.arc(x, y, 1.4 + a * 1.2, 0, TAU);
      ctx.fill();
    }

    // arcs
    for (let i = globeArcs.length - 1; i >= 0; i--) {
      const a = globeArcs[i];
      a.t += 0.016 * (1 + state.vAbs * 1.5);
      if (a.t >= a.life) { globeArcs.splice(i, 1); continue; }
      const p1 = projected[a.a], p2 = projected[a.b];
      if (p1.z < -0.2 && p2.z < -0.2) continue;
      const k = a.t / a.life;
      const x1 = cx + p1.x * R, y1 = cy + p1.y * R;
      const x2 = cx + p2.x * R, y2 = cy + p2.y * R;
      const mx = (x1 + x2) / 2 + (y2 - y1) * 0.14;
      const my = (y1 + y2) / 2 - (x2 - x1) * 0.14;
      ctx.strokeStyle = accent((1 - Math.abs(k - 0.5) * 2) * 0.7 * opacity);
      ctx.lineWidth = 1.2;
      ctx.beginPath();
      ctx.moveTo(x1, y1);
      ctx.quadraticCurveTo(mx, my, x2, y2);
      ctx.stroke();
      const t1 = clamp(k + 0.04, 0, 1);
      const hx = (1 - t1) * (1 - t1) * x1 + 2 * (1 - t1) * t1 * mx + t1 * t1 * x2;
      const hy = (1 - t1) * (1 - t1) * y1 + 2 * (1 - t1) * t1 * my + t1 * t1 * y2;
      ctx.fillStyle = accent(opacity);
      ctx.shadowBlur = 14;
      ctx.shadowColor = accent(0.9 * opacity);
      ctx.beginPath();
      ctx.arc(hx, hy, 2.8, 0, TAU);
      ctx.fill();
      ctx.shadowBlur = 0;
    }
    if (Math.random() < 0.04) newGlobeArc();
  }

  // ====== Endpoint network (Scene 2 + Scene 4) ======
  const endpoints = [];
  const links = [];
  function buildNetwork() {
    endpoints.length = 0; links.length = 0;
    for (let i = 0; i < 44; i++) {
      endpoints.push({
        id: i,
        x: rand(0.08, 0.92),
        y: rand(0.16, 0.84),
        r: rand(3, 5.6),
        state: 'ok',
        flash: 0,
        pulse: Math.random() * TAU,
      });
    }
    for (let i = 0; i < endpoints.length; i++) {
      const a = endpoints[i];
      const ds = endpoints
        .map((b, j) => ({ j, d: (a.x - b.x) ** 2 + (a.y - b.y) ** 2 }))
        .filter((o) => o.j !== i)
        .sort((p, q) => p.d - q.d);
      for (let k = 0; k < 3; k++) links.push({ a: i, b: ds[k].j, alive: 1 });
    }
  }
  buildNetwork();

  const packets = [];
  function spawnPacket(linkIdx, kind = 'normal') {
    if (linkIdx < 0 || linkIdx >= links.length) return;
    packets.push({ link: linkIdx, t: 0, speed: rand(0.6, 1.2), kind });
  }

  function setNetworkPhase(phase, trigger) {
    if (phase === 'reset') {
      endpoints.forEach((e) => (e.state = 'ok'));
      return;
    }
    if (phase === 'attack-start' && trigger) {
      const tgt = endpoints[(Math.random() * endpoints.length) | 0];
      tgt.state = 'infected';
      tgt.flash = 1;
      // spread on its links
      const neigh = links.filter((l) => l.a === tgt.id || l.b === tgt.id);
      neigh.forEach((l, i) => setTimeout(() => spawnPacket(links.indexOf(l), 'attack'), i * 120));
      window.__lastTarget = tgt.id;
    }
    if (phase === 'isolate' && trigger) {
      const id = window.__lastTarget;
      if (id != null) {
        endpoints[id].state = 'isolated';
      }
    }
    if (phase === 'secure') {
      endpoints.forEach((e) => { if (e.state !== 'isolated') e.state = 'secure'; });
    }
  }
  window.cinFx_phase = setNetworkPhase;

  function drawNetwork(opacity, mode) {
    const { ctx, W, H } = state;
    const ax = (e) => e.x * W;
    const ay = (e) => e.y * H;

    const ac = state.accent;
    const accentRGB = `${ac[0]},${ac[1]},${ac[2]}`;

    for (let i = 0; i < links.length; i++) {
      const l = links[i];
      const a = endpoints[l.a], b = endpoints[l.b];
      const isHot = a.state === 'infected' || b.state === 'infected';
      ctx.strokeStyle = isHot
        ? `rgba(255,40,80,${0.55 * opacity})`
        : `rgba(${accentRGB},${0.18 * opacity})`;
      ctx.lineWidth = isHot ? 1.4 : 0.8;
      ctx.beginPath();
      ctx.moveTo(ax(a), ay(a));
      ctx.lineTo(ax(b), ay(b));
      ctx.stroke();
    }

    // ambient packets driven by scroll velocity
    if (Math.random() < 0.15 + state.vAbs * 0.6) {
      spawnPacket((Math.random() * links.length) | 0, mode === 'attack' ? 'attack' : 'normal');
    }

    for (let i = packets.length - 1; i >= 0; i--) {
      const p = packets[i];
      p.t += 0.014 * p.speed * (1 + state.vAbs * 2);
      if (p.t >= 1) { packets.splice(i, 1); continue; }
      const l = links[p.link];
      if (!l) { packets.splice(i, 1); continue; }
      const a = endpoints[l.a], b = endpoints[l.b];
      const x = lerp(ax(a), ax(b), p.t);
      const y = lerp(ay(a), ay(b), p.t);
      const isAttack = p.kind === 'attack';
      const c = isAttack
        ? '255,40,80'
        : mode === 'resolved'
        ? '34,255,140'
        : accentRGB;
      ctx.shadowBlur = 10;
      ctx.shadowColor = `rgba(${c},0.9)`;
      ctx.fillStyle = `rgba(${c},${opacity})`;
      ctx.beginPath();
      ctx.arc(x, y, isAttack ? 3 : 2, 0, TAU);
      ctx.fill();
      ctx.shadowBlur = 0;
    }

    for (const e of endpoints) {
      e.pulse += 0.03;
      const x = ax(e), y = ay(e);
      let core, ring, R = e.r;
      if (e.state === 'infected') { core = '255,40,80'; ring = '255,40,80'; R *= 1.4; }
      else if (e.state === 'isolated') { core = '255,180,0'; ring = '255,180,0'; }
      else if (e.state === 'secure') { core = '34,255,140'; ring = '34,255,140'; }
      else { core = accentRGB; ring = accentRGB; }
      const pulse = 0.6 + 0.4 * Math.sin(e.pulse + e.id);
      ctx.fillStyle = `rgba(${ring},${0.18 * opacity * pulse})`;
      ctx.beginPath(); ctx.arc(x, y, R * 3.6, 0, TAU); ctx.fill();
      ctx.strokeStyle = `rgba(${ring},${0.7 * opacity})`;
      ctx.lineWidth = 1.4;
      ctx.beginPath(); ctx.arc(x, y, R * 1.8, 0, TAU); ctx.stroke();
      ctx.fillStyle = `rgba(${core},${opacity})`;
      ctx.shadowBlur = 14; ctx.shadowColor = `rgba(${core},${0.9 * opacity})`;
      ctx.beginPath(); ctx.arc(x, y, R, 0, TAU); ctx.fill();
      ctx.shadowBlur = 0;
      if (e.state === 'isolated') {
        ctx.strokeStyle = `rgba(255,200,80,${0.9 * opacity})`;
        ctx.lineWidth = 1.2;
        ctx.setLineDash([4, 4]);
        ctx.beginPath(); ctx.arc(x, y, R * 4, 0, TAU); ctx.stroke();
        ctx.setLineDash([]);
      }
      e.flash *= 0.92;
    }
  }

  // ====== Fusion (Scene 3) ======
  const fusionStreams = [
    { angle: Math.PI * 1.18, hue: '0,212,255' },
    { angle: Math.PI * 1.82, hue: '139,92,246' },
    { angle: Math.PI * 0.18, hue: '255,180,0' },
    { angle: Math.PI * 0.82, hue: '168,85,247' },
  ];
  const fusionParticles = [];
  const shapBurst = [];

  function drawFusion(opacity, gestureBend) {
    const { ctx, W, H } = state;
    const cx = W / 2, cy = H / 2;
    const R = Math.min(W, H) * 0.32;

    // streams
    for (const s of fusionStreams) {
      const sx = cx + Math.cos(s.angle) * R * 1.7;
      const sy = cy + Math.sin(s.angle) * R * 1.7;
      ctx.strokeStyle = `rgba(${s.hue},${0.18 * opacity})`;
      ctx.lineWidth = 1.2;
      ctx.beginPath();
      ctx.moveTo(sx, sy);
      // bend by gesture
      const mx = (sx + cx) / 2 + Math.cos(s.angle + Math.PI / 2) * 80 * gestureBend;
      const my = (sy + cy) / 2 + Math.sin(s.angle + Math.PI / 2) * 80 * gestureBend;
      ctx.quadraticCurveTo(mx, my, cx, cy);
      ctx.stroke();
      if (Math.random() < 0.5 * (1 + state.vAbs * 2)) {
        fusionParticles.push({ s, t: 0, j: rand(-0.4, 0.4), v: rand(0.7, 1.4) });
      }
    }

    for (let i = fusionParticles.length - 1; i >= 0; i--) {
      const p = fusionParticles[i];
      p.t += 0.018 * p.v * (1 + state.vAbs * 1.5);
      if (p.t >= 1) { fusionParticles.splice(i, 1); continue; }
      const sx = cx + Math.cos(p.s.angle) * R * 1.7;
      const sy = cy + Math.sin(p.s.angle) * R * 1.7;
      const mx = (sx + cx) / 2 + Math.cos(p.s.angle + Math.PI / 2) * 80 * gestureBend;
      const my = (sy + cy) / 2 + Math.sin(p.s.angle + Math.PI / 2) * 80 * gestureBend;
      const t = p.t;
      const px = (1-t)*(1-t)*sx + 2*(1-t)*t*mx + t*t*cx;
      const py = (1-t)*(1-t)*sy + 2*(1-t)*t*my + t*t*cy;
      ctx.fillStyle = `rgba(${p.s.hue},${(1 - p.t) * opacity})`;
      ctx.shadowBlur = 8; ctx.shadowColor = `rgba(${p.s.hue},${0.8 * opacity})`;
      ctx.beginPath();
      ctx.arc(px, py, 1.8, 0, TAU);
      ctx.fill();
      ctx.shadowBlur = 0;
    }

    // rotating rings
    const ac = state.accent;
    const accent = (a) => `rgba(${ac[0]},${ac[1]},${ac[2]},${a})`;
    for (let i = 0; i < 3; i++) {
      const r = R * (0.55 + i * 0.18);
      const dash = i % 2 === 0 ? [10, 8] : [3, 6];
      const speed = (i % 2 === 0 ? 1 : -1) * (0.3 + i * 0.15);
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(state.t * speed + gestureBend * 0.3);
      ctx.setLineDash(dash);
      ctx.strokeStyle = accent(0.45 * opacity);
      ctx.lineWidth = 1.4;
      ctx.beginPath();
      ctx.arc(0, 0, r, 0, TAU);
      ctx.stroke();
      ctx.setLineDash([]);
      for (let j = 0; j < 24; j++) {
        const a = (j / 24) * TAU;
        ctx.strokeStyle = accent(0.55 * opacity);
        ctx.beginPath();
        ctx.moveTo(Math.cos(a) * r, Math.sin(a) * r);
        ctx.lineTo(Math.cos(a) * (r + 6), Math.sin(a) * (r + 6));
        ctx.stroke();
      }
      ctx.restore();
    }

    // core
    const corePulse = 1 + 0.18 * Math.sin(state.t * 4) + state.vAbs * 0.4;
    const grad = ctx.createRadialGradient(cx, cy, 2, cx, cy, R * 0.5 * corePulse);
    grad.addColorStop(0, accent(0.95 * opacity));
    grad.addColorStop(0.4, accent(0.5 * opacity));
    grad.addColorStop(1, accent(0));
    ctx.fillStyle = grad;
    ctx.beginPath();
    ctx.arc(cx, cy, R * 0.5 * corePulse, 0, TAU);
    ctx.fill();

    // hex
    ctx.strokeStyle = `rgba(255,255,255,${opacity})`;
    ctx.lineWidth = 1.6;
    ctx.beginPath();
    for (let i = 0; i < 6; i++) {
      const a = (i / 6) * TAU + state.t * 0.4;
      const x = cx + Math.cos(a) * R * 0.18;
      const y = cy + Math.sin(a) * R * 0.18;
      if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    }
    ctx.closePath();
    ctx.stroke();

    if (Math.random() < 0.3 * opacity) {
      shapBurst.push({
        a: Math.random() * TAU,
        r: R * 0.2,
        v: rand(80, 180),
        life: 1,
        hue: ['0,212,255', '139,92,246', '34,255,140', '255,180,0'][(Math.random() * 4) | 0],
      });
    }
    for (let i = shapBurst.length - 1; i >= 0; i--) {
      const b = shapBurst[i];
      b.r += b.v * 0.016;
      b.life -= 0.012;
      if (b.life <= 0) { shapBurst.splice(i, 1); continue; }
      ctx.fillStyle = `rgba(${b.hue},${b.life * opacity})`;
      ctx.beginPath();
      ctx.arc(cx + Math.cos(b.a) * b.r, cy + Math.sin(b.a) * b.r, 2, 0, TAU);
      ctx.fill();
    }
  }

  // ====== Login portal collapse ======
  const portalParticles = [];
  function spawnPortalParticles() {
    for (let i = 0; i < 80; i++) {
      portalParticles.push({
        x: Math.random() * state.W,
        y: Math.random() * state.H,
        ox: state.W / 2 + rand(-180, 180),
        oy: state.H / 2 + rand(-100, 100),
        a: 1,
      });
    }
  }
  function drawPortal(opacity, collapseT) {
    if (!portalParticles.length && opacity > 0.05) spawnPortalParticles();
    const { ctx } = state;
    const ac = state.accent;
    for (const p of portalParticles) {
      const t = clamp(collapseT, 0, 1);
      const x = lerp(p.x, p.ox, t);
      const y = lerp(p.y, p.oy, t);
      ctx.fillStyle = `rgba(${ac[0]},${ac[1]},${ac[2]},${(1 - t * 0.7) * opacity})`;
      ctx.shadowBlur = 8; ctx.shadowColor = `rgba(${ac[0]},${ac[1]},${ac[2]},${opacity})`;
      ctx.beginPath();
      ctx.arc(x, y, 1.6 + (1 - t) * 1.5, 0, TAU);
      ctx.fill();
      ctx.shadowBlur = 0;
    }
  }

  // ====== Ambient dust ======
  const dust = [];
  function ambientStep(opacity) {
    if (Math.random() < 0.5) {
      dust.push({ x: Math.random() * state.W, y: Math.random() * state.H, r: rand(0.5, 2), life: 1, vy: rand(-12, -32), vx: rand(-6, 6) });
    }
    const ac = state.accent;
    for (let i = dust.length - 1; i >= 0; i--) {
      const p = dust[i];
      p.x += p.vx * 0.016;
      p.y += p.vy * 0.016;
      p.life -= 0.006;
      if (p.life <= 0) { dust.splice(i, 1); continue; }
      state.ctx.fillStyle = `rgba(${ac[0]},${ac[1]},${ac[2]},${p.life * 0.5 * opacity})`;
      state.ctx.beginPath();
      state.ctx.arc(p.x, p.y, p.r, 0, TAU);
      state.ctx.fill();
    }
  }

  // ====== Scene blending — 8 scenes total ======
  //  0  0.00–0.12  Boot / title
  //  1  0.12–0.24  Cyberspace watch (2D network)
  //  2  0.24–0.38  AI fusion (2D)
  //  3  0.38–0.50  Live threat response (2D network attack/resolved)
  //  4  0.50–0.65  GLOBAL THREAT MATRIX  (3D — three-stage.js owns it)
  //  5  0.65–0.78  AI CORRELATION CORE   (3D)
  //  6  0.78–0.90  AUTONOMOUS RESPONSE   (3D)
  //  7  0.90–1.00  Secure access portal (collapse + login)
  const RANGES = [
    [0.00, 0.12],
    [0.12, 0.24],
    [0.24, 0.38],
    [0.38, 0.50],
    [0.50, 0.65],
    [0.65, 0.78],
    [0.78, 0.90],
    [0.90, 1.00],
  ];
  function sceneOpacity(i) {
    const [a, b] = RANGES[i];
    const fade = 0.04;
    return clamp(
      smoothstep(a - fade, a + fade, state.pSmooth) -
      smoothstep(b - fade, b + fade, state.pSmooth),
      0, 1
    );
  }

  // ====== Main loop ======
  let last = performance.now();
  function frame(now) {
    const dt = Math.min(40, now - last) / 1000;
    last = now;
    if (!state.paused) state.t += dt;
    // smooth scroll target
    state.pSmooth += (state.p - state.pSmooth) * Math.min(1, dt * 8);
    state.shake = Math.max(0, state.shake - dt * 30);

    if (!state.canvas) { requestAnimationFrame(frame); return; }
    const { ctx, W, H } = state;
    ctx.clearRect(0, 0, W, H);

    // shake
    if (state.shake > 0) {
      ctx.save();
      ctx.translate(rand(-state.shake, state.shake), rand(-state.shake, state.shake));
    }

    // backdrop stars always
    drawStars(0.7);
    ambientStep(0.5);

    // Scene 1 — globe
    const o1 = sceneOpacity(0);
    if (o1 > 0.02) {
      const cx = W / 2, cy = H * 0.55 + smoothstep(0, 0.18, state.pSmooth) * 60;
      const R = Math.min(W, H) * 0.28 * (1 + state.pSmooth * 0.8);
      drawGlobe(cx, cy, R, o1, state.pSmooth * TAU * 0.8);
    }

    // Scene 2 — network
    const o2 = sceneOpacity(1);
    if (o2 > 0.02) {
      drawNetwork(o2, 'watch');
    }

    // Scene 3 — fusion
    const o3 = sceneOpacity(2);
    if (o3 > 0.02) {
      const bend = (state.v) * 0.6;
      drawFusion(o3, bend);
    }

    // Scene 4 — attack
    const o4 = sceneOpacity(3);
    if (o4 > 0.02) {
      // phase by sub-progress in scene 4
      const local = (state.pSmooth - RANGES[3][0]) / (RANGES[3][1] - RANGES[3][0]);
      let mode = 'watch';
      if (local > 0.15 && local < 0.6) mode = 'attack';
      else if (local >= 0.6) mode = 'resolved';
      drawNetwork(o4, mode);
    }

    // Scenes 5,6,7 (RANGES indices 4,5,6) are owned by three-stage.js (WebGL).
    // We skip 2D drawing for those — only ambient stars + grid render.

    // Scene 8 — collapse to login portal (index 7)
    const o5 = sceneOpacity(7);
    if (o5 > 0.02) {
      const local = (state.pSmooth - RANGES[7][0]) / (RANGES[7][1] - RANGES[7][0]);
      drawPortal(o5, local);
    } else {
      portalParticles.length = 0;
    }

    if (state.shake > 0) ctx.restore();

    requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);

  // ====== Public API ======
  window.cinFx = {
    setCanvas(c) { state.canvas = c; state.ctx = c.getContext('2d'); resize(); },
    setProgress(p) { state.p = clamp(p, 0, 1); },
    setVelocity(v) { state.v = v; state.vAbs = Math.min(1, Math.abs(v)); },
    setAccent(rgb) { state.accent = rgb; },
    setPaused(b) { state.paused = b; },
    setIntensity(k) { state.intensity = k; },
    triggerShake(amt) { state.shake = Math.max(state.shake, amt); },
    rebuild() { buildNetwork(); },
    sceneOpacity,
    RANGES,
  };
})();
