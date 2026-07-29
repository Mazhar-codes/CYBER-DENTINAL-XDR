/* ============================================================
   CYBER SENTINEL XDR — CINEMATIC ENGINE
   Canvas-driven scenes + scene controller + audio
   ============================================================ */

(function () {
  'use strict';

  // ===== Canvas + DPR =====
  const canvas = document.getElementById('fx');
  const ctx = canvas.getContext('2d');
  let W = 0, H = 0, DPR = Math.min(window.devicePixelRatio || 1, 2);

  function resize() {
    DPR = Math.min(window.devicePixelRatio || 1, 2);
    W = window.innerWidth;
    H = window.innerHeight;
    canvas.style.width = W + 'px';
    canvas.style.height = H + 'px';
    canvas.width = W * DPR;
    canvas.height = H * DPR;
    ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
  }
  window.addEventListener('resize', resize);
  resize();

  // ===== Globals =====
  const TAU = Math.PI * 2;
  const rand = (a, b) => a + Math.random() * (b - a);
  const lerp = (a, b, t) => a + (b - a) * t;
  const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
  const easeInOut = t => t < 0.5 ? 2*t*t : 1 - Math.pow(-2*t+2, 2)/2;
  const easeOut = t => 1 - Math.pow(1 - t, 3);

  // ===== State =====
  const state = {
    scene: 0,        // 0..4
    sceneT: 0,       // seconds in current scene
    globalT: 0,
    paused: false,
    loginActive: false,
    skipped: false,
    // tweaks
    accent: 'cyan',  // cyan | blue | violet | green
    intensity: 1,
    speed: 1,
    showTerminal: true,
    audio: false,
  };

  // accent map
  function accentColor() {
    switch (state.accent) {
      case 'blue':   return [59,130,246];
      case 'violet': return [139,92,246];
      case 'green':  return [0,255,160];
      case 'cyan':
      default:       return [0,212,255];
    }
  }
  function accentCss(a=1) { const [r,g,b]=accentColor(); return `rgba(${r},${g},${b},${a})`; }

  // ===== Particle field (persistent backdrop) =====
  const stars = [];
  for (let i=0; i<160; i++) {
    stars.push({
      x: Math.random(), y: Math.random(),
      z: Math.random()*0.8 + 0.2,
      v: Math.random()*0.04 + 0.01
    });
  }
  function drawStars(dt) {
    ctx.save();
    for (const s of stars) {
      s.x += s.v * 0.001 * state.speed;
      if (s.x > 1) s.x = 0;
      const r = s.z * 1.4;
      const a = 0.15 + s.z * 0.5;
      ctx.fillStyle = `rgba(140,200,255,${a})`;
      ctx.fillRect(s.x*W, s.y*H, r, r);
    }
    ctx.restore();
  }

  // ===== Globe (rotating wireframe sphere with meshed connections) =====
  const globePoints = [];
  for (let i=0; i<260; i++) {
    const phi = Math.acos(1 - 2*Math.random());
    const theta = TAU * Math.random();
    globePoints.push({
      x: Math.sin(phi)*Math.cos(theta),
      y: Math.sin(phi)*Math.sin(theta),
      z: Math.cos(phi),
      pulse: Math.random(),
    });
  }
  const globeArcs = [];
  function newGlobeArc() {
    const a = Math.floor(Math.random()*globePoints.length);
    let b = Math.floor(Math.random()*globePoints.length);
    if (b===a) b = (b+1)%globePoints.length;
    globeArcs.push({a, b, t: 0, life: rand(1.2, 2.4)});
  }
  for (let i=0;i<6;i++) newGlobeArc();

  function drawGlobe(cx, cy, R, opacity) {
    const t = state.globalT * 0.18 * state.speed;
    const cosA = Math.cos(0.32), sinA = Math.sin(0.32);
    const pts = globePoints.map(p => {
      // rotate y axis
      const x = Math.cos(t)*p.x + Math.sin(t)*p.z;
      const z1 = -Math.sin(t)*p.x + Math.cos(t)*p.z;
      // tilt x axis
      const y = cosA*p.y - sinA*z1;
      const z = sinA*p.y + cosA*z1;
      return { x, y, z, pulse: p.pulse };
    });

    // outer ring
    ctx.strokeStyle = accentCss(0.18 * opacity);
    ctx.lineWidth = 1;
    ctx.beginPath(); ctx.arc(cx, cy, R, 0, TAU); ctx.stroke();
    ctx.strokeStyle = accentCss(0.10 * opacity);
    ctx.beginPath(); ctx.arc(cx, cy, R*0.78, 0, TAU); ctx.stroke();
    ctx.beginPath(); ctx.arc(cx, cy, R*0.55, 0, TAU); ctx.stroke();

    // latitude/longitude wireframe
    ctx.strokeStyle = accentCss(0.18 * opacity);
    for (let lat=-60; lat<=60; lat+=20) {
      const phi = (lat) * Math.PI / 180;
      ctx.beginPath();
      for (let lon=0; lon<=360; lon+=4) {
        const th = lon * Math.PI/180;
        const px = Math.cos(phi)*Math.cos(th + t);
        const pz = Math.cos(phi)*Math.sin(th + t);
        const py = Math.sin(phi);
        const yy = cosA*py - sinA*pz;
        const zz = sinA*py + cosA*pz;
        if (zz < -0.05) { ctx.moveTo(cx+px*R, cy+yy*R); continue; }
        if (lon===0) ctx.moveTo(cx+px*R, cy+yy*R);
        else ctx.lineTo(cx+px*R, cy+yy*R);
      }
      ctx.stroke();
    }
    for (let lon=0; lon<360; lon+=20) {
      ctx.beginPath();
      for (let lat=-90; lat<=90; lat+=4) {
        const phi = lat*Math.PI/180;
        const th = lon*Math.PI/180;
        const px = Math.cos(phi)*Math.cos(th+t);
        const pz = Math.cos(phi)*Math.sin(th+t);
        const py = Math.sin(phi);
        const yy = cosA*py - sinA*pz;
        const zz = sinA*py + cosA*pz;
        if (zz < -0.05) { ctx.moveTo(cx+px*R, cy+yy*R); continue; }
        if (lat===-90) ctx.moveTo(cx+px*R, cy+yy*R);
        else ctx.lineTo(cx+px*R, cy+yy*R);
      }
      ctx.stroke();
    }

    // points & meshed lines
    for (let i=0; i<pts.length; i++) {
      const p = pts[i];
      if (p.z < -0.2) continue;
      const x = cx + p.x*R, y = cy + p.y*R;
      const a = (p.z + 1) / 2;
      const pulse = 0.6 + 0.4 * Math.sin(state.globalT*2 + p.pulse*10);
      ctx.fillStyle = accentCss(a * 0.9 * opacity * pulse);
      ctx.beginPath(); ctx.arc(x, y, 1.4 + a*1.2, 0, TAU); ctx.fill();
    }

    // arc lines (network paths)
    for (let i=globeArcs.length-1; i>=0; i--) {
      const a = globeArcs[i];
      a.t += 0.016 * state.speed;
      if (a.t >= a.life) { globeArcs.splice(i,1); continue; }
      const p1 = pts[a.a], p2 = pts[a.b];
      if (p1.z<-0.2 && p2.z<-0.2) continue;
      const k = a.t / a.life;
      const x1 = cx+p1.x*R, y1 = cy+p1.y*R;
      const x2 = cx+p2.x*R, y2 = cy+p2.y*R;
      const mx = (x1+x2)/2 + (y2-y1)*0.12;
      const my = (y1+y2)/2 - (x2-x1)*0.12;
      ctx.strokeStyle = accentCss((1-Math.abs(k-0.5)*2) * 0.7 * opacity);
      ctx.lineWidth = 1.2;
      ctx.beginPath();
      ctx.moveTo(x1, y1);
      ctx.quadraticCurveTo(mx, my, x2, y2);
      ctx.stroke();
      // moving head
      const t1 = clamp(k+0.05,0,1);
      const hx = (1-t1)*(1-t1)*x1 + 2*(1-t1)*t1*mx + t1*t1*x2;
      const hy = (1-t1)*(1-t1)*y1 + 2*(1-t1)*t1*my + t1*t1*y2;
      ctx.fillStyle = accentCss(opacity);
      ctx.shadowBlur = 12; ctx.shadowColor = accentCss(0.9*opacity);
      ctx.beginPath(); ctx.arc(hx, hy, 2.6, 0, TAU); ctx.fill();
      ctx.shadowBlur = 0;
    }
    if (Math.random() < 0.03) newGlobeArc();
  }

  // ===== Endpoint network (Scene 2 + Scene 4) =====
  const endpoints = [];
  const links = [];
  function buildNetwork() {
    endpoints.length = 0; links.length = 0;
    const N = 38;
    for (let i=0; i<N; i++) {
      endpoints.push({
        id: i,
        x: rand(0.12, 0.88),
        y: rand(0.18, 0.82),
        r: rand(3, 6),
        state: 'ok', // ok | scanning | infected | isolated | secure
        flash: 0,
        pulse: Math.random(),
      });
    }
    // spatial nearest-neighbor links
    for (let i=0; i<endpoints.length; i++) {
      const a = endpoints[i];
      const ds = endpoints.map((b, j) => ({j, d: (a.x-b.x)**2+(a.y-b.y)**2})).filter(o=>o.j!==i).sort((p,q)=>p.d-q.d);
      for (let k=0; k<3; k++) links.push({a:i, b:ds[k].j, alive: 1, attack: 0});
    }
  }
  buildNetwork();

  const attackPackets = []; // moving dots along links
  function spawnPacket(linkIdx, kind='normal') {
    attackPackets.push({ link: linkIdx, t: 0, speed: rand(0.6, 1.2), kind });
  }

  function drawNetwork(opacity, mode='watch') {
    // mode: watch (calm) | attack | resolved
    const ax = (e) => e.x*W;
    const ay = (e) => e.y*H;
    // links
    for (let i=0; i<links.length; i++) {
      const l = links[i];
      const a = endpoints[l.a], b = endpoints[l.b];
      const x1 = ax(a), y1 = ay(a), x2 = ax(b), y2 = ay(b);
      const isHot = a.state==='infected' || b.state==='infected' || l.attack>0;
      ctx.strokeStyle = isHot
        ? `rgba(255,40,80,${0.55*opacity})`
        : accentCss(0.18*opacity);
      ctx.lineWidth = isHot ? 1.4 : 0.8;
      ctx.beginPath(); ctx.moveTo(x1,y1); ctx.lineTo(x2,y2); ctx.stroke();
    }
    // packets
    for (let i=attackPackets.length-1; i>=0; i--) {
      const p = attackPackets[i];
      p.t += 0.012 * p.speed * state.speed;
      if (p.t >= 1) { attackPackets.splice(i,1); continue; }
      const l = links[p.link];
      if (!l) { attackPackets.splice(i,1); continue; }
      const a = endpoints[l.a], b = endpoints[l.b];
      const x = lerp(ax(a), ax(b), p.t);
      const y = lerp(ay(a), ay(b), p.t);
      const isAttack = p.kind === 'attack';
      const c = isAttack ? '255,40,80' : (mode==='resolved' ? '34,255,140' : accentColor().join(','));
      ctx.shadowBlur = 10; ctx.shadowColor = `rgba(${c},0.9)`;
      ctx.fillStyle = `rgba(${c},${opacity})`;
      ctx.beginPath(); ctx.arc(x, y, isAttack?3:2, 0, TAU); ctx.fill();
      ctx.shadowBlur = 0;
    }

    // endpoints
    for (const e of endpoints) {
      e.pulse += 0.02 * state.speed;
      const x = ax(e), y = ay(e);
      let core, ring, R = e.r;
      if (e.state === 'infected') { core = '255,40,80'; ring = '255,40,80'; R = e.r * 1.4; }
      else if (e.state === 'isolated') { core = '255,180,0'; ring = '255,180,0'; }
      else if (e.state === 'secure') { core = '34,255,140'; ring = '34,255,140'; }
      else { const [r,g,b]=accentColor(); core = `${r},${g},${b}`; ring = core; }
      const pulse = 0.6 + 0.4*Math.sin(e.pulse + e.id);
      // halo
      ctx.fillStyle = `rgba(${ring},${0.18*opacity*pulse})`;
      ctx.beginPath(); ctx.arc(x,y,R*3.6,0,TAU); ctx.fill();
      // ring
      ctx.strokeStyle = `rgba(${ring},${0.7*opacity})`;
      ctx.lineWidth = 1.4;
      ctx.beginPath(); ctx.arc(x,y,R*1.8,0,TAU); ctx.stroke();
      // core
      ctx.fillStyle = `rgba(${core},${opacity})`;
      ctx.shadowBlur = 14; ctx.shadowColor = `rgba(${core},${0.9*opacity})`;
      ctx.beginPath(); ctx.arc(x,y,R,0,TAU); ctx.fill();
      ctx.shadowBlur = 0;

      if (e.state === 'isolated') {
        // shield ring
        ctx.strokeStyle = `rgba(255,200,80,${0.9*opacity})`;
        ctx.lineWidth = 1.2;
        ctx.setLineDash([4,4]);
        ctx.beginPath(); ctx.arc(x,y,R*4,0,TAU); ctx.stroke();
        ctx.setLineDash([]);
      }
      e.flash *= 0.92;
    }
  }

  // ===== Fusion engine (Scene 3) =====
  const fusionStreams = [
    { angle: Math.PI*1.2, hue: '0,212,255', name:'NETWORK' },
    { angle: Math.PI*1.8, hue: '139,92,246', name:'USER BEHAVIOR' },
    { angle: Math.PI*0.2, hue: '255,180,0',  name:'SYSTEM' },
    { angle: Math.PI*0.8, hue: '124,58,237', name:'MALWARE' },
  ];
  const fusionParticles = [];
  function spawnFusionParticle(stream) {
    fusionParticles.push({
      stream, t: 0, jitter: rand(-0.4, 0.4), v: rand(0.7, 1.4),
    });
  }

  function drawFusion(opacity) {
    const cx = W/2, cy = H/2;
    const R = Math.min(W,H)*0.32;
    // streams
    for (const s of fusionStreams) {
      const sx = cx + Math.cos(s.angle)*R*1.6;
      const sy = cy + Math.sin(s.angle)*R*1.6;
      ctx.strokeStyle = `rgba(${s.hue},${0.18*opacity})`;
      ctx.lineWidth = 1.2;
      ctx.beginPath(); ctx.moveTo(sx,sy); ctx.lineTo(cx,cy); ctx.stroke();
      if (Math.random() < 0.45) spawnFusionParticle(s);
    }

    // moving particles
    for (let i=fusionParticles.length-1; i>=0; i--) {
      const p = fusionParticles[i];
      p.t += 0.018 * p.v * state.speed;
      if (p.t >= 1) { fusionParticles.splice(i,1); continue; }
      const s = p.stream;
      const sx = cx + Math.cos(s.angle)*R*1.6;
      const sy = cy + Math.sin(s.angle)*R*1.6;
      const px = lerp(sx, cx, p.t) + Math.cos(s.angle+Math.PI/2)*p.jitter*60*(1-p.t);
      const py = lerp(sy, cy, p.t) + Math.sin(s.angle+Math.PI/2)*p.jitter*60*(1-p.t);
      ctx.fillStyle = `rgba(${s.hue},${(1-p.t)*opacity})`;
      ctx.shadowBlur = 8; ctx.shadowColor = `rgba(${s.hue},${0.8*opacity})`;
      ctx.beginPath(); ctx.arc(px,py,1.8,0,TAU); ctx.fill();
      ctx.shadowBlur = 0;
    }

    // rotating rings
    for (let i=0; i<3; i++) {
      const r = R*(0.55 + i*0.18);
      const dash = i%2===0 ? [10,8] : [3,6];
      const speed = (i%2===0 ? 1 : -1) * (0.3 + i*0.15);
      ctx.save();
      ctx.translate(cx,cy);
      ctx.rotate(state.globalT * speed * state.speed);
      ctx.setLineDash(dash);
      ctx.strokeStyle = accentCss(0.45*opacity);
      ctx.lineWidth = 1.4;
      ctx.beginPath(); ctx.arc(0,0,r,0,TAU); ctx.stroke();
      ctx.setLineDash([]);
      // tick marks
      for (let j=0;j<24;j++) {
        const a = j/24*TAU;
        ctx.strokeStyle = accentCss(0.55*opacity);
        ctx.beginPath();
        ctx.moveTo(Math.cos(a)*r, Math.sin(a)*r);
        ctx.lineTo(Math.cos(a)*(r+6), Math.sin(a)*(r+6));
        ctx.stroke();
      }
      ctx.restore();
    }

    // core
    const corePulse = 1 + 0.18*Math.sin(state.globalT*4);
    const grad = ctx.createRadialGradient(cx,cy,2, cx,cy,R*0.5*corePulse);
    grad.addColorStop(0, accentCss(0.95*opacity));
    grad.addColorStop(0.4, accentCss(0.5*opacity));
    grad.addColorStop(1, accentCss(0));
    ctx.fillStyle = grad;
    ctx.beginPath(); ctx.arc(cx,cy,R*0.5*corePulse,0,TAU); ctx.fill();

    // hexagon core mark
    ctx.strokeStyle = `rgba(255,255,255,${opacity})`;
    ctx.lineWidth = 1.6;
    ctx.beginPath();
    for (let i=0;i<6;i++) {
      const a = i/6*TAU + state.globalT*0.4;
      const x = cx + Math.cos(a)*R*0.18;
      const y = cy + Math.sin(a)*R*0.18;
      if (i===0) ctx.moveTo(x,y); else ctx.lineTo(x,y);
    }
    ctx.closePath(); ctx.stroke();

    // SHAP "explanation" particles bursting outward
    if (Math.random() < 0.3 * opacity) {
      shapBurst.push({ a: Math.random()*TAU, r: R*0.2, v: rand(80, 160), life: 1, hue: ['0,212,255','139,92,246','34,255,140','255,180,0'][Math.floor(Math.random()*4)] });
    }
    for (let i=shapBurst.length-1;i>=0;i--) {
      const b = shapBurst[i];
      b.r += b.v * 0.016 * state.speed;
      b.life -= 0.012 * state.speed;
      if (b.life <= 0) { shapBurst.splice(i,1); continue; }
      ctx.fillStyle = `rgba(${b.hue},${b.life*opacity})`;
      ctx.beginPath();
      ctx.arc(cx+Math.cos(b.a)*b.r, cy+Math.sin(b.a)*b.r, 2, 0, TAU);
      ctx.fill();
    }
  }
  const shapBurst = [];

  // ===== Ambient particle bursts (universal) =====
  const ambient = [];
  function ambientStep(opacity) {
    if (Math.random() < 0.4) {
      ambient.push({ x: Math.random()*W, y: Math.random()*H, r: rand(0.5, 2), life: 1, vy: rand(-12, -32), vx: rand(-6, 6) });
    }
    for (let i=ambient.length-1;i>=0;i--) {
      const p = ambient[i];
      p.x += p.vx * 0.016 * state.speed;
      p.y += p.vy * 0.016 * state.speed;
      p.life -= 0.006 * state.speed;
      if (p.life <= 0) { ambient.splice(i,1); continue; }
      ctx.fillStyle = accentCss(p.life*0.5*opacity);
      ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, TAU); ctx.fill();
    }
  }

  // ===== Camera-style overlay (subtle parallax + shake) =====
  let shake = 0;
  function shakeOffset() {
    if (shake <= 0) return [0,0];
    return [rand(-shake,shake), rand(-shake,shake)];
  }

  // ===== Main animation loop =====
  let last = performance.now();
  function frame(now) {
    const dt = Math.min(40, now - last) / 1000;
    last = now;
    if (!state.paused) {
      state.sceneT += dt * state.speed;
      state.globalT += dt * state.speed;
    }
    shake = Math.max(0, shake - dt*30);

    ctx.clearRect(0,0,W,H);
    const [sx, sy] = shakeOffset();
    ctx.save();
    ctx.translate(sx, sy);

    drawStars(dt);
    ambientStep(0.7);

    if (state.scene === 0) {
      // boot — globe centered, opacity ramps
      const op = clamp(state.sceneT/1.4, 0, 1);
      drawGlobe(W/2, H/2 + 30, Math.min(W,H)*0.28, op);
    } else if (state.scene === 1) {
      // cyberspace — endpoints + globe receding
      const op = clamp(state.sceneT/1.0, 0, 1);
      drawNetwork(op, 'watch');
      // attack packets continuously
      if (state.sceneT > 1.5 && Math.random() < 0.15) {
        spawnPacket(Math.floor(Math.random()*links.length), 'normal');
      }
    } else if (state.scene === 2) {
      const op = clamp(state.sceneT/1.0, 0, 1);
      drawFusion(op);
    } else if (state.scene === 3) {
      // threat response
      const op = clamp(state.sceneT/0.6, 0, 1);
      const phase = scene4Phase();
      drawNetwork(op, phase);
      // visual flash via shake handled in events
    } else if (state.scene === 4) {
      // login transition + login bg — calm globe small + network
      drawGlobe(W*0.78, H/2, Math.min(W,H)*0.18, 0.7);
      drawNetwork(0.45, 'watch');
    }

    ctx.restore();
    requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);

  // Scene 4 has phases: pre-attack | attack | response | resolved
  function scene4Phase() {
    const t = state.sceneT;
    if (t < 1.2) return 'watch';
    if (t < 4) return 'attack';
    if (t < 6.5) return 'attack';
    return 'resolved';
  }

  // ===== Scene controller =====
  const SCENES = [
    { name: 'AI BOOT SEQUENCE',           dur: 7.0 },
    { name: 'CYBERSPACE WATCH',           dur: 7.5 },
    { name: 'AI FUSION ENGINE',           dur: 7.5 },
    { name: 'LIVE THREAT RESPONSE',       dur: 8.5 },
    { name: 'SECURE ACCESS',              dur: 4.0 },
  ];

  const $ = sel => document.querySelector(sel);
  const $$ = sel => document.querySelectorAll(sel);

  function showScene(i) {
    state.scene = i;
    state.sceneT = 0;
    $$('.scene').forEach((el, idx) => el.classList.toggle('show', idx === i));
    $('#chapter-ix').textContent = `SCENE ${String(i+1).padStart(2,'0')} / 05`;
    $('#chapter-nm').textContent = SCENES[i].name;
    onSceneEnter(i);
  }

  function startCinematic() {
    showScene(0);
    queueScene(0);
  }

  let sceneTimer = null;
  function queueScene(i) {
    clearTimeout(sceneTimer);
    if (i >= SCENES.length - 1) {
      // last scene → activate login at end
      sceneTimer = setTimeout(() => activateLogin(), SCENES[i].dur*1000);
      return;
    }
    sceneTimer = setTimeout(() => {
      showScene(i+1);
      queueScene(i+1);
    }, SCENES[i].dur*1000);
  }

  function activateLogin() {
    state.loginActive = true;
    $('#stage').classList.add('login-mode');
    $('#login').classList.add('active');
    $('#login').style.opacity = 1;
    audio.fadeOutAmbient();
  }

  function skip() {
    state.skipped = true;
    clearTimeout(sceneTimer);
    showScene(4);
    setTimeout(activateLogin, 600);
  }

  // ===== Per-scene entry: fire animations on the DOM overlays =====
  function onSceneEnter(i) {
    if (i === 0) animateBoot();
    if (i === 1) animateCyberspace();
    if (i === 2) animateFusion();
    if (i === 3) animateThreat();
    if (i === 4) animateLogin();
  }

  // === Scene 0: boot ===
  function animateBoot() {
    const term = $('#term');
    term.style.opacity = 0;
    term.innerHTML = '<div class="term-head">SYS · BOOT · CYBER-SENTINEL-XDR</div>';
    setTimeout(() => term.style.transition='opacity .6s ease', 50);
    setTimeout(() => term.style.opacity = 1, 200);

    const lines = [
      ['cy','> initializing CYBER SENTINEL XDR core...'],
      ['ok','[ ✓ ] kernel modules loaded'],
      ['ok','[ ✓ ] mfa subsystem online'],
      ['ok','[ ✓ ] endpoint sensor mesh ready'],
      ['cy','> linking AI fusion engine...'],
      ['dim','        - network domain ............ <span class="ok">OK</span>'],
      ['dim','        - user behavior ............. <span class="ok">OK</span>'],
      ['dim','        - system / sysmon ........... <span class="ok">OK</span>'],
      ['dim','        - malware analysis .......... <span class="ok">OK</span>'],
      ['ok','[ ✓ ] SHAP explainability primed'],
      ['ok','[ ✓ ] SOAR response engine armed'],
      ['warn','[ ! ] siren array on standby'],
      ['cy','> establishing secure tunnel...'],
      ['ok','[ ✓ ] TLS 1.3 / X25519 / AES-256-GCM'],
      ['cy','> fetching live threat intelligence ▌'],
    ];
    let li = 0;
    function nextLine() {
      if (li >= lines.length) return;
      const [cls, text] = lines[li++];
      const el = document.createElement('div');
      el.className = 'ln ' + cls;
      el.innerHTML = text;
      term.appendChild(el);
      audio.tick();
      if (li < lines.length) setTimeout(nextLine, 280 + Math.random()*120);
    }
    setTimeout(nextLine, 600);

    // progress bar
    $('#progress-shell').style.opacity = 1;
    $('#progress-fill').style.width = '0%';
    let p = 0;
    const step = () => {
      p = Math.min(100, p + rand(2.5, 6));
      $('#progress-fill').style.width = p + '%';
      $('#progress-pct').textContent = String(Math.floor(p)).padStart(3,'0') + '%';
      if (p < 100 && state.scene === 0) setTimeout(step, 180);
    };
    setTimeout(step, 400);

    // title fade in
    const tg = $('#title-group');
    tg.style.opacity = 0;
    setTimeout(() => {
      tg.style.transition = 'opacity 1s ease';
      tg.style.opacity = 1;
      $('#title-eyebrow').animate(
        [{opacity:0, letterSpacing:'24px'}, {opacity:1, letterSpacing:'8px'}],
        {duration: 1100, fill:'forwards', easing:'cubic-bezier(.4,0,.2,1)'}
      );
      $('#title-divider').animate([{width:'0px'},{width:'180px'}], {duration:900, fill:'forwards', delay:300, easing:'ease-out'});
      $('#title-sub').animate([{opacity:0, letterSpacing:'24px'},{opacity:1, letterSpacing:'12px'}], {duration:900, fill:'forwards', delay: 500, easing:'cubic-bezier(.4,0,.2,1)'});
    }, 200);
  }

  // === Scene 1: cyberspace ===
  function animateCyberspace() {
    fadeBootChrome();
    const tg = $('#title-group');
    tg.style.opacity = 0;
    $('#term').style.opacity = 0;
    $('#progress-shell').style.opacity = 0;

    // metric cards
    const m = [
      { sel: '#m1', val: '12,847', unit: 'EPS',  lbl: 'EVENTS / SEC' },
      { sel: '#m2', val: '1,204',  unit: 'NODES',lbl: 'ENDPOINTS WATCHED' },
      { sel: '#m3', val: '0.42',   unit: 'MS',   lbl: 'CORRELATION LATENCY' },
    ];
    m.forEach((c, i) => {
      const el = $(c.sel);
      if (!el) return;
      el.style.opacity = 0;
      setTimeout(() => {
        el.style.transition = 'opacity .6s ease, transform .6s ease';
        el.style.opacity = 1;
        el.style.transform = 'translateY(0)';
      }, 300 + i*220);
    });
  }

  function fadeBootChrome() {
    const tg = $('#title-group');
    tg.style.transition = 'opacity 1.1s ease, transform 1.1s ease';
    tg.style.transform = 'translate(-50%, -56%) scale(0.92)';
    tg.style.opacity = 0;
  }

  // === Scene 2: fusion ===
  function animateFusion() {
    // hide network overlays
    ['#m1','#m2','#m3'].forEach(s => { const el = $(s); if (el) el.style.opacity = 0; });

    const labels = $$('.fusion-label');
    labels.forEach((el, i) => {
      el.style.opacity = 0;
      setTimeout(() => {
        el.animate([{opacity:0, transform:'translateY(8px)'},{opacity:1, transform:'translateY(0)'}], {duration:600, fill:'forwards', easing:'cubic-bezier(.4,0,.2,1)'});
      }, 200 + i*250);
    });
    setTimeout(() => {
      $('#fusion-readout').animate([{opacity:0, transform:'translate(-50%, 12px)'},{opacity:1, transform:'translate(-50%, 0)'}], {duration:700, fill:'forwards', easing:'cubic-bezier(.4,0,.2,1)'});
    }, 1200);
  }

  // === Scene 3: threat ===
  function animateThreat() {
    // hide fusion overlays
    $$('.fusion-label').forEach(el => el.style.opacity = 0);
    $('#fusion-readout').style.opacity = 0;

    // schedule attack timeline
    const fb = $('#flash-red');
    const fs = $('#flash-secure');
    const banner = $('#alert-banner');
    const feed = $('#event-feed'); feed.innerHTML = '';
    feed.style.opacity = 1;

    // pick targets
    endpoints.forEach(e => e.state = 'ok');
    const tgt = endpoints[Math.floor(Math.random()*endpoints.length)];
    const neighbors = links.filter(l=>l.a===tgt.id || l.b===tgt.id);

    // 1.0s — banner
    setTimeout(() => {
      banner.style.opacity = 1;
      banner.animate([{opacity:0, letterSpacing:'24px'},{opacity:1, letterSpacing:'12px'}], {duration:500, fill:'forwards'});
      audio.alert();
      fb.animate([{opacity:0},{opacity:0.9},{opacity:0.3}],{duration:600, fill:'forwards'});
      shake = 14;
      tgt.state = 'infected';
      pushEvent(feed, '00:01.04', 'CRITICAL', 'Suspicious process spawn — endpoint 0x4F-A3', 'crit');
    }, 800);

    // 1.6s — spread
    setTimeout(() => {
      neighbors.forEach((l, i) => {
        setTimeout(() => spawnPacket(links.indexOf(l), 'attack'), i*120);
      });
      pushEvent(feed, '00:01.62', 'ALERT', 'Lateral movement detected — 4 hosts at risk', 'crit');
      fb.animate([{opacity:0.4},{opacity:0.7}],{duration:300, fill:'forwards'});
    }, 1600);

    // 3.2s — AI correlates
    setTimeout(() => {
      pushEvent(feed, '00:03.18', 'AI', 'Fusion engine: T1486 + T1021.001 → APT pattern', 'warn');
    }, 3200);

    // 4.2s — banner shifts to RESPONSE
    setTimeout(() => {
      banner.querySelector('.main').textContent = 'SOAR ENGAGED';
      banner.querySelector('.sub').textContent = 'AUTOMATED CONTAINMENT IN PROGRESS';
      banner.style.color = '#ffb400';
      banner.style.textShadow = '0 0 7px rgba(255,180,0,.9), 0 0 18px rgba(255,180,0,.5)';
      pushEvent(feed, '00:04.21', 'SOAR', 'Isolating endpoint 0x4F-A3 — kill switch armed', 'warn');
    }, 4200);

    // 5.2s — isolate
    setTimeout(() => {
      tgt.state = 'isolated';
      neighbors.forEach(l => {
        const other = endpoints[l.a===tgt.id?l.b:l.a];
        other.state = 'ok';
      });
      pushEvent(feed, '00:05.04', 'BLOCK', 'IP 198.51.100.77 blocked at perimeter', 'warn');
    }, 5200);

    // 6.4s — neutralized
    setTimeout(() => {
      banner.querySelector('.main').textContent = 'THREAT NEUTRALIZED';
      banner.querySelector('.sub').textContent = 'ALL ENDPOINTS SECURE';
      banner.style.color = 'rgba(34,255,140,1)';
      banner.style.textShadow = '0 0 7px rgba(34,255,140,.9), 0 0 18px rgba(34,255,140,.5)';
      endpoints.forEach(e => { if (e.state==='isolated') return; e.state = 'secure'; });
      fb.animate([{opacity:0.4},{opacity:0}],{duration:600, fill:'forwards'});
      fs.animate([{opacity:0},{opacity:0.8},{opacity:0.3}],{duration:700, fill:'forwards'});
      pushEvent(feed, '00:06.40', 'OK', 'Containment verified — system nominal', 'ok');
    }, 6400);

    // 7.6s — fade banner
    setTimeout(() => {
      banner.animate([{opacity:1},{opacity:0}],{duration:700, fill:'forwards'});
      fs.animate([{opacity:0.3},{opacity:0}],{duration:600, fill:'forwards'});
    }, 7600);
  }

  function pushEvent(feed, time, badge, msg, kind) {
    const el = document.createElement('div');
    el.className = 'event ' + (kind==='ok'?'ok':kind==='warn'?'warn':'');
    el.innerHTML = `<span class="t">${time}</span><span class="m">${msg}</span><span class="badge">${badge}</span>`;
    feed.appendChild(el);
    el.animate([{opacity:0, transform:'translateX(-12px)'},{opacity:1, transform:'translateX(0)'}], {duration:400, fill:'forwards', easing:'cubic-bezier(.4,0,.2,1)'});
    audio.tick();
    if (feed.children.length > 5) feed.removeChild(feed.children[0]);
  }

  // === Scene 4: login ===
  function animateLogin() {
    $('#event-feed').style.opacity = 0;
    $('#alert-banner').style.opacity = 0;
    // pre-render: bring login title eyebrow back as small handoff text
  }

  // ===== Audio (synthetic, WebAudio) =====
  const audio = (() => {
    let actx = null, master = null, ambientNode = null, ambientGain = null;
    function ensure() {
      if (actx) return;
      actx = new (window.AudioContext || window.webkitAudioContext)();
      master = actx.createGain(); master.gain.value = 0.2; master.connect(actx.destination);
    }
    function startAmbient() {
      ensure();
      if (ambientNode) return;
      const o1 = actx.createOscillator(); o1.type='sine'; o1.frequency.value = 60;
      const o2 = actx.createOscillator(); o2.type='sine'; o2.frequency.value = 90;
      const o3 = actx.createOscillator(); o3.type='triangle'; o3.frequency.value = 220;
      const lfo = actx.createOscillator(); lfo.frequency.value = 0.18;
      const lfoG = actx.createGain(); lfoG.gain.value = 16;
      lfo.connect(lfoG).connect(o3.frequency);
      const g = actx.createGain(); g.gain.value = 0;
      o1.connect(g); o2.connect(g); o3.connect(g);
      g.connect(master);
      o1.start(); o2.start(); o3.start(); lfo.start();
      g.gain.linearRampToValueAtTime(0.55, actx.currentTime + 1.2);
      ambientNode = {o1,o2,o3,lfo}; ambientGain = g;
    }
    function fadeOutAmbient() {
      if (!ambientGain) return;
      ambientGain.gain.linearRampToValueAtTime(0, actx.currentTime + 1.4);
    }
    function tick() {
      if (!state.audio) return;
      ensure();
      const o = actx.createOscillator(); o.type='square'; o.frequency.value = 880 + Math.random()*120;
      const g = actx.createGain(); g.gain.value = 0;
      o.connect(g); g.connect(master);
      g.gain.linearRampToValueAtTime(0.04, actx.currentTime + 0.005);
      g.gain.exponentialRampToValueAtTime(0.0001, actx.currentTime + 0.06);
      o.start(); o.stop(actx.currentTime + 0.07);
    }
    function alert() {
      if (!state.audio) return;
      ensure();
      const o = actx.createOscillator(); o.type='sawtooth'; o.frequency.value = 220;
      const g = actx.createGain(); g.gain.value = 0;
      o.connect(g); g.connect(master);
      g.gain.linearRampToValueAtTime(0.3, actx.currentTime + 0.02);
      o.frequency.linearRampToValueAtTime(880, actx.currentTime + 0.4);
      g.gain.linearRampToValueAtTime(0, actx.currentTime + 0.7);
      o.start(); o.stop(actx.currentTime + 0.75);
    }
    return { startAmbient, fadeOutAmbient, tick, alert };
  })();

  // ===== Wire UI =====
  $('#skip-btn').addEventListener('click', skip);
  const audioBtn = $('#audio-btn');
  audioBtn.addEventListener('click', () => {
    state.audio = !state.audio;
    audioBtn.classList.toggle('on', state.audio);
    audioBtn.querySelector('.icon-on').style.display = state.audio ? '' : 'none';
    audioBtn.querySelector('.icon-off').style.display = state.audio ? 'none' : '';
    if (state.audio) audio.startAmbient(); else audio.fadeOutAmbient();
  });

  // login interactivity
  $$('.role').forEach(el => el.addEventListener('click', () => {
    $$('.role').forEach(o => o.classList.remove('active'));
    el.classList.add('active');
  }));
  $('#login-btn').addEventListener('click', (e) => {
    e.preventDefault();
    const btn = $('#login-btn');
    btn.textContent = 'AUTHENTICATING...';
    btn.style.pointerEvents = 'none';
    setTimeout(() => { btn.textContent = '✓ ACCESS GRANTED'; btn.style.background = 'linear-gradient(135deg,#15803d,#166534)'; }, 1200);
  });

  // ===== Tweaks integration =====
  window.applyTweaks = function applyTweaks(t) {
    state.accent = t.accent || state.accent;
    state.intensity = t.intensity ?? state.intensity;
    state.speed = t.speed ?? state.speed;
    state.showTerminal = t.showTerminal ?? state.showTerminal;
    document.documentElement.style.setProperty('--accent-r', accentColor()[0]);
    document.documentElement.style.setProperty('--accent-g', accentColor()[1]);
    document.documentElement.style.setProperty('--accent-b', accentColor()[2]);
    document.documentElement.style.setProperty('--brand-cyan', accentCss(1));
    if (!state.showTerminal) $('#term').style.display = 'none';
    else $('#term').style.display = '';
  };
  window.cinematic = { skip, replay: () => { state.scene=0; state.sceneT=0; $('#login').classList.remove('active'); $('#login').style.opacity=0; $('#stage').classList.remove('login-mode'); startCinematic(); } };

  // ===== Boot it =====
  setTimeout(startCinematic, 400);
})();
