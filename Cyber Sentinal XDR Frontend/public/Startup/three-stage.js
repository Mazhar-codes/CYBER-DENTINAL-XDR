/* ============================================================
   CYBER SENTINEL XDR — Three.js Stage (WebGL scenes 5-7)
   Scene 5: GLOBAL THREAT MATRIX  (Earth + attack arcs + sats)
   Scene 6: AI CORRELATION CORE   (energy core + rings + neural)
   Scene 7: AUTONOMOUS RESPONSE   (grid + shockwave + dome)

   Public API on window.threeStage:
     .mount(canvas) .setProgress(p) .setVelocity(v)
     .setCursor(x,y) .setAccent([r,g,b]) .setQuality(0..1)
   ============================================================ */
(function () {
  'use strict';
  if (!window.THREE) { console.warn('three-stage: THREE not loaded'); return; }

  const TAU = Math.PI * 2;
  const lerp = (a, b, t) => a + (b - a) * t;
  const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
  const smoothstep = (e0, e1, x) => {
    const t = clamp((x - e0) / (e1 - e0), 0, 1);
    return t * t * (3 - 2 * t);
  };

  const S = {
    canvas: null, renderer: null, composer: null,
    scene: null, camera: null, clock: null,
    mounted: false,
    progress: 0, pSmooth: 0,
    velocity: 0, vSmooth: 0,
    cursor: { x: 0, y: 0 }, cursorSmooth: { x: 0, y: 0 },
    accent: new THREE.Color(0x00d4ff),
    elapsed: 0,
    quality: 1,
    // Scene scroll ranges (must match cinematic-engine.js)
    ranges: [[0.50, 0.65], [0.65, 0.78], [0.78, 0.90]],
    stages: [],
    W: 0, H: 0,
  };

  function rangeOpacity(i, p) {
    const [a, b] = S.ranges[i];
    const fade = 0.035;
    return clamp(
      smoothstep(a - fade, a + fade, p) - smoothstep(b - fade, b + fade, p),
      0, 1
    );
  }
  function rangeLocal(i, p) {
    const [a, b] = S.ranges[i];
    return clamp((p - a) / (b - a), 0, 1);
  }

  function resize() {
    if (!S.renderer) return;
    S.W = window.innerWidth;
    S.H = window.innerHeight;
    const dpr = Math.min(window.devicePixelRatio || 1, 2) * S.quality;
    S.renderer.setPixelRatio(dpr);
    S.renderer.setSize(S.W, S.H, false);
    if (S.composer) S.composer.setSize(S.W, S.H);
    S.camera.aspect = S.W / S.H;
    S.camera.updateProjectionMatrix();
  }
  window.addEventListener('resize', resize);

  function init(canvas) {
    if (S.mounted) return;
    S.canvas = canvas;
    try {
      S.renderer = new THREE.WebGLRenderer({
        canvas, antialias: true, alpha: true,
        powerPreference: 'high-performance',
      });
    } catch (e) {
      console.warn('three-stage: WebGL unavailable, 3D scenes disabled.', e);
      S.mounted = true; // prevent retries
      return;
    }
    if ('outputColorSpace' in S.renderer) {
      S.renderer.outputColorSpace = THREE.SRGBColorSpace;
    } else if ('outputEncoding' in S.renderer) {
      S.renderer.outputEncoding = THREE.sRGBEncoding;
    }
    S.renderer.toneMapping = THREE.ACESFilmicToneMapping;
    S.renderer.toneMappingExposure = 0.78;
    S.renderer.setClearColor(0x000000, 0);

    S.camera = new THREE.PerspectiveCamera(50, 1, 0.05, 200);
    S.camera.position.set(0, 0, 8);

    S.scene = new THREE.Scene();
    S.scene.fog = new THREE.FogExp2(0x020610, 0.055);

    S.scene.add(new THREE.AmbientLight(0xffffff, 0.22));
    const key = new THREE.DirectionalLight(0x90c0ff, 0.85);
    key.position.set(5, 4, 6);
    S.scene.add(key);
    const rim = new THREE.PointLight(0xff3366, 0.75, 30);
    rim.position.set(-4, -2, -3);
    S.scene.add(rim);
    const cy = new THREE.PointLight(0x00d4ff, 0.95, 26);
    cy.position.set(3, 2, -2);
    S.scene.add(cy);

    // Post-processing (bloom) — tamed: localized edge glow, not flood.
    if (THREE.EffectComposer && THREE.UnrealBloomPass && THREE.RenderPass) {
      try {
        S.composer = new THREE.EffectComposer(S.renderer);
        S.composer.addPass(new THREE.RenderPass(S.scene, S.camera));
        const bloom = new THREE.UnrealBloomPass(
          new THREE.Vector2(window.innerWidth, window.innerHeight),
          0.38, 0.32, 0.28
        );
        S.composer.addPass(bloom);
        S.bloom = bloom;
      } catch (e) { console.warn('bloom unavailable', e); S.composer = null; }
    }

    S.stages.push(buildMatrix());
    S.stages.push(buildCore());
    S.stages.push(buildResponse());
    S.stages.forEach(st => S.scene.add(st.group));

    S.clock = new THREE.Clock();
    resize();
    S.mounted = true;
    requestAnimationFrame(render);
  }

  function updateCamera(dt) {
    const p = S.pSmooth;
    const op0 = rangeOpacity(0, p);
    const op1 = rangeOpacity(1, p);
    const op2 = rangeOpacity(2, p);
    // Base
    let tx = 0, ty = 0, tz = 8;
    // Stage 0 — pull back, slight tilt
    tx = lerp(tx, 0, op0);
    ty = lerp(ty, 0.2, op0);
    tz = lerp(tz, 6.4, op0);
    // Stage 1 — close on core
    tz = lerp(tz, 5.2, op1);
    ty = lerp(ty, 0.0, op1);
    // Stage 2 — elevated 3/4 view of floor
    ty = lerp(ty, 1.6 * op2, Math.min(1, op2 * 1.3));
    tz = lerp(tz, 7.0, op2);
    // Cursor parallax
    tx += S.cursorSmooth.x * 0.5;
    ty += S.cursorSmooth.y * 0.35;
    // Subtle camera breathing — slow inertia easing
    const br = S.elapsed;
    tx += Math.sin(br * 0.32) * 0.06;
    ty += Math.cos(br * 0.27) * 0.04;
    // Velocity dolly
    tz += S.vSmooth * 4.5;
    const k = Math.min(1, dt * 3);
    S.camera.position.x = lerp(S.camera.position.x, tx, k);
    S.camera.position.y = lerp(S.camera.position.y, ty, k);
    S.camera.position.z = lerp(S.camera.position.z, tz, k);
    S.camera.lookAt(0, 0 + op2 * (-0.4), 0);
  }

  function render() {
    requestAnimationFrame(render);
    const dt = Math.min(0.05, S.clock.getDelta());
    S.elapsed += dt;
    // smooth
    S.pSmooth += (S.progress - S.pSmooth) * Math.min(1, dt * 8);
    S.vSmooth += (S.velocity - S.vSmooth) * Math.min(1, dt * 6);
    S.cursorSmooth.x += (S.cursor.x - S.cursorSmooth.x) * Math.min(1, dt * 5);
    S.cursorSmooth.y += (S.cursor.y - S.cursorSmooth.y) * Math.min(1, dt * 5);

    let anyActive = false;
    for (let i = 0; i < 3; i++) {
      const op = rangeOpacity(i, S.pSmooth);
      S.stages[i].group.visible = op > 0.005;
      if (op > 0.005) anyActive = true;
      S.stages[i].update(dt, op);
    }
    updateCamera(dt);

    if (S.bloom) {
      // gentle gesture modulation — stays in a tight, controlled range.
      const k = 0.32 + Math.min(0.18, Math.abs(S.vSmooth) * 1.2);
      S.bloom.strength = k;
      S.bloom.radius = 0.30 + Math.min(0.15, Math.abs(S.vSmooth) * 0.8);
    }

    if (!anyActive) {
      // clear once to remove any lingering frame, then idle
      S.renderer.clear();
      return;
    }
    if (S.composer) S.composer.render(dt);
    else S.renderer.render(S.scene, S.camera);
  }

  // ============================================================
  // STAGE 0 — GLOBAL THREAT MATRIX
  // ============================================================
  function buildMatrix() {
    const group = new THREE.Group();
    const R = 1.9;

    // Earth core
    const earthM = new THREE.MeshStandardMaterial({
      color: 0x0a1830, metalness: 0.45, roughness: 0.55,
      emissive: 0x081428, emissiveIntensity: 0.5,
    });
    const earth = new THREE.Mesh(new THREE.SphereGeometry(R, 80, 60), earthM);
    group.add(earth);

    // Wireframe shell
    const wire = new THREE.Mesh(
      new THREE.SphereGeometry(R * 1.003, 40, 30),
      new THREE.MeshBasicMaterial({
        color: 0x00d4ff, wireframe: true, transparent: true, opacity: 0.18,
        blending: THREE.AdditiveBlending, depthWrite: false,
      })
    );
    group.add(wire);

    // Atmosphere fresnel
    const atmoUniforms = { uColor: { value: new THREE.Color(0x00d4ff) } };
    const atmo = new THREE.Mesh(
      new THREE.SphereGeometry(R * 1.08, 48, 32),
      new THREE.ShaderMaterial({
        uniforms: atmoUniforms,
        transparent: true, depthWrite: false,
        blending: THREE.AdditiveBlending, side: THREE.BackSide,
        vertexShader: `varying vec3 vN;void main(){vN=normalize(normalMatrix*normal);gl_Position=projectionMatrix*modelViewMatrix*vec4(position,1.0);}`,
        fragmentShader: `varying vec3 vN;uniform vec3 uColor;void main(){float i=pow(0.62-dot(vN,vec3(0,0,1)),2.0);gl_FragColor=vec4(uColor,1.0)*i;}`,
      })
    );
    group.add(atmo);

    // Cities / endpoint points
    const cityCount = 280;
    const cityPos = new Float32Array(cityCount * 3);
    const cityArr = [];
    for (let i = 0; i < cityCount; i++) {
      const phi = Math.acos(1 - 2 * Math.random());
      const theta = TAU * Math.random();
      const rr = R * 1.005;
      const x = rr * Math.sin(phi) * Math.cos(theta);
      const y = rr * Math.sin(phi) * Math.sin(theta);
      const z = rr * Math.cos(phi);
      cityPos[i * 3] = x; cityPos[i * 3 + 1] = y; cityPos[i * 3 + 2] = z;
      cityArr.push([x, y, z]);
    }
    const cityGeo = new THREE.BufferGeometry();
    cityGeo.setAttribute('position', new THREE.BufferAttribute(cityPos, 3));
    group.add(new THREE.Points(cityGeo, new THREE.PointsMaterial({
      size: 0.045, color: 0x00d4ff,
      transparent: true, opacity: 0.95,
      blending: THREE.AdditiveBlending, depthWrite: false,
      sizeAttenuation: true,
    })));

    // Attack arcs
    const arcGroup = new THREE.Group();
    group.add(arcGroup);
    function spawnArc(hot) {
      const i = (Math.random() * cityArr.length) | 0;
      let j = (Math.random() * cityArr.length) | 0;
      if (j === i) j = (j + 1) % cityArr.length;
      const p1 = new THREE.Vector3().fromArray(cityArr[i]);
      const p2 = new THREE.Vector3().fromArray(cityArr[j]);
      const mid = p1.clone().add(p2).multiplyScalar(0.5);
      mid.normalize().multiplyScalar(R * (1.55 + Math.random() * 0.45));
      const curve = new THREE.CatmullRomCurve3([p1, mid, p2]);
      const pts = curve.getPoints(48);
      const geo = new THREE.BufferGeometry().setFromPoints(pts);
      const color = hot ? 0xff3366 : 0x00d4ff;
      const mat = new THREE.LineBasicMaterial({
        color, transparent: true, opacity: 0,
        blending: THREE.AdditiveBlending, depthWrite: false,
      });
      const line = new THREE.Line(geo, mat);
      // head sprite
      const head = new THREE.Sprite(new THREE.SpriteMaterial({
        color, transparent: true, opacity: 0,
        blending: THREE.AdditiveBlending, depthWrite: false,
      }));
      head.scale.set(0.12, 0.12, 1);
      line.add(head);
      line.userData = { life: 0, max: 1.6 + Math.random() * 0.8, curve, head, mat };
      arcGroup.add(line);
    }

    // Satellites
    const satGroup = new THREE.Group();
    for (let i = 0; i < 5; i++) {
      const sat = new THREE.Mesh(
        new THREE.OctahedronGeometry(0.085, 0),
        new THREE.MeshStandardMaterial({
          color: 0x00d4ff, emissive: 0x00d4ff, emissiveIntensity: 1.2,
          metalness: 0.85, roughness: 0.25,
        })
      );
      sat.userData = {
        radius: R * (1.45 + Math.random() * 0.35),
        speed: 0.25 + Math.random() * 0.3,
        offset: Math.random() * TAU,
        tilt: (Math.random() - 0.5) * 0.9,
      };
      const ring = new THREE.Mesh(
        new THREE.RingGeometry(0.16, 0.2, 24),
        new THREE.MeshBasicMaterial({
          color: 0x00d4ff, transparent: true, opacity: 0.55,
          side: THREE.DoubleSide, blending: THREE.AdditiveBlending, depthWrite: false,
        })
      );
      ring.rotation.x = Math.PI / 2;
      sat.add(ring);
      satGroup.add(sat);
    }
    group.add(satGroup);

    // Floating hex HUD fragments
    const hexGroup = new THREE.Group();
    for (let i = 0; i < 6; i++) {
      const hex = new THREE.Mesh(
        new THREE.RingGeometry(0.3, 0.32, 6),
        new THREE.MeshBasicMaterial({
          color: 0x00d4ff, transparent: true, opacity: 0.38,
          side: THREE.DoubleSide, blending: THREE.AdditiveBlending, depthWrite: false,
        })
      );
      hex.position.set(
        (Math.random() - 0.5) * 9,
        (Math.random() - 0.5) * 5,
        -2.5 - Math.random() * 3
      );
      hex.userData = { spin: (Math.random() - 0.5) * 0.6, phase: Math.random() * TAU };
      hexGroup.add(hex);
    }
    group.add(hexGroup);

    // Radar sweep
    const sweep = new THREE.Mesh(
      new THREE.RingGeometry(R * 1.12, R * 1.14, 96),
      new THREE.MeshBasicMaterial({
        color: 0x00d4ff, side: THREE.DoubleSide,
        transparent: true, opacity: 0.45,
        blending: THREE.AdditiveBlending, depthWrite: false,
      })
    );
    sweep.rotation.x = Math.PI / 2;
    group.add(sweep);

    let arcTimer = 0;

    function update(dt, op) {
      const local = rangeLocal(0, S.pSmooth);
      const s = 0.86 + op * 0.18;
      group.scale.setScalar(s);

      const baseSpin = 0.08 + Math.abs(S.vSmooth) * 0.5;
      earth.rotation.y += dt * baseSpin;
      wire.rotation.y += dt * baseSpin;
      atmo.rotation.y += dt * baseSpin * 0.5;
      group.rotation.y += S.vSmooth * 0.9 * dt * 18;
      group.rotation.x = lerp(group.rotation.x, S.cursorSmooth.y * 0.35, dt * 4);

      arcTimer += dt;
      if (op > 0.05 && arcTimer > (0.09 - op * 0.04)) {
        arcTimer = 0;
        spawnArc(Math.random() < 0.32);
        spawnArc(Math.random() < 0.32);
      }
      for (let i = arcGroup.children.length - 1; i >= 0; i--) {
        const arc = arcGroup.children[i];
        arc.userData.life += dt * (1 + Math.abs(S.vSmooth) * 0.6);
        const t = arc.userData.life / arc.userData.max;
        if (t >= 1) {
          arcGroup.remove(arc);
          arc.geometry.dispose(); arc.userData.mat.dispose();
          arc.userData.head.material.dispose();
          continue;
        }
        const peak = 1 - Math.abs(t - 0.5) * 2;
        arc.userData.mat.opacity = peak * 0.95;
        const head = arc.userData.head;
        const pos = arc.userData.curve.getPoint(clamp(t * 1.25, 0, 1));
        head.position.copy(pos);
        head.material.opacity = peak;
      }

      satGroup.children.forEach(sat => {
        const u = sat.userData;
        const a = S.elapsed * u.speed + u.offset;
        sat.position.set(
          Math.cos(a) * u.radius,
          Math.sin(u.tilt) * Math.cos(a * 0.7) * 0.65,
          Math.sin(a) * u.radius
        );
        sat.rotation.y = a * 2;
        sat.rotation.x = a;
      });

      hexGroup.children.forEach(h => {
        h.rotation.z += dt * h.userData.spin;
        h.position.y += Math.sin(S.elapsed * 0.5 + h.userData.phase) * 0.0008;
      });

      sweep.rotation.z = S.elapsed * 1.4;
    }

    return { group, update };
  }

  // ============================================================
  // STAGE 1 — AI CORRELATION CORE
  // ============================================================
  function buildCore() {
    const group = new THREE.Group();

    const coreUniforms = {
      uTime: { value: 0 },
      uPulse: { value: 0 },
      uColorA: { value: new THREE.Color(0x00d4ff) },
      uColorB: { value: new THREE.Color(0x8b5cf6) },
    };
    const core = new THREE.Mesh(
      new THREE.IcosahedronGeometry(1, 2),
      new THREE.ShaderMaterial({
        uniforms: coreUniforms,
        transparent: true, blending: THREE.AdditiveBlending, depthWrite: false,
        vertexShader: `
          varying vec3 vN; varying vec3 vP;
          uniform float uTime; uniform float uPulse;
          void main() {
            vN = normalize(normalMatrix * normal);
            vec3 p = position;
            float d = sin(p.x * 4.0 + uTime * 2.0) * cos(p.y * 4.0 + uTime * 1.6) * 0.05;
            d += sin(p.z * 6.0 + uTime * 3.0) * 0.03;
            p += normal * (d + uPulse * 0.18);
            vP = p;
            gl_Position = projectionMatrix * modelViewMatrix * vec4(p, 1.0);
          }`,
        fragmentShader: `
          varying vec3 vN; varying vec3 vP;
          uniform vec3 uColorA; uniform vec3 uColorB; uniform float uTime;
          void main() {
            float f = abs(dot(vN, vec3(0,0,1)));
            float fres = pow(1.0 - f, 2.4);
            vec3 c = mix(uColorA, uColorB, 0.5 + 0.5 * sin(uTime + vP.y * 3.0));
            c += fres * 0.45;
            gl_FragColor = vec4(c, 0.42 + fres * 0.30);
          }`
      })
    );
    group.add(core);

    const shell = new THREE.Mesh(
      new THREE.IcosahedronGeometry(1.4, 1),
      new THREE.MeshBasicMaterial({
        color: 0x00d4ff, wireframe: true,
        transparent: true, opacity: 0.32,
        blending: THREE.AdditiveBlending, depthWrite: false,
      })
    );
    group.add(shell);

    // Holographic rings
    const rings = [];
    const ringColors = [0x00d4ff, 0x8b5cf6, 0xa855f7, 0xffb400, 0x00d4ff];
    for (let i = 0; i < 5; i++) {
      const r = 1.8 + i * 0.32;
      const torus = new THREE.Mesh(
        new THREE.TorusGeometry(r, 0.006 + Math.random() * 0.005, 8, 96),
        new THREE.MeshBasicMaterial({
          color: ringColors[i], transparent: true, opacity: 0.38,
          blending: THREE.AdditiveBlending, depthWrite: false,
        })
      );
      torus.rotation.x = Math.random() * TAU;
      torus.rotation.y = Math.random() * TAU;
      torus.userData = {
        axis: new THREE.Vector3(Math.random() - 0.5, Math.random() - 0.5, Math.random() - 0.5).normalize(),
        speed: 0.2 + Math.random() * 0.3 * (i % 2 ? -1 : 1),
      };
      rings.push(torus);
      group.add(torus);
    }

    // SHAP particle burst
    const N = 1400;
    const positions = new Float32Array(N * 3);
    const colors = new Float32Array(N * 3);
    const vel = [];
    const life = new Float32Array(N);
    const palette = [[0, 0.83, 1], [0.55, 0.36, 0.96], [0.66, 0.33, 0.97], [1, 0.71, 0]];
    for (let i = 0; i < N; i++) {
      const d = new THREE.Vector3().randomDirection();
      vel.push({ d, s: 0.35 + Math.random() * 1.6 });
      life[i] = Math.random() * 3;
      const c = palette[(Math.random() * 4) | 0];
      colors[i * 3] = c[0]; colors[i * 3 + 1] = c[1]; colors[i * 3 + 2] = c[2];
      positions[i * 3] = d.x * 0.12; positions[i * 3 + 1] = d.y * 0.12; positions[i * 3 + 2] = d.z * 0.12;
    }
    const burstGeo = new THREE.BufferGeometry();
    burstGeo.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    burstGeo.setAttribute('color', new THREE.BufferAttribute(colors, 3));
    const burst = new THREE.Points(burstGeo, new THREE.PointsMaterial({
      size: 0.032, vertexColors: true,
      transparent: true, opacity: 0.55,
      blending: THREE.AdditiveBlending, depthWrite: false,
      sizeAttenuation: true,
    }));
    group.add(burst);

    // Volumetric beams
    const beamGroup = new THREE.Group();
    const beamColors = [0x00d4ff, 0x8b5cf6, 0xffb400, 0xa855f7];
    for (let i = 0; i < 4; i++) {
      const beamM = new THREE.ShaderMaterial({
        transparent: true, blending: THREE.AdditiveBlending, depthWrite: false,
        side: THREE.DoubleSide,
        uniforms: {
          uColor: { value: new THREE.Color(beamColors[i]) },
          uTime: { value: 0 },
        },
        vertexShader: `varying vec2 vUv;void main(){vUv=uv;gl_Position=projectionMatrix*modelViewMatrix*vec4(position,1.0);}`,
        fragmentShader: `
          varying vec2 vUv;
          uniform vec3 uColor;
          uniform float uTime;
          void main(){
            float horiz = 1.0 - abs(vUv.x - 0.5) * 2.0;
            float vert = sin(vUv.y * 3.14159);
            float pulse = 0.6 + 0.4 * sin(uTime * 1.2 + vUv.y * 6.0);
            float a = horiz * vert * pulse * 0.22;
            gl_FragColor = vec4(uColor, a);
          }`
      });
      const beam = new THREE.Mesh(new THREE.PlaneGeometry(0.1, 12), beamM);
      beam.rotation.z = (i / 4) * TAU;
      beam.userData = { ang: (i / 4) * TAU, mat: beamM };
      beamGroup.add(beam);
    }
    group.add(beamGroup);

    // Neural nodes + dynamic connections
    const nodeCount = 28;
    const nodes = [];
    for (let i = 0; i < nodeCount; i++) {
      const phi = Math.acos(1 - 2 * Math.random());
      const theta = TAU * Math.random();
      const r = 2.45 + Math.random() * 0.4;
      nodes.push(new THREE.Vector3(
        r * Math.sin(phi) * Math.cos(theta),
        r * Math.sin(phi) * Math.sin(theta),
        r * Math.cos(phi)
      ));
    }
    const nodeArr = new Float32Array(nodeCount * 3);
    nodes.forEach((n, i) => { nodeArr[i*3]=n.x; nodeArr[i*3+1]=n.y; nodeArr[i*3+2]=n.z; });
    const nodeGeo = new THREE.BufferGeometry();
    nodeGeo.setAttribute('position', new THREE.BufferAttribute(nodeArr, 3));
    group.add(new THREE.Points(nodeGeo, new THREE.PointsMaterial({
      size: 0.09, color: 0xffffff,
      transparent: true, opacity: 0.85,
      blending: THREE.AdditiveBlending, depthWrite: false,
    })));

    const connGroup = new THREE.Group();
    group.add(connGroup);
    function spawnConn() {
      const i = (Math.random() * nodeCount) | 0;
      let j = (Math.random() * nodeCount) | 0;
      if (j === i) j = (j + 1) % nodeCount;
      const g = new THREE.BufferGeometry().setFromPoints([nodes[i], nodes[j]]);
      const m = new THREE.LineBasicMaterial({
        color: Math.random() < 0.4 ? 0x8b5cf6 : 0x00d4ff,
        transparent: true, opacity: 0,
        blending: THREE.AdditiveBlending, depthWrite: false,
      });
      const ln = new THREE.Line(g, m);
      ln.userData = { life: 0, max: 0.9 + Math.random() * 0.6 };
      connGroup.add(ln);
    }
    let connTimer = 0;

    function update(dt, op) {
      const s = 0.85 + op * 0.22;
      group.scale.setScalar(s);

      coreUniforms.uTime.value = S.elapsed;
      coreUniforms.uPulse.value = 0.25 + 0.18 * Math.sin(S.elapsed * 0.9) + Math.abs(S.vSmooth) * 0.25;
      core.rotation.y += dt * 0.18;
      core.rotation.x += dt * 0.09;
      shell.rotation.y -= dt * 0.14;
      shell.rotation.z += dt * 0.07;

      group.rotation.y = lerp(group.rotation.y, S.cursorSmooth.x * 0.6, dt * 4);
      group.rotation.x = lerp(group.rotation.x, -S.cursorSmooth.y * 0.4, dt * 4);

      rings.forEach(r => {
        const u = r.userData;
        r.rotateOnAxis(u.axis, dt * u.speed * 0.45 * (1 + Math.abs(S.vSmooth) * 1.4));
      });

      const pos = burst.geometry.attributes.position.array;
      const speedScale = 1 + Math.abs(S.vSmooth) * 2;
      for (let i = 0; i < N; i++) {
        life[i] += dt * speedScale;
        if (life[i] > 3) {
          life[i] = 0;
          const d = new THREE.Vector3().randomDirection();
          vel[i].d = d; vel[i].s = 0.35 + Math.random() * 1.6;
          pos[i*3] = d.x * 0.12; pos[i*3+1] = d.y * 0.12; pos[i*3+2] = d.z * 0.12;
        } else {
          const v = vel[i];
          pos[i*3] += v.d.x * v.s * dt;
          pos[i*3+1] += v.d.y * v.s * dt;
          pos[i*3+2] += v.d.z * v.s * dt;
        }
      }
      burst.geometry.attributes.position.needsUpdate = true;

      beamGroup.children.forEach(b => {
        b.userData.mat.uniforms.uTime.value = S.elapsed;
        b.rotation.z = b.userData.ang + S.elapsed * 0.2;
      });
      beamGroup.rotation.y = S.elapsed * 0.1;

      connTimer += dt;
      if (op > 0.05 && connTimer > 0.06) {
        connTimer = 0;
        spawnConn();
      }
      for (let i = connGroup.children.length - 1; i >= 0; i--) {
        const c = connGroup.children[i];
        c.userData.life += dt;
        const t = c.userData.life / c.userData.max;
        if (t >= 1) {
          connGroup.remove(c);
          c.geometry.dispose(); c.material.dispose();
          continue;
        }
        c.material.opacity = (1 - Math.abs(t - 0.5) * 2) * 0.85;
      }
    }

    return { group, update };
  }

  // ============================================================
  // STAGE 2 — AUTONOMOUS RESPONSE
  // ============================================================
  function buildResponse() {
    const group = new THREE.Group();

    // Reflective-ish floor
    const floor = new THREE.Mesh(
      new THREE.PlaneGeometry(40, 40),
      new THREE.MeshStandardMaterial({
        color: 0x030710, metalness: 0.7, roughness: 0.55,
        emissive: 0x06101e, emissiveIntensity: 0.12,
      })
    );
    floor.rotation.x = -Math.PI / 2;
    floor.position.y = -1.5;
    group.add(floor);

    // floor grid
    const grid = new THREE.GridHelper(40, 40, 0x00d4ff, 0x00d4ff);
    grid.material.transparent = true;
    grid.material.opacity = 0.12;
    grid.material.blending = THREE.AdditiveBlending;
    grid.position.y = -1.49;
    group.add(grid);

    // Endpoint cubes
    const cubes = [];
    const CX = 9, CZ = 9;
    const cubeGroup = new THREE.Group();
    for (let z = 0; z < CZ; z++) {
      for (let x = 0; x < CX; x++) {
        const cube = new THREE.Mesh(
          new THREE.BoxGeometry(0.26, 0.26, 0.26),
          new THREE.MeshStandardMaterial({
            color: 0xff3366, emissive: 0xff0033, emissiveIntensity: 0.75,
            metalness: 0.6, roughness: 0.3,
          })
        );
        cube.position.set((x - (CX - 1) / 2) * 0.7, -1.0, (z - (CZ - 1) / 2) * 0.7);
        const d = Math.sqrt(
          ((x - (CX - 1) / 2) * 0.7) ** 2 +
          ((z - (CZ - 1) / 2) * 0.7) ** 2
        );
        cube.userData = { dist: d, baseY: -1.0, state: 'infected', flashT: 0 };
        cubeGroup.add(cube);
        cubes.push(cube);
      }
    }
    group.add(cubeGroup);

    // Shockwave rings
    const waves = [];
    for (let i = 0; i < 3; i++) {
      const w = new THREE.Mesh(
        new THREE.TorusGeometry(0.5, 0.025, 16, 96),
        new THREE.MeshBasicMaterial({
          color: 0x00d4ff, transparent: true, opacity: 0,
          blending: THREE.AdditiveBlending, depthWrite: false,
        })
      );
      w.rotation.x = Math.PI / 2;
      w.position.y = -0.99;
      waves.push(w);
      group.add(w);
    }

    // Origin pulse
    const pulse = new THREE.Mesh(
      new THREE.SphereGeometry(0.3, 32, 32),
      new THREE.MeshBasicMaterial({
        color: 0x00d4ff, transparent: true, opacity: 0,
        blending: THREE.AdditiveBlending, depthWrite: false,
      })
    );
    pulse.position.y = -1.0;
    group.add(pulse);

    // Containment dome
    const domeU = { uTime: { value: 0 }, uColor: { value: new THREE.Color(0x00d4ff) }, uOpacity: { value: 0 } };
    const dome = new THREE.Mesh(
      new THREE.SphereGeometry(3.4, 64, 32, 0, TAU, 0, Math.PI / 2),
      new THREE.ShaderMaterial({
        uniforms: domeU,
        transparent: true, blending: THREE.AdditiveBlending, depthWrite: false,
        side: THREE.DoubleSide,
        vertexShader: `varying vec3 vN;varying vec2 vUv;void main(){vN=normalize(normalMatrix*normal);vUv=uv;gl_Position=projectionMatrix*modelViewMatrix*vec4(position,1.0);}`,
        fragmentShader: `
          varying vec3 vN; varying vec2 vUv;
          uniform vec3 uColor; uniform float uTime; uniform float uOpacity;
          void main(){
            float grid = step(0.97, fract(vUv.x*24.0)) + step(0.97, fract(vUv.y*12.0));
            float fres = pow(1.0 - abs(dot(vN, vec3(0,0,1))), 1.6);
            float p = 0.5 + 0.5 * sin(uTime*3.0 - vUv.y*12.0);
            float a = (grid*0.4 + fres*0.7 + p*0.08) * uOpacity;
            gl_FragColor = vec4(uColor, a);
          }`
      })
    );
    dome.position.y = -1.0;
    group.add(dome);

    // Atmospheric dust
    const dustN = 700;
    const dpos = new Float32Array(dustN * 3);
    for (let i = 0; i < dustN; i++) {
      dpos[i*3] = (Math.random() - 0.5) * 14;
      dpos[i*3+1] = Math.random() * 4 - 1;
      dpos[i*3+2] = (Math.random() - 0.5) * 14;
    }
    const dustGeo = new THREE.BufferGeometry();
    dustGeo.setAttribute('position', new THREE.BufferAttribute(dpos, 3));
    const dust = new THREE.Points(dustGeo, new THREE.PointsMaterial({
      size: 0.025, color: 0x80c8ff,
      transparent: true, opacity: 0.45,
      blending: THREE.AdditiveBlending, depthWrite: false,
      sizeAttenuation: true,
    }));
    group.add(dust);

    function update(dt, op) {
      const lt = rangeLocal(2, S.pSmooth);
      // Wave radius rides progress + gesture momentum
      const baseR = lt * 5.6;
      const push = clamp(S.vSmooth * 4, -1, 2);
      const waveR = Math.max(0.05, baseR + push * 0.3);

      waves.forEach((w, i) => {
        const r = Math.max(0.05, waveR + i * 0.5 - i * 0.15);
        w.scale.set(r, r, 1);
        const fade = clamp(1 - r / 6.5, 0, 1);
        w.material.opacity = fade * (op > 0.05 ? 0.95 : 0);
      });

      const pAmp = (1 - lt) * 1.6;
      pulse.scale.setScalar(1 + 0.4 * Math.sin(S.elapsed * 6) * pAmp);
      pulse.material.opacity = pAmp * 0.7;

      cubes.forEach(c => {
        if (waveR > c.userData.dist * 0.95 && c.userData.state === 'infected') {
          c.userData.state = 'secure';
          c.userData.flashT = 0;
        }
        c.userData.flashT += dt;
        const ft = c.userData.flashT;
        if (c.userData.state === 'secure') {
          c.material.color.lerp(new THREE.Color(0x00d4ff), 0.06);
          c.material.emissive.lerp(new THREE.Color(0x00aaff), 0.06);
          const lift = 0.16 * Math.exp(-ft * 3) * Math.sin(ft * 12);
          c.position.y = c.userData.baseY + lift;
          c.rotation.y += dt * 0.2;
        } else {
          // glitchy infected
          c.position.y = c.userData.baseY + Math.sin(S.elapsed * 8 + c.userData.dist * 3) * 0.02;
          c.rotation.y += dt * 0.4;
        }
      });

      domeU.uTime.value = S.elapsed;
      const domeOp = clamp(lt * 1.2 - 0.05, 0, 1) * 0.85;
      domeU.uOpacity.value = domeOp;
      const ds = 1 + waveR * 0.08;
      dome.scale.set(ds, ds, ds);

      group.rotation.y = lerp(group.rotation.y, S.cursorSmooth.x * 0.18, dt * 4);

      const dpa = dust.geometry.attributes.position.array;
      for (let i = 0; i < dustN; i++) {
        dpa[i*3+1] += dt * 0.12;
        if (dpa[i*3+1] > 3) dpa[i*3+1] = -1;
      }
      dust.geometry.attributes.position.needsUpdate = true;
    }

    return { group, update };
  }

  // ============================================================
  // PUBLIC API
  // ============================================================
  window.threeStage = {
    mount(canvas) { init(canvas); },
    setProgress(p) { S.progress = clamp(p, 0, 1); },
    setVelocity(v) { S.velocity = v; },
    setCursor(x, y) { S.cursor.x = clamp(x, -1, 1); S.cursor.y = clamp(y, -1, 1); },
    setAccent(rgb) { S.accent.setRGB(rgb[0] / 255, rgb[1] / 255, rgb[2] / 255); },
    setQuality(q) { S.quality = clamp(q, 0.5, 1); resize(); },
    ranges: () => S.ranges.slice(),
  };
})();
