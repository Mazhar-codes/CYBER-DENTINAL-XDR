# Cyber Sentinel XDR — Design System

A complete design system for **Cyber Sentinel XDR**, an Extended Detection & Response (XDR) platform for Security Operations Centers. The product surfaces real-time network, endpoint, user-behavior, malware and Sysmon telemetry, correlates them via a fusion engine, and lets analysts trigger SOAR-style responses (kill process, block IP, isolate host, quarantine file).

The visual language is **dark-cyber**: deep navy surfaces, blue-cyan brand, neon glows on alerts, severity-coded chromatic accents, and tracked-out caps labels reminiscent of military / SOC HUDs. Animations are restrained but signature — pulses on live indicators, scan-lines, glitch on unauthorized-access, and Framer Motion transitions between views.

## Sources

- **Codebase** (mounted, read-only): `src/` — React + TypeScript + Socket.IO + Framer Motion + ECharts. Key files:
  - `src/styles/global.css` — animation library, glow utilities, cyber-grid background
  - `src/styles/theme.ts` — token export (`bg`, `primary`, `success`, `warning`, `danger`, glows)
  - `src/components/shared/{Sidebar,SeverityBadge,StatCard,LiveIndicator,types.ts}` — atoms
  - `src/components/views/*` — the surfaces (Overview / Network / Alerts / Endpoint / Malware / Sysmon / UserBehavior / SystemStatus)
  - `src/components/NetworkMonitor.tsx` — top-level shell + socket plumbing
  - `src/pages/{LoginPage,RegisterPage,MFASetupPage}.tsx` — auth flows with OTP, glitch banner, particle bg
- **Logo asset:** `assets/logo-cyber-sentinel.svg` (lifted from `src/logo.svg`)

## Index

| File | Purpose |
| --- | --- |
| `colors_and_type.css` | All design tokens — color, type, spacing, radius, shadow, glow |
| `assets/` | Logos and icon references |
| `preview/` | Cards rendered in the Design System tab |
| `ui_kits/attack-graph/` | The **Cyber Attack Graph** UI kit (this project's deliverable) |
| `SKILL.md` | Agent SKILL definition (cross-compatible with Claude Code) |

## Products represented

This system covers **one product**, the Cyber Sentinel XDR web dashboard. The user has asked us to design **a new view inside it**: the **Cyber Attack Graph** — a node-link visualization of multi-stage attacks across endpoints, processes, IPs, files and users, with real-time updates, hover detail, side-panel SHAP explanation, sequential path lighting, and pulse-on-alert.

## Content fundamentals

**Tone:** terse, factual, machine-adjacent. Labels read like a Linux daemon's status output — UPPERCASE TRACKED-OUT, no marketing voice. Body text is short and observational ("Live flow analysis — 3-stage ML pipeline"). The product never says *we* or *you*; it states what the system is doing in third person ("Monitoring active — network loop running", "No correlated attacks detected — system monitoring all domains").

**Casing rules**
- **UPPERCASE** for status/severity/source labels: `LIVE`, `ATTACK`, `NORMAL`, `CRITICAL`, `MONITORING ACTIVE`, `RESPOND`. Always tracked out (`letter-spacing: 1px`+).
- **Title Case** for nav, view headers, section headers ("Network Detection", "Alerts & Incidents", "Correlated Attacks").
- **lowercase** for hint text and footers ("99 rows", "top 3 ▾", "HIGH / CRITICAL only").
- Numbers use bare integers in stat cards; percentages always to 1dp (`62.4%`); IPs in mono cyan/indigo.

**Copywriting examples (lifted from the codebase)**
- Headers: "Network Detection", "Alerts & Incidents", "Combined alert stream from network detection and user behavior analysis"
- Empty states: "No correlated attacks detected — system monitoring all domains", "Start monitoring to see live network flows."
- Status: "Monitoring active — network loop running", "Capturing flows…", "First capture in progress…"
- Buttons: "Start Monitoring", "Stop Monitoring", "Simulate Attack", "Respond", "Sign Out", "Enable Sound Alerts"
- Errors: glitch text "ACCESS DENIED", "Replay blocked — code already used", "Account locked — try again in 15 minutes"

**No emoji as decoration.** A handful of unicode symbols *do* show up: shield 🛡️ in the brand mark, lightning ⚡ on Simulate Attack, check ✓ on confirmations, and attack-type glyphs (💥 DoS, 🌊 DDoS, 🔍 PortScan, 🔨 BruteForce, 🕷️ WebAttack, 🤖 Botnet, 🩸 Heartbleed, 🥷 Infiltration). Treat these as semantic icons, not flourishes — never invent new ones. Prefer the geometric unicode glyphs the sidebar uses (`◈ ⬡ ◉ ◬ ▣ ◫ ⬣`) for nav-style decoration.

## Visual foundations

**Palette.** Surface stack: `#0a1120` (app) → `#0d1629/#0a1120` (sidebar gradient) → `#1e293b/#162032` (panel gradient, 135°) → `#192334` (zebra). Brand is dual: legacy cyan `#00d4ff` (used in glow/text-shadow effects, neon utility) and tactical blue `#3b82f6 → #1d4ed8` (gradient, primary action, nav-active). Severity is the working palette: CRITICAL `#dc2626`, HIGH `#ea580c`, MEDIUM `#d97706`, LOW `#22c55e`. Attack types each get their own color (DoS red, PortScan orange, WebAttack purple, Botnet rose, Heartbleed dark red, etc).

**Type.** Inter sans for everything chrome (substituted via Google Fonts; codebase imports it from system + Segoe UI fallback). Fira Code mono for IPs, timestamps, file paths, MITRE IDs, percentages in tables. Inter weights used: 400 (body), 500 (label), 700 (emphasis), 800 (stat values, headers). No serif anywhere. Headings get `letter-spacing: -0.5px`; eyebrows/labels get `+1.5px` to `+2px` (the SOC HUD signature).

**Spacing.** 4-px scale; common rhythm is `padding: 18-22px` on cards, `gap: 10-16px` between cards, `padding: 24px` on page containers. Stat cards are 130-140px min-width; main panels fill columns.

**Backgrounds.** No imagery, no photography. The surface is solid navy plus an animated 40-px **cyber grid** (`linear-gradient` 1px lines at 4% blue alpha, slowly translating). Auth pages add a subtle particle layer (floating dots with `float-up` keyframe). Never use bluish-purple gradients; the only gradients are the panel gradient (135°), sidebar gradient (180°), topbar gradient (90°), brand-blue button gradient, and danger button gradient.

**Animation.** All easings are `cubic-bezier(0.4, 0, 0.2, 1)` (the codebase's house ease). Durations: `0.15s` for hover/state, `0.18-0.25s` for entrances/route changes, `1.4s` for pulses, `3s` for scan-lines, `8s` for the slow grid drift. Framer Motion handles view transitions: `initial={{opacity:0,x:20}} animate={{opacity:1,x:0}} exit={{opacity:0,x:-20}}`. Live indicators **pulse opacity**, alerts **pulse border + box-shadow**, severity dots have a 6-px colored glow.

**Hover / press states.** Buttons: `filter: brightness(1.15)` plus a **same-color glow** (e.g. blue button gets `0 0 20px rgba(59,130,246,0.4)` on hover). Severity / type chips: subtle bg deepening from `${color}1a` to `${color}22` and border from `${color}44` to `${color}55`. No scale-up; the brand keeps a flat-press feel except for Framer-motion `whileHover={{scale:1.05}}` on top-bar action buttons (the rare exception). Disabled state: bg `#1e293b`, color `#334155`, `cursor: not-allowed`, no glow.

**Borders.** Single 1-px border in `#1e293b` is universal. Cards get a **left accent border of 4px in the semantic color** — this is the most recognizable shape in the system (severity stat cards, alert summary blocks). Chips combine a low-opacity background (`color1a`) with a low-opacity border (`color44`).

**Shadows + glow.** Two systems running in parallel. Depth shadow is conventional `0 2px 8px rgba(0,0,0,0.3)` on cards, `0 8px 24px rgba(0,0,0,0.6)` on popovers. **Glow** is the brand voice: every alert state, live indicator, severity dot, and active button gets an outer `box-shadow` colored by its semantic color (cyan/blue/red/green/amber). Glow ranges from 6px (dot indicator) to 30-40px (CRITICAL alert). Inner glows (`inset 0 0 20px ...`) appear on the unauthorized-access overlay and pulse-border keyframe.

**Transparency + blur.** Used sparingly. The Toaster, the user-avatar pill, and the glass card variant all use `rgba(0,20,40,0.6-0.95)` with `backdrop-filter: blur(12px)`. Modals over the dashboard fade through `rgba(0,0,0,0.7)` overlays. No blur on regular surfaces — they stay opaque so data reads cleanly.

**Corner radii.** A consistent ladder: `4px` (micro chip), `6px` (small button, severity tag), `8px` (button, input, pill button), `10px` (stat card), `12px` (large card), `14px` (main panel, the most-used). Pill capsules use `20px` for the LIVE / RESPOND / status badges.

**Cards.** The canonical card is `linear-gradient(135deg, #1e293b → #162032)` + `1px solid #1e293b` + `border-radius: 14px` + `padding: 14-22px` + the depth shadow. Stat-card variant adds `4px solid {accent}` left border and a faint colored radial in the top-right corner (an 80px-radius `${accent}0d` blob that bleeds in). Alert/critical variant adds a same-color 20px box-shadow glow.

**Layout.** Sidebar (220px expanded, 60px collapsed) on the left, fixed-height topbar (56px), scrollable main. Page containers `padding: 24px`, `gap: 16-18px` between sections. Stat strips are `display: flex; gap: 10px; flex-wrap: wrap;` with each card `flex: 1; min-width: 110-130px`. Main two-column layouts are `grid-template-columns: 2fr 1fr`. Tables are full-width inside their panel with sticky-feeling headers (`background: #0a1120`, uppercase 10-px tracked labels).

## Iconography

Three layers, in order of preference:

1. **Geometric unicode glyphs** — already used in the sidebar (`◈ ⬡ ◉ ◬ ▣ ◫ ⬣`) and severity dots. Keep using these for any nav/decoration; they read as "tactical HUD" without needing an icon font.
2. **Lucide icons via CDN** — for any new icon need (shield, network, alert-triangle, eye, lock, file, user, server, terminal). Lucide's stroke-based geometric style matches the unicode glyphs and the codebase's general aesthetic. Loaded from `https://unpkg.com/lucide@latest`. **Flagged as a substitution** — the codebase doesn't currently ship with an icon font and uses unicode + emoji exclusively, so we're proposing Lucide as the formal icon system going forward. Confirm with engineering.
3. **Semantic emoji** — only the eight attack-type glyphs (💥 🌊 🔍 🔨 🕷️ 🤖 🩸 🥷) and the brand shield 🛡️ in the sidebar logo. Plus ⚡ on Simulate Attack, ✓ on confirmations, 🔔 on Enable Sound. **Do not invent new emoji** — match this exact palette or fall back to Lucide.

No SVG icons exist in the codebase except `src/logo.svg` (the React default — see asset). The brand mark in the sidebar is a CSS-painted rounded square with the shield emoji centered + a blue-gradient bg + cyan glow. We reproduce this faithfully in the UI kit.

## Font substitution

Inter and Fira Code are referenced by name only; no `.ttf`/`.woff` ships with the codebase. We pull both from Google Fonts. **Flag:** if engineering self-hosts these in production, drop the woff2 files into `fonts/` and we'll wire them up.

## CAVEATS / asks

- The product currently uses `🛡️` emoji as the brand mark. We've kept it as-is in the UI kit; consider commissioning a real wordmark.
- Lucide icons are proposed as the formal icon system — currently the codebase mixes unicode glyphs and emoji ad-hoc.
- Fonts are pulled from Google CDN; please supply self-hosted woff2 if needed.
