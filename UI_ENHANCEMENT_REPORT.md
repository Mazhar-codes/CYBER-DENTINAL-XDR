# Cyber Sentinel XDR — UI Enhancement Report
Generated: 2026-06-30

## Overview

Six objectives were implemented across the React/TypeScript frontend:
intelligent font scaling, professional design tokens, a full dark/light theme system,
attack-graph node/label improvements, responsive breakpoints, and a SettingsView
pre-existing build-blocker fix.

---

## Files Modified

| File | Change Type |
|------|-------------|
| `src/index.css` | Full rewrite — font-size 18px, @import theme.css, design tokens, responsive breakpoints, table hover, .card class |
| `src/theme.css` | **New file** — dark/light CSS variable system |
| `src/hooks/useTheme.ts` | **New file** — localStorage-backed theme toggle hook |
| `src/App.tsx` | Added `useTheme()` initialization call |
| `src/components/shared/Sidebar.tsx` | Added `theme`/`onToggleTheme` props + sun/moon button |
| `src/components/NetworkMonitor.tsx` | Wired `useTheme`, passed props to Sidebar, updated main bg/topbar to CSS vars |
| `src/components/shared/StatCard.tsx` | Background → `var(--bg-card)`, shadow → `var(--shadow-*)`, value font-size 30px |
| `src/components/views/AlertsView.tsx` | Panel + filter bar backgrounds → CSS vars, KPI card label font-size 11px |
| `src/components/views/EndpointView.tsx` | Panel + KPI card backgrounds → CSS vars, label font-size 11px |
| `src/components/views/OverviewView.tsx` | Panel background → CSS vars |
| `src/components/views/NetworkView.tsx` | Panel + filter bar + stat cards → CSS vars |
| `src/components/views/AttackGraphView/AttackGraph.tsx` | Label font-sizes +1px, new `ag-glow-critical` SVG filter, edge opacity 0.65 |
| `src/components/views/SettingsView.tsx` | Fixed pre-existing `autoResponse` TDZ build error (moved declaration above its useCallback dependency) |

---

## Theme Architecture

### How It Works

1. `src/theme.css` defines two CSS rule blocks — `[data-theme="dark"]` and `[data-theme="light"]` — each setting ~30 CSS custom properties for backgrounds, text, borders, severity colors, shadows, and scrollbars.

2. `src/hooks/useTheme.ts` reads `localStorage('xdr-theme')` on mount (defaults to `'dark'`), runs a `useEffect` that writes `document.documentElement.setAttribute('data-theme', theme)` and saves back to localStorage on every toggle.

3. `src/App.tsx` calls `useTheme()` at the application root so the theme initializes before any page renders (including unauthenticated pages like login/register).

4. `src/components/NetworkMonitor.tsx` also calls `useTheme()` to obtain `theme` and `toggleTheme`, passing them as `theme` and `onToggleTheme` props to `<Sidebar>`.

5. `src/components/shared/Sidebar.tsx` renders a sun/moon toggle button in the bottom section (above the user card). Clicking it calls `onToggleTheme()`, which switches the `data-theme` attribute and the entire UI transitions via CSS variable cascading.

### Key Variables

| Variable | Dark | Light |
|----------|------|-------|
| `--bg-primary` | `#0a0e1a` | `#f0f4f8` |
| `--bg-card` | `#111827` | `#ffffff` |
| `--bg-sidebar` | `#080c18` | `#1e293b` |
| `--text-primary` | `#e2e8f0` | `#1e293b` |
| `--text-heading` | `#f1f5f9` | `#0f172a` |
| `--border-color` | `rgba(255,255,255,0.08)` | `rgba(0,0,0,0.10)` |
| `--table-row-hover` | `rgba(255,255,255,0.03)` | `rgba(0,0,0,0.03)` |

The sidebar uses `--bg-sidebar` which is dark (`#1e293b`) in both themes — it never goes white.

---

## Font Scaling Changes

| Breakpoint | Base font-size |
|------------|---------------|
| ≤ 1366px | 16px |
| Default (1367–1919px) | **18px** (was 17px) |
| ≥ 1920px | 19px |
| ≥ 2560px | 21px |

Derived increases in components:
- `StatCard` KPI value: 28px → 30px; sub-label: 11px → 12px
- `AlertsView` / `EndpointView` stat card value: 22px → 24px; label: 10px → 11px
- `AttackGraph` node labels: server 12→13, endpoint/alert/CRITICAL 11→12, others 10→11

---

## Attack Graph Improvements (Objective 4)

- **CRITICAL node glow**: New SVG filter `ag-glow-critical` with `stdDeviation=6` (vs 3.5 for regular red glow). Applied to CRITICAL nodes that are not in replay/lit state.
- **Label font-sizes**: Increased across all node types (see Font Scaling above).
- **Edge opacity**: Normal (non-malicious, non-monitor) edges raised from 0.6 → 0.65.
- **Node radius**: All node types already ≥16 SVG units — well above the 8-unit threshold; no change needed.

---

## Pre-existing Bug Fixed

**`SettingsView.tsx` — `autoResponse` temporal dead zone error**

The `autoResponse` `const` was declared at line 545 but referenced in a `useCallback` dependency array at line 539. JavaScript `const` does not hoist initializers, causing a TS2448 block-scoped-variable-used-before-declaration error that blocked `npm run build`. Fixed by moving the `autoResponse` state declaration above `handleApplyThresholds` in section D (Detection Thresholds), removing the duplicate declaration in section E.

---

## Rollback Instructions

To restore the frontend to its pre-enhancement state:

1. Copy all files from `D:\Cyber Sentinal\__BACKUP_src_before_ui_enhancement` back into `D:\Cyber Sentinal\Cyber Sentinal XDR Frontend\src\`, overwriting everything.
2. Delete `D:\Cyber Sentinal\Cyber Sentinal XDR Frontend\src\theme.css` (new file, not in backup).
3. Delete `D:\Cyber Sentinal\Cyber Sentinal XDR Frontend\src\hooks\useTheme.ts` (new file, not in backup).
4. Run `npm run build` to verify.
