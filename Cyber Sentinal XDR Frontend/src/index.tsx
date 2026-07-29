import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import App from './App';
import reportWebVitals from './reportWebVitals';

// ── Global Border-Draw Effect ────────────────────────────────────────────────
// Fires on every mousedown on any non-disabled <button>.
// An SVG is appended to document.body (fixed-positioned) so it never gets
// clipped by overflow:hidden on the button itself, and auto-removed when done.
(function attachBorderDrawEffect() {
  const SVG_NS = 'http://www.w3.org/2000/svg';
  const DURATION = 520; // ms — must match xdr-border-draw-stroke duration

  document.addEventListener('mousedown', (e: MouseEvent) => {
    const target = e.target as HTMLElement;
    const btn = target.closest('button') as HTMLButtonElement | null;
    if (!btn || btn.disabled || btn.getAttribute('aria-disabled') === 'true') return;

    // Compute layout
    const r = btn.getBoundingClientRect();
    const br = parseFloat(getComputedStyle(btn).borderRadius) || 6;
    const W = r.width;
    const H = r.height;
    // Perimeter of a rounded rect (slight over-estimate so the dash fully completes)
    const perimeter = Math.ceil(2 * (W + H));

    // Resolve accent colour from CSS custom property at call time
    const accentColor = getComputedStyle(document.documentElement)
      .getPropertyValue('--accent-cyan').trim() || '#2FE0E0';

    // Build fixed-position SVG overlay on body, sized to exactly the button's
    // own box (no outward padding) with overflow:hidden as a hard clip — this
    // guarantees the drawn border can never bleed past the button into a
    // neighbouring element (e.g. the sidebar's edge) even by a pixel.
    const svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('width',  String(W));
    svg.setAttribute('height', String(H));
    svg.style.cssText = [
      'position:fixed',
      `top:${r.top}px`,
      `left:${r.left}px`,
      'pointer-events:none',
      'overflow:hidden',
      `z-index:2147483647`,
      `animation:xdr-border-draw-fade ${DURATION + 80}ms ease forwards`,
    ].join(';');

    const rect = document.createElementNS(SVG_NS, 'rect');
    rect.setAttribute('x',      '1');
    rect.setAttribute('y',      '1');
    rect.setAttribute('width',  String(Math.max(0, W - 2)));
    rect.setAttribute('height', String(Math.max(0, H - 2)));
    rect.setAttribute('rx',     String(Math.max(0, br - 1)));
    rect.setAttribute('ry',     String(Math.max(0, br - 1)));
    rect.setAttribute('fill',   'none');
    rect.setAttribute('stroke', accentColor);
    rect.setAttribute('stroke-width',     '2');
    rect.setAttribute('stroke-dasharray', String(perimeter));
    rect.setAttribute('stroke-dashoffset', String(perimeter));
    rect.style.animation =
      `xdr-border-draw-stroke ${DURATION}ms cubic-bezier(0.4,0,0.2,1) forwards`;

    svg.appendChild(rect);
    document.body.appendChild(svg);

    setTimeout(() => {
      if (svg.parentNode) svg.parentNode.removeChild(svg);
    }, DURATION + 200);
  });
})();

// ────────────────────────────────────────────────────────────────────────────

const root = ReactDOM.createRoot(
  document.getElementById('root') as HTMLElement
);
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);

// If you want to start measuring performance in your app, pass a function
// to log results (for example: reportWebVitals(console.log))
// or send to an analytics endpoint. Learn more: https://bit.ly/CRA-vitals
reportWebVitals();
