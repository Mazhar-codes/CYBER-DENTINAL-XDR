# Cyber Attack Graph — UI Kit

A node-link visualization of multi-stage cyber attacks for the Cyber Sentinel XDR dashboard. Designed against the codebase's existing tokens (panel gradient, severity palette, neon glow, Inter + Fira Code).

## Files
- `index.html` — interactive demo (open this)
- `AttackGraph.jsx` — D3 force-simulation graph with neon edges, pulse-on-alert
- `NodeDetailPanel.jsx` — slide-in side panel with SHAP, timeline, suggested response
- `GraphLegend.jsx` — node + edge legend
- `GraphControls.jsx` — zoom/pan/replay attack chain
- `mockData.js` — simulated WebSocket telemetry

## Surfaces shown
- **Attack Graph view** — full canvas with hovering tooltips, click-to-open side panel, sequential path lighting on attack replay, pulse halos on CRITICAL nodes.

The kit is a faithful recreation that fits next to existing views (Network, Alerts, Endpoint) and reuses Sidebar / topbar chrome.
