---
name: Attack Graph Feature — Integration State 2026-05-09
description: D3 Attack Graph view architectural assessment; reference kit found at Attack_Graph/ui_kits/attack-graph/; integration not yet started
type: project
---

Reference kit (AttackGraph.jsx, NodeDetailPanel.jsx, GraphControls.jsx, mockData.js, attack-graph.css, app.jsx) is a vanilla-JS CDN bundle — must be fully converted to TypeScript ESM before CRA integration.

**Critical findings:**
- D3 v7 already installed (d3 ^7.9.0, @types/d3 ^7.4.3) — no new install needed
- window.* global exports are incompatible with CRA module bundling — all must be removed
- NodeDetailPanel EXECUTE button has no role gate — CWE-285 risk if wired naively
- attack-graph.css sets body { overflow:hidden } globally — must be scoped
- SHAP format mismatch: mock uses {feature, value, dir}; real fusion_alert.shap emits string list or {reason:[...]}
- Simulation rebuilds on every data prop reference change — will lose node positions on each Socket.IO event

**Backend data availability:**
- src_ip, attack_type, severity, threat_score, shap, endpoint_id — all available in fusion_alert and soc_alert
- Edge type (downloaded/executed/lateral) — NOT available; no relationship-type field exists in any event
- Edge ordering / chain number — NOT available; must be inferred client-side from timestamps or added to GET /attack-graph
- GeoIP (country/ASN) — NOT available; no GeoIP lookup in backend
- Process-level nodes (PID, cmdline) — partially available via endpoint_alert and malware_alert only

**ViewId union change required:**
- Sidebar.tsx line 3: add "attackgraph" to the union
- NetworkMonitor.tsx ExtViewId: add "attackgraph"
- NetworkMonitor.tsx if-else router: add new branch
- No exhaustive switch statements exist — TypeScript will not error on missing branch, but branch must be added manually

**Why:** New Attack Graph view being integrated into SOC dashboard from design reference kit.
**How to apply:** When working on AttackGraphView.tsx or Socket.IO adapter: use stable graphRef pattern for simulation, detect SHAP format before rendering bar chart, always gate EXECUTE on analyst/admin role via authAxios.
