/* global React, ReactDOM */
const { useState, useEffect, useMemo } = React;

function App() {
  const data = window.MOCK_GRAPH;
  const [selected, setSelected] = useState(null);
  const [hoveredId, setHoveredId] = useState(null);
  const totalSteps = data.EDGES.filter(e => e.malicious).length;
  const [replayStep, setReplayStep] = useState(totalSteps); // start fully lit
  const [paused, setPaused] = useState(true);
  const [eventRate, setEventRate] = useState(38.4);
  const [alertCount, setAlertCount] = useState(7);

  // Auto-replay animation
  useEffect(() => {
    if (paused) return;
    const id = setInterval(() => {
      setReplayStep(s => {
        if (s >= totalSteps) { setPaused(true); return totalSteps; }
        return s + 1;
      });
    }, 900);
    return () => clearInterval(id);
  }, [paused, totalSteps]);

  // Simulated WebSocket telemetry
  useEffect(() => {
    const id = setInterval(() => {
      setEventRate(r => Math.max(8, Math.min(120, r + (Math.random() - 0.5) * 12)));
      if (Math.random() < 0.18) setAlertCount(c => c + 1);
    }, 1400);
    return () => clearInterval(id);
  }, []);

  const startReplay = () => { setReplayStep(0); setPaused(false); };

  return (
    <div className="app">
      <Sidebar alertCount={alertCount} />
      <div className="main">
        <div className="topbar">
          <span className="topbar-title">Attack Graph</span>
          <span className="topbar-sub mono">/ correlation engine v3.2</span>
          <div className="topbar-spacer" />
          <span className="topbar-pill"><span className="dot" />WSS · LIVE</span>
          <button className="topbar-btn" onClick={startReplay}>▶  REPLAY ATTACK</button>
          <button className="topbar-btn topbar-btn-danger">ISOLATE FLEET</button>
        </div>

        <div className="stats">
          <Stat label="ACTIVE ATTACKS" value={alertCount} delta="+3 in 5m"      c="#dc2626" />
          <Stat label="NODES OBSERVED" value={data.NODES.length} delta="streaming" c="#00d4ff" />
          <Stat label="MEAN RISK"      value={73} delta="+12 vs 1h" c="#ea580c" />
          <Stat label="EVENTS / SEC"   value={eventRate.toFixed(1)} delta="ML-pipeline-v3" c="#a78bfa" />
        </div>

        <div className="graph-wrap">
          <div className="graph-area">
            <window.AttackGraph
              data={data}
              onNodeClick={setSelected}
              hoveredId={hoveredId}
              setHoveredId={setHoveredId}
              replayStep={replayStep}
              paused={paused}
            />
            {selected && (
              <window.NodeDetailPanel
                node={selected}
                data={data}
                onClose={() => setSelected(null)}
                onJumpToStep={(i) => { setReplayStep(i); setPaused(true); }}
              />
            )}
          </div>
          <div className="right-rail">
            <window.GraphControls
              replayStep={replayStep}
              totalSteps={totalSteps}
              paused={paused}
              setPaused={setPaused}
              setReplayStep={setReplayStep}
              alertCount={alertCount}
              eventRate={eventRate}
            />
            <window.GraphLegend />
            <RecentEvents data={data} />
          </div>
        </div>
      </div>
    </div>
  );
}

function Stat({ label, value, delta, c }) {
  return (
    <div className="stat" style={{ "--c": c }}>
      <div className="stat-lbl">{label}</div>
      <div className="stat-val">{value}</div>
      <div className="stat-delta">{delta}</div>
    </div>
  );
}

function Sidebar({ alertCount }) {
  const items = [
    { l: "Overview",      g: "▣", k: "ov" },
    { l: "Attack Graph",  g: "◈", k: "ag", active: true, badge: alertCount },
    { l: "Alerts",        g: "▲", k: "al" },
    { l: "Endpoints",     g: "▥", k: "ep" },
    { l: "Network",       g: "⬡", k: "nw" },
    { l: "Sysmon",        g: "⬣", k: "sy" },
    { l: "Malware",       g: "◬", k: "mw" },
    { l: "Users",         g: "◉", k: "us" },
  ];
  const sysItems = [
    { l: "Audit Log",     g: "▤", k: "au" },
    { l: "System Status", g: "▦", k: "ss" },
    { l: "Settings",      g: "⚙", k: "se" },
  ];
  return (
    <div className="sidebar">
      <div className="sb-brand">
        <div className="sb-logo">🛡️</div>
        <div>
          <div className="sb-name">CYBER SENTINEL</div>
          <div className="sb-tag">XDR PLATFORM</div>
        </div>
      </div>
      <div className="sb-section">DETECTION</div>
      {items.map(i => (
        <div key={i.k} className={"sb-item" + (i.active ? " active" : "")}>
          <span className="sb-glyph">{i.g}</span>
          <span>{i.l}</span>
          {i.badge ? <span className="sb-badge">{i.badge}</span> : null}
        </div>
      ))}
      <div className="sb-section">SYSTEM</div>
      {sysItems.map(i => (
        <div key={i.k} className="sb-item">
          <span className="sb-glyph">{i.g}</span>
          <span>{i.l}</span>
        </div>
      ))}
      <div className="sb-foot">
        <div className="sb-foot-avatar">SK</div>
        <div>
          <div className="sb-foot-name">soc.kelly</div>
          <div className="sb-foot-role">TIER-2 ANALYST</div>
        </div>
      </div>
    </div>
  );
}

function RecentEvents({ data }) {
  const events = data.TIMELINE.slice().reverse().slice(0, 5);
  return (
    <div className="ag-legend">
      <div className="ag-legend-head" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span>RECENT EVENTS</span>
        <span style={{ display: "inline-flex", alignItems: "center", gap: "4px", color: "#22c55e" }}>
          <span className="ag-ctl-livedot" /> live
        </span>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: "5px" }}>
        {events.map((e, i) => (
          <div key={i} style={{ display: "grid", gridTemplateColumns: "52px 1fr", gap: "8px", alignItems: "baseline", padding: "4px 0", borderBottom: i < events.length - 1 ? "1px dashed rgba(255,255,255,0.05)" : "none" }}>
            <span className="mono" style={{ fontSize: "9px", color: "#64748b" }}>{e.ts}</span>
            <span style={{ fontSize: "10px", color: "#cbd5e1" }}>
              <span style={{ color: "#fca5a5", textTransform: "capitalize", fontWeight: 700 }}>{e.action}</span>
              <span className="mono" style={{ color: "#64748b", marginLeft: "6px" }}>{e.src} → {e.dst}</span>
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
