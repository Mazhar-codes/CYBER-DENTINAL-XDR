/* global React */
// GraphLegend.jsx + GraphControls.jsx
const { useState: useStateGC } = React;

function GraphLegend() {
  const items = [
    { k: "endpoint", g: "▣", c: "#3b82f6", l: "Endpoint" },
    { k: "process",  g: "⬣", c: "#a78bfa", l: "Process" },
    { k: "ip",       g: "◈", c: "#00d4ff", l: "IP / Domain" },
    { k: "file",     g: "◬", c: "#f97316", l: "File" },
    { k: "user",     g: "◉", c: "#22c55e", l: "User" },
  ];
  return (
    <div className="ag-legend">
      <div className="ag-legend-head">NODE TYPES</div>
      <div className="ag-legend-list">
        {items.map(i => (
          <div key={i.k} className="ag-legend-item">
            <span className="ag-legend-dot" style={{ color: i.c, borderColor: i.c + "55", background: i.c + "1a" }}>{i.g}</span>
            <span className="ag-legend-lbl">{i.l}</span>
          </div>
        ))}
      </div>
      <div className="ag-legend-head" style={{ marginTop: "12px" }}>EDGES</div>
      <div className="ag-legend-edges">
        <div className="ag-legend-edge"><span className="ag-edge-line ag-edge-mal" /><span>Attack chain (lit)</span></div>
        <div className="ag-legend-edge"><span className="ag-edge-line ag-edge-pot" /><span>Potential malicious</span></div>
        <div className="ag-legend-edge"><span className="ag-edge-line ag-edge-norm" /><span>Normal activity</span></div>
      </div>
    </div>
  );
}

function GraphControls({ replayStep, totalSteps, paused, setPaused, setReplayStep, alertCount, eventRate }) {
  return (
    <div className="ag-controls">
      <div className="ag-controls-row">
        <button className="ag-ctl-btn"
          onClick={() => setReplayStep(0)} title="Reset">
          <span style={{ fontSize: "13px" }}>⟲</span>
        </button>
        <button className="ag-ctl-btn ag-ctl-play"
          onClick={() => setPaused(p => !p)}>
          {paused ? "▶  REPLAY" : "❚❚ PAUSE"}
        </button>
        <button className="ag-ctl-btn"
          onClick={() => setReplayStep(s => Math.min(s + 1, totalSteps))} title="Step">
          <span style={{ fontSize: "13px" }}>▷|</span>
        </button>
        <div className="ag-ctl-step mono">
          STEP {String(replayStep).padStart(2, "0")} <span style={{ color: "#475569" }}>/ {String(totalSteps).padStart(2, "0")}</span>
        </div>
      </div>
      <div className="ag-ctl-track">
        <div className="ag-ctl-track-fill" style={{ width: `${(replayStep / totalSteps) * 100}%` }} />
        {Array.from({ length: totalSteps }).map((_, i) => (
          <div key={i} className={"ag-ctl-tick" + (i < replayStep ? " hot" : "")}
            style={{ left: `${((i + 1) / totalSteps) * 100}%` }}
            onClick={() => setReplayStep(i + 1)} />
        ))}
      </div>
      <div className="ag-controls-row" style={{ justifyContent: "space-between" }}>
        <div className="ag-ctl-stat">
          <span className="ag-ctl-stat-lbl">ACTIVE ALERTS</span>
          <span className="ag-ctl-stat-val" style={{ color: "#dc2626" }}>{alertCount}</span>
        </div>
        <div className="ag-ctl-stat">
          <span className="ag-ctl-stat-lbl">EVENTS / SEC</span>
          <span className="ag-ctl-stat-val mono" style={{ color: "#00d4ff" }}>{eventRate.toFixed(1)}</span>
        </div>
        <div className="ag-ctl-stat">
          <span className="ag-ctl-stat-lbl">WS</span>
          <span className="ag-ctl-stat-val" style={{ color: "#22c55e", display: "inline-flex", alignItems: "center", gap: "5px" }}>
            <span className="ag-ctl-livedot" /> CONNECTED
          </span>
        </div>
      </div>
    </div>
  );
}

window.GraphLegend = GraphLegend;
window.GraphControls = GraphControls;
