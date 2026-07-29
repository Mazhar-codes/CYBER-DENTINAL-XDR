/* global React */
// NodeDetailPanel.jsx — slide-in side panel: SHAP / Timeline / Response
const { useState: useStateNDP } = React;

function NodeDetailPanel({ node, data, onClose, onJumpToStep }) {
  const [tab, setTab] = useStateNDP("shap");
  if (!node) return null;
  const sev = window.AG_SEV_COLOR[node.severity];
  const style = window.AG_NODE_STYLE[node.type];
  const shap = data.SHAP[node.id] || [];
  const responses = data.RESPONSES[node.id] || [];

  return (
    <div className="ag-panel">
      <div className="ag-panel-head" style={{ borderColor: sev + "44" }}>
        <div className="ag-panel-head-row">
          <span className="ag-panel-glyph" style={{ background: style.color + "22", color: style.color, borderColor: style.color + "55" }}>
            {style.glyph}
          </span>
          <div className="ag-panel-titles">
            <div className="ag-panel-eyebrow" style={{ color: sev }}>{node.severity} · {style.label}</div>
            <div className="ag-panel-title">{node.label}</div>
          </div>
          <button className="ag-panel-close" onClick={onClose}>×</button>
        </div>
        <div className="ag-panel-meta">
          {node.ip      && <span className="mono ag-meta-chip">{node.ip}</span>}
          {node.pid     && <span className="mono ag-meta-chip">PID {node.pid}</span>}
          {node.dept    && <span className="ag-meta-chip">{node.dept}</span>}
          {node.country && <span className="mono ag-meta-chip">{node.country}</span>}
          {node.hash    && <span className="mono ag-meta-chip">SHA {node.hash}</span>}
        </div>
        <div className="ag-panel-risk">
          <span className="ag-panel-risk-lbl">RISK SCORE</span>
          <div className="ag-panel-risk-bar">
            <div className="ag-panel-risk-fill" style={{ width: `${node.risk}%`, background: `linear-gradient(90deg, ${sev}, ${sev}aa)`, boxShadow: `0 0 12px ${sev}` }} />
          </div>
          <span className="ag-panel-risk-val" style={{ color: sev }}>{node.risk}<span style={{ opacity: 0.5, fontSize: "11px" }}>/100</span></span>
        </div>
      </div>

      <div className="ag-panel-tabs">
        {[
          { k: "shap", l: "SHAP Explanation" },
          { k: "tl",   l: "Timeline" },
          { k: "resp", l: "Suggested Response" },
        ].map(t => (
          <button key={t.k}
            className={"ag-panel-tab" + (tab === t.k ? " active" : "")}
            onClick={() => setTab(t.k)}>
            {t.l}
          </button>
        ))}
      </div>

      <div className="ag-panel-body">
        {tab === "shap" && (
          <div className="ag-shap">
            {shap.length === 0 && <div className="ag-empty">No model attribution recorded for this node.</div>}
            <div className="ag-shap-head">FEATURE CONTRIBUTIONS · ml-pipeline-v3</div>
            {shap.map((s, i) => {
              const pct = Math.abs(s.value) * 100 / 0.5; // normalize visual
              const positive = s.dir === "+";
              return (
                <div key={i} className="ag-shap-row">
                  <div className="ag-shap-feat mono">{s.feature}</div>
                  <div className="ag-shap-bar-wrap">
                    <div className="ag-shap-bar" style={{
                      width: `${Math.min(pct, 100)}%`,
                      background: positive ? "#dc2626" : "#22c55e",
                      boxShadow: `0 0 8px ${positive ? "#dc2626" : "#22c55e"}66`,
                      marginLeft: positive ? 0 : "auto"
                    }} />
                  </div>
                  <div className="ag-shap-val mono" style={{ color: positive ? "#fca5a5" : "#86efac" }}>
                    {positive ? "+" : ""}{s.value.toFixed(2)}
                  </div>
                </div>
              );
            })}
            <div className="ag-shap-foot">
              <span>Higher values push toward <strong style={{ color: "#fca5a5" }}>MALICIOUS</strong>; negative values toward BENIGN.</span>
            </div>
          </div>
        )}

        {tab === "tl" && (
          <div className="ag-tl">
            {data.TIMELINE.map((t, i) => (
              <div key={i}
                className={"ag-tl-row" + (t.src === node.id || t.dst === node.id ? " active" : "")}
                onClick={() => onJumpToStep(i + 1)}>
                <div className="ag-tl-step mono">#{String(i + 1).padStart(2, "0")}</div>
                <div className="ag-tl-time mono">{t.ts}</div>
                <div className="ag-tl-action">
                  <span className="ag-tl-action-name">{t.action}</span>
                  <span className="ag-tl-edge mono">{idLbl(data, t.src)} <span style={{ color: "#ef4444" }}>→</span> {idLbl(data, t.dst)}</span>
                </div>
              </div>
            ))}
          </div>
        )}

        {tab === "resp" && (
          <div className="ag-resp">
            {responses.length === 0 && <div className="ag-empty">No automated response playbook matched this node.</div>}
            {responses.map((r, i) => (
              <div key={i} className="ag-resp-card">
                <div className="ag-resp-head">
                  <span className="ag-resp-name">{r.action}</span>
                  <span className={`ag-resp-risk ag-resp-risk-${r.risk}`}>{r.risk.toUpperCase()} RISK</span>
                </div>
                <div className="ag-resp-body">
                  <div className="ag-resp-target mono">target: {r.target}</div>
                  <div className="ag-resp-dur mono">eta: {r.duration}</div>
                </div>
                <div className="ag-resp-actions">
                  <button className="ag-resp-btn ag-resp-btn-go">EXECUTE</button>
                  <button className="ag-resp-btn ag-resp-btn-cancel">DISMISS</button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function idLbl(data, id) {
  const n = data.NODES.find(x => x.id === id);
  return n ? n.label : id;
}

window.NodeDetailPanel = NodeDetailPanel;
