/* global React, d3 */
// AttackGraph.jsx — D3 force-directed cyber attack graph
const { useEffect, useRef, useState, useMemo, useCallback } = React;

const NODE_STYLE = {
  endpoint: { glyph: "▣", color: "#3b82f6",  size: 26, label: "Endpoint" },
  process:  { glyph: "⬣", color: "#a78bfa",  size: 22, label: "Process"  },
  ip:       { glyph: "◈", color: "#00d4ff",  size: 22, label: "IP / Domain" },
  file:     { glyph: "◬", color: "#f97316",  size: 22, label: "File"     },
  user:     { glyph: "◉", color: "#22c55e",  size: 22, label: "User"     },
};

const SEV_COLOR = {
  CRITICAL: "#dc2626",
  HIGH:     "#ea580c",
  MEDIUM:   "#d97706",
  LOW:      "#22c55e",
};

function colorFor(node) {
  if (node.severity === "CRITICAL" || node.severity === "HIGH") return SEV_COLOR[node.severity];
  return NODE_STYLE[node.type].color;
}

function AttackGraph({ data, onNodeClick, hoveredId, setHoveredId, replayStep, paused }) {
  const svgRef = useRef(null);
  const containerRef = useRef(null);
  const simRef = useRef(null);
  const [transform, setTransform] = useState({ k: 1, x: 0, y: 0 });
  const [tooltip, setTooltip] = useState(null);
  const [simReady, setSimReady] = useState(false);
  const [, setTick] = useState(0);

  // Stable copies for d3 (it mutates in place)
  const nodes = useMemo(() => data.NODES.map(n => ({ ...n })), [data]);
  const links = useMemo(() => data.EDGES.map(e => ({ ...e })), [data]);

  // Build force simulation once
  useEffect(() => {
    const W = containerRef.current.clientWidth;
    const H = containerRef.current.clientHeight;

    const sim = d3.forceSimulation(nodes)
      .force("link", d3.forceLink(links).id(d => d.id).distance(d => d.malicious ? 130 : 100).strength(0.55))
      .force("charge", d3.forceManyBody().strength(-520))
      .force("center", d3.forceCenter(W / 2, H / 2))
      .force("collide", d3.forceCollide(38))
      .alphaDecay(0.025);

    simRef.current = sim;

    // Throttle React re-renders so we don't thrash
    let raf = null;
    let firstTick = true;
    sim.on("tick", () => {
      if (firstTick) { firstTick = false; setSimReady(true); }
      if (raf) return;
      raf = requestAnimationFrame(() => { raf = null; setTick(t => t + 1); });
    });

    return () => { sim.stop(); if (raf) cancelAnimationFrame(raf); };
  }, [nodes, links]);

  // Pan / zoom
  useEffect(() => {
    const svg = d3.select(svgRef.current);
    const zoom = d3.zoom()
      .scaleExtent([0.4, 2.5])
      .on("zoom", (event) => {
        setTransform(event.transform);
      });
    svg.call(zoom);
    return () => svg.on(".zoom", null);
  }, []);

  // Drag — bind data on .node groups so d3.drag callbacks get the datum
  useEffect(() => {
    const t = setTimeout(() => {
      const sel = d3.select(svgRef.current).selectAll("g.node")
        .data(nodes, d => d.id);
      const drag = d3.drag()
        .on("start", (event, d) => {
          if (!event.active) simRef.current.alphaTarget(0.3).restart();
          d.fx = d.x; d.fy = d.y;
        })
        .on("drag", (event, d) => { d.fx = event.x; d.fy = event.y; })
        .on("end", (event, d) => {
          if (!event.active) simRef.current.alphaTarget(0);
          d.fx = null; d.fy = null;
        });
      sel.call(drag);
    }, 50);
    return () => clearTimeout(t);
  }, [nodes]);

  // Which links are "lit" up to current replayStep
  const litChain = useMemo(() => {
    const set = new Set();
    links.forEach(l => {
      if (!l.source || !l.target) return;
      if (l.malicious && l.chain && l.chain <= replayStep) {
        const sId = typeof l.source === "object" ? l.source.id : l.source;
        const tId = typeof l.target === "object" ? l.target.id : l.target;
        set.add(`${sId}->${tId}-${l.chain}`);
      }
    });
    return set;
  }, [links, replayStep]);

  // Which nodes are involved in lit chain (for pulse halo)
  const litNodes = useMemo(() => {
    const set = new Set();
    links.forEach(l => {
      if (!l.source || !l.target) return;
      if (l.malicious && l.chain && l.chain <= replayStep) {
        set.add(typeof l.source === "object" ? l.source.id : l.source);
        set.add(typeof l.target === "object" ? l.target.id : l.target);
      }
    });
    return set;
  }, [links, replayStep]);

  const handleEnter = (e, n) => {
    setHoveredId(n.id);
    const rect = containerRef.current.getBoundingClientRect();
    setTooltip({ node: n, x: e.clientX - rect.left + 14, y: e.clientY - rect.top + 14 });
  };
  const handleLeave = () => { setHoveredId(null); setTooltip(null); };
  const handleMove = (e) => {
    if (!tooltip) return;
    const rect = containerRef.current.getBoundingClientRect();
    setTooltip(t => t && ({ ...t, x: e.clientX - rect.left + 14, y: e.clientY - rect.top + 14 }));
  };

  return (
    <div ref={containerRef} className="ag-canvas" onMouseMove={handleMove}>
      <svg ref={svgRef} width="100%" height="100%">
        <defs>
          {/* Soft outer glow filter for malicious lit edges/nodes */}
          <filter id="glow-red" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="3.5" result="b" />
            <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
          <filter id="glow-cyan" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="2.5" result="b" />
            <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
          {/* Arrow markers */}
          <marker id="arrow-red" viewBox="0 -5 10 10" refX="22" refY="0" markerWidth="6" markerHeight="6" orient="auto">
            <path d="M0,-5L10,0L0,5" fill="#ef4444" />
          </marker>
          <marker id="arrow-cyan" viewBox="0 -5 10 10" refX="22" refY="0" markerWidth="6" markerHeight="6" orient="auto">
            <path d="M0,-5L10,0L0,5" fill="#3b82f6" opacity="0.55" />
          </marker>
          {/* Animated dash for lit edges */}
          <linearGradient id="hot-grad" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%"  stopColor="#fbbf24" />
            <stop offset="50%" stopColor="#ef4444" />
            <stop offset="100%" stopColor="#7f1d1d" />
          </linearGradient>
        </defs>

        <g transform={`translate(${transform.x},${transform.y}) scale(${transform.k})`}>
          {/* Edges */}
          <g className="links">
            {simReady && links.map((l, i) => {
              const s = l.source, t = l.target;
              if (typeof s !== "object" || s.x == null || t.x == null) return null;
              const sId = s.id;
              const tId = t.id;
              const lit = l.malicious && l.chain && l.chain <= replayStep;
              const isMal = l.malicious;
              const isHovered = hoveredId && (hoveredId === sId || hoveredId === tId);
              const dimmed = hoveredId && !isHovered;
              const dx = t.x - s.x, dy = t.y - s.y;
              const dr = Math.sqrt(dx * dx + dy * dy) * 1.8;
              const dPath = `M${s.x},${s.y}A${dr},${dr} 0 0,1 ${t.x},${t.y}`;

              return (
                <g key={i} opacity={dimmed ? 0.18 : 1}>
                  {lit && (
                    <path d={dPath} className="link link-glow"
                      stroke="#ef4444" strokeWidth={6} fill="none" opacity={0.4}
                      filter="url(#glow-red)" />
                  )}
                  <path
                    d={dPath}
                    className="link"
                    stroke={lit ? "url(#hot-grad)" : (isMal ? "#7f1d1d" : "#1e3a5f")}
                    strokeWidth={lit ? 2.4 : (isMal ? 1.6 : 1.2)}
                    strokeDasharray={lit ? "6 4" : (isMal ? "3 4" : "0")}
                    fill="none"
                    markerEnd={`url(#${lit || isMal ? "arrow-red" : "arrow-cyan"})`}
                    style={lit ? { animation: "dashflow 1.2s linear infinite" } : null}
                  />
                  {isHovered && <EdgeLabel link={l} nodes={nodes} />}
                </g>
              );
            })}
          </g>

          {/* Nodes */}
          <g className="nodes">
            {simReady && nodes.map(n => {
              if (n.x == null) return null;
              const style = NODE_STYLE[n.type];
              const c = colorFor(n);
              const isCrit = n.severity === "CRITICAL";
              const isLit = litNodes.has(n.id);
              const isHovered = hoveredId === n.id;
              const dimmed = hoveredId && !isHovered &&
                !links.some(l => {
                  if (!l.source || !l.target) return false;
                  const sId = typeof l.source === "object" ? l.source.id : l.source;
                  const tId = typeof l.target === "object" ? l.target.id : l.target;
                  return (sId === hoveredId && tId === n.id) || (tId === hoveredId && sId === n.id);
                });

              return (
                <g key={n.id} className="node"
                   data-id={n.id}
                   transform={`translate(${n.x},${n.y})`}
                   opacity={dimmed ? 0.3 : 1}
                   onMouseEnter={(e) => handleEnter(e, n)}
                   onMouseLeave={handleLeave}
                   onClick={() => onNodeClick(n)}
                   style={{ cursor: "pointer" }}>
                  {/* Pulse halo for critical / lit */}
                  {(isCrit || isLit) && (
                    <circle r={style.size + 8} fill="none"
                      stroke={isLit ? "#ef4444" : c}
                      strokeWidth={1.5} opacity={0.6}
                      style={{ animation: `pulse-${isLit ? "red" : "sev"} 1.6s ease-out infinite` }} />
                  )}
                  {/* Outer ring */}
                  <circle r={style.size} fill="#0a1120" stroke={c}
                    strokeWidth={isHovered ? 2.5 : 1.6}
                    filter={isCrit || isLit ? "url(#glow-red)" : (isHovered ? "url(#glow-cyan)" : null)} />
                  {/* Inner fill */}
                  <circle r={style.size - 6} fill={c} opacity={0.15} />
                  {/* Glyph */}
                  <text textAnchor="middle" dominantBaseline="central"
                    fontSize={style.size - 4} fill={c} fontWeight="700"
                    style={{ userSelect: "none", pointerEvents: "none" }}>
                    {style.glyph}
                  </text>
                  {/* Label below */}
                  <text textAnchor="middle" y={style.size + 14}
                    fontSize="10" fill="#94a3b8"
                    fontFamily="'Fira Code', monospace"
                    fontWeight={isHovered ? 700 : 500}
                    style={{ userSelect: "none", pointerEvents: "none" }}>
                    {n.label}
                  </text>
                  {/* Risk badge */}
                  <g transform={`translate(${style.size - 4}, ${-style.size + 4})`}>
                    <circle r="9" fill={SEV_COLOR[n.severity]} stroke="#0a1120" strokeWidth="1.5" />
                    <text textAnchor="middle" dominantBaseline="central"
                      fontSize="8" fill="#fff" fontWeight="800"
                      style={{ pointerEvents: "none" }}>
                      {n.risk}
                    </text>
                  </g>
                </g>
              );
            })}
          </g>
        </g>
      </svg>

      {/* Hover tooltip */}
      {tooltip && <NodeTooltip node={tooltip.node} x={tooltip.x} y={tooltip.y} />}

      {/* Zoom indicator */}
      <div className="ag-zoom-indicator">
        <span className="mono">{Math.round(transform.k * 100)}%</span>
      </div>
    </div>
  );
}

function EdgeLabel({ link, nodes }) {
  const s = link.source, t = link.target;
  if (!s || !t || typeof s !== "object" || typeof t !== "object" || s.x == null || t.x == null) return null;
  const mx = (s.x + t.x) / 2;
  const my = (s.y + t.y) / 2;
  return (
    <g transform={`translate(${mx},${my})`}>
      <rect x="-32" y="-9" width="64" height="18" rx="4"
        fill="#0a1120" stroke="#1e293b" strokeWidth="1" />
      <text textAnchor="middle" dominantBaseline="central"
        fontSize="9" fill={link.malicious ? "#fca5a5" : "#94a3b8"}
        fontFamily="'Fira Code', monospace" fontWeight="600"
        style={{ textTransform: "uppercase", letterSpacing: "0.5px" }}>
        {link.type}
      </text>
    </g>
  );
}

function NodeTooltip({ node, x, y }) {
  const sev = SEV_COLOR[node.severity];
  return (
    <div className="ag-tooltip" style={{ left: x, top: y, borderColor: sev + "55" }}>
      <div className="ag-tooltip-head" style={{ background: `linear-gradient(90deg, ${sev}25, transparent)` }}>
        <span className="ag-tooltip-type" style={{ color: NODE_STYLE[node.type].color }}>
          {NODE_STYLE[node.type].glyph} {NODE_STYLE[node.type].label}
        </span>
        <span className="ag-tooltip-sev" style={{ background: sev + "22", color: sev, borderColor: sev + "55" }}>
          {node.severity}
        </span>
      </div>
      <div className="ag-tooltip-body">
        <div className="ag-tooltip-label">{node.label}</div>
        <div className="ag-tooltip-grid">
          {node.ip      && <><span>IP</span><span className="mono">{node.ip}</span></>}
          {node.os      && <><span>OS</span><span>{node.os}</span></>}
          {node.dept    && <><span>Dept</span><span>{node.dept}</span></>}
          {node.pid     && <><span>PID</span><span className="mono">{node.pid}</span></>}
          {node.cmd     && <><span>cmd</span><span className="mono ag-trunc">{node.cmd}</span></>}
          {node.country && <><span>Geo</span><span>{node.country} · {node.asn}</span></>}
          {node.path    && <><span>Path</span><span className="mono ag-trunc">{node.path}</span></>}
          {node.hash    && <><span>SHA256</span><span className="mono">{node.hash}</span></>}
        </div>
        <div className="ag-tooltip-risk">
          <div className="ag-tooltip-risklbl">RISK SCORE</div>
          <div className="ag-tooltip-riskbar">
            <div className="ag-tooltip-riskfill" style={{ width: `${node.risk}%`, background: sev, boxShadow: `0 0 8px ${sev}` }} />
          </div>
          <div className="ag-tooltip-riskval" style={{ color: sev }}>{node.risk}/100</div>
        </div>
        <div className="ag-tooltip-hint">CLICK FOR FULL ANALYSIS →</div>
      </div>
    </div>
  );
}

window.AttackGraph = AttackGraph;
window.AG_NODE_STYLE = NODE_STYLE;
window.AG_SEV_COLOR = SEV_COLOR;
