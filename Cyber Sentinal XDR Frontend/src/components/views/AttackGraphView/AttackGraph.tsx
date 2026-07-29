// AttackGraph.tsx — D3 force-directed cyber attack graph
// Converted from AttackGraph.jsx

import React, {
  useEffect,
  useRef,
  useState,
  useMemo,
  useCallback,
} from "react";
import * as d3 from "d3";
import styles from "./attack-graph.module.css";
import { GraphNode, GraphEdge, GraphData, NODE_STYLE, SEV_COLOR } from "./types";

// ── 30fps throttle constant ───────────────────────────────────────────────────
const FRAME_INTERVAL_MS = 1000 / 30;

interface Props {
  data: GraphData;
  onNodeClick: (node: GraphNode) => void;
  highlightedPath?: string[];
  /** Scores below this threshold are rendered as low-severity (grey/blue) */
  fusionHighThreshold?: number;
  /** Scores at or above this threshold are rendered as CRITICAL (red) */
  fusionCriticalThreshold?: number;
}

// ── Color helpers ────────────────────────────────────────────────────────────

function colorFor(node: GraphNode, fusionHighThreshold = 0.70, fusionCriticalThreshold = 0.85): string {
  // XDR Server hub is always cyan
  if (node.type === "server") return "#00d4ff";
  // Endpoint nodes: health color-coding — green=safe, amber=medium, orange=high, red=critical
  if (node.type === "endpoint") {
    if (node.severity === "CRITICAL" || (node.risk ?? 0) >= fusionCriticalThreshold * 100) return "#ef4444";
    if (node.severity === "HIGH"     || (node.risk ?? 0) >= fusionHighThreshold * 100)      return "#f97316";
    if (node.severity === "MEDIUM")                                                           return "#f59e0b";
    return "#22c55e"; // green = healthy / online
  }
  // For all other node types: threshold-based coloring using the numeric risk score (0–100)
  const riskFraction = (node.risk ?? 0) / 100;
  if (riskFraction >= fusionCriticalThreshold) return SEV_COLOR["CRITICAL"];
  if (riskFraction >= fusionHighThreshold) return SEV_COLOR["HIGH"];
  // Node's declared severity is HIGH/CRITICAL but risk is below threshold — show as blue
  if (node.severity === "CRITICAL" || node.severity === "HIGH") return "#3b82f6";
  return (NODE_STYLE[node.type] ?? NODE_STYLE["ip"]).color;
}

// ── Edge label (shown on hover) ──────────────────────────────────────────────

function EdgeLabel({ link }: { link: GraphEdge }) {
  const s = link.source as GraphNode;
  const t = link.target as GraphNode;
  if (
    !s || !t ||
    typeof s !== "object" || typeof t !== "object" ||
    s.x == null || s.y == null ||
    t.x == null || t.y == null
  ) return null;
  const mx = ((s.x ?? 0) + (t.x ?? 0)) / 2;
  const my = ((s.y ?? 0) + (t.y ?? 0)) / 2;
  return (
    <g transform={`translate(${mx},${my})`}>
      <rect x="-32" y="-9" width="64" height="18" rx="4"
        fill="var(--bg-primary)" stroke="#1e293b" strokeWidth="1" />
      <text textAnchor="middle" dominantBaseline="central"
        fontSize="9"
        fill={link.malicious ? "#fca5a5" : "#94a3b8"}
        fontFamily="'Fira Code', monospace"
        fontWeight="600"
        style={{ textTransform: "uppercase", letterSpacing: "0.5px" }}>
        {/* Never render "Unknown" as an edge label */}
        {link.type && link.type.toLowerCase() !== "unknown"
          ? link.type
          : link.malicious ? "attack" : "→"}
      </text>
    </g>
  );
}

// ── Hover tooltip ────────────────────────────────────────────────────────────

interface TooltipState {
  node: GraphNode;
  x: number;
  y: number;
}

function NodeTooltip({ node, x, y }: TooltipState) {
  const sev = SEV_COLOR[node.severity] ?? "#6b7280";
  const style = NODE_STYLE[node.type] ?? NODE_STYLE["ip"];
  // Source IP: prefer explicit src_ip, fall back to ip
  const srcDisplay = node.src_ip || node.ip || null;
  const dstDisplay = node.dst_ip || null;
  // Format timestamp to HH:MM:SS if available
  const tsDisplay = node.timestamp
    ? (() => {
        try { return new Date(node.timestamp).toLocaleTimeString(); }
        catch { return node.timestamp; }
      })()
    : null;
  return (
    <div
      className={styles.tooltip}
      style={{ left: x, top: y, borderColor: sev + "55" }}
    >
      <div
        className={styles.tooltipHead}
        style={{ background: `linear-gradient(90deg, ${sev}25, transparent)` }}
      >
        <span
          className={styles.tooltipType}
          style={{ color: style.color }}
        >
          {style.glyph} {style.label}
        </span>
        <span
          className={styles.tooltipSev}
          style={{
            background: sev + "22",
            color: sev,
            borderColor: sev + "55",
          }}
        >
          {node.severity}
        </span>
      </div>
      <div className={styles.tooltipBody}>
        <div className={styles.tooltipLabel}>{node.label}</div>
        <div className={styles.tooltipGrid}>
          {node.attack_type && <><span>Attack</span><span style={{ color: sev, fontWeight: 700 }}>{node.attack_type}</span></>}
          {srcDisplay       && <><span>Source</span><span style={{ fontFamily: "monospace" }}>{srcDisplay}</span></>}
          {dstDisplay       && <><span>Target</span><span style={{ fontFamily: "monospace" }}>{dstDisplay}</span></>}
          {node.os          && <><span>OS</span><span>{node.os}</span></>}
          {node.dept        && <><span>Dept</span><span>{node.dept}</span></>}
          {node.pid         && <><span>PID</span><span style={{ fontFamily: "monospace" }}>{node.pid}</span></>}
          {node.cmd && !node.attack_type && <><span>Cmd</span><span style={{ fontFamily: "monospace" }} className={styles.trunc}>{node.cmd}</span></>}
          {node.country     && <><span>Geo</span><span>{node.country} · {node.asn}</span></>}
          {node.path        && <><span>Path</span><span style={{ fontFamily: "monospace" }} className={styles.trunc}>{node.path}</span></>}
          {node.hash        && <><span>SHA256</span><span style={{ fontFamily: "monospace" }}>{node.hash}</span></>}
          {node.mitre_technique && <><span>MITRE</span><span style={{ color: "#a78bfa", fontFamily: "monospace" }}>{node.mitre_technique}</span></>}
          {tsDisplay        && <><span>Time</span><span style={{ fontFamily: "monospace" }}>{tsDisplay}</span></>}
          {node.shap_reasons && node.shap_reasons.length > 0 && (
            <><span>SHAP</span><span style={{ color: "var(--text-secondary)" }} className={styles.trunc}>{node.shap_reasons.slice(0, 2).join(", ")}</span></>
          )}
        </div>
        <div className={styles.tooltipRisk}>
          <div className={styles.tooltipRiskLbl}>RISK SCORE</div>
          <div className={styles.tooltipRiskBar}>
            <div
              className={styles.tooltipRiskFill}
              style={{
                width: `${node.risk ?? 0}%`,
                background: sev,
                boxShadow: `0 0 8px ${sev}`,
              }}
            />
          </div>
          <div className={styles.tooltipRiskVal} style={{ color: sev }}>
            {node.risk ?? 0}/100
          </div>
        </div>
        <div className={styles.tooltipHint}>CLICK FOR FULL ANALYSIS →</div>
      </div>
    </div>
  );
}

// ── Main AttackGraph component ───────────────────────────────────────────────

export default function AttackGraph({ data, onNodeClick, highlightedPath = [], fusionHighThreshold = 0.70, fusionCriticalThreshold = 0.85 }: Props) {
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const simRef = useRef<d3.Simulation<GraphNode, GraphEdge> | null>(null);

  const [transform, setTransform] = useState<d3.ZoomTransform>(d3.zoomIdentity);
  const [tooltip, setTooltip] = useState<TooltipState | null>(null);
  const [simReady, setSimReady] = useState(false);
  const [hoveredId, setHoveredId] = useState<string | null>(null);

  // RAF-based re-render counter — throttled to 30fps.
  // renderTick is intentionally read in the JSX (via void) to ensure React
  // schedules a repaint whenever the D3 simulation updates node positions.
  const renderTickRef = useRef(0);
  const [renderTick, setRenderTick] = useState(0);
  const lastFrameTimeRef = useRef(0);
  void renderTick; // suppress "assigned but never used" warning

  // Track the node-ID set so simulation only rebuilds when topology changes,
  // not on every D3 position tick.
  const nodeIdsKey = useMemo(
    () => data.NODES.map((n) => n.id).sort().join("|"),
    [data.NODES]
  );
  // Whether drag has already been bound for the current ID set
  const dragBoundKeyRef = useRef<string>("");

  // Replay step derived from highlightedPath — how many chain edges to light
  const replayStep = highlightedPath.length;

  // Stable copies for D3 (it mutates x/y/vx/vy in place).
  // Crucially, we pull the current D3-computed positions back out of the live
  // simulation before spreading each node.  Without this, a socket-triggered
  // state update creates fresh objects with no x/y, causing D3 to randomise
  // every existing node's position and making them appear to vanish.
  const nodes = useMemo<GraphNode[]>(() => {
    const posMap = new Map<string, { x?: number; y?: number; vx?: number; vy?: number }>();
    if (simRef.current) {
      for (const n of simRef.current.nodes() as GraphNode[]) {
        if (n.id) posMap.set(n.id, { x: n.x, y: n.y, vx: n.vx ?? 0, vy: n.vy ?? 0 });
      }
    }
    return data.NODES.map((n) => {
      const pos = posMap.get(n.id);
      return pos ? { ...n, ...pos } : { ...n };
    });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data.NODES]);

  // Filter out any edge whose source or target ID is not present in the nodes
  // array.  D3 forceLink throws "node not found: <id>" at initialization time
  // if a link references a node that hasn't been added yet — most commonly
  // "endpoint_server" appearing in command_result / malware_alert edges before
  // the matching endpoint node arrives from the backend snapshot.
  const links = useMemo<GraphEdge[]>(() => {
    const nodeIds = new Set(data.NODES.map((n) => n.id));
    return data.EDGES
      .filter((e) => {
        const srcId = typeof e.source === "object" ? (e.source as GraphNode).id : e.source as string;
        const tgtId = typeof e.target === "object" ? (e.target as GraphNode).id : e.target as string;
        return nodeIds.has(srcId) && nodeIds.has(tgtId);
      })
      .map((e) => ({ ...e }));
  }, [data]);

  // ── Build or update force simulation — only when node topology changes ──────
  useEffect(() => {
    if (!containerRef.current) return;
    const W = containerRef.current.clientWidth || 800;
    const H = containerRef.current.clientHeight || 600;

    // ── Type-based target positions — spread nodes by role to prevent clustering
    // Endpoint nodes gravitate center-left; alert nodes center-right;
    // IP/domain nodes push upward; process/file/user nodes push downward.
    function xTargetFor(n: GraphNode): number {
      switch (n.type) {
        case "server":          return W * 0.5;
        case "endpoint":        return W * 0.3;
        case "alert":           return W * 0.7;
        case "ip":              return W * 0.5;
        case "process":
        case "file":            return W * 0.5;
        case "user":            return W * 0.3;
        case "response_action": return W * 0.7;
        default:                return W * 0.5;
      }
    }
    function yTargetFor(n: GraphNode): number {
      switch (n.type) {
        case "server":          return H * 0.45;
        case "ip":              return H * 0.25;
        case "endpoint":        return H * 0.5;
        case "alert":           return H * 0.5;
        case "user":            return H * 0.65;
        case "process":
        case "file":            return H * 0.75;
        case "response_action": return H * 0.65;
        default:                return H * 0.5;
      }
    }
    // Server hub is strongly pinned to center; all other nodes float freely
    function strengthFor(n: GraphNode): number {
      return n.type === "server" ? 0.9 : 0.05;
    }

    let raf: number | null = null;

    if (simRef.current) {
      // Simulation already exists — update nodes and links in place so that
      // existing node positions are preserved and only new nodes are added.
      // This prevents the graph from re-exploding every time an alert fires.
      simRef.current.nodes(nodes);
      (simRef.current.force("link") as d3.ForceLink<GraphNode, GraphEdge> | null)
        ?.links(links);
      // Also keep positional forces referencing the current container size
      (simRef.current.force("x") as d3.ForceX<GraphNode> | null)
        ?.x(xTargetFor).strength(strengthFor);
      (simRef.current.force("y") as d3.ForceY<GraphNode> | null)
        ?.y(yTargetFor).strength(strengthFor);
      // Use a gentle reheat (0.2) instead of 0.5 — existing nodes already have
      // positions so a lower alpha is enough to settle new nodes without
      // throwing the whole graph into chaos on every socket update.
      simRef.current.alpha(0.2).restart();
      return;
    }

    // ── Initial simulation creation (first mount) ──────────────────────────
    const sim = d3
      .forceSimulation<GraphNode, GraphEdge>(nodes)
      .force(
        "link",
        d3
          .forceLink<GraphNode, GraphEdge>(links)
          .id((d) => d.id)
          .distance((d) => ((d as GraphEdge).malicious ? 160 : 120))
          .strength(0.45)
      )
      .force("charge", d3.forceManyBody<GraphNode>().strength(-300))
      .force("center", d3.forceCenter(W / 2, H / 2).strength(0.04))
      .force("collision", d3.forceCollide<GraphNode>().radius(35).strength(0.85))
      .force("x", d3.forceX<GraphNode>().x(xTargetFor).strength(strengthFor))
      .force("y", d3.forceY<GraphNode>().y(yTargetFor).strength(strengthFor))
      .alphaDecay(0.022)
      // Keep the simulation above alphaMin so it never fully freezes.
      // Dragging a node calls alphaTarget(0.3) which temporarily overrides
      // this floor; after drag-end it falls back to 0.01 and the layout
      // continues to settle gently with new data.
      .alphaMin(0.01);

    simRef.current = sim;

    let firstTick = true;
    sim.on("tick", () => {
      if (firstTick) {
        firstTick = false;
        setSimReady(true);
      }
      if (raf) return;
      raf = requestAnimationFrame((now) => {
        raf = null;
        // Throttle React re-renders to 30fps
        if (now - lastFrameTimeRef.current >= FRAME_INTERVAL_MS) {
          lastFrameTimeRef.current = now;
          renderTickRef.current += 1;
          setRenderTick(renderTickRef.current);
        }
      });
    });

    return () => {
      sim.stop();
      simRef.current = null;
      if (raf) cancelAnimationFrame(raf);
    };
    // Only re-run when the set of node IDs or edge topology changes,
    // not on every position tick that comes from D3's own mutations.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodeIdsKey]);

  // ── Restart simulation when data changes (keeps graph live) ──────────────
  // When new nodes or edges arrive via socket, the topology changes but the
  // simulation may have already decayed below alphaMin.  Re-heat it to 0.3
  // so the layout adjusts to accommodate the new data.  Only runs when the
  // node-ID key or edge count changes — not on every D3 position tick.
  const edgeCount = links.length;
  useEffect(() => {
    const sim = simRef.current;
    if (!sim) return;
    if (sim.alpha() < 0.05) {
      sim.alpha(0.3).restart();
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodeIdsKey, edgeCount]);

  // ── Keep link force in sync whenever edges change ─────────────────────────
  // The nodeIdsKey effect only fires when node *topology* changes.  When edges
  // change without topology changes (snapshot reload, new alert edge on an
  // existing endpoint), D3 never receives the fresh link objects from useMemo,
  // so source/target stay as strings and every edge renders null.
  // This effect syncs the link force on every links change.
  useEffect(() => {
    const sim = simRef.current;
    if (!sim) return;
    const lf = sim.force("link") as d3.ForceLink<GraphNode, GraphEdge> | null;
    if (!lf) return;
    lf.links(links);
    if (sim.alpha() < 0.05) sim.alpha(0.08).restart();
  }, [links]);

  // ── Pan / zoom ────────────────────────────────────────────────────────────
  useEffect(() => {
    if (!svgRef.current) return;
    const svg = d3.select<SVGSVGElement, unknown>(svgRef.current);
    const zoom = d3
      .zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.4, 2.5])
      .on("zoom", (event: d3.D3ZoomEvent<SVGSVGElement, unknown>) => {
        setTransform(event.transform);
      });
    svg.call(zoom);
    return () => {
      svg.on(".zoom", null);
    };
  }, []);

  // ── Drag — bind without .data() since elements are React-rendered ──────────
  // Only rebind when node topology changes (nodeIdsKey), not on every position tick.
  useEffect(() => {
    if (!svgRef.current || !simRef.current) return;
    // Skip re-binding if node IDs haven't changed since last bind
    if (dragBoundKeyRef.current === nodeIdsKey) return;

    const sim = simRef.current;
    const t = setTimeout(() => {
      if (!svgRef.current) return;
      dragBoundKeyRef.current = nodeIdsKey;

      const drag = d3
        .drag<SVGGElement, unknown>()
        .on("start", function (event) {
          const id = this.getAttribute("data-id");
          const d = nodes.find((n) => n.id === id);
          if (!d) return;
          if (!event.active) sim.alphaTarget(0.3).restart();
          d.fx = d.x ?? 0;
          d.fy = d.y ?? 0;
        })
        .on("drag", function (event) {
          const id = this.getAttribute("data-id");
          const d = nodes.find((n) => n.id === id);
          if (!d) return;
          d.fx = event.x;
          d.fy = event.y;
        })
        .on("end", function (event) {
          const id = this.getAttribute("data-id");
          const d = nodes.find((n) => n.id === id);
          if (!d) return;
          if (!event.active) sim.alphaTarget(0);
          d.fx = null;
          d.fy = null;
        });

      d3.select<SVGSVGElement, unknown>(svgRef.current)
        .selectAll<SVGGElement, unknown>("g.ag-node")
        .call(drag);
    }, 50);
    return () => clearTimeout(t);
  }, [nodeIdsKey, nodes]);

  // ── Which links are "lit" based on replayStep ─────────────────────────────
  const litChainKeys = useMemo(() => {
    const set = new Set<string>();
    links.forEach((l) => {
      if (!l.source || !l.target) return;
      if (l.malicious && l.chain != null && l.chain <= replayStep) {
        const sId = typeof l.source === "object" ? (l.source as GraphNode).id : l.source as string;
        const tId = typeof l.target === "object" ? (l.target as GraphNode).id : l.target as string;
        set.add(`${sId}->${tId}-${l.chain}`);
      }
    });
    return set;
  }, [links, replayStep]);

  // ── Which nodes are involved in lit chain ─────────────────────────────────
  const litNodeIds = useMemo(() => {
    const set = new Set<string>();
    links.forEach((l) => {
      if (!l.source || !l.target) return;
      if (l.malicious && l.chain != null && l.chain <= replayStep) {
        set.add(typeof l.source === "object" ? (l.source as GraphNode).id : l.source as string);
        set.add(typeof l.target === "object" ? (l.target as GraphNode).id : l.target as string);
      }
    });
    return set;
  }, [links, replayStep]);

  // ── Mouse handlers ────────────────────────────────────────────────────────
  const handleEnter = useCallback(
    (e: React.MouseEvent, n: GraphNode) => {
      setHoveredId(n.id);
      if (!containerRef.current) return;
      const rect = containerRef.current.getBoundingClientRect();
      setTooltip({ node: n, x: e.clientX - rect.left + 14, y: e.clientY - rect.top + 14 });
    },
    []
  );

  const handleLeave = useCallback(() => {
    setHoveredId(null);
    setTooltip(null);
  }, []);

  const handleMove = useCallback(
    (e: React.MouseEvent) => {
      if (!tooltip || !containerRef.current) return;
      const rect = containerRef.current.getBoundingClientRect();
      setTooltip((t) =>
        t ? { ...t, x: e.clientX - rect.left + 14, y: e.clientY - rect.top + 14 } : null
      );
    },
    [tooltip]
  );

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <div
      ref={containerRef}
      className={styles.canvas}
      onMouseMove={handleMove}
    >
      <svg ref={svgRef} width="100%" height="100%">
        <defs>
          {/* Glow filters */}
          <filter id="ag-glow-red" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="3.5" result="b" />
            <feMerge>
              <feMergeNode in="b" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          {/* Stronger glow for CRITICAL nodes */}
          <filter id="ag-glow-critical" x="-60%" y="-60%" width="220%" height="220%">
            <feGaussianBlur stdDeviation="6" result="b" />
            <feMerge>
              <feMergeNode in="b" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <filter id="ag-glow-cyan" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="2.5" result="b" />
            <feMerge>
              <feMergeNode in="b" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>

          {/* Arrow markers */}
          <marker
            id="ag-arrow-red"
            viewBox="0 -5 10 10"
            refX="22"
            refY="0"
            markerWidth="6"
            markerHeight="6"
            orient="auto"
          >
            <path d="M0,-5L10,0L0,5" fill="#ef4444" />
          </marker>
          <marker
            id="ag-arrow-cyan"
            viewBox="0 -5 10 10"
            refX="22"
            refY="0"
            markerWidth="6"
            markerHeight="6"
            orient="auto"
          >
            <path d="M0,-5L10,0L0,5" fill="#3b82f6" opacity="0.55" />
          </marker>
          <marker
            id="ag-arrow-green"
            viewBox="0 -5 10 10"
            refX="22"
            refY="0"
            markerWidth="6"
            markerHeight="6"
            orient="auto"
          >
            <path d="M0,-5L10,0L0,5" fill="#22c55e" opacity="0.65" />
          </marker>

          {/* Animated gradient for lit edges */}
          <linearGradient id="ag-hot-grad" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%"   stopColor="#fbbf24" />
            <stop offset="50%"  stopColor="#ef4444" />
            <stop offset="100%" stopColor="#7f1d1d" />
          </linearGradient>

          {/* Keyframes via style tag inside defs */}
          <style>{`
            @keyframes ag-dashflow { from { stroke-dashoffset: 20; } to { stroke-dashoffset: 0; } }
            @keyframes ag-pulse-red { 0% { opacity: 0.8; } 100% { r: 1.6; opacity: 0; } }
          `}</style>
        </defs>

        <g transform={`translate(${transform.x},${transform.y}) scale(${transform.k})`}>
          {/* Edges */}
          <g>
            {simReady &&
              links.map((l, i) => {
                const s = l.source as GraphNode;
                const t = l.target as GraphNode;
                if (
                  typeof s !== "object" || typeof t !== "object" ||
                  s.x == null || s.y == null ||
                  t.x == null || t.y == null
                ) return null;

                const sId = s.id;
                const tId = (t as GraphNode).id;
                const chainKey = `${sId}->${tId}-${l.chain}`;
                const lit = l.malicious && l.chain != null && litChainKeys.has(chainKey);
                const isMal = l.malicious;
                const isMonitor = l.type === "monitors";
                const isHovered = hoveredId != null && (hoveredId === sId || hoveredId === tId);
                const dimmed = hoveredId != null && !isHovered;

                const sx = s.x ?? 0;
                const sy = s.y ?? 0;
                const tx = (t as GraphNode).x ?? 0;
                const ty = (t as GraphNode).y ?? 0;
                const dx = tx - sx;
                const dy = ty - sy;
                const dr = Math.sqrt(dx * dx + dy * dy) * 1.8;
                const dPath = `M${sx},${sy}A${dr},${dr} 0 0,1 ${tx},${ty}`;

                return (
                  <g key={i} opacity={dimmed ? (isMonitor ? 0.1 : 0.18) : 1}>
                    {lit && (
                      <path
                        d={dPath}
                        stroke="#ef4444"
                        strokeWidth={6}
                        fill="none"
                        opacity={0.4}
                        filter="url(#ag-glow-red)"
                      />
                    )}
                    <path
                      d={dPath}
                      stroke={
                        lit        ? "url(#ag-hot-grad)"
                        : isMonitor ? "#22c55e"
                        : isMal    ? "#7f1d1d"
                        :             "#3b82f6"
                      }
                      strokeWidth={lit ? 2.4 : isMal ? 1.6 : isMonitor ? 0.9 : 1.0}
                      strokeDasharray={lit ? "6 4" : isMal ? "3 4" : isMonitor ? "0" : "4 4"}
                      strokeOpacity={lit ? 1 : isMal ? 1 : isMonitor ? 0.45 : 0.65}
                      fill="none"
                      markerEnd={`url(#${lit || isMal ? "ag-arrow-red" : isMonitor ? "ag-arrow-green" : "ag-arrow-cyan"})`}
                      style={lit ? { animation: "ag-dashflow 1.2s linear infinite" } : undefined}
                    />
                    {isHovered && <EdgeLabel link={l} />}
                  </g>
                );
              })}
          </g>

          {/* Nodes */}
          <g>
            {simReady &&
              nodes.map((n) => {
                if (n.x == null) return null;
                // Skip nodes with no meaningful label — they would render as
                // an unlabelled coloured circle, confusing operators.
                const lbl = n.label?.trim() ?? "";
                if (!lbl || lbl.toLowerCase() === "unknown") return null;
                const style = NODE_STYLE[n.type] ?? NODE_STYLE["ip"];
                const c = colorFor(n, fusionHighThreshold, fusionCriticalThreshold);
                const isCrit = n.severity === "CRITICAL";
                const isLit = litNodeIds.has(n.id);
                const isHov = hoveredId === n.id;
                const dimmed =
                  hoveredId != null &&
                  !isHov &&
                  !links.some((l) => {
                    if (!l.source || !l.target) return false;
                    const ls = typeof l.source === "object" ? (l.source as GraphNode).id : l.source as string;
                    const lt = typeof l.target === "object" ? (l.target as GraphNode).id : l.target as string;
                    return (
                      (ls === hoveredId && lt === n.id) ||
                      (lt === hoveredId && ls === n.id)
                    );
                  });

                return (
                  <g
                    key={n.id}
                    className="ag-node"
                    data-id={n.id}
                    transform={`translate(${n.x},${n.y})`}
                    opacity={dimmed ? 0.3 : 1}
                    onMouseEnter={(e) => handleEnter(e, n)}
                    onMouseLeave={handleLeave}
                    onClick={() => onNodeClick(n)}
                    style={{ cursor: "pointer" }}
                  >
                    {/* Pulse halo — server hub always pulses cyan; endpoints pulse in their health color; CRITICAL/lit nodes pulse red */}
                    {(isCrit || isLit || n.type === "endpoint" || n.type === "server") && (
                      <circle
                        r={style.size + (n.type === "server" ? 10 : n.type === "endpoint" ? 6 : 8)}
                        fill="none"
                        stroke={isLit ? "#ef4444" : n.type === "server" ? "#00d4ff" : c}
                        strokeWidth={n.type === "server" ? 2.0 : n.type === "endpoint" ? 1.2 : 1.5}
                        opacity={n.type === "server" ? 0.5 : n.type === "endpoint" && !isCrit ? 0.35 : 0.6}
                        style={{
                          animation: `${isLit ? "ag-pulse-red" : "ag-pulse-sev"} ${n.type === "server" ? "3s" : n.type === "endpoint" ? "2.4s" : "1.6s"} ease-out infinite`,
                        }}
                      />
                    )}
                    {/* Outer ring */}
                    <circle
                      r={style.size}
                      fill="var(--bg-primary)"
                      stroke={c}
                      strokeWidth={isHov ? 2.5 : isCrit ? 2.2 : n.type === "endpoint" ? 2.0 : 1.6}
                      filter={
                        isCrit && !isLit
                          ? "url(#ag-glow-critical)"
                          : isLit
                          ? "url(#ag-glow-red)"
                          : n.type === "server" || n.type === "endpoint" || isHov
                          ? "url(#ag-glow-cyan)"
                          : undefined
                      }
                    />
                    {/* Inner fill */}
                    <circle r={style.size - 6} fill={c} opacity={n.type === "endpoint" ? 0.2 : 0.15} />
                    {/* Glyph */}
                    <text
                      textAnchor="middle"
                      dominantBaseline="central"
                      fontSize={style.size - 4}
                      fill={c}
                      fontWeight="700"
                      style={{ userSelect: "none", pointerEvents: "none" }}
                    >
                      {style.glyph}
                    </text>
                    {/* Label — endpoint nodes always visible with sky-blue text;
                        threat/alert nodes prominent red; others slate */}
                    <text
                      textAnchor="middle"
                      y={style.size + 15}
                      fontSize={n.type === "server" ? "13" : n.type === "endpoint" || n.type === "alert" || isCrit ? "12" : "11"}
                      fill={
                        n.type === "server"
                          ? "#00d4ff"
                          : n.type === "endpoint"
                          ? c
                          : n.type === "alert"
                          ? "#fca5a5"
                          : isCrit
                          ? "#fca5a5"
                          : n.severity === "HIGH"
                          ? "#fcd34d"
                          : "#94a3b8"
                      }
                      fontFamily="'Fira Code', monospace"
                      fontWeight={isHov || isCrit || n.type === "server" || n.type === "endpoint" || n.type === "alert" ? 700 : 500}
                      style={{ userSelect: "none", pointerEvents: "none" }}
                    >
                      {lbl}
                    </text>
                    {/* Risk badge — not shown on server hub (it's infrastructure, not a scored threat) */}
                    {n.type !== "server" && (
                      <g transform={`translate(${style.size - 4}, ${-style.size + 4})`}>
                        <circle
                          r="9"
                          fill={SEV_COLOR[n.severity]}
                          stroke="var(--bg-primary)"
                          strokeWidth="1.5"
                        />
                        <text
                          textAnchor="middle"
                          dominantBaseline="central"
                          fontSize="8"
                          fill="#fff"
                          fontWeight="800"
                          style={{ pointerEvents: "none" }}
                        >
                          {n.risk}
                        </text>
                      </g>
                    )}
                  </g>
                );
              })}
          </g>
        </g>
      </svg>

      {/* Hover tooltip */}
      {tooltip && (
        <NodeTooltip node={tooltip.node} x={tooltip.x} y={tooltip.y} />
      )}

      {/* Zoom indicator */}
      <div className={styles.zoomIndicator}>
        {Math.round(transform.k * 100)}%
      </div>
    </div>
  );
}
