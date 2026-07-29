// AttackChainGraph.tsx — Interactive D3 force-graph showing the attack chain
// for a single incident in AttackReconstructionView.
//
// Nodes: attacker IP (red), endpoint (blue), process (orange), alert (yellow), model (green)
// Edges: attacked / spawned / detected / on
//
// Uses the same D3 SVG approach as AttackGraph.tsx — no canvas, no extra deps.

import React, {
  useEffect,
  useRef,
  useState,
  useMemo,
  useCallback,
} from "react";
import * as d3 from "d3";

// ── Node / edge types ─────────────────────────────────────────────────────────

type ChainNodeType = "attacker" | "endpoint" | "process" | "model" | "alert";

interface ChainNode {
  id: string;
  label: string;
  type: ChainNodeType;
  color: string;
  // D3 mutable fields
  x?: number;
  y?: number;
  fx?: number | null;
  fy?: number | null;
  vx?: number;
  vy?: number;
}

interface ChainEdge {
  source: string | ChainNode;
  target: string | ChainNode;
  label: string;
  color: string;
}

// ── Node style constants ──────────────────────────────────────────────────────

const NODE_CFG: Record<ChainNodeType, { glyph: string; size: number }> = {
  attacker: { glyph: "☠", size: 22 },
  endpoint: { glyph: "▣", size: 22 },
  process:  { glyph: "⬣", size: 20 },
  model:    { glyph: "◈", size: 20 },
  alert:    { glyph: "⚠", size: 22 },
};

// ── ReplayData type (minimal — only the fields this component reads) ──────────

interface FusionAlertData {
  threat_score?: number;
  severity?: string;
  attack_type?: string;
  sources?: string[];
  src_ip?: string;
  source_ip?: string;
}

interface TimelineEntry {
  event_type?: string;
  data?: Record<string, unknown>;
  [key: string]: unknown;
}

interface ReplayDataSlice {
  endpoint_id?: string;
  hostname?: string;
  fusion_alert?: FusionAlertData | null;
  attack_type?: string;
  timeline?: TimelineEntry[];
}

// ── Graph builder ─────────────────────────────────────────────────────────────

function buildChainGraph(data: ReplayDataSlice): { nodes: ChainNode[]; edges: ChainEdge[] } {
  const nodes: ChainNode[] = [];
  const edges: ChainEdge[] = [];
  const nodeIds = new Set<string>();

  function addNode(n: ChainNode) {
    if (!nodeIds.has(n.id)) {
      nodes.push(n);
      nodeIds.add(n.id);
    }
  }

  // Endpoint / server node — always present
  const endpointId = data.endpoint_id ?? "server_host";
  const endpointLabel =
    data.hostname && data.hostname !== endpointId
      ? data.hostname
      : endpointId.length > 20
      ? endpointId.slice(0, 20) + "…"
      : endpointId;

  addNode({ id: endpointId, label: endpointLabel, type: "endpoint", color: "#3b82f6" });

  // Attacker IP — from fusion alert if available
  const srcIp =
    data.fusion_alert?.src_ip ??
    data.fusion_alert?.source_ip ??
    null;

  if (srcIp) {
    addNode({ id: srcIp, label: srcIp, type: "attacker", color: "#ef4444" });
    edges.push({
      source: srcIp,
      target: endpointId,
      label: "attacked",
      color: "#ef4444",
    });
  }

  // Detection models that contributed
  const sources = data.fusion_alert?.sources ?? [];
  const modelColors: Record<string, string> = {
    network: "#00d4ff",
    user:    "#f97316",
    system:  "#8b5cf6",
    malware: "#dc2626",
  };

  sources.forEach((src) => {
    const modelId = `model_${src}`;
    const color = modelColors[src.toLowerCase()] ?? "#22c55e";
    addNode({ id: modelId, label: src.toUpperCase(), type: "model", color });

    // Alert node (one per model)
    const alertType = data.attack_type ?? data.fusion_alert?.attack_type ?? "ALERT";
    const alertId = `alert_${src}`;
    addNode({ id: alertId, label: alertType.slice(0, 16), type: "alert", color: "#eab308" });

    edges.push({ source: modelId, target: alertId, label: "detected", color });
    edges.push({ source: alertId, target: endpointId, label: "on", color: "var(--text-muted)" });
  });

  // Processes from sysmon timeline entries
  const seen = new Set<string>();
  (data.timeline ?? []).forEach((entry) => {
    const et = String(entry.event_type ?? "").toLowerCase();
    if (!et.includes("sysmon")) return;
    const procName =
      (entry.data?.process_name as string | undefined) ??
      (entry.data?.Image as string | undefined) ??
      "";
    if (!procName) return;

    // Use base name only (no full path) to keep labels short
    const baseName = procName.includes("\\")
      ? procName.split("\\").pop() ?? procName
      : procName;
    const procId = `proc_${baseName.replace(/\W/g, "_")}`;
    if (seen.has(procId)) return;
    seen.add(procId);

    addNode({ id: procId, label: baseName.slice(0, 20), type: "process", color: "#f97316" });
    edges.push({
      source: endpointId,
      target: procId,
      label: "spawned",
      color: "#f97316",
    });
  });

  return { nodes, edges };
}

// ── Tooltip ───────────────────────────────────────────────────────────────────

interface TooltipState {
  node: ChainNode;
  x: number;
  y: number;
}

function ChainTooltip({ node, x, y }: TooltipState) {
  const typeLabels: Record<ChainNodeType, string> = {
    attacker: "Attacker IP",
    endpoint: "Endpoint",
    process:  "Process",
    model:    "Detection Model",
    alert:    "Alert",
  };
  return (
    <div
      style={{
        position: "absolute",
        left: x,
        top: y,
        background: "var(--bg-primary)",
        border: `1px solid ${node.color}55`,
        borderRadius: 8,
        padding: "8px 12px",
        zIndex: 100,
        pointerEvents: "none",
        minWidth: 130,
        boxShadow: `0 4px 20px ${node.color}22`,
      }}
    >
      <div
        style={{
          fontSize: 9,
          fontWeight: 700,
          letterSpacing: 1.2,
          color: node.color,
          textTransform: "uppercase",
          marginBottom: 4,
          fontFamily: "'Fira Code', monospace",
        }}
      >
        {typeLabels[node.type] ?? node.type}
      </div>
      <div
        style={{
          fontSize: 11,
          fontWeight: 700,
          color: "var(--text-primary)",
          fontFamily: "'Fira Code', monospace",
          wordBreak: "break-all",
        }}
      >
        {node.label}
      </div>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

interface Props {
  replayData: ReplayDataSlice;
  width?: number;
  height?: number;
}

export default function AttackChainGraph({ replayData, width, height = 360 }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const simRef = useRef<d3.Simulation<ChainNode, ChainEdge> | null>(null);

  const [transform, setTransform] = useState<d3.ZoomTransform>(d3.zoomIdentity);
  const [renderTick, setRenderTick] = useState(0);
  const [simReady, setSimReady] = useState(false);
  const [tooltip, setTooltip] = useState<TooltipState | null>(null);

  // Build graph from replay data
  const { nodes, edges } = useMemo(() => buildChainGraph(replayData), [replayData]);

  // Stable D3-mutated copies
  const simNodes = useMemo<ChainNode[]>(() => nodes.map((n) => ({ ...n })), [nodes]);
  const simEdges = useMemo<ChainEdge[]>(() => edges.map((e) => ({ ...e })), [edges]);

  const nodeIdsKey = useMemo(() => nodes.map((n) => n.id).sort().join("|"), [nodes]);
  const rafRef = useRef<number | null>(null);

  // ── Force simulation ───────────────────────────────────────────────────────
  useEffect(() => {
    const W = containerRef.current?.clientWidth ?? (width ?? 600);
    const H = height;

    if (simRef.current) simRef.current.stop();

    const sim = d3
      .forceSimulation<ChainNode, ChainEdge>(simNodes)
      .force(
        "link",
        d3
          .forceLink<ChainNode, ChainEdge>(simEdges)
          .id((d) => d.id)
          .distance(100)
          .strength(0.5)
      )
      .force("charge", d3.forceManyBody<ChainNode>().strength(-220))
      .force("center", d3.forceCenter(W / 2, H / 2))
      .force("collision", d3.forceCollide<ChainNode>().radius(30).strength(0.8))
      .alphaDecay(0.02)
      .alphaMin(0.01);

    simRef.current = sim;

    let firstTick = true;
    sim.on("tick", () => {
      if (firstTick) {
        firstTick = false;
        setSimReady(true);
      }
      if (rafRef.current) return;
      rafRef.current = requestAnimationFrame(() => {
        rafRef.current = null;
        setRenderTick((t) => t + 1);
      });
    });

    return () => {
      sim.stop();
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodeIdsKey, height, width]);

  // Re-heat simulation on data change
  useEffect(() => {
    const sim = simRef.current;
    if (!sim) return;
    if (sim.alpha() < 0.05) sim.alpha(0.3).restart();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodeIdsKey]);

  // ── Pan / zoom ─────────────────────────────────────────────────────────────
  useEffect(() => {
    if (!svgRef.current) return;
    const svg = d3.select<SVGSVGElement, unknown>(svgRef.current);
    const zoom = d3
      .zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.3, 3])
      .on("zoom", (ev: d3.D3ZoomEvent<SVGSVGElement, unknown>) => {
        setTransform(ev.transform);
      });
    svg.call(zoom);
    return () => { svg.on(".zoom", null); };
  }, []);

  // ── Drag ───────────────────────────────────────────────────────────────────
  useEffect(() => {
    if (!svgRef.current || !simRef.current) return;
    const sim = simRef.current;
    const t = setTimeout(() => {
      if (!svgRef.current) return;
      const drag = d3
        .drag<SVGGElement, unknown>()
        .on("start", function (event) {
          const id = this.getAttribute("data-id");
          const d = simNodes.find((n) => n.id === id);
          if (!d) return;
          if (!event.active) sim.alphaTarget(0.3).restart();
          d.fx = d.x ?? 0;
          d.fy = d.y ?? 0;
        })
        .on("drag", function (event) {
          const id = this.getAttribute("data-id");
          const d = simNodes.find((n) => n.id === id);
          if (!d) return;
          d.fx = event.x;
          d.fy = event.y;
        })
        .on("end", function (event) {
          const id = this.getAttribute("data-id");
          const d = simNodes.find((n) => n.id === id);
          if (!d) return;
          if (!event.active) sim.alphaTarget(0);
          d.fx = null;
          d.fy = null;
        });

      d3.select<SVGSVGElement, unknown>(svgRef.current)
        .selectAll<SVGGElement, unknown>("g.acg-node")
        .call(drag);
    }, 60);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodeIdsKey, simNodes]);

  // ── Mouse helpers ──────────────────────────────────────────────────────────
  const handleEnter = useCallback((e: React.MouseEvent, n: ChainNode) => {
    if (!containerRef.current) return;
    const rect = containerRef.current.getBoundingClientRect();
    setTooltip({ node: n, x: e.clientX - rect.left + 14, y: e.clientY - rect.top + 14 });
  }, []);

  const handleLeave = useCallback(() => setTooltip(null), []);

  const handleMove = useCallback((e: React.MouseEvent) => {
    if (!tooltip || !containerRef.current) return;
    const rect = containerRef.current.getBoundingClientRect();
    setTooltip((t) => t ? { ...t, x: e.clientX - rect.left + 14, y: e.clientY - rect.top + 14 } : null);
  }, [tooltip]);

  void renderTick; // consumed to trigger re-render on each D3 tick

  if (nodes.length === 0) {
    return (
      <div
        style={{
          height,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          color: "var(--text-muted)",
          fontSize: 12,
          fontFamily: "'Fira Code', monospace",
          background: "linear-gradient(135deg, #0d1629, #0a1120)",
          border: "1px solid var(--border-color)",
          borderRadius: 14,
        }}
      >
        No attack chain data available for this incident.
      </div>
    );
  }

  return (
    <div
      ref={containerRef}
      style={{
        position: "relative",
        height,
        background: "linear-gradient(135deg, #0d1629, #0a1120)",
        border: "1px solid var(--border-color)",
        borderRadius: 14,
        overflow: "hidden",
        userSelect: "none",
      }}
      onMouseMove={handleMove}
    >
      {/* Panel header */}
      <div
        style={{
          position: "absolute",
          top: 10,
          left: 14,
          zIndex: 5,
          fontFamily: "'Fira Code', monospace",
          fontSize: 9,
          fontWeight: 700,
          letterSpacing: 1.8,
          color: "var(--text-secondary)",
          textTransform: "uppercase",
          pointerEvents: "none",
        }}
      >
        Attack Chain Graph
      </div>

      <svg ref={svgRef} width="100%" height="100%">
        <defs>
          <marker id="acg-arrow" viewBox="0 -5 10 10" refX="22" refY="0"
            markerWidth="6" markerHeight="6" orient="auto">
            <path d="M0,-5L10,0L0,5" fill="#475569" />
          </marker>
          {/* Per-color arrow markers */}
          {["#ef4444", "#f97316", "#22c55e", "#64748b", "#00d4ff", "#8b5cf6", "#dc2626", "#eab308"].map((c) => {
            const id = `acg-arrow-${c.replace("#", "")}`;
            return (
              <marker key={id} id={id} viewBox="0 -5 10 10" refX="22" refY="0"
                markerWidth="6" markerHeight="6" orient="auto">
                <path d="M0,-5L10,0L0,5" fill={c} />
              </marker>
            );
          })}
          <filter id="acg-glow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="2.5" result="b" />
            <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
        </defs>

        <g transform={`translate(${transform.x},${transform.y}) scale(${transform.k})`}>
          {/* Edges */}
          {simReady && simEdges.map((e, i) => {
            const s = e.source as ChainNode;
            const t = e.target as ChainNode;
            if (typeof s !== "object" || typeof t !== "object") return null;
            if (s.x == null || t.x == null) return null;
            const sx = s.x ?? 0, sy = s.y ?? 0;
            const tx = (t as ChainNode).x ?? 0, ty = (t as ChainNode).y ?? 0;
            const dx = tx - sx, dy = ty - sy;
            const dr = Math.sqrt(dx * dx + dy * dy) * 1.6;
            const markerId = `acg-arrow-${e.color.replace("#", "")}`;
            return (
              <g key={i}>
                <path
                  d={`M${sx},${sy}A${dr},${dr} 0 0,1 ${tx},${ty}`}
                  stroke={e.color}
                  strokeWidth={1.4}
                  strokeOpacity={0.6}
                  fill="none"
                  markerEnd={`url(#${markerId})`}
                />
                {/* Edge label at midpoint */}
                {(() => {
                  const mx = (sx + tx) / 2;
                  const my = (sy + ty) / 2;
                  return (
                    <g transform={`translate(${mx},${my})`}>
                      <rect x="-22" y="-8" width="44" height="16" rx="3"
                        fill="var(--bg-primary)" stroke="#1e293b" strokeWidth="1" />
                      <text textAnchor="middle" dominantBaseline="central"
                        fontSize="8" fill={e.color} fontFamily="'Fira Code', monospace"
                        fontWeight="700" style={{ textTransform: "uppercase" }}>
                        {e.label}
                      </text>
                    </g>
                  );
                })()}
              </g>
            );
          })}

          {/* Nodes */}
          {simReady && simNodes.map((n) => {
            if (n.x == null) return null;
            const cfg = NODE_CFG[n.type] ?? NODE_CFG.alert;
            return (
              <g
                key={n.id}
                className="acg-node"
                data-id={n.id}
                transform={`translate(${n.x},${n.y})`}
                style={{ cursor: "pointer" }}
                onMouseEnter={(e) => handleEnter(e, n)}
                onMouseLeave={handleLeave}
              >
                {/* Outer ring */}
                <circle r={cfg.size} fill="var(--bg-primary)" stroke={n.color}
                  strokeWidth={1.8} filter="url(#acg-glow)" />
                {/* Inner fill */}
                <circle r={cfg.size - 5} fill={n.color} opacity={0.14} />
                {/* Glyph */}
                <text textAnchor="middle" dominantBaseline="central"
                  fontSize={cfg.size - 5} fill={n.color} fontWeight="700"
                  style={{ userSelect: "none", pointerEvents: "none" }}>
                  {cfg.glyph}
                </text>
                {/* Label */}
                <text textAnchor="middle" y={cfg.size + 13} fontSize="9"
                  fill="#94a3b8" fontFamily="'Fira Code', monospace" fontWeight="600"
                  style={{ userSelect: "none", pointerEvents: "none" }}>
                  {n.label}
                </text>
              </g>
            );
          })}
        </g>
      </svg>

      {/* Legend */}
      <div
        style={{
          position: "absolute",
          bottom: 10,
          right: 12,
          display: "flex",
          gap: 10,
          flexWrap: "wrap",
          pointerEvents: "none",
        }}
      >
        {([
          { color: "#ef4444", label: "Attacker" },
          { color: "#3b82f6", label: "Endpoint" },
          { color: "#f97316", label: "Process" },
          { color: "#22c55e", label: "Model" },
          { color: "#eab308", label: "Alert" },
        ] as { color: string; label: string }[]).map(({ color, label }) => (
          <span
            key={label}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 4,
              fontSize: 9,
              fontFamily: "'Fira Code', monospace",
              color: "var(--text-secondary)",
              fontWeight: 700,
            }}
          >
            <span
              style={{
                display: "inline-block",
                width: 8,
                height: 8,
                borderRadius: "50%",
                background: color,
                boxShadow: `0 0 4px ${color}`,
              }}
            />
            {label}
          </span>
        ))}
      </div>

      {tooltip && (
        <ChainTooltip node={tooltip.node} x={tooltip.x} y={tooltip.y} />
      )}
    </div>
  );
}
