// useAttackGraphData.ts
// Custom hook: live Socket.IO data + REST snapshot → GraphData shape
// Subscribes to "network_anomaly", "fusion_alert", "graph_update",
// "malware_alert", "user_anomaly", "command_result" events.
// Falls back to mockData only after snapshot fetch completes with zero nodes.

import { useState, useEffect, useRef, useCallback } from "react";
import { io, Socket } from "socket.io-client";
import {
  GraphData,
  GraphNode,
  GraphEdge,
  NodeType,
  Severity,
  ShapEntry,
  BackendNode,
  BackendEdge,
} from "./types";
import { BACKEND_URL } from "../../../config";

// ── Mock SHAP / responses (fallback) ─────────────────────────────────────────
const MOCK_SHAP: GraphData["SHAP"] = {
  "live-src": [
    { feature: "encoded_command_length",         value: 0.34, dir: "+" },
    { feature: "outbound_connection_to_new_asn", value: 0.21, dir: "+" },
    { feature: "beacon_jitter_score",            value: 0.18, dir: "+" },
    { feature: "user_in_admin_group",            value: -0.04, dir: "−" },
  ],
};

const MOCK_RESPONSES: GraphData["RESPONSES"] = {
  "live-src": [
    { action: "Block at firewall", target: "Source IP",     risk: "low", duration: "3s"         },
    { action: "Isolate endpoint",  target: "Source host",   risk: "med", duration: "1m"         },
    { action: "Hunt across fleet", target: "all endpoints", risk: "low", duration: "background" },
  ],
};

// ── Score → severity ──────────────────────────────────────────────────────────
function scoreToSeverity(score: number): Severity {
  if (score >= 0.85) return "CRITICAL";
  if (score >= 0.70) return "HIGH";
  if (score >= 0.40) return "MEDIUM";
  return "LOW";
}

// ── Attack type → node risk 0–100 ─────────────────────────────────────────────
function attackTypeToRisk(attackType: string, severity: Severity): number {
  const baseMap: Record<string, number> = {
    DoS: 80, DDoS: 90, PortScan: 60, BruteForce: 70,
    WebAttack: 75, Botnet: 85, Heartbleed: 88, Infiltration: 95,
    Malware: 85, "Endpoint Alert": 55, "Network Alert": 55,
    Anomaly: 50, BENIGN: 5,
  };
  const base = baseMap[attackType] ?? 50;
  const boost = severity === "CRITICAL" ? 10 : severity === "HIGH" ? 5 : 0;
  return Math.min(100, base + boost);
}

// ── Infer node type from IP ────────────────────────────────────────────────────
function inferNodeType(ip: string): NodeType {
  if (
    ip.startsWith("10.") ||
    ip.startsWith("192.168.") ||
    ip.startsWith("172.")
  ) {
    return "endpoint";
  }
  return "ip";
}

// ── Ensure every node gets a non-empty display label ──────────────────────────
// Never returns "Unknown" — use a descriptive fallback instead.
function safeLabel(primary: string | undefined | null, fallback: string): string {
  const val = (primary ?? "").trim();
  // Reject bare "Unknown" and "unknown" — treat as absent
  if (!val || val.toLowerCase() === "unknown") return fallback;
  return val;
}

// ── Build the best available human-readable label for any node ────────────────
function getNodeLabel(node: {
  type?: string;
  attack_type?: string;
  prediction?: string;
  label?: string;
  ip?: string;
  src_ip?: string;
  id?: string;
  severity?: string;
  command?: string;
  cmd?: string;
}): string {
  const isThreaten =
    node.type === "alert" ||
    node.type === "ip" ||
    (node.severity === "HIGH" || node.severity === "CRITICAL");

  if (isThreaten || node.type === "alert") {
    // Priority: attack classification → prediction string → label → IP
    return (
      safeLabel(node.attack_type, "") ||
      safeLabel(node.prediction, "") ||
      safeLabel(node.label, "") ||
      safeLabel(node.ip ?? node.src_ip, "") ||
      `${node.severity ?? "ALERT"} Event`
    );
  }
  if (node.type === "endpoint") {
    return (
      safeLabel(node.label, "") ||
      safeLabel(node.ip, "") ||
      safeLabel(node.id?.replace(/^ep-/, "").replace(/-/g, "."), "") ||
      "Endpoint"
    );
  }
  if (node.type === "ip") {
    return (
      safeLabel(node.ip, "") ||
      safeLabel(node.src_ip, "") ||
      safeLabel(node.label, "") ||
      safeLabel(node.id?.replace(/^ip-/, "").replace(/-/g, "."), "") ||
      "Host"
    );
  }
  if (node.type === "process") {
    return (
      safeLabel(node.command ?? node.cmd, "") ||
      safeLabel(node.label, "") ||
      "Process"
    );
  }
  if (node.type === "user") {
    return safeLabel(node.label, "") || "User";
  }
  if (node.type === "response_action") {
    return safeLabel(node.command ?? node.label, "") || "Response";
  }
  // Final generic fallback — use ID fragment rather than "Unknown"
  return (
    safeLabel(node.label, "") ||
    safeLabel(node.attack_type, "") ||
    (node.id ? String(node.id).slice(0, 16) : "Node")
  );
}

// ── Backend → GraphNode mapper ─────────────────────────────────────────────────
function backendNodeToGraphNode(n: BackendNode): GraphNode {
  const ip = n.metadata?.ip ?? n.metadata?.source_ip ?? "";
  const attackType = n.metadata?.attack_type ?? n.metadata?.label ?? "";
  const dstIp = n.metadata?.destination_ip ?? n.metadata?.dst_ip ?? "";

  const partial = {
    type: n.type,
    attack_type: attackType || undefined,
    prediction: n.metadata?.prediction ?? undefined,
    label: n.label,
    ip,
    src_ip: ip || undefined,
    id: n.node_id,
    severity: n.severity,
    command: attackType || undefined,
    cmd: attackType || undefined,
  };

  return {
    id: n.node_id,
    type: n.type,
    label: getNodeLabel(partial),
    risk: isNaN(n.risk_score) ? 0 : Math.round(n.risk_score),
    severity: n.severity,
    ip,
    src_ip: ip || undefined,
    dst_ip: dstIp || undefined,
    attack_type: attackType || undefined,
    os: n.metadata?.os ?? "",
    department: n.metadata?.username ?? n.metadata?.user ?? "",
    dept: n.metadata?.username ?? n.metadata?.user ?? "",
    pid: n.metadata?.pid,
    command: attackType || (n.metadata?.command ?? ""),
    cmd: attackType || (n.metadata?.cmd ?? ""),
    geo: n.metadata?.geo ?? "",
    hash: n.metadata?.hash ?? "",
    endpoint_id: n.endpoint_id,
    timestamp: n.timestamp,
    mitre_technique: n.metadata?.mitre_technique ?? undefined,
    shap_reasons: Array.isArray(n.metadata?.shap_reasons) ? n.metadata.shap_reasons : undefined,
    score: typeof n.risk_score === "number" ? Math.round(n.risk_score) : undefined,
    createdAt: Date.now(),
  };
}

// ── Backend → GraphEdge mapper ─────────────────────────────────────────────────
const MALICIOUS_RELATIONS = new Set([
  "triggered_alert", "triggered", "spawned",
  "connected_to", "lateral", "exfil", "executed",
]);

function backendEdgeToGraphEdge(e: BackendEdge): GraphEdge {
  const isMalicious =
    MALICIOUS_RELATIONS.has(e.relation) ||
    ["HIGH", "CRITICAL"].includes(e.metadata?.severity ?? "");
  return {
    id: e.edge_id,
    source: e.source,
    target: e.target,
    type: e.relation,
    relation: e.relation,
    malicious: isMalicious,
    timestamp: e.timestamp,
  };
}

// ── Extract SHAP entries from backend node metadata ────────────────────────────
function extractShapFromMetadata(
  nodeId: string,
  metadata: Record<string, any>,
  shapMap: Record<string, ShapEntry[]>
): void {
  if (Array.isArray(metadata?.shap) && metadata.shap.length > 0) {
    shapMap[nodeId] = metadata.shap.map((s: any) => ({
      feature: s.feature ?? s.name ?? "unknown",
      value: typeof s.value === "number" ? s.value : parseFloat(s.value ?? "0"),
    }));
  }
}

// ── Node TTL constants (milliseconds) ─────────────────────────────────────────
// CRITICAL nodes survive 30 min, HIGH 15 min, MEDIUM/LOW 5 min.
const NODE_TTL_MS: Record<Severity, number> = {
  CRITICAL: 30 * 60 * 1000,
  HIGH:     15 * 60 * 1000,
  MEDIUM:    5 * 60 * 1000,
  LOW:       5 * 60 * 1000,
};

// ── Hook return type ──────────────────────────────────────────────────────────
interface UseAttackGraphDataReturn {
  data: GraphData;
  isConnected: boolean;
  eventsPerSec: number;
  alertCount: number;
  isLoadingSnapshot: boolean;
  clearGraph: () => void;
}

// ── Constants ─────────────────────────────────────────────────────────────────

// Keep at most 200 nodes and 400 edges (rolling window, newest wins)
const MAX_NODES = 200;
const MAX_EDGES = 400;

// Legacy rolling window used by client-side flow builder.
// These are now set equal to MAX_NODES/MAX_EDGES so that addFlow() never
// trims snapshot nodes that were loaded into the graph by the REST fetch.
// Previously FLOW_MAX_NODES=40 caused all snapshot nodes to be evicted the
// moment the first live socket event arrived and called addFlow().
const FLOW_MAX_NODES = MAX_NODES;
const FLOW_MAX_EDGES = MAX_EDGES;

// ── Helper: edge map key ──────────────────────────────────────────────────────
function edgeKey(source: string, target: string, type: string): string {
  return `${source}→${target}:${type}`;
}

// ── Helper: resolve string id from GraphEdge source/target ───────────────────
function resolveId(ref: string | GraphNode): string {
  return typeof ref === "string" ? ref : ref.id;
}

// ─────────────────────────────────────────────────────────────────────────────
export function useAttackGraphData(): UseAttackGraphDataReturn {
  const [data, setData] = useState<GraphData>({
    NODES: [],
    EDGES: [],
    SHAP: MOCK_SHAP,
    RESPONSES: MOCK_RESPONSES,
    TIMELINE: [],
  });
  const [isConnected, setIsConnected] = useState(false);
  const [alertCount, setAlertCount] = useState(0);
  const [isLoadingSnapshot, setIsLoadingSnapshot] = useState(true);

  // Sliding window for events/sec calculation
  const eventTimestampsRef = useRef<number[]>([]);
  const [eventsPerSec, setEventsPerSec] = useState(0);

  // ── clearGraph: wipe all nodes/edges and re-fetch snapshot ────────────────
  // snapshotTrigger increment re-runs the snapshot fetch useEffect.
  const [snapshotTrigger, setSnapshotTrigger] = useState(0);

  const clearGraph = useCallback(() => {
    setData((prev) => ({
      ...prev,
      NODES: [],
      EDGES: [],
      TIMELINE: [],
    }));
    nodeIdSetRef.current.clear();
    edgeKeySetRef.current.clear();
    // Re-fetch the snapshot so post-clear the graph shows persisted data again
    setSnapshotTrigger((t) => t + 1);
  }, []);

  // Track node/edge IDs to avoid O(n) find on every event (used by addFlow)
  const nodeIdSetRef = useRef<Set<string>>(new Set());
  const edgeKeySetRef = useRef<Set<string>>(new Set());

  // Track the last time each endpoint node was seen alive (wall-clock ms).
  // Used to suppress false-positive node removal during the short telemetry gap
  // between an endpoint's 5-second ingest cycle and its 3-second command poll.
  const endpointLastSeenRef = useRef<Map<string, number>>(new Map());

  // Ref so graph_update handler can write SHAP without closure staleness
  const shapMapRef = useRef<Record<string, ShapEntry[]>>(MOCK_SHAP);

  const recordEvent = useCallback(() => {
    const now = Date.now();
    eventTimestampsRef.current.push(now);
    eventTimestampsRef.current = eventTimestampsRef.current.filter(
      (t) => now - t < 10_000
    );
    setEventsPerSec(eventTimestampsRef.current.length / 10);
  }, []);

  // Decay the events/sec counter every second so it drops to 0 when events stop
  useEffect(() => {
    const id = setInterval(() => {
      const now = Date.now();
      eventTimestampsRef.current = eventTimestampsRef.current.filter(
        (t) => now - t < 10_000
      );
      setEventsPerSec(eventTimestampsRef.current.length / 10);
    }, 1_000);
    return () => clearInterval(id);
  }, []);

  // ── TTL-based node cleanup — runs every 60 seconds ─────────────────────────
  // Removes nodes whose createdAt age exceeds their severity-specific TTL,
  // then removes any edges that referenced those nodes.
  useEffect(() => {
    const id = setInterval(() => {
      setData((prev) => {
        const now = Date.now();
        const survivors = new Set<string>();
        const expiredIds = new Set<string>();

        for (const node of prev.NODES) {
          const ttl = NODE_TTL_MS[node.severity] ?? NODE_TTL_MS.MEDIUM;
          const age = now - (node.createdAt ?? now);
          if (age > ttl) {
            expiredIds.add(node.id);
          } else {
            survivors.add(node.id);
          }
        }

        if (expiredIds.size === 0) return prev;

        const newNodes = prev.NODES.filter((n) => !expiredIds.has(n.id));
        const newEdges = prev.EDGES.filter((e) => {
          const src = resolveId(e.source);
          const tgt = resolveId(e.target);
          return survivors.has(src) && survivors.has(tgt);
        });

        // Keep ref sets in sync
        nodeIdSetRef.current = new Set(newNodes.map((n) => n.id));
        edgeKeySetRef.current = new Set(
          newEdges.map((e) => edgeKey(resolveId(e.source), resolveId(e.target), e.type))
        );

        return { ...prev, NODES: newNodes, EDGES: newEdges };
      });
    }, 60_000);
    return () => clearInterval(id);
  }, []);

  // ── Fetch initial snapshot ─────────────────────────────────────────────────
  useEffect(() => {
    let cancelled = false;

    async function fetchSnapshot(hoursParam = 1): Promise<void> {
      try {
        const token = localStorage.getItem("access_token");
        const res = await fetch(
          `${BACKEND_URL}/attack-graph/snapshot?hours=${hoursParam}&min_score=0.10`,
          { headers: token ? { Authorization: `Bearer ${token}` } : {} }
        );

        if (!res.ok) {
          if (process.env.NODE_ENV === 'development') {
            console.warn(`[AttackGraph] snapshot returned ${res.status}`);
          }
          return;
        }

        const payload = await res.json() as { nodes?: BackendNode[]; edges?: BackendEdge[] };
        if (cancelled) return;

        const nodes = payload.nodes ?? [];
        const edges = payload.edges ?? [];

        // If no nodes returned on the initial 2-hour window, widen to 24 hours
        if (nodes.length === 0 && hoursParam < 24) {
          if (process.env.NODE_ENV === 'development') {
            console.info("[AttackGraph] 2-hour window empty — retrying with 24h");
          }
          return fetchSnapshot(24);
        }

        if (nodes.length === 0 && edges.length === 0) return;

        const now = Date.now();
        const newShap: Record<string, ShapEntry[]> = { ...shapMapRef.current };
        const graphNodes = nodes.map((bn) => {
          extractShapFromMetadata(bn.node_id, bn.metadata ?? {}, newShap);
          const gn = backendNodeToGraphNode(bn);
          // Snapshot nodes get current time as createdAt so TTL starts from load
          gn.createdAt = now;
          return gn;
        });
        const graphEdges = edges.map(backendEdgeToGraphEdge);

        shapMapRef.current = newShap;

        // Rebuild ref sets
        nodeIdSetRef.current = new Set(graphNodes.map((n) => n.id));
        edgeKeySetRef.current = new Set(
          graphEdges.map((e) => edgeKey(resolveId(e.source), resolveId(e.target), e.type))
        );

        setData((prev) => ({
          ...prev,
          NODES: graphNodes.slice(-MAX_NODES),
          EDGES: graphEdges.slice(-MAX_EDGES),
          SHAP: newShap,
        }));
      } catch (err) {
        if (process.env.NODE_ENV === 'development') {
          console.error("[AttackGraph] snapshot fetch error:", err);
        }
      } finally {
        if (!cancelled) setIsLoadingSnapshot(false);
      }
    }

    fetchSnapshot();
    return () => { cancelled = true; };
  // snapshotTrigger re-runs this effect when clearGraph() is called
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [snapshotTrigger]);

  // ── Fetch /endpoint/list to seed topology — server hub + all online endpoints ─
  useEffect(() => {
    let cancelled = false;
    async function fetchTopology(): Promise<void> {
      try {
        const token = localStorage.getItem("access_token");
        const res = await fetch(`${BACKEND_URL}/endpoint/list`, {
          headers: token ? { Authorization: `Bearer ${token}` } : {},
        });
        if (!res.ok || cancelled) return;
        const _raw = await res.json();
        const endpoints: Array<{
          endpoint_id: string;
          hostname?: string;
          ip_address?: string;
          os?: string;
          status?: string;
        }> = Array.isArray(_raw) ? _raw : (_raw.endpoints ?? _raw.data ?? []);

        const serverNodeId = "ep-server_host";
        const now = Date.now();

        setData((prev) => {
          const nodeMap = new Map(prev.NODES.map((n) => [n.id, n]));
          const addedEdges: GraphEdge[] = [];

          // Always ensure the central XDR Server hub node is present
          if (!nodeMap.has(serverNodeId)) {
            nodeMap.set(serverNodeId, {
              id: serverNodeId,
              type: "server" as NodeType,
              label: "XDR Server",
              risk: 0,
              severity: "LOW",
              ip: "",
              os: "",
              createdAt: now,
            });
            nodeIdSetRef.current.add(serverNodeId);
          }

          // Add each online endpoint and a "monitors" edge from the server
          for (const ep of endpoints) {
            if (ep.status === "offline") continue;
            const nid = `ep-${ep.endpoint_id}`;
            if (!nodeMap.has(nid)) {
              nodeMap.set(nid, {
                id: nid,
                type: "endpoint",
                label: safeLabel(ep.hostname, ep.endpoint_id),
                risk: 10,
                severity: "LOW",
                ip: ep.ip_address ?? "",
                os: ep.os ?? "",
                endpoint_id: ep.endpoint_id,
                createdAt: now,
              });
              nodeIdSetRef.current.add(nid);
            }
            const ek = edgeKey(serverNodeId, nid, "monitors");
            if (!edgeKeySetRef.current.has(ek)) {
              addedEdges.push({
                id: ek,
                source: serverNodeId,
                target: nid,
                type: "monitors",
                relation: "monitors",
                malicious: false,
                timestamp: new Date().toISOString(),
              });
              edgeKeySetRef.current.add(ek);
            }
          }

          const allNodes = Array.from(nodeMap.values()).slice(-MAX_NODES);
          const allEdges = [...prev.EDGES, ...addedEdges].slice(-MAX_EDGES);
          nodeIdSetRef.current = new Set(allNodes.map((n) => n.id));
          return { ...prev, NODES: allNodes, EDGES: allEdges };
        });
      } catch {
        // Silently ignore — topology is non-critical
      }
    }
    fetchTopology();
    return () => { cancelled = true; };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [snapshotTrigger]);

  // ── addFlow — client-side low-latency graph builder ────────────────────────
  const addFlow = useCallback(
    (
      srcIp: string,
      dstIp: string,
      attackType: string,
      severity: Severity,
      risk: number,
      ts: string
    ) => {
      recordEvent();
      const srcId = `ip-${srcIp.replace(/\./g, "-")}`;
      const dstId = `ip-${dstIp.replace(/\./g, "-")}`;
      const ek = `${srcId}=>${dstId}=>${attackType}`;
      // Normalise attack type — never store raw "Unknown"
      const normalAttackType =
        attackType && attackType.toLowerCase() !== "unknown" ? attackType : "";

      setData((prev) => {
        const newNodes = [...prev.NODES];
        const newEdges = [...prev.EDGES];

        if (!nodeIdSetRef.current.has(srcId)) {
          const srcPartial = {
            type: inferNodeType(srcIp) as string,
            attack_type: normalAttackType || undefined,
            ip: srcIp,
            src_ip: srcIp,
            id: srcId,
            severity,
          };
          newNodes.push({
            id: srcId,
            label: getNodeLabel(srcPartial),
            type: inferNodeType(srcIp),
            severity,
            risk,
            ip: srcIp,
            src_ip: srcIp,
            dst_ip: dstIp || undefined,
            attack_type: normalAttackType || undefined,
            timestamp: ts,
            createdAt: Date.now(),
          });
          nodeIdSetRef.current.add(srcId);
        } else {
          const idx = newNodes.findIndex((n) => n.id === srcId);
          if (idx >= 0) {
            const sevOrder: Severity[] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
            const prev_node = newNodes[idx];
            const shouldUpgrade = sevOrder.indexOf(severity) > sevOrder.indexOf(prev_node.severity);
            newNodes[idx] = {
              ...prev_node,
              ...(shouldUpgrade ? { severity, risk } : {}),
              // Update attack_type if we now have a real one and didn't before
              attack_type: prev_node.attack_type || normalAttackType || undefined,
              dst_ip: prev_node.dst_ip || (dstIp || undefined),
            };
            // Recompute label after enrichment
            newNodes[idx] = {
              ...newNodes[idx],
              label: getNodeLabel(newNodes[idx]),
            };
          }
        }

        if (!nodeIdSetRef.current.has(dstId) && dstIp) {
          const dstPartial = {
            type: inferNodeType(dstIp) as string,
            ip: dstIp,
            src_ip: dstIp,
            id: dstId,
            severity: "LOW" as Severity,
          };
          newNodes.push({
            id: dstId,
            label: getNodeLabel(dstPartial),
            type: inferNodeType(dstIp),
            severity: "LOW",
            risk: 10,
            ip: dstIp,
            src_ip: dstIp,
            timestamp: ts,
            createdAt: Date.now(),
          });
          nodeIdSetRef.current.add(dstId);
        }

        if (!edgeKeySetRef.current.has(ek) && dstIp) {
          const isMal = attackType !== "BENIGN" && attackType.toLowerCase() !== "unknown" && Boolean(attackType);
          const chainNum = isMal ? newEdges.filter((e) => e.malicious).length + 1 : undefined;
          newEdges.push({
            source: srcId,
            target: dstId,
            type: attackType,
            malicious: isMal,
            chain: chainNum,
            ts,
          });
          edgeKeySetRef.current.add(ek);

          if (isMal) {
            const newTimeline = [
              ...prev.TIMELINE,
              { ts: new Date(ts).toLocaleTimeString(), src: srcId, dst: dstId, action: attackType },
            ].slice(-20);

            const trimmedNodes = newNodes.slice(-FLOW_MAX_NODES);
            const trimmedEdges = newEdges.slice(-FLOW_MAX_EDGES);
            nodeIdSetRef.current = new Set(trimmedNodes.map((n) => n.id));
            edgeKeySetRef.current = new Set(
              trimmedEdges.map((e) => `${resolveId(e.source)}=>${resolveId(e.target)}=>${e.type}`)
            );
            return { ...prev, NODES: trimmedNodes, EDGES: trimmedEdges, TIMELINE: newTimeline };
          }
        }

        const trimmedNodes = newNodes.slice(-FLOW_MAX_NODES);
        const trimmedEdges = newEdges.slice(-FLOW_MAX_EDGES);
        nodeIdSetRef.current = new Set(trimmedNodes.map((n) => n.id));
        edgeKeySetRef.current = new Set(
          trimmedEdges.map((e) => `${resolveId(e.source)}=>${resolveId(e.target)}=>${e.type}`)
        );
        return { ...prev, NODES: trimmedNodes, EDGES: trimmedEdges };
      });
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    []
  );

  // ── Socket.IO subscriptions ────────────────────────────────────────────────
  useEffect(() => {
    const socket: Socket = io(BACKEND_URL, {
      transports: ["websocket", "polling"],
      reconnection: true,
      reconnectionAttempts: Infinity,
      reconnectionDelay: 2000,
      auth: { token: localStorage.getItem("access_token") },
    });

    socket.on("connect", () => setIsConnected(true));
    socket.on("disconnect", () => setIsConnected(false));

    // ── graph_update — authoritative backend merge ──────────────────────────
    socket.on("graph_update", (update: { nodes?: BackendNode[]; edges?: BackendEdge[] }) => {
      recordEvent();
      setData((prev) => {
        const nodeMap = new Map(prev.NODES.map((n) => [n.id, n]));
        const eMap = new Map(
          prev.EDGES.map((e) => [edgeKey(resolveId(e.source), resolveId(e.target), e.type), e])
        );
        const newShap = { ...shapMapRef.current };

        for (const bn of update.nodes ?? []) {
          nodeMap.set(bn.node_id, backendNodeToGraphNode(bn));
          extractShapFromMetadata(bn.node_id, bn.metadata ?? {}, newShap);
        }
        for (const be of update.edges ?? []) {
          const ge = backendEdgeToGraphEdge(be);
          eMap.set(edgeKey(resolveId(ge.source), resolveId(ge.target), ge.type), ge);
        }

        shapMapRef.current = newShap;

        const allNodes = Array.from(nodeMap.values()).slice(-MAX_NODES);
        const allEdges = Array.from(eMap.values()).slice(-MAX_EDGES);

        // Keep ref sets in sync
        nodeIdSetRef.current = new Set(allNodes.map((n) => n.id));
        edgeKeySetRef.current = new Set(
          allEdges.map((e) => edgeKey(resolveId(e.source), resolveId(e.target), e.type))
        );

        return { ...prev, NODES: allNodes, EDGES: allEdges, SHAP: newShap };
      });
    });

    // ── network (server monitoring loop) ───────────────────────────────────
    socket.on("network", (raw: Record<string, unknown>) => {
      recordEvent();
      const srcIp = (raw.source_ip as string) ?? "";
      const dstIp = (raw.destination_ip as string) ?? "";
      const rawAttackType = (raw.attack_type as string) ?? "";
      // Prefer attack_type if valid; fall back to prediction string; never use "Unknown"
      const attackType =
        rawAttackType && rawAttackType.toLowerCase() !== "unknown"
          ? rawAttackType
          : (raw.prediction as string) ?? "Anomaly";
      const prediction = raw.prediction as string;
      if (!srcIp || prediction !== "ANOMALY") return;
      const sevStr = (raw.severity as string) ?? "MEDIUM";
      const severity = (["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(sevStr)
        ? sevStr : "MEDIUM") as Severity;
      const risk = attackTypeToRisk(attackType, severity);
      const ts = (raw.timestamp as string) ?? (raw.ts as string) ?? new Date().toISOString();
      addFlow(srcIp, dstIp, attackType, severity, risk, ts);
    });

    // ── network_anomaly (from endpoint psutil connections) ─────────────────
    const handleNetworkAnomaly = (raw: Record<string, unknown>) => {
      const sevStr = (raw.severity as string) ?? "HIGH";
      const severity = (["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(sevStr)
        ? sevStr : "HIGH") as Severity;
      // Show CRITICAL and HIGH always; allow MEDIUM only if the event is recent (within 5 min)
      if (severity === "LOW") return;
      if (severity === "MEDIUM") {
        const rawTs = (raw.ts as string) ?? (raw.timestamp as string) ?? "";
        if (rawTs) {
          const age = Date.now() - new Date(rawTs).getTime();
          if (age > 5 * 60 * 1000) return;
        } else {
          return; // No timestamp — skip MEDIUM without confirmation
        }
      }

      // Only add to graph for actual attacks, not every flow
      const rawAttackType = (raw.attack_type as string) ?? "";
      const confidence = (raw.confidence as number) ?? 0;
      const isAttack = (raw as any).is_attack === true || Boolean(rawAttackType) || confidence >= 60;
      if (!isAttack) return;

      recordEvent();
      const srcIp =
        (raw.source_ip as string) ??
        (raw.src_ip as string) ??
        (raw.hostname as string) ??
        (raw.endpoint_id as string) ??
        "";
      const dstIp = (raw.destination_ip as string) ?? (raw.dst_ip as string) ?? "";
      if (!srcIp) return;
      const attackType =
        rawAttackType && rawAttackType.toLowerCase() !== "unknown"
          ? rawAttackType
          : (raw.prediction as string) ?? "Network Alert";
      const risk = attackTypeToRisk(attackType, severity);
      const ts = (raw.ts as string) ?? (raw.timestamp as string) ?? new Date().toISOString();

      // Standard IP-to-IP flow for the flow graph
      addFlow(srcIp, dstIp || "0.0.0.0", attackType, severity, risk, ts);

      // Additionally draw an IP → endpoint edge when endpoint_id is known
      const epId = (raw.endpoint_id as string) ?? "";
      if (epId) {
        const ipNid = `ip-${srcIp.replace(/\./g, "-")}`;
        const epNid = `ep-${epId}`;
        const riskScore = Math.min(100, Math.round(confidence > 0 ? confidence : risk));
        setData((prev) => {
          const existingIp = prev.NODES.find((n) => n.id === ipNid);
          const epExists = prev.NODES.some((n) => n.id === epNid);
          const newNodes: GraphNode[] = [];
          const newEdges: GraphEdge[] = [];
          if (!existingIp) {
            newNodes.push({
              id: ipNid,
              type: "ip",
              label: getNodeLabel({ type: "ip", ip: srcIp, src_ip: srcIp, id: ipNid, severity, attack_type: attackType }),
              risk: riskScore,
              severity,
              ip: srcIp,
              src_ip: srcIp,
              attack_type: attackType || undefined,
              endpoint_id: epId,
              timestamp: ts,
              createdAt: Date.now(),
            });
          }
          if (epExists && !prev.EDGES.some((e) => resolveId(e.source) === ipNid && resolveId(e.target) === epNid)) {
            newEdges.push({
              id: `${ipNid}-${epNid}-attack`,
              source: ipNid,
              target: epNid,
              type: "attacked",
              relation: "attacked",
              malicious: true,
              timestamp: ts,
            });
          }
          if (newNodes.length === 0 && newEdges.length === 0) return prev;
          return {
            ...prev,
            NODES: [...prev.NODES, ...newNodes].slice(-MAX_NODES),
            EDGES: [...prev.EDGES, ...newEdges].slice(-MAX_EDGES),
          };
        });
      }

      if (severity === "HIGH" || severity === "CRITICAL") {
        setAlertCount((c) => c + 1);
      }
    };
    socket.on("network_anomaly", handleNetworkAnomaly);

    // ── fusion_alert (multi-model fused threat) ────────────────────────────
    const handleFusionAlert = (raw: Record<string, unknown>) => {
      if (!raw || typeof raw.threat_score === "undefined") return;
      // Only add fusion nodes when threat_score >= 0.70
      const score = (raw.threat_score as number) ?? 0;
      if (score < 0.70) return;

      recordEvent();
      const sevStr = (raw.severity as string) ?? "";
      const severity: Severity = (["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(sevStr)
        ? sevStr : scoreToSeverity(score)) as Severity;

      if (severity === "HIGH" || severity === "CRITICAL") {
        setAlertCount((c) => c + 1);
      }

      const source = (raw.source as string) ?? "ml_detector";
      const rawAttackType = (raw.attack_type as string) ?? "";
      // Normalise — never propagate bare "Unknown" through the graph
      const attackType =
        rawAttackType && rawAttackType.toLowerCase() !== "unknown" ? rawAttackType : "";
      const endpointId = (raw.endpoint_id as string) ?? "server_host";
      const ts = (raw.ts as string) ?? new Date().toISOString();
      const srcIp = (raw.source_ip as string) ?? (raw.src_ip as string) ?? "";
      const dstIp = (raw.destination_ip as string) ?? (raw.dst_ip as string) ?? "";
      const riskScore = Math.round(score * 100);

      const srcId = `ep-${endpointId.replace(/[^a-zA-Z0-9]/g, "-")}`;
      const fusionNodeId = `fusion-${source.replace(/[^a-zA-Z0-9]/g, "-")}-${Date.now()}`;

      setData((prev) => {
        const newNodes = [...prev.NODES];
        const newEdges = [...prev.EDGES];

        if (!nodeIdSetRef.current.has(srcId)) {
          const epPartial = {
            type: "endpoint",
            label: endpointId,
            ip: srcIp,
            id: srcId,
            severity,
          };
          newNodes.push({
            id: srcId,
            label: getNodeLabel(epPartial),
            type: "endpoint",
            severity,
            risk: riskScore,
            ip: srcIp || undefined,
            src_ip: srcIp || undefined,
            timestamp: ts,
            createdAt: Date.now(),
          });
          nodeIdSetRef.current.add(srcId);
        }

        if (!nodeIdSetRef.current.has(fusionNodeId)) {
          const fusionPartial = {
            type: "alert",
            attack_type: attackType || undefined,
            ip: srcIp,
            src_ip: srcIp,
            id: fusionNodeId,
            severity,
          };
          // Label: "PortScan (fusion)" or "HIGH Event (fusion)" — never "Unknown (fusion)"
          const fusionLabel = getNodeLabel(fusionPartial) + " (fusion)";
          newNodes.push({
            id: fusionNodeId,
            label: fusionLabel,
            type: "alert",
            severity,
            risk: riskScore,
            attack_type: attackType || undefined,
            src_ip: srcIp || undefined,
            dst_ip: dstIp || undefined,
            score: riskScore,
            timestamp: ts,
            createdAt: Date.now(),
          });
          nodeIdSetRef.current.add(fusionNodeId);
        }

        const ek = edgeKey(srcId, fusionNodeId, attackType);
        if (!edgeKeySetRef.current.has(ek)) {
          const chainNum = newEdges.filter((e) => e.malicious).length + 1;
          newEdges.push({
            source: srcId, target: fusionNodeId, type: attackType,
            malicious: true, chain: chainNum, ts,
          });
          edgeKeySetRef.current.add(ek);
        }

        const trimmedNodes = newNodes.slice(-FLOW_MAX_NODES);
        const trimmedEdges = newEdges.slice(-FLOW_MAX_EDGES);
        nodeIdSetRef.current = new Set(trimmedNodes.map((n) => n.id));
        edgeKeySetRef.current = new Set(
          trimmedEdges.map((e) => edgeKey(resolveId(e.source), resolveId(e.target), e.type))
        );
        return { ...prev, NODES: trimmedNodes, EDGES: trimmedEdges };
      });

      // Add src_ip node and edge to the endpoint node if a source IP is present
      if (srcIp) {
        const ipNid = `ip-${srcIp.replace(/\./g, "-")}`;
        setData((prev) => {
          const existingIp = prev.NODES.find((n) => n.id === ipNid);
          const epExists = prev.NODES.some((n) => n.id === srcId);
          const newNodes: GraphNode[] = existingIp
            ? prev.NODES
            : [
                ...prev.NODES,
                {
                  id: ipNid,
                  type: "ip",
                  label: getNodeLabel({ type: "ip", ip: srcIp, src_ip: srcIp, id: ipNid, severity }),
                  risk: riskScore,
                  severity,
                  ip: srcIp,
                  src_ip: srcIp,
                  endpoint_id: endpointId,
                  timestamp: ts,
                  createdAt: Date.now(),
                } as GraphNode,
              ];
          const ipEdgeId = `${ipNid}-${srcId}`;
          const alreadyHasEdge = prev.EDGES.some(
            (e) => resolveId(e.source) === ipNid && resolveId(e.target) === srcId
          );
          const newEdges =
            epExists && !alreadyHasEdge
              ? [
                  ...prev.EDGES,
                  {
                    id: ipEdgeId,
                    source: ipNid,
                    target: srcId,
                    type: "attacked",
                    relation: "attacked",
                    malicious: true,
                    timestamp: ts,
                  } as GraphEdge,
                ].slice(-MAX_EDGES)
              : prev.EDGES;
          return {
            ...prev,
            NODES: newNodes.slice(-MAX_NODES),
            EDGES: newEdges,
          };
        });
      }
    };
    socket.on("fusion_alert", handleFusionAlert);

    // ── malware_alert ──────────────────────────────────────────────────────
    socket.on("malware_alert", (event: any) => {
      if (event.label === "benign") return;
      recordEvent();

      const epId = event.endpoint_id ?? "server";
      const procName = event.process_name ?? event.file_path ?? "";
      const score = Math.round((event.score ?? event.confidence ?? 0.5) * 100);
      const sev: Severity = event.label === "malicious" ? "CRITICAL" : "MEDIUM";

      const epNodeId = `endpoint_${epId}`;
      const procNodeId = `process_${epId}_${(procName || "proc").replace(/\W/g, "_")}`;

      setData((prev) => {
        const nowTs = Date.now();
        const epNode: GraphNode = {
          id: epNodeId, type: "endpoint",
          label: safeLabel(epId, "Server"),
          risk: score, severity: sev, ip: "", os: "",
          command: procName || undefined,
          createdAt: nowTs,
        };
        const procNode: GraphNode = {
          id: procNodeId, type: "process",
          label: safeLabel(procName, "Suspicious Process"),
          risk: score, severity: sev,
          command: event.label ?? "malware",
          hash: event.sha256 ?? "",
          attack_type: "Malware",
          createdAt: nowTs,
        };
        const newEdge: GraphEdge = {
          source: epNodeId, target: procNodeId, type: "spawned",
          malicious: true, timestamp: event.timestamp,
        };

        const nodeMap = new Map(prev.NODES.map((n) => [n.id, n]));
        nodeMap.set(epNodeId, epNode);
        nodeMap.set(procNodeId, procNode);

        const edgeExists = prev.EDGES.some(
          (e) => resolveId(e.source) === epNodeId && resolveId(e.target) === procNodeId && e.type === "spawned"
        );
        const edges = edgeExists ? prev.EDGES : [...prev.EDGES, newEdge];

        const newShap: Record<string, ShapEntry[]> = { ...prev.SHAP };
        if (Array.isArray(event.shap_explanation) && event.shap_explanation.length > 0) {
          newShap[procNodeId] = event.shap_explanation.map((s: any) => ({
            feature: s.feature ?? s.name ?? "feature",
            value: s.value ?? 0,
          }));
          shapMapRef.current = newShap;
        }

        return { ...prev, NODES: Array.from(nodeMap.values()), EDGES: edges, SHAP: newShap };
      });

      if (["HIGH", "CRITICAL"].includes(sev)) setAlertCount((c) => c + 1);
    });

    // ── user_anomaly ───────────────────────────────────────────────────────
    socket.on("user_anomaly", (event: any) => {
      // Fix 2: only add user anomaly nodes when score >= 0.70 or severity HIGH/CRITICAL
      const rawScore = event.score ?? event.anomaly_score ?? 0;
      const rawSev = event.severity ?? "";
      const isHighSev = rawSev === "HIGH" || rawSev === "CRITICAL";
      if (rawScore < 0.70 && !isHighSev) return;

      recordEvent();
      const username = event.username ?? event.user ?? "";
      const epId = event.endpoint_id ?? "server";
      const score = Math.round((event.score ?? event.anomaly_score ?? 0.5) * 100);
      const sev: Severity = (["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(event.severity ?? "")
        ? event.severity : "MEDIUM") as Severity;

      const userNodeId = `user_${username}`;
      const epNodeId = `endpoint_${epId}`;

      const nowTs = Date.now();
      const userNode: GraphNode = {
        id: userNodeId, type: "user",
        label: safeLabel(username, "Anomalous User"),
        risk: score, severity: sev, department: event.reason ?? "", ip: "", os: "",
        createdAt: nowTs,
      };
      const epNode: GraphNode = {
        id: epNodeId, type: "endpoint",
        label: safeLabel(epId, "Server"),
        risk: score, severity: sev, ip: "", os: "",
        createdAt: nowTs,
      };
      const newEdge: GraphEdge = {
        source: userNodeId, target: epNodeId, type: "authenticated_as",
        malicious: score > 60, timestamp: event.timestamp,
      };

      setData((prev) => {
        const nodeMap = new Map(prev.NODES.map((n) => [n.id, n]));
        nodeMap.set(userNodeId, userNode);
        const existing = nodeMap.get(epNodeId);
        nodeMap.set(epNodeId, {
          ...(existing ?? epNode),
          risk: Math.max(existing?.risk ?? 0, score),
        });
        // Deduplicate edges — only add if a user→endpoint "authenticated_as" edge doesn't exist yet
        const edgeExists = prev.EDGES.some(
          (e) => resolveId(e.source) === userNodeId && resolveId(e.target) === epNodeId && e.type === "authenticated_as"
        );
        const edges = edgeExists ? prev.EDGES : [...prev.EDGES, newEdge];
        return { ...prev, NODES: Array.from(nodeMap.values()), EDGES: edges };
      });
    });

    // ── endpoint_alert ─────────────────────────────────────────────────────
    socket.on("endpoint_alert", (event: any) => {
      // Fix 2: only add endpoint alert nodes for HIGH/CRITICAL severity
      const rawSev = (event.severity as string) ?? "MEDIUM";
      if (rawSev !== "HIGH" && rawSev !== "CRITICAL") return;

      recordEvent();
      const epId = event.endpoint_id ?? event.hostname ?? "";
      const score = Math.round((event.threat_score ?? event.score ?? 0.5) * 100);
      const sevStr = (event.severity as string) ?? "MEDIUM";
      const sev: Severity = (["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(sevStr)
        ? sevStr : "MEDIUM") as Severity;
      const rawAttackType = (event.attack_type as string) ?? "";
      const attackType =
        rawAttackType && rawAttackType.toLowerCase() !== "unknown"
          ? rawAttackType
          : "Endpoint Alert";
      const srcIp = (event.source_ip as string) ?? epId;
      const dstIp = (event.destination_ip as string) ?? "0.0.0.0";
      const ts = (event.ts as string) ?? new Date().toISOString();

      addFlow(srcIp || epId || "0.0.0.0", dstIp, attackType, sev, score, ts);
      if (sev === "HIGH" || sev === "CRITICAL") setAlertCount((c) => c + 1);
    });

    // ── sysmon_alert — Sysmon behavioral events (EID 1/3/7/8/10/11) ──────────
    // Only HIGH/CRITICAL Sysmon events are added to the graph to avoid noise.
    socket.on("sysmon_alert", (event: any) => {
      const rawSev = (event.severity as string) ?? "MEDIUM";
      if (rawSev !== "HIGH" && rawSev !== "CRITICAL") return;

      recordEvent();
      const epId = event.endpoint_id ?? event.hostname ?? "server";
      const score = Math.round((event.anomaly_score ?? event.score ?? 0.5) * 100);
      const sev: Severity = (rawSev === "CRITICAL" ? "CRITICAL" : "HIGH") as Severity;
      const attackType = (event.attack_type as string) ?? "Sysmon Behavioral Alert";
      const ts = (event.ts ?? event.timestamp ?? new Date().toISOString()) as string;

      addFlow(epId, "server_host", attackType, sev, score, ts);
      setAlertCount((c) => c + 1);
    });

    // ── command_result (response action completed) ─────────────────────────
    // Response nodes use a stable ID keyed on epId+action (not Date.now())
    // to prevent infinite node accumulation.  We cap response_action nodes at 10.
    socket.on("command_result", (event: any) => {
      // Instant removal — isolate_host means the endpoint has been explicitly disconnected
      // via a SOAR action; this is never a transient gap, always remove immediately.
      if (event.action === "isolate_host" && event.status === "completed") {
        const nid = `ep-${event.endpoint_id ?? ""}`;
        if (nid !== "ep-") {
          endpointLastSeenRef.current.delete(nid);
          setData((prev) => ({
            ...prev,
            NODES: prev.NODES.filter((n) => n.id !== nid),
            EDGES: prev.EDGES.filter(
              (e) => resolveId(e.source) !== nid && resolveId(e.target) !== nid
            ),
          }));
          nodeIdSetRef.current.delete(nid);
        }
        return;
      }

      recordEvent();
      const epId = event.endpoint_id ?? "server";
      const action = event.action ?? "response";
      const status = event.status ?? "completed";

      // Stable ID — no timestamp, prevents unbounded node growth
      const respNodeId = `response_${epId}_${action}`;
      const epNodeId = `endpoint_${epId}`;

      const nowTs = Date.now();
      const respNode: GraphNode = {
        id: respNodeId, type: "response_action",
        label: safeLabel(action, "Response Action"),
        risk: 0, severity: "LOW", command: status, ip: "", os: "",
        createdAt: nowTs,
      };
      const epNode: GraphNode = {
        id: epNodeId, type: "endpoint",
        label: safeLabel(epId, "Server"),
        risk: 0, severity: "LOW", ip: "", os: "",
        createdAt: nowTs,
      };
      const newEdge: GraphEdge = {
        source: epNodeId, target: respNodeId, type: "responded_by",
        malicious: false, timestamp: new Date().toISOString(),
      };

      const MAX_RESPONSE_NODES = 10;

      setData((prev) => {
        const nodeMap = new Map(prev.NODES.map((n) => [n.id, n]));
        if (!nodeMap.has(epNodeId)) nodeMap.set(epNodeId, epNode);

        // If this exact response node already exists, update it in place
        if (!nodeMap.has(respNodeId)) {
          // Cap response_action nodes at MAX_RESPONSE_NODES by evicting oldest ones
          const existingRespNodes = Array.from(nodeMap.values()).filter(
            (n) => n.type === "response_action"
          );
          if (existingRespNodes.length >= MAX_RESPONSE_NODES) {
            // Remove the first (oldest) response node
            nodeMap.delete(existingRespNodes[0].id);
          }
        }
        nodeMap.set(respNodeId, respNode);

        // Deduplicate edges for this response node
        const edgeExists = prev.EDGES.some(
          (e) => resolveId(e.source) === epNodeId && resolveId(e.target) === respNodeId && e.type === "responded_by"
        );
        const edges = edgeExists ? prev.EDGES : [...prev.EDGES, newEdge];
        return { ...prev, NODES: Array.from(nodeMap.values()), EDGES: edges };
      });
    });

    // ── endpoint_update — real-time endpoint heartbeat → shows connected host ──
    // Creates or updates an endpoint node whenever an endpoint sends telemetry.
    // Also draws a "monitors" edge from server_host → the endpoint if the
    // server node already exists in the graph.
    socket.on("endpoint_update", (event: any) => {
      if (!event.endpoint_id) return;

      const nid = `ep-${event.endpoint_id}`;

      if (event.status === "isolated") {
        // Isolated = explicit SOAR action completed — remove immediately regardless
        // of last-seen time, because the host has been disconnected on purpose.
        setData((prev) => ({
          ...prev,
          NODES: prev.NODES.filter((n) => n.id !== nid),
          EDGES: prev.EDGES.filter(
            (e) => resolveId(e.source) !== nid && resolveId(e.target) !== nid
          ),
        }));
        nodeIdSetRef.current.delete(nid);
        endpointLastSeenRef.current.delete(nid);
        return;
      }

      if (event.status === "offline") {
        // "offline" can arrive transiently during the 5s telemetry / 3s command-poll
        // cycle.  Only remove the node if we have not heard from this endpoint within
        // the last 40 seconds; otherwise the removal is spurious.
        const lastSeen = endpointLastSeenRef.current.get(nid) ?? 0;
        const ageMs = Date.now() - lastSeen;
        if (ageMs < 40_000) return; // recently active — do not remove
        setData((prev) => ({
          ...prev,
          NODES: prev.NODES.filter((n) => n.id !== nid),
          EDGES: prev.EDGES.filter(
            (e) => resolveId(e.source) !== nid && resolveId(e.target) !== nid
          ),
        }));
        nodeIdSetRef.current.delete(nid);
        endpointLastSeenRef.current.delete(nid);
        return;
      }

      // Any non-offline, non-isolated update means the endpoint is alive — refresh timestamp.
      endpointLastSeenRef.current.set(nid, Date.now());

      const threatScore = event.threat_score as number | undefined;
      const severity: Severity =
        (threatScore ?? 0) >= 0.85
          ? "CRITICAL"
          : (threatScore ?? 0) >= 0.7
          ? "HIGH"
          : "LOW";
      const risk = threatScore ? Math.round(threatScore * 100) : 10;

      const epNode: GraphNode = {
        id: nid,
        type: "endpoint",
        label: safeLabel(event.hostname, event.endpoint_id),
        risk,
        severity,
        ip: event.ip_address ?? "",
        os: event.os ?? "",
        endpoint_id: event.endpoint_id,
        timestamp: event.timestamp ?? new Date().toISOString(),
        createdAt: Date.now(),
        meta: { ip: event.ip_address, status: event.status ?? "online" },
      } as GraphNode & { meta?: Record<string, unknown> };

      // Only add NEW nodes for recently-seen endpoints (recency guard prevents
      // stale entries from previous sessions populating the attack graph).
      const lastSeenRaw = event.last_seen ?? event.timestamp;
      const isRecent = (() => {
        if (!lastSeenRaw) return false;
        try {
          const age = (Date.now() - new Date(lastSeenRaw).getTime()) / 1000;
          return age <= 60;
        } catch {
          return false;
        }
      })();

      setData((prev) => {
        const nodeMap = new Map(prev.NODES.map((n) => [n.id, n]));

        // If the node already exists, update it in place (preserve position etc.)
        const existing = nodeMap.get(nid);

        // If node doesn't exist yet, only add it if the endpoint is recent
        if (!existing && !isRecent) return prev;

        nodeMap.set(nid, existing ? { ...existing, ...epNode } : epNode);

        // Add server→endpoint "monitors" edge if server node exists
        const serverNodeId = "ep-server_host";
        const serverExists = nodeMap.has(serverNodeId);
        const monitorEdgeKey = edgeKey(serverNodeId, nid, "monitors");
        const edgeAlreadyExists = edgeKeySetRef.current.has(monitorEdgeKey);

        let newEdges = prev.EDGES;
        if (serverExists && !edgeAlreadyExists) {
          const monitorEdge: GraphEdge = {
            id: monitorEdgeKey,
            source: serverNodeId,
            target: nid,
            type: "monitors",
            relation: "monitors",
            malicious: false,
            timestamp: new Date().toISOString(),
          };
          newEdges = [...prev.EDGES, monitorEdge].slice(-MAX_EDGES);
          edgeKeySetRef.current.add(monitorEdgeKey);
        }

        const allNodes = Array.from(nodeMap.values()).slice(-MAX_NODES);
        nodeIdSetRef.current = new Set(allNodes.map((n) => n.id));

        return { ...prev, NODES: allNodes, EDGES: newEdges };
      });
    });

    // ── endpoint_offline — remove the node and its edges from the graph ───────
    // Apply the same 40s debounce used by endpoint_update "offline" messages.
    // Backend fires endpoint_offline after 35s; the endpoint heartbeats every 5s.
    // If we have seen this endpoint within 40s, the offline signal is a timing
    // artefact — suppress it to keep the monitors edge visible.
    // If this was a genuine isolation (SOAR action), it was already handled by
    // the command_result / endpoint_update "isolated" paths, which bypass this debounce.
    const handleEndpointOffline = (data: { endpoint_id?: string; hostname?: string }) => {
      const offlineId = `ep-${data.endpoint_id ?? ""}`;
      const lastSeen = endpointLastSeenRef.current.get(offlineId) ?? 0;
      const ageMs = Date.now() - lastSeen;
      if (ageMs < 40_000) return;

      endpointLastSeenRef.current.delete(offlineId);
      setData((prev) => ({
        ...prev,
        NODES: prev.NODES.filter((n) => n.id !== offlineId),
        EDGES: prev.EDGES.filter(
          (e) => resolveId(e.source) !== offlineId && resolveId(e.target) !== offlineId
        ),
      }));
      nodeIdSetRef.current.delete(offlineId);
    };
    socket.on("endpoint_offline", handleEndpointOffline);

    // ── graph_update_remove — explicit node removal from backend ─────────────
    const handleGraphRemove = (data: { remove_node_ids?: string[] }) => {
      const ids = new Set(data.remove_node_ids ?? []);
      if (ids.size === 0) return;
      setData((prev) => {
        const newNodes = prev.NODES.filter((n) => !ids.has(n.id));
        const newEdges = prev.EDGES.filter(
          (e) => !ids.has(resolveId(e.source)) && !ids.has(resolveId(e.target))
        );
        nodeIdSetRef.current = new Set(newNodes.map((n) => n.id));
        edgeKeySetRef.current = new Set(
          newEdges.map((e) => edgeKey(resolveId(e.source), resolveId(e.target), e.type ?? ""))
        );
        return { ...prev, NODES: newNodes, EDGES: newEdges };
      });
    };
    socket.on("graph_update_remove", handleGraphRemove);

    return () => {
      socket.off("connect");
      socket.off("disconnect");
      socket.off("graph_update");
      socket.off("network");
      socket.off("network_anomaly", handleNetworkAnomaly);
      socket.off("fusion_alert", handleFusionAlert);
      socket.off("malware_alert");
      socket.off("user_anomaly");
      socket.off("endpoint_alert");
      socket.off("sysmon_alert");
      socket.off("command_result");
      socket.off("endpoint_update");
      socket.off("endpoint_offline", handleEndpointOffline);
      socket.off("graph_update_remove", handleGraphRemove);
      socket.disconnect();
    };
  }, [addFlow, recordEvent]);

  return { data, isConnected, eventsPerSec, alertCount, isLoadingSnapshot, clearGraph };
}
