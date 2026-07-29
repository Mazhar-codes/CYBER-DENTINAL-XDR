// Attack Graph TypeScript interfaces — derived from mockData.js + backend socket contracts

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export type NodeType = "endpoint" | "process" | "ip" | "file" | "user" | "alert" | "response_action" | "threat_actor" | "technique" | "server";

export interface GraphNode {
  id: string;
  label: string;
  type: NodeType;
  severity: Severity;
  /** Risk score 0–100 */
  risk: number;
  ip?: string;
  os?: string;
  dept?: string;
  department?: string;
  pid?: number;
  cmd?: string;
  command?: string;
  country?: string;
  geo?: string;
  asn?: string;
  path?: string;
  hash?: string;
  timestamp?: string;
  details?: Record<string, unknown>;
  /** Backend endpoint_id for SOAR commands */
  endpoint_id?: string;
  /** Attack classification label (e.g. "PortScan", "DDoS", "BruteForce") */
  attack_type?: string;
  /** Source IP address */
  src_ip?: string;
  /** Destination IP address */
  dst_ip?: string;
  /** ML prediction string */
  prediction?: string;
  /** Confidence / threat score 0–100 */
  score?: number;
  /** SHAP reason strings from backend */
  shap_reasons?: string[];
  /** MITRE ATT&CK technique ID (e.g. "T1046") */
  mitre_technique?: string;
  /** Detection layer that produced this node (e.g. "network", "user", "system") */
  source_layer?: string;
  /** Model confidence 0–100 */
  confidence?: number;
  /** Incident ID this node belongs to */
  incident_id?: string;
  /** Creation timestamp (Date.now()) — used for TTL-based cleanup */
  createdAt?: number;
  // D3 mutates these during simulation
  x?: number;
  y?: number;
  fx?: number | null;
  fy?: number | null;
  vx?: number;
  vy?: number;
}

export interface GraphEdge {
  /** Stable dedup key — set by backendEdgeToGraphEdge or endpoint_update handler */
  id?: string;
  source: string | GraphNode;
  target: string | GraphNode;
  type: string;
  /** True when this edge belongs to the detected attack chain */
  malicious: boolean;
  /** Relation label (e.g. "monitors", "triggered_alert") */
  relation?: string;
  /** Attack chain order (1-indexed) — used for replay animation */
  chain?: number;
  ts?: string;
  weight?: number;
  timestamp?: string;
  /** MITRE ATT&CK technique ID on this edge */
  mitre_technique?: string;
  /** Attack type classification */
  attack_type?: string;
  /** Human-readable edge label */
  label?: string;
  /** ML model confidence 0–100 */
  confidence?: number;
  /** Fusion correlation score 0–1 */
  correlation_score?: number;
}

export interface ShapEntry {
  feature: string;
  /** Raw SHAP value; positive = pushes toward malicious */
  value: number;
  /** Original dir field from kit mockData */
  dir?: string;
  direction?: "positive" | "negative";
}

export interface ResponseSuggestion {
  action: string;
  target: string;
  risk: "low" | "med" | "high";
  duration: string;
}

export interface TimelineEntry {
  ts: string;
  src: string;
  dst: string;
  action: string;
  severity?: Severity;
  nodeId?: string;
  timestamp?: string;
  event?: string;
}

export interface GraphData {
  NODES: GraphNode[];
  EDGES: GraphEdge[];
  SHAP: Record<string, ShapEntry[]>;
  RESPONSES: Record<string, ResponseSuggestion[]>;
  TIMELINE: TimelineEntry[];
}

// Node style table — mirrors AttackGraph.jsx NODE_STYLE
export const NODE_STYLE: Record<NodeType, { glyph: string; color: string; size: number; label: string }> = {
  server:          { glyph: "⬡", color: "#00d4ff",  size: 32, label: "XDR Server"      },
  endpoint:        { glyph: "▣", color: "#3b82f6",  size: 26, label: "Endpoint"        },
  process:         { glyph: "⬣", color: "#a78bfa",  size: 22, label: "Process"         },
  ip:              { glyph: "◈", color: "#00d4ff",  size: 22, label: "IP / Domain"     },
  file:            { glyph: "◬", color: "#f97316",  size: 22, label: "File"            },
  user:            { glyph: "◉", color: "#22c55e",  size: 22, label: "User"            },
  alert:           { glyph: "⚠", color: "#dc2626",  size: 26, label: "Active Threat"   },
  response_action: { glyph: "✓", color: "#22c55e",  size: 22, label: "Response Action" },
  threat_actor:    { color: "#dc2626", glyph: "☠",  size: 22, label: "Threat Actor"    },
  technique:       { color: "#a78bfa", glyph: "⬡",  size: 16, label: "Technique"       },
};

// Severity color table — maps to SEVERITY_COLOUR in shared/types.ts
export const SEV_COLOR: Record<Severity, string> = {
  CRITICAL: "#dc2626",
  HIGH:     "#ef4444",
  MEDIUM:   "#f59e0b",
  LOW:      "#3b82f6",
};

// ── Backend wire-format types ─────────────────────────────────────────────────

export interface BackendNode {
  node_id: string;
  type: NodeType;
  label: string;
  endpoint_id: string;
  risk_score: number;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  metadata: Record<string, any>;
  timestamp: string;
  last_updated: string;
}

export interface BackendEdge {
  edge_id: string;
  source: string;
  target: string;
  relation: string;
  endpoint_id: string;
  metadata: Record<string, any>;
  timestamp: string;
  last_updated: string;
}
