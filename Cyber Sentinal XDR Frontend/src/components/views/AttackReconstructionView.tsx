// AttackReconstructionView.tsx — 3-panel full-screen incident investigation view
// Layout: LEFT (mini graph + endpoint summary) | CENTER (replay timeline + controls) | RIGHT (fusion + SHAP + analyst notes)

import React, { useState, useEffect, useRef, useCallback } from "react";
import { motion } from "framer-motion";
import { authAxios } from "../../services/authService";
import ReplayTimeline, { TimelineEvent } from "./AttackGraphView/ReplayTimeline";
import FusionDecisionPanel from "./AttackGraphView/FusionDecisionPanel";
import DetectionPipelineFlow from "./DetectionPipelineFlow";
import AttackChainGraph from "./AttackChainGraph";
import DualOrbitLoader from "../shared/DualOrbitLoader";

// ── Types ────────────────────────────────────────────────────────────────────

interface ReplayCommand {
  command_id?: string;
  action: string;
  target?: string;
  status?: string;       // "completed" | "failed" | "pending" | "sent"
  success?: boolean;
  result_message?: string;
  created_at?: string;
  executed_at?: string;
}

interface ReplayData {
  // Top-level fields (flattened from incident_doc by the backend)
  incident_id: string;
  endpoint_id?: string;
  hostname?: string;
  ip_address?: string;
  os?: string;
  username?: string;
  attack_type?: string;
  severity?: string;
  mitre_technique?: string;
  created_at?: string;
  // Linked response plan id + whether a PDF report already exists for this
  // incident (see AttackReconstructionView's Download/Generate PDF button)
  plan_id?: string;
  has_report?: boolean;
  // Narrative text — plain-English incident summary if backend provides it
  narrative?: string;
  // Sub-documents
  timeline?: RawTimelineEntry[];
  fusion_alert?: FusionAlertData | null;
  shap?: {
    predicted_class?: string;
    reason?: string[];
    top_features?: Array<{
      feature: string;
      shap_value: number;
      feature_value?: number;
    }>;
    raw?: Record<string, unknown>;
  } | null;
  // SOAR commands that were executed for this incident
  commands?: ReplayCommand[];
  // Kept for backward compat — nested originals
  incident?: Record<string, unknown> | null;
  plan?: Record<string, unknown> | null;
  advisory_actions?: unknown[];
  case_notes?: Array<{ note?: string; created_at?: string; analyst?: string; incident_id?: string }> | null;
}

interface RawTimelineEntry {
  ts?: string;
  timestamp?: string;
  event_type?: string;
  // sub-field presence is used to infer type
  network?: Record<string, unknown>;
  system?: Record<string, unknown>;
  malware?: Record<string, unknown>;
  user?: Record<string, unknown>;
  data?: Record<string, unknown>;
  [key: string]: unknown;
}

interface FusionAlertData {
  threat_score: number;
  severity: string;
  attack_type: string;
  sources: string[];
  components?: {
    network?: { score: number; weight: number; contribution: number };
    user?: { score: number; weight: number; contribution: number };
    system?: { score: number; weight: number; contribution: number };
    malware?: { score: number; weight: number; contribution: number };
  };
  mitre_technique?: string;
}

export interface AttackReconstructionViewProps {
  incidentId: string;
  onBack: () => void;
}

// ── Severity helpers ──────────────────────────────────────────────────────────

const SEV_COLORS: Record<string, string> = {
  CRITICAL: "#dc2626",
  HIGH:     "#ef4444",
  MEDIUM:   "#f59e0b",
  LOW:      "#3b82f6",
};

function sevColor(sev?: string): string {
  return SEV_COLORS[(sev ?? "").toUpperCase()] ?? "#64748b";
}

// ── Map raw log entries → TimelineEvent[] ─────────────────────────────────────

function mapToTimelineEvents(raw: RawTimelineEntry[]): TimelineEvent[] {
  return raw.map((entry, idx) => {
    const ts = (entry.ts ?? entry.timestamp ?? new Date().toISOString()) as string;

    // Determine event_type from declared field or presence of sub-field data
    let eventType: TimelineEvent["event_type"] = "fusion_alert";
    if (entry.event_type) {
      const et = String(entry.event_type);
      if (
        et === "network_anomaly" || et === "system_anomaly" || et === "fusion_alert" ||
        et === "malware_alert" || et === "sysmon_alert" || et === "response_action" ||
        et === "user_anomaly"
      ) {
        eventType = et as TimelineEvent["event_type"];
      } else if (et.includes("network") || et === "endpoint_log") {
        eventType = "network_anomaly";
      } else if (et.includes("system")) {
        eventType = "system_anomaly";
      } else if (et.includes("malware")) {
        eventType = "malware_alert";
      } else if (et.includes("sysmon")) {
        eventType = "sysmon_alert";
      } else if (et.includes("response")) {
        eventType = "response_action";
      } else if (et === "user_anomaly" || et.includes("user")) {
        eventType = "user_anomaly";
      }
    } else if (entry.network) {
      eventType = "network_anomaly";
    } else if (entry.system) {
      eventType = "system_anomaly";
    } else if (entry.malware) {
      eventType = "malware_alert";
    } else if (entry.user) {
      eventType = "user_anomaly";
    }

    // Build unified data payload
    const data: Record<string, unknown> =
      (entry.data as Record<string, unknown>) ??
      (entry.network as Record<string, unknown>) ??
      (entry.system as Record<string, unknown>) ??
      (entry.malware as Record<string, unknown>) ??
      (entry.user as Record<string, unknown>) ??
      {};

    // Carry through top-level fields that may be useful
    if (entry.severity) data.severity = entry.severity;
    if (entry.attack_type) data.attack_type = entry.attack_type;
    if (entry.confidence) data.confidence = entry.confidence;

    // Derive source_label from event_type or explicit source field
    let source_label: string | undefined;
    const rawSource = String(entry.source ?? entry.event_type ?? "").toLowerCase();
    if (rawSource.includes("sysmon")) source_label = "Sysmon";
    else if (rawSource.includes("endpoint")) source_label = "Endpoint";
    else if (rawSource.includes("network")) source_label = "Network";
    else if (rawSource.includes("fusion")) source_label = "Fusion";
    else if (rawSource.includes("system")) source_label = "System";
    else if (rawSource.includes("malware")) source_label = "Malware";
    else if (rawSource.includes("user")) source_label = "User";
    else if (rawSource.includes("response")) source_label = "Response";

    // Derive score from various possible score fields
    const rawScore =
      (entry.threat_score as number | undefined) ??
      (entry.anomaly_score as number | undefined) ??
      (entry.score as number | undefined) ??
      (data.threat_score as number | undefined) ??
      (data.anomaly_score as number | undefined) ??
      (data.score as number | undefined);
    const score = rawScore != null ? (rawScore > 1 ? rawScore / 100 : rawScore) : undefined;

    return { ts, event_type: eventType, data, step: idx, source_label, score };
  });
}

// ── Event-type visual config ──────────────────────────────────────────────────

const EVENT_TYPE_CONFIG: Record<string, { icon: string; color: string; label: string }> = {
  network_anomaly: { icon: "◆", color: "#ef4444", label: "Network" },
  fusion_alert:    { icon: "⚡", color: "var(--accent-amber)", label: "Fusion"  },
  system_anomaly:  { icon: "▲", color: "var(--accent-purple)", label: "System"  },
  malware_alert:   { icon: "☣", color: "#dc2626", label: "Malware" },
  sysmon_alert:    { icon: "◈", color: "#06b6d4", label: "Sysmon"  },
  response_action: { icon: "🛡", color: "#22c55e", label: "Response"},
  user_anomaly:    { icon: "◉", color: "#f97316", label: "User"    },
  endpoint_log:    { icon: "▣", color: "#3b82f6", label: "Endpoint"},
};

function eventConfig(et: string) {
  return EVENT_TYPE_CONFIG[et] ?? { icon: "●", color: "var(--text-muted)", label: et };
}

// ── Mini node diagram — data-driven when timeline events exist ────────────────

interface MiniGraphProps {
  severity?: string;
  events?: TimelineEvent[];
  currentStep?: number;
}

function MiniGraph({ severity, events = [], currentStep = 0 }: MiniGraphProps) {
  const sevCol = sevColor(severity);

  // When no timeline events are available, render the static 4-stage pipeline diagram.
  if (events.length === 0) {
    const staticNodes = [
      { x: 70, y: 30,  label: "Endpoint", icon: "▣", color: "#3b82f6" },
      { x: 70, y: 105, label: "Detection", icon: "◈", color: "var(--accent-cyan)" },
      { x: 70, y: 180, label: "Fusion",    icon: "⚡", color: sevCol   },
      { x: 70, y: 255, label: "Response",  icon: "🛡", color: "#22c55e" },
    ];
    return (
      <svg width={140} height={290} viewBox="0 0 140 290">
        <defs>
          <marker id="arr-s" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
            <path d="M0,0 L6,3 L0,6 Z" fill="#334155" />
          </marker>
          <filter id="node-glow-s">
            <feGaussianBlur stdDeviation="2" result="blur" />
            <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
          </filter>
        </defs>
        {staticNodes.slice(0, -1).map((n, i) => (
          <line key={i} x1={n.x} y1={n.y + 18} x2={staticNodes[i + 1].x} y2={staticNodes[i + 1].y - 18}
            stroke="#1e293b" strokeWidth={2} strokeDasharray="4 3" markerEnd="url(#arr-s)" />
        ))}
        {staticNodes.map((n, i) => (
          <g key={i}>
            <circle cx={n.x} cy={n.y} r={16} fill={`${n.color}18`} stroke={n.color}
              strokeWidth={1.5} filter="url(#node-glow-s)" style={{ opacity: 0.9 }} />
            <text x={n.x} y={n.y + 5} textAnchor="middle" fontSize={12} fill={n.color}>{n.icon}</text>
            <text x={n.x} y={n.y + 30} textAnchor="middle" fontSize={8} fill="#475569"
              fontFamily="'Fira Code', monospace" fontWeight={700} letterSpacing={0.5}>
              {n.label.toUpperCase()}
            </text>
          </g>
        ))}
      </svg>
    );
  }

  // Data-driven: build nodes from the unique event_types present in the timeline.
  // Each distinct event_type becomes one node; they are laid out vertically in
  // the order they first appear (chronological).  The current replay step
  // highlights the active node.
  const orderedTypes: string[] = [];
  const seenTypes = new Set<string>();
  for (const ev of events) {
    if (!seenTypes.has(ev.event_type)) {
      seenTypes.add(ev.event_type);
      orderedTypes.push(ev.event_type);
    }
  }

  // Cap to 6 nodes so they fit in the SVG viewport
  const visibleTypes = orderedTypes.slice(0, 6);
  const activeType = events[Math.min(currentStep, events.length - 1)]?.event_type ?? "";

  const nodeR = 16;
  const yStep = Math.min(60, Math.floor(260 / Math.max(visibleTypes.length - 1, 1)));
  const svgH  = 30 + (visibleTypes.length - 1) * yStep + 50;

  const graphNodes = visibleTypes.map((et, i) => {
    const cfg = eventConfig(et);
    return { x: 70, y: 30 + i * yStep, label: cfg.label, icon: cfg.icon, color: cfg.color, active: et === activeType };
  });

  return (
    <svg width={140} height={Math.max(svgH, 120)} viewBox={`0 0 140 ${Math.max(svgH, 120)}`}>
      <defs>
        <marker id="arr-d" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
          <path d="M0,0 L6,3 L0,6 Z" fill="#334155" />
        </marker>
        <filter id="node-glow-d">
          <feGaussianBlur stdDeviation="3" result="blur" />
          <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
      </defs>

      {/* Edges connecting sequential nodes */}
      {graphNodes.slice(0, -1).map((n, i) => (
        <line key={i}
          x1={n.x} y1={n.y + nodeR}
          x2={graphNodes[i + 1].x} y2={graphNodes[i + 1].y - nodeR}
          stroke={graphNodes[i + 1].active ? graphNodes[i + 1].color : "#1e293b"}
          strokeWidth={graphNodes[i + 1].active ? 2 : 1.5}
          strokeDasharray={graphNodes[i + 1].active ? "none" : "4 3"}
          markerEnd="url(#arr-d)"
          style={{ opacity: graphNodes[i + 1].active ? 1 : 0.4 }}
        />
      ))}

      {/* Nodes */}
      {graphNodes.map((n, i) => (
        <g key={i}>
          {/* Active pulse ring */}
          {n.active && (
            <circle cx={n.x} cy={n.y} r={nodeR + 5}
              fill="none" stroke={n.color} strokeWidth={1}
              style={{ opacity: 0.35 }} />
          )}
          <circle cx={n.x} cy={n.y} r={nodeR}
            fill={n.active ? `${n.color}30` : `${n.color}12`}
            stroke={n.color}
            strokeWidth={n.active ? 2 : 1.5}
            filter="url(#node-glow-d)"
            style={{ opacity: n.active ? 1 : 0.55 }}
          />
          <text x={n.x} y={n.y + 5} textAnchor="middle" fontSize={11} fill={n.color}>
            {n.icon}
          </text>
          <text x={n.x} y={n.y + nodeR + 14} textAnchor="middle" fontSize={7} fill={n.active ? "#94a3b8" : "#475569"}
            fontFamily="'Fira Code', monospace" fontWeight={700} letterSpacing={0.5}>
            {n.label.toUpperCase()}
          </text>
        </g>
      ))}
    </svg>
  );
}

// ── Replay controls bar ───────────────────────────────────────────────────────

interface ReplayControlsProps {
  step: number;
  total: number;
  paused: boolean;
  speedMultiplier: number;
  onPlayPause: () => void;
  onReset: () => void;
  onStep: () => void;
  onScrub: (step: number) => void;
  onSpeedChange: (speed: number) => void;
}

const SPEED_OPTIONS = [0.5, 1, 2, 4] as const;

function ReplayControls({ step, total, paused, speedMultiplier, onPlayPause, onReset, onStep, onScrub, onSpeedChange }: ReplayControlsProps) {
  const pct = total > 0 ? (step / Math.max(total - 1, 1)) * 100 : 0;

  return (
    <div
      style={{
        background: "var(--bg-secondary)",
        border: "1px solid var(--border-color)",
        borderRadius: 10,
        padding: "10px 14px",
        display: "flex",
        flexDirection: "column",
        gap: 8,
        flexShrink: 0,
      }}
    >
      {/* Button row */}
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <button
          onClick={onReset}
          aria-label="Reset replay"
          style={ctlBtnStyle}
        >
          ⟲
        </button>

        <button
          onClick={onPlayPause}
          aria-label={paused ? "Play replay" : "Pause replay"}
          style={{
            ...ctlBtnStyle,
            flex: 1,
            background: "linear-gradient(135deg, #3b82f6, #1d4ed8)",
            border: "none",
            color: "#fff",
            boxShadow: "0 0 10px rgba(59,130,246,0.35)",
          }}
        >
          {paused ? "▶  PLAY" : "❚❚ PAUSE"}
        </button>

        <button
          onClick={onStep}
          disabled={step >= total - 1}
          aria-label="Step forward"
          style={{ ...ctlBtnStyle, opacity: step >= total - 1 ? 0.4 : 1 }}
        >
          ▷|
        </button>

        {/* Speed multiplier selector */}
        <div style={{ display: "flex", gap: 2 }}>
          {SPEED_OPTIONS.map((s) => (
            <button
              key={s}
              onClick={() => onSpeedChange(s)}
              aria-label={`Set speed ${s}x`}
              style={{
                ...ctlBtnStyle,
                padding: "4px 7px",
                fontSize: 9,
                fontWeight: 800,
                background: speedMultiplier === s ? "rgba(59,130,246,0.2)" : "#1e293b",
                color: speedMultiplier === s ? "#3b82f6" : "#475569",
                border: speedMultiplier === s ? "1px solid rgba(59,130,246,0.4)" : "1px solid #334155",
              }}
            >
              {s}x
            </button>
          ))}
        </div>

        <span
          style={{
            fontFamily: "'Fira Code', monospace",
            fontSize: 10,
            color: "var(--text-secondary)",
            fontWeight: 700,
            whiteSpace: "nowrap",
          }}
        >
          {String(step + 1).padStart(2, "0")}/{String(total).padStart(2, "0")}
        </span>
      </div>

      {/* Scrubber track */}
      {total > 1 && (
        <div
          style={{
            position: "relative",
            height: 4,
            background: "var(--bg-card)",
            borderRadius: 2,
            cursor: "pointer",
          }}
          onClick={(e) => {
            const rect = e.currentTarget.getBoundingClientRect();
            const ratio = (e.clientX - rect.left) / rect.width;
            onScrub(Math.round(ratio * (total - 1)));
          }}
        >
          <div
            style={{
              position: "absolute",
              left: 0,
              top: 0,
              height: "100%",
              width: `${pct}%`,
              background: "linear-gradient(90deg, #3b82f6, #00d4ff)",
              borderRadius: 2,
              boxShadow: "0 0 6px #00d4ff66",
              transition: "width 0.2s ease",
            }}
          />
          {/* Thumb */}
          <div
            style={{
              position: "absolute",
              top: -4,
              left: `${pct}%`,
              transform: "translateX(-50%)",
              width: 12,
              height: 12,
              borderRadius: "50%",
              background: "#00d4ff",
              boxShadow: "0 0 8px #00d4ff",
              cursor: "grab",
            }}
          />
        </div>
      )}
    </div>
  );
}

const ctlBtnStyle: React.CSSProperties = {
  background: "var(--bg-card)",
  border: "1px solid var(--border-color)",
  color: "var(--text-secondary)",
  padding: "6px 12px",
  borderRadius: 7,
  fontSize: 11,
  fontWeight: 700,
  cursor: "pointer",
  fontFamily: "inherit",
  transition: "all 0.15s",
};

// ── SHAP bar list ─────────────────────────────────────────────────────────────

interface ShapFeature {
  feature: string;
  shap_value: number;
  feature_value?: number;
}

interface ShapListProps {
  features: ShapFeature[];
  /** Fallback contributing models shown when features list is empty */
  contributingModels?: string[];
}

function ShapList({ features, contributingModels }: ShapListProps) {
  if (!features || features.length === 0) {
    // Fallback: show contributing models from the fusion alert
    if (contributingModels && contributingModels.length > 0) {
      return (
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <div style={{ fontSize: 10, color: "var(--text-secondary)", fontStyle: "italic", marginBottom: 4 }}>
            Feature-level SHAP not available. Showing contributing detection models:
          </div>
          {contributingModels.map((model, i) => {
            const modelColors: Record<string, string> = {
              network: "#00d4ff",
              user: "#f97316",
              system: "#8b5cf6",
              malware: "#dc2626",
            };
            const color = modelColors[model.toLowerCase()] ?? "#64748b";
            const weight = 1 / contributingModels.length;
            return (
              <div key={i} style={{ display: "grid", gridTemplateColumns: "1fr 90px 46px", gap: 8, alignItems: "center" }}>
                <div style={{ fontSize: 10, fontFamily: "'Fira Code', monospace", color: "var(--text-secondary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {model.charAt(0).toUpperCase() + model.slice(1)} Detector
                </div>
                <div style={{ height: 5, background: "var(--bg-primary)", border: "1px solid var(--border-color)", borderRadius: 3, overflow: "hidden" }}>
                  <div style={{ height: "100%", width: `${Math.round(weight * 100)}%`, background: color, boxShadow: `0 0 5px ${color}55`, borderRadius: 3 }} />
                </div>
                <div style={{ fontSize: 10, fontWeight: 800, fontFamily: "'Fira Code', monospace", color, textAlign: "right" }}>
                  {Math.round(weight * 100)}%
                </div>
              </div>
            );
          })}
        </div>
      );
    }
    return (
      <div style={{ color: "var(--text-muted)", fontSize: 12, fontStyle: "italic" }}>
        No SHAP explanation available for this incident.
      </div>
    );
  }

  const maxAbs = Math.max(...features.map((f) => Math.abs(f.shap_value)), 0.001);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
      {features.slice(0, 8).map((f, i) => {
        const rawPct = (Math.abs(f.shap_value) / maxAbs) * 100;
        // Minimum 2% width so zero-value features remain visible
        const pct = rawPct < 2 ? 2 : rawPct;
        const positive = f.shap_value >= 0;
        const barColor = positive ? "#dc2626" : "#22c55e";
        return (
          <div key={i} style={{ display: "grid", gridTemplateColumns: "1fr 90px 46px", gap: 8, alignItems: "center" }}>
            <div
              style={{
                fontSize: 10,
                fontFamily: "'Fira Code', monospace",
                color: "var(--text-secondary)",
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
            >
              {f.feature}
            </div>
            <div
              style={{
                height: 5,
                background: "var(--bg-primary)",
                border: "1px solid var(--border-color)",
                borderRadius: 3,
                overflow: "hidden",
              }}
            >
              <div
                style={{
                  height: "100%",
                  width: `${pct}%`,
                  background: barColor,
                  boxShadow: `0 0 5px ${barColor}55`,
                  borderRadius: 3,
                  transition: "width 0.3s",
                  marginLeft: positive ? 0 : "auto",
                }}
              />
            </div>
            <div
              style={{
                fontSize: 10,
                fontWeight: 800,
                fontFamily: "'Fira Code', monospace",
                color: positive ? "#fca5a5" : "#86efac",
                textAlign: "right",
              }}
            >
              {positive ? "+" : ""}{f.shap_value.toFixed(3)}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── Narrative panel ───────────────────────────────────────────────────────────

interface NarrativePanelProps {
  narrative?: string;
  fusionAlert?: FusionAlertData | null;
  attackType?: string;
  severity?: string;
  hostname?: string;
  mitreTechnique?: string;
  commands?: ReplayCommand[];
  plan?: Record<string, unknown> | null;
  createdAt?: string;
}

function NarrativePanel({ narrative, fusionAlert, attackType, severity, hostname, mitreTechnique, commands, plan, createdAt }: NarrativePanelProps) {
  // If backend provides a narrative, show it verbatim.
  // Otherwise generate a concise client-side summary from all available data.
  const text = narrative ?? (() => {
    const parts: string[] = [];
    const sev = (severity ?? "UNKNOWN").toUpperCase();
    const type = attackType ?? fusionAlert?.attack_type ?? "Unknown Threat";
    const host = hostname ?? "an endpoint";
    const score = fusionAlert?.threat_score != null
      ? `Threat score: ${Math.round(fusionAlert.threat_score * 100)}%.`
      : "";
    const mitre = mitreTechnique ?? fusionAlert?.mitre_technique ?? (plan as any)?.mitre_technique;
    const sources = (fusionAlert?.sources ?? []).map(s => s.charAt(0).toUpperCase() + s.slice(1)).join(", ");

    // Timestamp mention
    if (createdAt) {
      try {
        const ts = new Date(createdAt).toLocaleString();
        parts.push(`Incident detected at ${ts}.`);
      } catch { /* ignore */ }
    }

    parts.push(`${sev} severity ${type} detected on ${host}.`);
    if (score) parts.push(score);
    if (sources) parts.push(`Detection sources: ${sources}.`);
    if (mitre) parts.push(`MITRE ATT&CK technique: ${mitre}.`);

    // Response commands count
    const cmdCount = commands?.length ?? 0;
    if (cmdCount > 0) {
      const completedCount = commands!.filter(c => c.success === true || c.status === "completed").length;
      parts.push(
        `${cmdCount} SOAR response command${cmdCount !== 1 ? "s were" : " was"} issued` +
        (completedCount > 0 ? `; ${completedCount} completed successfully.` : ".")
      );
    }

    // Recommended actions count from plan
    const planActions = (plan as any)?.recommended_actions;
    if (Array.isArray(planActions) && planActions.length > 0) {
      parts.push(`Response plan includes ${planActions.length} recommended action${planActions.length !== 1 ? "s" : ""}.`);
    }

    return parts.join(" ");
  })();

  const sc = sevColor(severity);

  return (
    <div
      style={{
        background: `linear-gradient(135deg, ${sc}08, #0d1629)`,
        border: `1px solid ${sc}30`,
        borderLeft: `4px solid ${sc}`,
        borderRadius: 12,
        padding: "12px 16px",
        flexShrink: 0,
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          marginBottom: 8,
        }}
      >
        <span style={{ fontSize: 12, color: sc }}>&#128269;</span>
        <span
          style={{
            fontFamily: "'Fira Code', monospace",
            fontSize: 9,
            fontWeight: 700,
            letterSpacing: 1.5,
            color: "var(--text-secondary)",
            textTransform: "uppercase",
          }}
        >
          Investigation Summary
        </span>
        {!narrative && (
          <span
            style={{
              fontSize: 8,
              fontWeight: 700,
              letterSpacing: 0.8,
              color: "var(--text-muted)",
              background: "var(--bg-card)",
              border: "1px solid var(--border-color)",
              borderRadius: 4,
              padding: "1px 6px",
              marginLeft: "auto",
            }}
          >
            AUTO-GENERATED
          </span>
        )}
      </div>
      <p
        style={{
          margin: 0,
          fontSize: 12,
          color: "var(--text-secondary)",
          lineHeight: 1.6,
          fontStyle: narrative ? "normal" : "italic",
        }}
      >
        {text}
      </p>
    </div>
  );
}

// ── Response Actions panel ────────────────────────────────────────────────────

interface ResponseActionsPanelProps {
  commands: ReplayCommand[];
}

const ACTION_LABELS_MAP: Record<string, string> = {
  block_ip:               "Block IP",
  unblock_ip:             "Unblock IP",
  isolate_host:           "Isolate Host",
  unisolate_host:         "Unisolate Host",
  kill_process:           "Kill Process",
  quarantine_file:        "Quarantine File",
  restore_quarantine_file:"Restore File",
  lock_account:           "Lock Account",
  unlock_account:         "Unlock Account",
  scan_filesystem:        "Scan Filesystem",
  monitor_persistence:    "Monitor Persistence",
  alert_admin:            "Alert Admin",
  update_software:        "Update Software",
  patch_openssl:          "Patch OpenSSL",
  rotate_certificates:    "Rotate Certificates",
  check_exposed_secrets:  "Check Exposed Secrets",
};

function ResponseActionsPanel({ commands }: ResponseActionsPanelProps) {
  const [expandedIdx, setExpandedIdx] = React.useState<number | null>(null);

  if (commands.length === 0) {
    return (
      <div style={{ color: "var(--text-muted)", fontSize: 12, fontStyle: "italic", padding: "12px 16px" }}>
        No SOAR commands recorded for this incident.
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 5, padding: "12px 16px" }}>
      {commands.map((cmd, idx) => {
        const isCompleted = cmd.success === true || cmd.status === "completed";
        const isFailed    = cmd.success === false && cmd.status !== "pending" && cmd.status !== "sent";
        const isPending   = cmd.status === "pending" || cmd.status === "sent";
        const isExpanded  = expandedIdx === idx;

        let statusIcon = "⏳";
        let statusColor = "#f59e0b";
        let statusLabel = "PENDING";
        if (isCompleted) { statusIcon = "✓"; statusColor = "#00ff88"; statusLabel = "DONE"; }
        else if (isFailed) { statusIcon = "✗"; statusColor = "#ff3366"; statusLabel = "FAILED"; }

        const actionLabel = ACTION_LABELS_MAP[cmd.action] ?? cmd.action;
        const hasDetail = !!(cmd.result_message);

        return (
          <div key={idx} style={{ borderRadius: 7, overflow: "hidden" }}>
            <div
              onClick={() => hasDetail && setExpandedIdx(isExpanded ? null : idx)}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 8,
                padding: "7px 10px",
                background: isCompleted
                  ? "rgba(0,255,136,0.04)"
                  : isFailed
                  ? "rgba(255,51,102,0.05)"
                  : "rgba(245,158,11,0.04)",
                border: `1px solid ${isCompleted ? "rgba(0,255,136,0.15)" : isFailed ? "rgba(255,51,102,0.15)" : "rgba(245,158,11,0.15)"}`,
                borderRadius: isExpanded ? "7px 7px 0 0" : 7,
                cursor: hasDetail ? "pointer" : "default",
              }}
            >
              {/* Status badge */}
              <span
                style={{
                  flexShrink: 0,
                  fontSize: 10,
                  fontWeight: 800,
                  letterSpacing: 0.5,
                  color: statusColor,
                  background: `${statusColor}18`,
                  border: `1px solid ${statusColor}40`,
                  borderRadius: 6,
                  padding: "2px 7px",
                  minWidth: 50,
                  textAlign: "center",
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 4,
                }}
              >
                {isPending && (
                  <span style={{ display: "inline-block", width: 7, height: 7, border: `1.5px solid ${statusColor}`, borderTopColor: "transparent", borderRadius: "50%", animation: "xdr-spin 0.7s linear infinite" }} />
                )}
                {statusIcon} {statusLabel}
              </span>

              {/* Action name */}
              <span style={{ fontSize: 11, fontWeight: 700, color: "var(--text-secondary)", flex: 1 }}>
                {actionLabel}
              </span>

              {/* Target */}
              {cmd.target && (
                <span
                  style={{
                    fontSize: 10,
                    fontFamily: "'Fira Code', monospace",
                    color: "var(--accent-amber)",
                    background: "rgba(245,158,11,0.08)",
                    border: "1px solid rgba(245,158,11,0.2)",
                    borderRadius: 4,
                    padding: "1px 6px",
                    flexShrink: 0,
                    maxWidth: 120,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {cmd.target}
                </span>
              )}

              {/* Timestamp */}
              {(cmd.executed_at ?? cmd.created_at) && (
                <span
                  style={{
                    fontSize: 9,
                    fontFamily: "'Fira Code', monospace",
                    color: "var(--text-muted)",
                    flexShrink: 0,
                  }}
                >
                  {(() => {
                    try {
                      return new Date(cmd.executed_at ?? cmd.created_at!).toLocaleTimeString([], {
                        hour: "2-digit", minute: "2-digit", second: "2-digit",
                      });
                    } catch { return ""; }
                  })()}
                </span>
              )}

              {/* Expand chevron */}
              {hasDetail && (
                <span style={{ fontSize: 9, color: "var(--text-muted)", flexShrink: 0 }}>
                  {isExpanded ? "▲" : "▼"}
                </span>
              )}
            </div>

            {/* Expandable result message */}
            {isExpanded && hasDetail && (
              <div
                style={{
                  background: "#080f1e",
                  border: `1px solid ${isCompleted ? "rgba(0,255,136,0.15)" : "rgba(255,51,102,0.15)"}`,
                  borderTop: "none",
                  borderRadius: "0 0 7px 7px",
                  padding: "8px 10px",
                  fontSize: 11,
                  color: "var(--text-muted)",
                  fontFamily: "'Fira Code', monospace",
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-all",
                }}
              >
                {cmd.result_message}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ── Investigation lifecycle types ─────────────────────────────────────────────

type InvestigationStatus = "OPEN" | "INVESTIGATING" | "CONFIRMED_THREAT" | "CONTAINED" | "CLOSED";
type Priority = "P0" | "P1" | "P2" | "P3" | "P4";
type CenterTab = "timeline" | "agents" | "evidence" | "confirm";

const INVESTIGATION_STAGES: InvestigationStatus[] = [
  "OPEN", "INVESTIGATING", "CONFIRMED_THREAT", "CONTAINED", "CLOSED",
];

const STAGE_LABELS: Record<InvestigationStatus, string> = {
  OPEN: "OPEN",
  INVESTIGATING: "INVESTIGATING",
  CONFIRMED_THREAT: "CONFIRMED THREAT",
  CONTAINED: "CONTAINED",
  CLOSED: "CLOSED",
};

const STAGE_COLORS: Record<InvestigationStatus, string> = {
  OPEN: "#64748b",
  INVESTIGATING: "#3b82f6",
  CONFIRMED_THREAT: "#f59e0b",
  CONTAINED: "#22c55e",
  CLOSED: "#475569",
};

const PRIORITY_LABELS: Priority[] = ["P0", "P1", "P2", "P3", "P4"];

const PRIORITY_COLORS: Record<Priority, string> = {
  P0: "#dc2626",
  P1: "#ef4444",
  P2: "#f59e0b",
  P3: "#3b82f6",
  P4: "#64748b",
};

const PRIORITY_DESCRIPTIONS: Record<Priority, string> = {
  P0: "Domain Controller",
  P1: "Critical Asset",
  P2: "High Value",
  P3: "Medium",
  P4: "Low",
};

function defaultPriorityFromSeverity(sev?: string): Priority {
  const s = (sev ?? "").toUpperCase();
  if (s === "CRITICAL") return "P1";
  if (s === "HIGH") return "P2";
  if (s === "MEDIUM") return "P3";
  return "P4";
}

// ── Investigation Lifecycle Bar ───────────────────────────────────────────────

interface LifecycleBarProps {
  status: InvestigationStatus;
  onStageClick: (stage: InvestigationStatus) => void;
  investigationStartTime: number | null;
}

function InvestigationLifecycleBar({ status, onStageClick, investigationStartTime }: LifecycleBarProps) {
  const [elapsedStr, setElapsedStr] = useState("00:00");

  useEffect(() => {
    if (!investigationStartTime) { setElapsedStr("00:00"); return; }
    const tick = () => {
      const secs = Math.floor((Date.now() - investigationStartTime) / 1000);
      const mm = String(Math.floor(secs / 60)).padStart(2, "0");
      const ss = String(secs % 60).padStart(2, "0");
      setElapsedStr(`${mm}:${ss}`);
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [investigationStartTime]);

  const currentIdx = INVESTIGATION_STAGES.indexOf(status);

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 0,
        padding: "6px 20px",
        background: "#060c18",
        borderBottom: "1px solid var(--border-color)",
        flexShrink: 0,
        flexWrap: "wrap",
        rowGap: 6,
      }}
    >
      {INVESTIGATION_STAGES.map((stage, idx) => {
        const isActive = stage === status;
        const isPast = idx < currentIdx;
        const color = STAGE_COLORS[stage];
        return (
          <React.Fragment key={stage}>
            <button
              onClick={() => onStageClick(stage)}
              title={`Set status to ${STAGE_LABELS[stage]}`}
              style={{
                background: isActive ? `${color}22` : isPast ? `${color}0d` : "transparent",
                border: `1px solid ${isActive ? color : isPast ? `${color}44` : "#1e293b"}`,
                borderRadius: 20,
                padding: "3px 12px",
                fontSize: 9,
                fontWeight: isActive ? 800 : 600,
                color: isActive ? color : isPast ? `${color}99` : "#334155",
                cursor: "pointer",
                letterSpacing: 0.8,
                fontFamily: "'Fira Code', monospace",
                transition: "all 0.15s",
                whiteSpace: "nowrap",
                boxShadow: isActive ? `0 0 8px ${color}44` : "none",
              }}
            >
              {isPast && "✓ "}{STAGE_LABELS[stage]}
            </button>
            {idx < INVESTIGATION_STAGES.length - 1 && (
              <div
                style={{
                  width: 20,
                  height: 1,
                  background: idx < currentIdx ? STAGE_COLORS[INVESTIGATION_STAGES[idx]] + "66" : "#1e293b",
                  flexShrink: 0,
                }}
              />
            )}
          </React.Fragment>
        );
      })}

      {/* Running timer */}
      {investigationStartTime && (
        <div
          style={{
            marginLeft: "auto",
            display: "flex",
            alignItems: "center",
            gap: 6,
          }}
        >
          <span
            style={{
              width: 6,
              height: 6,
              borderRadius: "50%",
              background: "#3b82f6",
              display: "inline-block",
              animation: "xdr-pulse 1s ease-in-out infinite",
              flexShrink: 0,
            }}
          />
          <span
            style={{
              fontFamily: "'Fira Code', monospace",
              fontSize: 10,
              fontWeight: 700,
              color: "#3b82f6",
              letterSpacing: 1,
            }}
          >
            {elapsedStr}
          </span>
        </div>
      )}
    </div>
  );
}

// ── Agent Details Tab ─────────────────────────────────────────────────────────

interface AgentCardProps {
  agentName: string;
  agentColor: string;
  score: number | null;
  details: Array<{ label: string; value: string }>;
  confidence: "HIGH" | "MEDIUM" | "LOW" | "N/A";
}

function AgentScoreBar({ score, color }: { score: number | null; color: string }) {
  if (score == null) return <span style={{ fontSize: 10, color: "var(--text-muted)", fontStyle: "italic" }}>N/A</span>;
  const pct = Math.round(Math.min(score, 1) * 100);
  const barColor = score > 0.7 ? "#ef4444" : score > 0.4 ? "#f59e0b" : "#22c55e";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8, flex: 1 }}>
      <div
        style={{
          flex: 1,
          height: 6,
          background: "var(--bg-primary)",
          border: "1px solid var(--border-color)",
          borderRadius: 3,
          overflow: "hidden",
        }}
      >
        <div
          style={{
            height: "100%",
            width: `${pct}%`,
            background: barColor,
            boxShadow: `0 0 5px ${barColor}66`,
            borderRadius: 3,
            transition: "width 0.4s ease",
          }}
        />
      </div>
      <span
        style={{
          fontSize: 10,
          fontWeight: 800,
          fontFamily: "'Fira Code', monospace",
          color: barColor,
          minWidth: 34,
          textAlign: "right",
        }}
      >
        {pct}%
      </span>
    </div>
  );
}

function AgentCard({ agentName, agentColor, score, details, confidence }: AgentCardProps) {
  const [expanded, setExpanded] = useState(false);
  const isDim = score == null || score === 0;
  const confColors: Record<string, string> = { HIGH: "#ef4444", MEDIUM: "#f59e0b", LOW: "#22c55e", "N/A": "#334155" };
  const confColor = confColors[confidence] ?? "#334155";

  return (
    <div
      style={{
        background: isDim ? "#060c18" : "linear-gradient(135deg, #0d1629, #0a1120)",
        border: `1px solid ${isDim ? "#1e293b" : agentColor + "44"}`,
        borderRadius: 10,
        overflow: "hidden",
        opacity: isDim ? 0.55 : 1,
      }}
    >
      {/* Card header — always visible */}
      <div
        onClick={() => setExpanded((e) => !e)}
        style={{
          display: "flex",
          alignItems: "center",
          gap: 10,
          padding: "10px 14px",
          cursor: "pointer",
        }}
      >
        <span
          style={{
            width: 8,
            height: 8,
            borderRadius: "50%",
            background: agentColor,
            boxShadow: `0 0 5px ${agentColor}88`,
            flexShrink: 0,
          }}
        />
        <span
          style={{
            fontSize: 11,
            fontWeight: 700,
            color: isDim ? "#334155" : "#94a3b8",
            flex: 1,
            fontFamily: "'Fira Code', monospace",
          }}
        >
          {agentName}
        </span>
        {/* Confidence badge */}
        <span
          style={{
            fontSize: 9,
            fontWeight: 700,
            color: confColor,
            background: `${confColor}18`,
            border: `1px solid ${confColor}44`,
            borderRadius: 5,
            padding: "1px 7px",
            letterSpacing: 0.5,
            flexShrink: 0,
          }}
        >
          {confidence}
        </span>
        {/* Score bar inline */}
        <div style={{ width: 100, flexShrink: 0 }}>
          <AgentScoreBar score={score} color={agentColor} />
        </div>
        {/* Chevron */}
        <span style={{ fontSize: 9, color: "var(--text-muted)", flexShrink: 0 }}>
          {expanded ? "▲" : "▼"}
        </span>
      </div>

      {/* Expanded details */}
      {expanded && (
        <div
          style={{
            borderTop: `1px solid ${agentColor}22`,
            padding: "10px 14px",
            display: "flex",
            flexDirection: "column",
            gap: 6,
          }}
        >
          {details.map((d, i) => (
            <div key={i} style={{ display: "flex", gap: 8, alignItems: "flex-start" }}>
              <span
                style={{
                  fontSize: 9,
                  fontWeight: 700,
                  color: "var(--text-muted)",
                  fontFamily: "'Fira Code', monospace",
                  letterSpacing: 0.8,
                  textTransform: "uppercase",
                  minWidth: 80,
                  flexShrink: 0,
                  paddingTop: 1,
                }}
              >
                {d.label}
              </span>
              <span
                style={{
                  fontSize: 11,
                  color: "var(--text-secondary)",
                  wordBreak: "break-all",
                  lineHeight: 1.4,
                  fontFamily: d.value.length > 20 ? "'Fira Code', monospace" : "inherit",
                }}
              >
                {d.value}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

interface AgentDetailsTabProps {
  fusionAlert: FusionAlertData | null | undefined;
  events: TimelineEvent[];
}

function AgentDetailsTab({ fusionAlert, events }: AgentDetailsTabProps) {
  const components = fusionAlert?.components;

  // Extract network event details
  const netEvents = events.filter((e) => e.event_type === "network_anomaly");
  const firstNet = netEvents[0];
  const netScore = components?.network?.score ?? null;
  const netConf: AgentCardProps["confidence"] =
    netScore == null ? "N/A" : netScore > 0.7 ? "HIGH" : netScore > 0.4 ? "MEDIUM" : "LOW";
  const netDetails: AgentCardProps["details"] = [
    { label: "Score", value: netScore != null ? `${Math.round(netScore * 100)}%` : "N/A" },
    { label: "Source IP", value: String((firstNet?.data as any)?.src_ip ?? (firstNet?.data as any)?.source_ip ?? "N/A") },
    { label: "Dest IP", value: String((firstNet?.data as any)?.dst_ip ?? (firstNet?.data as any)?.destination_ip ?? "N/A") },
    { label: "Pattern", value: String((firstNet?.data as any)?.attack_type ?? fusionAlert?.attack_type ?? "Anomalous traffic pattern") },
    { label: "Events", value: `${netEvents.length} network event${netEvents.length !== 1 ? "s" : ""}` },
  ];

  // Extract malware event details
  const malEvents = events.filter((e) => e.event_type === "malware_alert");
  const firstMal = malEvents[0];
  const malScore = components?.malware?.score ?? null;
  const malConf: AgentCardProps["confidence"] =
    malScore == null ? "N/A" : malScore > 0.7 ? "HIGH" : malScore > 0.4 ? "MEDIUM" : "LOW";
  const malDetails: AgentCardProps["details"] = [
    { label: "Score", value: malScore != null ? `${Math.round(malScore * 100)}%` : "N/A" },
    { label: "File", value: String((firstMal?.data as any)?.file_path ?? "N/A") },
    { label: "Verdict", value: String((firstMal?.data as any)?.label ?? "N/A") },
    { label: "Entropy", value: String((firstMal?.data as any)?.entropy ?? "N/A") },
    { label: "MD5", value: String((firstMal?.data as any)?.md5 ?? (firstMal?.data as any)?.file_hash ?? "N/A") },
  ];

  // Extract system event details
  const sysEvents = events.filter((e) => e.event_type === "system_anomaly");
  const firstSys = sysEvents[0];
  const sysScore = components?.system?.score ?? null;
  const sysConf: AgentCardProps["confidence"] =
    sysScore == null ? "N/A" : sysScore > 0.7 ? "HIGH" : sysScore > 0.4 ? "MEDIUM" : "LOW";
  const sysDetails: AgentCardProps["details"] = [
    { label: "Score", value: sysScore != null ? `${Math.round(sysScore * 100)}%` : "N/A" },
    { label: "CPU%", value: String((firstSys?.data as any)?.cpu_percent ?? "N/A") },
    { label: "Memory%", value: String((firstSys?.data as any)?.memory_percent ?? "N/A") },
    { label: "Type", value: String((firstSys?.data as any)?.behavioral_attack_type ?? (firstSys?.data as any)?.attack_type ?? "Resource anomaly") },
    { label: "Events", value: `${sysEvents.length} system event${sysEvents.length !== 1 ? "s" : ""}` },
  ];

  // Extract user event details
  const userEvents = events.filter((e) => e.event_type === "user_anomaly");
  const firstUser = userEvents[0];
  const userScore = components?.user?.score ?? null;
  const userConf: AgentCardProps["confidence"] =
    userScore == null ? "N/A" : userScore > 0.7 ? "HIGH" : userScore > 0.4 ? "MEDIUM" : "LOW";
  const userAssessment =
    userScore == null ? "N/A" :
    userScore < 0.4 ? "No insider threat detected" :
    userScore < 0.7 ? "Suspicious user activity" : "High risk insider behavior";
  const userDetails: AgentCardProps["details"] = [
    { label: "Score", value: userScore != null ? `${Math.round(userScore * 100)}%` : "N/A" },
    { label: "Session", value: String((firstUser?.data as any)?.session ?? (firstUser?.data as any)?.username ?? "N/A") },
    { label: "Assessment", value: userAssessment },
    { label: "Events", value: `${userEvents.length} user event${userEvents.length !== 1 ? "s" : ""}` },
  ];

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: 8,
        padding: "10px 2px",
        overflowY: "auto",
        flex: 1,
      }}
    >
      <div style={{ fontSize: 9, color: "var(--text-muted)", fontFamily: "'Fira Code', monospace", letterSpacing: 1, marginBottom: 2 }}>
        CLICK A CARD TO EXPAND AGENT DETAILS
      </div>
      <AgentCard
        agentName="Network Detection Agent"
        agentColor="#ef4444"
        score={netScore}
        details={netDetails}
        confidence={netConf}
      />
      <AgentCard
        agentName="Malware Analysis Agent"
        agentColor="#dc2626"
        score={malScore}
        details={malDetails}
        confidence={malConf}
      />
      <AgentCard
        agentName="System Monitor Agent"
        agentColor="#8b5cf6"
        score={sysScore}
        details={sysDetails}
        confidence={sysConf}
      />
      <AgentCard
        agentName="User Behavior Agent"
        agentColor="#f97316"
        score={userScore}
        details={userDetails}
        confidence={userConf}
      />
    </div>
  );
}

// ── Evidence Tab ──────────────────────────────────────────────────────────────

type EvidenceStatus = "CONFIRMED" | "FOUND" | "DETECTED" | "ANOMALOUS" | "KNOWN" | "CLEAR" | "NORMAL" | "UNKNOWN" | "NOT_FOUND";

const EVIDENCE_STATUS_COLORS: Record<EvidenceStatus, string> = {
  CONFIRMED: "#22c55e",
  FOUND: "#22c55e",
  DETECTED: "#22c55e",
  ANOMALOUS: "#22c55e",
  KNOWN: "#22c55e",
  CLEAR: "#64748b",
  NORMAL: "#64748b",
  UNKNOWN: "#64748b",
  NOT_FOUND: "#ef4444",
};

const EVIDENCE_STATUS_LABELS: Record<EvidenceStatus, string> = {
  CONFIRMED: "CONFIRMED",
  FOUND: "FOUND",
  DETECTED: "DETECTED",
  ANOMALOUS: "ANOMALOUS",
  KNOWN: "KNOWN THREAT",
  CLEAR: "CLEAR",
  NORMAL: "NORMAL",
  UNKNOWN: "UNKNOWN",
  NOT_FOUND: "NOT FOUND",
};

interface EvidenceStepProps {
  stepNum: number;
  title: string;
  description: string;
  status: EvidenceStatus;
  detail?: string;
}

function EvidenceStep({ stepNum, title, description, status, detail }: EvidenceStepProps) {
  const isPositive = ["CONFIRMED", "FOUND", "DETECTED", "ANOMALOUS", "KNOWN"].includes(status);
  const color = EVIDENCE_STATUS_COLORS[status];
  return (
    <div
      style={{
        display: "flex",
        gap: 12,
        padding: "10px 12px",
        background: isPositive ? `${color}08` : "#060c18",
        border: `1px solid ${isPositive ? color + "33" : "#1e293b"}`,
        borderRadius: 10,
      }}
    >
      {/* Step circle */}
      <div
        style={{
          width: 24,
          height: 24,
          borderRadius: "50%",
          background: isPositive ? `${color}22` : "#1e293b",
          border: `2px solid ${isPositive ? color : "#334155"}`,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          fontSize: 10,
          fontWeight: 800,
          color: isPositive ? color : "#475569",
          flexShrink: 0,
          fontFamily: "'Fira Code', monospace",
        }}
      >
        {stepNum}
      </div>
      {/* Content */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 3 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{ fontSize: 11, fontWeight: 700, color: "var(--text-secondary)", flex: 1 }}>{title}</span>
          <span
            style={{
              fontSize: 9,
              fontWeight: 800,
              color,
              background: `${color}18`,
              border: `1px solid ${color}44`,
              borderRadius: 5,
              padding: "1px 7px",
              letterSpacing: 0.5,
              flexShrink: 0,
            }}
          >
            {EVIDENCE_STATUS_LABELS[status]}
          </span>
        </div>
        <div style={{ fontSize: 10, color: "var(--text-secondary)", lineHeight: 1.4 }}>{description}</div>
        {detail && (
          <div
            style={{
              fontSize: 10,
              color: isPositive ? color : "#64748b",
              fontFamily: "'Fira Code', monospace",
              background: `${color}0d`,
              borderRadius: 5,
              padding: "3px 7px",
              marginTop: 2,
            }}
          >
            {detail}
          </div>
        )}
      </div>
    </div>
  );
}

interface EvidenceTabProps {
  events: TimelineEvent[];
  fusionAlert: FusionAlertData | null | undefined;
  attackType?: string;
  mitreTechnique?: string;
}

function EvidenceTab({ events, fusionAlert, attackType, mitreTechnique }: EvidenceTabProps) {
  const malEvents = events.filter((e) => e.event_type === "malware_alert");
  const netEvents = events.filter((e) => e.event_type === "network_anomaly");
  const userEvents = events.filter((e) => e.event_type === "user_anomaly");
  const netScore = fusionAlert?.components?.network?.score ?? 0;
  const userScore = fusionAlert?.components?.user?.score ?? 0;

  // Derive unique endpoint IDs from events
  const endpointIds = new Set<string>();
  events.forEach((e) => {
    const eid = (e.data as any)?.endpoint_id;
    if (eid) endpointIds.add(eid);
  });
  const hasLateralMovement = endpointIds.size > 1;

  // Top destination IP from network events
  const topDstIp = (() => {
    const counts: Record<string, number> = {};
    netEvents.forEach((e) => {
      const ip = String((e.data as any)?.dst_ip ?? (e.data as any)?.destination_ip ?? "");
      if (ip && ip !== "N/A" && ip !== "undefined") counts[ip] = (counts[ip] ?? 0) + 1;
    });
    const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
    return sorted[0]?.[0] ?? null;
  })();

  // Known attack types
  const KNOWN_ATTACK_TYPES = new Set([
    "DoS", "DDoS", "PortScan", "BruteForce", "C2 Beaconing", "Infiltration",
    "Ransomware", "Malware Activity", "Lateral Movement", "WebAttack", "Botnet",
    "Backdoor", "FTP Exploit", "SMB Exploit", "Browser Exploit", "PDF Exploit",
  ]);
  const isKnownAttack = attackType ? KNOWN_ATTACK_TYPES.has(attackType) : false;

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: 8,
        padding: "10px 2px",
        overflowY: "auto",
        flex: 1,
      }}
    >
      <EvidenceStep
        stepNum={1}
        title="File Analysis"
        description="Checking for malicious file execution events..."
        status={malEvents.length > 0 ? "FOUND" : "NOT_FOUND"}
        detail={
          malEvents.length > 0
            ? `${malEvents.length} malware event${malEvents.length !== 1 ? "s" : ""} — ${String((malEvents[0].data as any)?.label ?? "suspicious")} verdict`
            : undefined
        }
      />
      <EvidenceStep
        stepNum={2}
        title="Network Correlation"
        description="Correlating network flows with known threat signatures..."
        status={netScore > 0.5 ? "CONFIRMED" : "CLEAR"}
        detail={
          netEvents.length > 0
            ? `${netEvents.length} network event${netEvents.length !== 1 ? "s" : ""}${topDstIp ? ` · Top dst: ${topDstIp}` : ""} · Score: ${Math.round(netScore * 100)}%`
            : undefined
        }
      />
      <EvidenceStep
        stepNum={3}
        title="Lateral Movement Check"
        description="Checking for multi-endpoint spread and pivoting behavior..."
        status={hasLateralMovement ? "DETECTED" : "CLEAR"}
        detail={
          hasLateralMovement
            ? `Spread across ${endpointIds.size} endpoints`
            : "Activity confined to single endpoint"
        }
      />
      <EvidenceStep
        stepNum={4}
        title="User Correlation"
        description="Analyzing user behavior for insider threat indicators..."
        status={userScore > 0.5 ? "ANOMALOUS" : "NORMAL"}
        detail={
          userEvents.length > 0
            ? `${userEvents.length} user event${userEvents.length !== 1 ? "s" : ""} · Risk score: ${Math.round(userScore * 100)}%`
            : userScore > 0
            ? `User behavior score: ${Math.round(userScore * 100)}%`
            : undefined
        }
      />
      <EvidenceStep
        stepNum={5}
        title="Historical Analysis"
        description="Cross-referencing attack pattern with threat intelligence database..."
        status={isKnownAttack ? "KNOWN" : "UNKNOWN"}
        detail={
          attackType
            ? `Attack type: ${attackType}${mitreTechnique ? ` · MITRE: ${mitreTechnique}` : ""}`
            : "No attack classification available"
        }
      />
    </div>
  );
}

// ── Threat Confirmation Tab ───────────────────────────────────────────────────

interface ThreatConfirmTabProps {
  checks: { realThreat: boolean; scopeDefined: boolean; impactAssessed: boolean };
  onChecksChange: (c: { realThreat: boolean; scopeDefined: boolean; impactAssessed: boolean }) => void;
  onActivateResponse: () => void;
  onMarkFalsePositive: () => void;
  evidenceCount: number;
  createdAt?: string;
  priority: Priority;
}

function ThreatConfirmTab({
  checks,
  onChecksChange,
  onActivateResponse,
  onMarkFalsePositive,
  evidenceCount,
  createdAt,
  priority,
}: ThreatConfirmTabProps) {
  const allChecked = checks.realThreat && checks.scopeDefined && checks.impactAssessed;

  const timeSinceDetection = (() => {
    if (!createdAt) return "N/A";
    try {
      const secs = Math.floor((Date.now() - new Date(createdAt).getTime()) / 1000);
      if (secs < 60) return `${secs}s`;
      const mins = Math.floor(secs / 60);
      if (mins < 60) return `${mins}m ${secs % 60}s`;
      return `${Math.floor(mins / 60)}h ${mins % 60}m`;
    } catch { return "N/A"; }
  })();

  const checkItems: Array<{ key: keyof typeof checks; label: string; description: string }> = [
    {
      key: "realThreat",
      label: "REAL THREAT",
      description: "Evidence supports an actual attack — not a false positive or misconfigured alert",
    },
    {
      key: "scopeDefined",
      label: "SCOPE DEFINED",
      description: "Attack scope has been assessed — isolated incident vs. widespread compromise",
    },
    {
      key: "impactAssessed",
      label: "IMPACT ASSESSED",
      description: "Business impact and sensitive data risk have been evaluated and documented",
    },
  ];

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: 10,
        padding: "10px 2px",
        overflowY: "auto",
        flex: 1,
      }}
    >
      {/* Checklist */}
      <div
        style={{
          background: "linear-gradient(135deg, #0d1629, #0a1120)",
          border: "1px solid var(--border-color)",
          borderRadius: 10,
          overflow: "hidden",
        }}
      >
        <div
          style={{
            padding: "8px 14px",
            borderBottom: "1px solid var(--border-color)",
            fontSize: 9,
            fontWeight: 700,
            letterSpacing: 1.5,
            color: "var(--text-secondary)",
            fontFamily: "'Fira Code', monospace",
            textTransform: "uppercase",
          }}
        >
          Go / No-Go Checklist
        </div>
        <div style={{ padding: "10px 14px", display: "flex", flexDirection: "column", gap: 8 }}>
          {checkItems.map((item) => {
            const isChecked = checks[item.key];
            return (
              <label
                key={item.key}
                style={{
                  display: "flex",
                  gap: 10,
                  alignItems: "flex-start",
                  cursor: "pointer",
                  padding: "8px 10px",
                  borderRadius: 8,
                  background: isChecked ? "rgba(34,197,94,0.06)" : "transparent",
                  border: `1px solid ${isChecked ? "rgba(34,197,94,0.25)" : "#1e293b"}`,
                  transition: "all 0.15s",
                }}
              >
                <input
                  type="checkbox"
                  checked={isChecked}
                  onChange={(e) => onChecksChange({ ...checks, [item.key]: e.target.checked })}
                  style={{ marginTop: 1, width: 14, height: 14, cursor: "pointer", accentColor: "#22c55e" }}
                />
                <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                  <span
                    style={{
                      fontSize: 10,
                      fontWeight: 800,
                      color: isChecked ? "#22c55e" : "#94a3b8",
                      letterSpacing: 0.8,
                    }}
                  >
                    {item.label}
                  </span>
                  <span style={{ fontSize: 10, color: "var(--text-secondary)", lineHeight: 1.4 }}>
                    {item.description}
                  </span>
                </div>
              </label>
            );
          })}
        </div>
      </div>

      {/* Activate response button */}
      <button
        onClick={onActivateResponse}
        disabled={!allChecked}
        style={{
          padding: "10px 16px",
          borderRadius: 8,
          border: `1px solid ${allChecked ? "rgba(34,197,94,0.5)" : "#1e293b"}`,
          background: allChecked ? "rgba(34,197,94,0.12)" : "#060c18",
          color: allChecked ? "#22c55e" : "#334155",
          fontWeight: 800,
          fontSize: 11,
          cursor: allChecked ? "pointer" : "not-allowed",
          letterSpacing: 0.8,
          transition: "all 0.15s",
          boxShadow: allChecked ? "0 0 12px rgba(34,197,94,0.2)" : "none",
        }}
      >
        {allChecked ? "ACTIVATE RESPONSE PLAN" : "Complete checklist to activate"}
      </button>

      {/* False positive button */}
      <button
        onClick={onMarkFalsePositive}
        style={{
          padding: "8px 16px",
          borderRadius: 8,
          border: "1px solid rgba(239,68,68,0.35)",
          background: "rgba(239,68,68,0.06)",
          color: "#ef4444",
          fontWeight: 700,
          fontSize: 11,
          cursor: "pointer",
          letterSpacing: 0.5,
          transition: "all 0.15s",
        }}
      >
        MARK AS FALSE POSITIVE
      </button>

      {/* Summary stats */}
      <div
        style={{
          background: "#060c18",
          border: "1px solid var(--border-color)",
          borderRadius: 10,
          padding: "10px 14px",
          display: "grid",
          gridTemplateColumns: "1fr 1fr 1fr",
          gap: 8,
        }}
      >
        {[
          { label: "Evidence Items", value: String(evidenceCount), color: evidenceCount > 2 ? "#ef4444" : "#94a3b8" },
          { label: "Time Since Detection", value: timeSinceDetection, color: "var(--accent-amber)" },
          { label: "Priority", value: priority, color: PRIORITY_COLORS[priority] },
        ].map(({ label, value, color }) => (
          <div key={label} style={{ display: "flex", flexDirection: "column", gap: 3, alignItems: "center" }}>
            <span style={{ fontSize: 15, fontWeight: 800, color, fontFamily: "'Fira Code', monospace" }}>
              {value}
            </span>
            <span style={{ fontSize: 8, color: "var(--text-muted)", fontFamily: "'Fira Code', monospace", letterSpacing: 0.8, textAlign: "center" }}>
              {label.toUpperCase()}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Detection Scores Mini Panel (LEFT panel) ──────────────────────────────────

interface DetectionScoresMiniPanelProps {
  fusionAlert: FusionAlertData | null | undefined;
}

function DetectionScoresMiniPanel({ fusionAlert }: DetectionScoresMiniPanelProps) {
  const components = fusionAlert?.components;
  const agents: Array<{ label: string; key: keyof NonNullable<typeof components>; color: string }> = [
    { label: "Network",  key: "network", color: "#ef4444" },
    { label: "Malware",  key: "malware", color: "#dc2626" },
    { label: "System",   key: "system",  color: "var(--accent-purple)" },
    { label: "User",     key: "user",    color: "#f97316" },
  ];

  return (
    <div
      style={{
        background: "linear-gradient(135deg, #0d1629, #0a1120)",
        border: "1px solid var(--border-color)",
        borderRadius: 14,
        padding: "12px 14px",
        display: "flex",
        flexDirection: "column",
        gap: 8,
        flexShrink: 0,
      }}
    >
      <div
        style={{
          fontFamily: "'Fira Code', monospace",
          fontSize: 9,
          fontWeight: 700,
          letterSpacing: 1.8,
          color: "var(--text-secondary)",
          textTransform: "uppercase",
          marginBottom: 2,
        }}
      >
        Detection Scores
      </div>
      {agents.map(({ label, key, color }) => {
        const score = components?.[key]?.score ?? null;
        const pct = score != null ? Math.round(Math.min(score, 1) * 100) : 0;
        const barColor = score == null ? "#1e293b" : score > 0.7 ? "#ef4444" : score > 0.4 ? "#f59e0b" : "#22c55e";
        return (
          <div key={key} style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span
              style={{
                fontSize: 9,
                fontWeight: 700,
                color,
                fontFamily: "'Fira Code', monospace",
                width: 52,
                flexShrink: 0,
              }}
            >
              {label}
            </span>
            <div
              style={{
                flex: 1,
                height: 5,
                background: "var(--bg-primary)",
                border: "1px solid var(--border-color)",
                borderRadius: 3,
                overflow: "hidden",
              }}
            >
              <div
                style={{
                  height: "100%",
                  width: `${pct}%`,
                  background: barColor,
                  boxShadow: score != null && score > 0 ? `0 0 4px ${barColor}66` : "none",
                  borderRadius: 3,
                  transition: "width 0.4s ease",
                }}
              />
            </div>
            <span
              style={{
                fontSize: 10,
                fontWeight: 700,
                fontFamily: "'Fira Code', monospace",
                color: score != null ? barColor : "#334155",
                width: 30,
                textAlign: "right",
                flexShrink: 0,
              }}
            >
              {score != null ? `${pct}%` : "—"}
            </span>
          </div>
        );
      })}
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function AttackReconstructionView({
  incidentId,
  onBack,
}: AttackReconstructionViewProps) {
  const [data, setData] = useState<ReplayData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // PDF report download / on-demand generation
  const [pdfBusy, setPdfBusy] = useState(false);
  const [pdfError, setPdfError] = useState<string | null>(null);

  // Replay state
  const [replayStep, setReplayStep] = useState(0);
  const [paused, setPaused] = useState(true);
  const [speedMultiplier, setSpeedMultiplier] = useState(1);
  const tickerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  // Ref so the interval callback always reads the current events.length without stale closure
  const eventsLengthRef = useRef(0);

  // Analyst notes
  const [notes, setNotes] = useState("");
  const [notesSaved, setNotesSaved] = useState(false);
  const [notesSaving, setNotesSaving] = useState(false);

  // Derived timeline events
  const [events, setEvents] = useState<TimelineEvent[]>([]);

  // Investigation workflow state
  const [investigationStatus, setInvestigationStatus] = useState<InvestigationStatus>("OPEN");
  const [priority, setPriority] = useState<Priority>("P3");
  const [investigationStartTime, setInvestigationStartTime] = useState<number | null>(null);
  const [activeTab, setActiveTab] = useState<CenterTab>("timeline");
  const [confirmChecks, setConfirmChecks] = useState({
    realThreat: false,
    scopeDefined: false,
    impactAssessed: false,
  });

  // ── Fetch replay data ──────────────────────────────────────────────────────
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    // Use a relative path so the authAxios baseURL applies — avoids double-URL
    // if REACT_APP_BACKEND_URL happens to differ between authService and this file.
    // If the primary /replay/{id} endpoint returns 404, fall back to
    // /replay/plan/{id} which accepts plan IDs directly.
    authAxios
      .get<ReplayData>(`/replay/${incidentId}`)
      .catch(async (err) => {
        if (err?.response?.status === 404) {
          // Try the plan-based endpoint as a fallback
          return authAxios.get<ReplayData>(`/replay/plan/${incidentId}`);
        }
        throw err;
      })
      .then((res) => {
        if (cancelled) return;
        const d = res.data;

        if (process.env.NODE_ENV === "development") {
          console.log(
            `[AttackReconstruction] /replay/${incidentId} response:`,
            { timeline_length: d.timeline?.length ?? 0, has_fusion: !!d.fusion_alert, has_shap: !!d.shap, has_plan: !!d.plan }
          );
        }

        setData(d);
        const mapped = mapToTimelineEvents(d.timeline ?? []);
        setEvents(mapped);
        setReplayStep(0);

        // Initialize priority from severity
        setPriority(defaultPriorityFromSeverity(d.severity));

        // Pre-populate analyst notes textarea with the most recent case note
        // returned by /replay so existing investigation notes are not lost.
        if (Array.isArray(d.case_notes) && d.case_notes.length > 0) {
          const latestNote = d.case_notes[0];
          const noteText: string =
            (latestNote as any)?.note ??
            (latestNote as any)?.content ??
            (latestNote as any)?.text ??
            "";
          if (noteText) setNotes(noteText);
        }
      })
      .catch((err) => {
        if (cancelled) return;
        const status = err?.response?.status;
        if (process.env.NODE_ENV === "development") {
          console.error(`[AttackReconstruction] fetch error (status=${status}):`, err?.message);
        }
        if (status === 404) {
          setError(
            `Incident not found. Both /replay/${incidentId.slice(-12)} and /replay/plan/${incidentId.slice(-12)} returned 404. ` +
            `Ensure the incident has been persisted and the backend replay endpoints exist.`
          );
        } else if (status === 403) {
          setError("Access denied — analyst or admin role required.");
        } else if (status === 401) {
          setError("Session expired — please log in again.");
        } else {
          setError(`Failed to load incident data (HTTP ${status ?? "network error"}): ${err?.message ?? "Unknown error"}`);
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => { cancelled = true; };
  }, [incidentId]);

  // Keep eventsLengthRef in sync so interval callback never reads stale length
  useEffect(() => {
    eventsLengthRef.current = events.length;
  }, [events.length]);

  // ── Auto-play ticker ───────────────────────────────────────────────────────
  useEffect(() => {
    if (paused || events.length === 0) {
      if (tickerRef.current) {
        clearInterval(tickerRef.current);
        tickerRef.current = null;
      }
      return;
    }
    const intervalMs = Math.round(900 / Math.max(speedMultiplier, 0.25));
    tickerRef.current = setInterval(() => {
      setReplayStep((s) => {
        // Read from ref — never stale inside interval callback
        if (s >= eventsLengthRef.current - 1) {
          setPaused(true);
          return s;
        }
        return s + 1;
      });
    }, intervalMs);
    return () => {
      if (tickerRef.current) clearInterval(tickerRef.current);
    };
  }, [paused, events.length, speedMultiplier]);

  // ── Handlers ───────────────────────────────────────────────────────────────
  const handlePlayPause = useCallback(() => {
    if (replayStep >= eventsLengthRef.current - 1) {
      setReplayStep(0);
      setPaused(false);
    } else {
      setPaused((p) => !p);
    }
  }, [replayStep]);

  const handleReset = useCallback(() => {
    setPaused(true);
    setReplayStep(0);
  }, []);

  const handleStep = useCallback(() => {
    setPaused(true);
    setReplayStep((s) => Math.min(s + 1, eventsLengthRef.current - 1));
  }, []);

  const handleScrub = useCallback((step: number) => {
    setPaused(true);
    setReplayStep(Math.max(0, Math.min(step, eventsLengthRef.current - 1)));
  }, []);

  const handleSaveNotes = useCallback(async () => {
    if (!notes.trim() || !data) return;
    setNotesSaving(true);
    try {
      await authAxios.post(`/case-notes`, {
        endpoint_id: data.endpoint_id ?? incidentId,
        note: notes.trim(),
        incident_id: incidentId,
        attack_type: data.attack_type,
        severity: data.severity,
      });
      setNotesSaved(true);
      setTimeout(() => setNotesSaved(false), 3000);
    } catch {
      // Non-critical — silently fail (case-notes endpoint may not exist yet)
    } finally {
      setNotesSaving(false);
    }
  }, [notes, data, incidentId]);

  const handleExportJson = useCallback(() => {
    if (!data) return;
    try {
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `incident_${incidentId}.json`;
      anchor.click();
      setTimeout(() => URL.revokeObjectURL(url), 5000);
    } catch {
      // Silently ignore
    }
  }, [data, incidentId]);

  const triggerBlobDownload = (blob: Blob, filename: string) => {
    const blobUrl = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = blobUrl;
    anchor.download = filename;
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(blobUrl), 5000);
  };

  const b64ToBlob = (b64: string, type: string) => {
    const byteChars = atob(b64);
    const byteNumbers = new Array(byteChars.length);
    for (let i = 0; i < byteChars.length; i++) byteNumbers[i] = byteChars.charCodeAt(i);
    return new Blob([new Uint8Array(byteNumbers)], { type });
  };

  const handleDownloadPdf = useCallback(async () => {
    if (!data || pdfBusy) return;
    setPdfError(null);
    setPdfBusy(true);
    try {
      if (data.has_report && data.incident_id) {
        // A report already exists (server confirmed via /replay) — download it directly.
        const res = await authAxios.get(`/reports/${data.incident_id}/download`, { responseType: "blob" });
        triggerBlobDownload(new Blob([res.data], { type: "application/pdf" }), `incident_${data.incident_id}.pdf`);
      } else {
        // No report exists yet for this incident/plan — generate one on demand
        // using the already-working /reports/generate endpoint, then download
        // the PDF it returns (embedded as base64, so no second request needed).
        const planIdForGen = data.plan_id || (data.plan as any)?.plan_id || incidentId;
        if (!planIdForGen) {
          throw new Error("No response plan is linked to this incident — a report cannot be generated.");
        }
        const genRes = await authAxios.post("/reports/generate", { plan_id: planIdForGen });
        const newIncidentId: string = genRes.data?.incident_id;
        const pdfB64: string = genRes.data?.pdf_content_b64;
        if (pdfB64) {
          triggerBlobDownload(b64ToBlob(pdfB64, "application/pdf"), `incident_${newIncidentId}.pdf`);
        }
        setData((prev) => (prev ? { ...prev, incident_id: newIncidentId, has_report: true } : prev));
      }
    } catch (err: any) {
      const status = err?.response?.status;
      if (status === 403) {
        setPdfError("Report generation requires analyst or admin privileges.");
      } else if (status === 404) {
        setPdfError("No incident report found on the server for this incident.");
      } else {
        setPdfError(err?.response?.data?.detail || err?.message || "Failed to download PDF report.");
      }
    } finally {
      setPdfBusy(false);
    }
  }, [data, pdfBusy, incidentId]);

  // ── Investigation workflow handlers ────────────────────────────────────────
  const handleStartInvestigation = useCallback(() => {
    if (investigationStatus === "OPEN") {
      setInvestigationStatus("INVESTIGATING");
      setInvestigationStartTime(Date.now());
    }
  }, [investigationStatus]);

  const handleStageClick = useCallback((stage: InvestigationStatus) => {
    setInvestigationStatus(stage);
    if (stage !== "OPEN" && investigationStartTime === null) {
      setInvestigationStartTime(Date.now());
    }
  }, [investigationStartTime]);

  const handleActivateResponse = useCallback(() => {
    setInvestigationStatus("CONFIRMED_THREAT");
  }, []);

  const handleMarkFalsePositive = useCallback(() => {
    setInvestigationStatus("CLOSED");
  }, []);

  // Compute evidence count (positive evidence steps) from timeline data
  const evidenceCount = (() => {
    const malCount = events.filter((e) => e.event_type === "malware_alert").length;
    const netScore = data?.fusion_alert?.components?.network?.score ?? 0;
    const userScore = data?.fusion_alert?.components?.user?.score ?? 0;
    const endpointIds = new Set<string>();
    events.forEach((e) => { const eid = (e.data as any)?.endpoint_id; if (eid) endpointIds.add(eid); });
    let count = 0;
    if (malCount > 0) count++;
    if (netScore > 0.5) count++;
    if (endpointIds.size > 1) count++;
    if (userScore > 0.5) count++;
    const KNOWN_ATTACK_TYPES = new Set(["DoS","DDoS","PortScan","BruteForce","C2 Beaconing","Infiltration","Ransomware","Malware Activity","Lateral Movement","WebAttack","Botnet","Backdoor","FTP Exploit","SMB Exploit","Browser Exploit","PDF Exploit"]);
    if (data?.attack_type && KNOWN_ATTACK_TYPES.has(data.attack_type)) count++;
    return count;
  })();

  // ── Loading state ──────────────────────────────────────────────────────────
  if (loading) {
    return (
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          height: "100%",
          padding: 40,
        }}
      >
        <DualOrbitLoader size={60} label="Loading incident reconstruction..." />
      </div>
    );
  }

  // ── Error state ────────────────────────────────────────────────────────────
  if (error) {
    return (
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          height: "100%",
          gap: 16,
          padding: 40,
        }}
      >
        <div style={{ fontSize: 32 }}>⚠</div>
        <div style={{ color: "#ef4444", fontSize: 14, fontWeight: 700, textAlign: "center" }}>
          {error}
        </div>
        <button
          onClick={onBack}
          style={{
            padding: "8px 20px",
            borderRadius: 8,
            border: "1px solid var(--border-color)",
            background: "var(--bg-card)",
            color: "var(--text-secondary)",
            fontWeight: 700,
            fontSize: 12,
            cursor: "pointer",
          }}
        >
          Back to Incidents
        </button>
      </div>
    );
  }

  // ── Empty-data guard ───────────────────────────────────────────────────────
  // The /replay endpoint exists and returned 200, but the incident bundle has
  // no timeline events AND no fusion alert.  This happens when the incident was
  // created but the backend hasn't stored associated logs yet (e.g. the plan
  // was just generated and endpoint_logs haven't been ingested for this ID).
  const hasAnyData =
    (data?.timeline?.length ?? 0) > 0 ||
    data?.fusion_alert != null ||
    data?.shap != null ||
    data?.plan != null ||
    (data?.commands?.length ?? 0) > 0;

  if (data && !hasAnyData) {
    return (
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          height: "100%",
          gap: 16,
          padding: 40,
        }}
      >
        <div style={{ fontSize: 32 }}>◈</div>
        <div
          style={{
            color: "var(--accent-amber)",
            fontSize: 14,
            fontWeight: 700,
            textAlign: "center",
            maxWidth: 480,
            lineHeight: 1.6,
          }}
        >
          No reconstruction data available for this incident.
        </div>
        <div
          style={{
            color: "var(--text-secondary)",
            fontSize: 12,
            textAlign: "center",
            maxWidth: 520,
            lineHeight: 1.7,
          }}
        >
          No timeline events were found for incident{" "}
          <span style={{ fontFamily: "monospace", color: "#818cf8" }}>#{incidentId.slice(-12)}</span>.
          The incident may have occurred before detailed event logging was enabled, or events
          may have expired. Check the Backend section for raw logs.
        </div>
        <div style={{ display: "flex", gap: 10, marginTop: 8 }}>
          <button
            onClick={onBack}
            style={{
              padding: "8px 20px",
              borderRadius: 8,
              border: "1px solid var(--border-color)",
              background: "var(--bg-card)",
              color: "var(--text-secondary)",
              fontWeight: 700,
              fontSize: 12,
              cursor: "pointer",
            }}
          >
            Back to Incidents
          </button>
        </div>
      </div>
    );
  }

  const sev = (data?.severity ?? "MEDIUM").toUpperCase();
  const sc = sevColor(sev);
  const shapFeatures = data?.shap?.top_features ?? [];

  // ── Render ─────────────────────────────────────────────────────────────────
  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.22 }}
      style={{
        display: "flex",
        flexDirection: "column",
        height: "100%",
        background: "#04070d",
        overflow: "hidden",
      }}
    >
      {/* ── Header bar ─────────────────────────────────────────────────────── */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 12,
          padding: "10px 20px",
          background: "linear-gradient(90deg, #0d1629, #0a1120)",
          borderBottom: "1px solid var(--border-color)",
          flexShrink: 0,
          flexWrap: "wrap",
        }}
      >
        {/* Back button */}
        <button
          onClick={onBack}
          aria-label="Back to incidents"
          style={{
            display: "flex",
            alignItems: "center",
            gap: 6,
            padding: "5px 12px",
            borderRadius: 7,
            border: "1px solid var(--border-color)",
            background: "transparent",
            color: "var(--text-secondary)",
            fontWeight: 700,
            fontSize: 11,
            cursor: "pointer",
            transition: "all 0.15s",
            flexShrink: 0,
          }}
        >
          ← Back to Incidents
        </button>

        {/* Divider */}
        <div style={{ width: 1, height: 20, background: "var(--bg-card)", flexShrink: 0 }} />

        {/* Incident ID */}
        <div style={{ display: "flex", flexDirection: "column" }}>
          <span
            style={{
              fontFamily: "'Fira Code', monospace",
              fontSize: 8,
              fontWeight: 700,
              letterSpacing: 1.5,
              color: "var(--text-muted)",
              textTransform: "uppercase",
            }}
          >
            Incident
          </span>
          <span
            style={{
              fontFamily: "'Fira Code', monospace",
              fontSize: 11,
              fontWeight: 700,
              color: "#818cf8",
            }}
          >
            #{incidentId.slice(-12)}
          </span>
        </div>

        {/* Severity badge */}
        <span
          style={{
            background: `${sc}22`,
            color: sc,
            border: `1px solid ${sc}55`,
            borderRadius: 6,
            padding: "4px 10px",
            fontSize: 10,
            fontWeight: 800,
            letterSpacing: 1,
            textTransform: "uppercase",
            flexShrink: 0,
          }}
        >
          {sev}
        </span>

        {/* Priority selector */}
        <div style={{ display: "flex", alignItems: "center", gap: 5, flexShrink: 0 }}>
          <span style={{ fontSize: 9, color: "var(--text-muted)", fontFamily: "'Fira Code', monospace", fontWeight: 700 }}>
            PRIORITY
          </span>
          <select
            value={priority}
            onChange={(e) => setPriority(e.target.value as Priority)}
            style={{
              background: `${PRIORITY_COLORS[priority]}18`,
              border: `1px solid ${PRIORITY_COLORS[priority]}55`,
              color: PRIORITY_COLORS[priority],
              borderRadius: 6,
              padding: "3px 7px",
              fontSize: 10,
              fontWeight: 800,
              fontFamily: "'Fira Code', monospace",
              cursor: "pointer",
              outline: "none",
              letterSpacing: 0.5,
            }}
          >
            {PRIORITY_LABELS.map((p) => (
              <option key={p} value={p} style={{ background: "var(--bg-secondary)", color: PRIORITY_COLORS[p] }}>
                {p} — {PRIORITY_DESCRIPTIONS[p]}
              </option>
            ))}
          </select>
        </div>

        {/* Attack type */}
        {data?.attack_type && (
          <span
            style={{
              background: "#78350f22",
              color: "#fbbf24",
              border: "1px solid #78350f44",
              borderRadius: 6,
              padding: "4px 10px",
              fontSize: 10,
              fontWeight: 700,
              flexShrink: 0,
            }}
          >
            {data.attack_type}
          </span>
        )}

        {/* MITRE technique */}
        {data?.mitre_technique && (
          <span
            style={{
              background: "#431407",
              color: "#fb923c",
              border: "1px solid #7c2d1244",
              borderRadius: 6,
              padding: "4px 10px",
              fontSize: 10,
              fontWeight: 700,
              fontFamily: "'Fira Code', monospace",
              flexShrink: 0,
            }}
          >
            {data.mitre_technique}
          </span>
        )}

        {/* Timestamp */}
        {data?.created_at && (
          <span
            style={{
              fontFamily: "'Fira Code', monospace",
              fontSize: 10,
              color: "var(--text-muted)",
              marginLeft: "auto",
              flexShrink: 0,
            }}
          >
            {new Date(data.created_at).toLocaleString()}
          </span>
        )}

        {/* Start Investigation button */}
        <button
          onClick={handleStartInvestigation}
          disabled={investigationStatus !== "OPEN"}
          aria-label="Start investigation"
          style={{
            padding: "5px 12px",
            borderRadius: 7,
            border: `1px solid ${investigationStatus === "OPEN" ? "rgba(59,130,246,0.45)" : "rgba(59,130,246,0.15)"}`,
            background: investigationStatus === "OPEN" ? "rgba(59,130,246,0.12)" : "transparent",
            color: investigationStatus === "OPEN" ? "#3b82f6" : "#334155",
            fontWeight: 700,
            fontSize: 10,
            letterSpacing: 0.5,
            cursor: investigationStatus === "OPEN" ? "pointer" : "not-allowed",
            flexShrink: 0,
            transition: "all 0.15s",
          }}
        >
          {investigationStatus === "OPEN" ? "Start Investigation" : "Investigating..."}
        </button>

        {/* Export JSON — pure client-side snapshot */}
        <button
          onClick={handleExportJson}
          aria-label="Export incident data as JSON"
          style={{
            padding: "5px 12px",
            borderRadius: 7,
            border: "1px solid rgba(0,212,255,0.25)",
            background: "rgba(0,212,255,0.05)",
            color: "var(--accent-cyan)",
            fontWeight: 700,
            fontSize: 10,
            letterSpacing: 0.5,
            cursor: "pointer",
            flexShrink: 0,
            transition: "all 0.15s",
          }}
        >
          Export JSON
        </button>

        {/* Download / Generate PDF */}
        <button
          onClick={handleDownloadPdf}
          disabled={pdfBusy}
          aria-label={data?.has_report ? "Download incident PDF report" : "Generate incident PDF report"}
          title={data?.has_report ? undefined : "No report exists yet for this incident — click to generate one"}
          style={{
            padding: "5px 12px",
            borderRadius: 7,
            border: "1px solid rgba(139,92,246,0.35)",
            background: "rgba(139,92,246,0.07)",
            color: "#c4b5fd",
            fontWeight: 700,
            fontSize: 10,
            letterSpacing: 0.5,
            cursor: pdfBusy ? "wait" : "pointer",
            opacity: pdfBusy ? 0.6 : 1,
            flexShrink: 0,
            transition: "all 0.15s",
          }}
        >
          {pdfBusy ? "Working…" : data?.has_report ? "Download PDF" : "Generate Report"}
        </button>

        {pdfError && (
          <span
            role="alert"
            style={{
              fontSize: 10,
              fontWeight: 600,
              color: "#fca5a5",
              background: "rgba(239,68,68,0.08)",
              border: "1px solid rgba(239,68,68,0.25)",
              borderRadius: 6,
              padding: "4px 9px",
              flexShrink: 1,
              maxWidth: 320,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
            title={pdfError}
          >
            {pdfError}
          </span>
        )}
      </div>

      {/* ── Investigation lifecycle bar ──────────────────────────────────────── */}
      <InvestigationLifecycleBar
        status={investigationStatus}
        onStageClick={handleStageClick}
        investigationStartTime={investigationStartTime}
      />

      {/* ── 3-panel body ───────────────────────────────────────────────────── */}
      <div
        style={{
          flex: 1,
          display: "grid",
          gridTemplateColumns: "30% 40% 30%",
          gap: 12,
          padding: 14,
          minHeight: 0,
          overflow: "hidden",
        }}
      >
        {/* ── LEFT: Attack graph + endpoint summary ────────────────────────── */}
        <motion.div
          initial={{ opacity: 0, x: -16 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.05, duration: 0.2 }}
          style={{
            display: "flex",
            flexDirection: "column",
            gap: 12,
            overflow: "hidden",
          }}
        >
          {/* Mini attack graph */}
          <div
            style={{
              background: "linear-gradient(135deg, #0d1629, #0a1120)",
              border: "1px solid var(--border-color)",
              borderRadius: 14,
              padding: "14px 16px",
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              gap: 10,
            }}
          >
            <div
              style={{
                fontFamily: "'Fira Code', monospace",
                fontSize: 9,
                fontWeight: 700,
                letterSpacing: 1.8,
                color: "var(--text-secondary)",
                textTransform: "uppercase",
                alignSelf: "flex-start",
              }}
            >
              Attack Path
            </div>
            <MiniGraph severity={data?.severity} events={events} currentStep={replayStep} />
          </div>

          {/* Endpoint summary card */}
          <div
            style={{
              background: "linear-gradient(135deg, #0d1629, #0a1120)",
              border: "1px solid var(--border-color)",
              borderRadius: 14,
              padding: "14px 16px",
              display: "flex",
              flexDirection: "column",
              gap: 10,
              flex: 1,
              overflow: "hidden",
            }}
          >
            <div
              style={{
                fontFamily: "'Fira Code', monospace",
                fontSize: 9,
                fontWeight: 700,
                letterSpacing: 1.8,
                color: "var(--text-secondary)",
                textTransform: "uppercase",
              }}
            >
              Endpoint
            </div>

            {[
              { k: "Hostname", v: data?.hostname ?? data?.endpoint_id ?? "—", color: "var(--accent-cyan)" },
              { k: "IP",       v: data?.ip_address ?? "—",                     color: "var(--text-secondary)" },
              { k: "OS",       v: data?.os ?? "—",                             color: "var(--text-secondary)" },
              { k: "User",     v: data?.username ?? "—",                       color: "#60a5fa" },
            ].map(({ k, v, color }) => (
              <div key={k} style={{ display: "flex", flexDirection: "column", gap: 1 }}>
                <span
                  style={{
                    fontFamily: "'Fira Code', monospace",
                    fontSize: 8,
                    fontWeight: 700,
                    letterSpacing: 1.2,
                    color: "var(--text-muted)",
                    textTransform: "uppercase",
                  }}
                >
                  {k}
                </span>
                <span
                  style={{
                    fontSize: 12,
                    fontWeight: 700,
                    color,
                    fontFamily: "'Fira Code', monospace",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {v}
                </span>
              </div>
            ))}

            {/* Event count stat */}
            <div
              style={{
                marginTop: "auto",
                padding: "10px 12px",
                background: "rgba(0,212,255,0.06)",
                border: "1px solid rgba(0,212,255,0.15)",
                borderRadius: 8,
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
              }}
            >
              <span style={{ fontSize: 10, color: "var(--text-secondary)", fontFamily: "'Fira Code', monospace" }}>
                Timeline Events
              </span>
              <span
                style={{
                  fontSize: 18,
                  fontWeight: 800,
                  color: "var(--accent-cyan)",
                  fontFamily: "'Fira Code', monospace",
                }}
              >
                {events.length}
              </span>
            </div>
          </div>

          {/* Detection Scores mini panel */}
          <DetectionScoresMiniPanel fusionAlert={data?.fusion_alert} />
        </motion.div>

        {/* ── CENTER: Narrative + tabbed investigation panels ───────────────── */}
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1, duration: 0.2 }}
          style={{
            display: "flex",
            flexDirection: "column",
            gap: 10,
            overflow: "hidden",
          }}
        >
          {/* Narrative / investigation summary — always visible above tabs */}
          <NarrativePanel
            narrative={data?.narrative}
            fusionAlert={data?.fusion_alert}
            attackType={data?.attack_type}
            severity={data?.severity}
            hostname={data?.hostname ?? data?.endpoint_id}
            mitreTechnique={data?.mitre_technique}
            commands={data?.commands}
            plan={data?.plan}
            createdAt={data?.created_at}
          />

          {/* Tab bar */}
          <div
            style={{
              display: "flex",
              gap: 6,
              flexShrink: 0,
            }}
          >
            {(
              [
                { id: "timeline" as CenterTab, label: "Timeline" },
                { id: "agents"   as CenterTab, label: "Agent Details" },
                { id: "evidence" as CenterTab, label: "Evidence" },
                { id: "confirm"  as CenterTab, label: "Threat Confirm" },
              ] as Array<{ id: CenterTab; label: string }>
            ).map(({ id, label }) => {
              const isActive = activeTab === id;
              return (
                <button
                  key={id}
                  onClick={() => setActiveTab(id)}
                  style={{
                    padding: "5px 14px",
                    borderRadius: 20,
                    border: `1px solid ${isActive ? "rgba(0,212,255,0.45)" : "#1e293b"}`,
                    background: isActive ? "rgba(0,212,255,0.1)" : "transparent",
                    color: isActive ? "#00d4ff" : "#475569",
                    fontSize: 10,
                    fontWeight: isActive ? 800 : 600,
                    cursor: "pointer",
                    letterSpacing: 0.5,
                    fontFamily: "'Fira Code', monospace",
                    transition: "all 0.15s",
                    whiteSpace: "nowrap",
                    boxShadow: isActive ? "0 0 8px rgba(0,212,255,0.2)" : "none",
                  }}
                >
                  {label}
                </button>
              );
            })}
          </div>

          {/* Tab content area */}
          <div
            style={{
              flex: 1,
              display: "flex",
              flexDirection: "column",
              overflow: "hidden",
              minHeight: 0,
            }}
          >
            {/* Tab: Timeline */}
            {activeTab === "timeline" && (
              <>
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    marginBottom: 8,
                    flexShrink: 0,
                  }}
                >
                  <span
                    style={{
                      fontFamily: "'Fira Code', monospace",
                      fontSize: 9,
                      fontWeight: 700,
                      letterSpacing: 1.8,
                      color: "var(--text-secondary)",
                      textTransform: "uppercase",
                    }}
                  >
                    Attack Timeline
                  </span>
                  <span
                    style={{
                      fontFamily: "'Fira Code', monospace",
                      fontSize: 9,
                      color: "var(--text-muted)",
                    }}
                  >
                    Step {replayStep + 1}/{Math.max(events.length, 1)}
                  </span>
                </div>

                {/* Scrollable event log */}
                <div
                  style={{
                    flex: 1,
                    background: "linear-gradient(135deg, #0d1629, #0a1120)",
                    border: "1px solid var(--border-color)",
                    borderRadius: 14,
                    overflow: "hidden",
                    display: "flex",
                    flexDirection: "column",
                    padding: "4px 0",
                  }}
                >
                  {events.length === 0 ? (
                    <div
                      style={{
                        flex: 1,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        color: "var(--text-muted)",
                        fontSize: 12,
                        fontStyle: "italic",
                        padding: 24,
                        textAlign: "center",
                      }}
                    >
                      No timeline events available for this incident.
                    </div>
                  ) : (
                    <ReplayTimeline
                      events={events}
                      currentStep={replayStep}
                      onStepClick={handleScrub}
                    />
                  )}
                </div>

                {/* Playback controls */}
                <div style={{ marginTop: 8, flexShrink: 0 }}>
                  <ReplayControls
                    step={replayStep}
                    total={events.length}
                    paused={paused}
                    speedMultiplier={speedMultiplier}
                    onPlayPause={handlePlayPause}
                    onReset={handleReset}
                    onStep={handleStep}
                    onScrub={handleScrub}
                    onSpeedChange={setSpeedMultiplier}
                  />
                </div>
              </>
            )}

            {/* Tab: Agent Details */}
            {activeTab === "agents" && (
              <AgentDetailsTab
                fusionAlert={data?.fusion_alert}
                events={events}
              />
            )}

            {/* Tab: Evidence */}
            {activeTab === "evidence" && (
              <EvidenceTab
                events={events}
                fusionAlert={data?.fusion_alert}
                attackType={data?.attack_type}
                mitreTechnique={data?.mitre_technique}
              />
            )}

            {/* Tab: Threat Confirmation */}
            {activeTab === "confirm" && (
              <ThreatConfirmTab
                checks={confirmChecks}
                onChecksChange={setConfirmChecks}
                onActivateResponse={handleActivateResponse}
                onMarkFalsePositive={handleMarkFalsePositive}
                evidenceCount={evidenceCount}
                createdAt={data?.created_at}
                priority={priority}
              />
            )}
          </div>
        </motion.div>

        {/* ── RIGHT: Fusion decision + SHAP + analyst notes ─────────────────── */}
        <motion.div
          initial={{ opacity: 0, x: 16 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.15, duration: 0.2 }}
          style={{
            display: "flex",
            flexDirection: "column",
            gap: 12,
            overflow: "hidden",
            overflowY: "auto",
          }}
        >
          {/* Attack Chain Graph — interactive node graph of the attack path */}
          <AttackChainGraph
            replayData={{
              endpoint_id: data?.endpoint_id,
              hostname: data?.hostname,
              fusion_alert: data?.fusion_alert ?? undefined,
              attack_type: data?.attack_type,
              timeline: data?.timeline as any[] ?? [],
            }}
            height={280}
          />

          {/* Detection Pipeline Flow — how this incident was detected */}
          <DetectionPipelineFlow
            fusionAlert={data?.fusion_alert}
            timeline={data?.timeline as any[] ?? []}
            attackType={data?.attack_type}
            severity={data?.severity}
            commands={data?.commands ?? []}
          />

          {/* Fusion decision */}
          <FusionDecisionPanel fusionAlert={data?.fusion_alert ?? null} />

          {/* SHAP explanation */}
          <div
            style={{
              background: "linear-gradient(135deg, #0d1629, #0a1120)",
              border: "1px solid var(--border-color)",
              borderRadius: 14,
              overflow: "hidden",
              flexShrink: 0,
            }}
          >
            <div
              style={{
                padding: "10px 16px",
                borderBottom: "1px solid var(--border-color)",
                display: "flex",
                alignItems: "center",
                gap: 8,
              }}
            >
              <span style={{ fontSize: 13, color: "#a78bfa" }}>◈</span>
              <span
                style={{
                  fontFamily: "'Fira Code', monospace",
                  fontSize: 9,
                  fontWeight: 700,
                  letterSpacing: 1.5,
                  color: "var(--text-secondary)",
                  textTransform: "uppercase",
                  flex: 1,
                }}
              >
                SHAP Explanation
              </span>
              {data?.shap?.predicted_class && (
                <span
                  style={{
                    fontSize: 9,
                    fontWeight: 700,
                    color: "#fbbf24",
                    background: "#78350f22",
                    border: "1px solid #78350f44",
                    borderRadius: 5,
                    padding: "1px 7px",
                  }}
                >
                  {data.shap.predicted_class}
                </span>
              )}
            </div>

            <div style={{ padding: "14px 16px", display: "flex", flexDirection: "column", gap: 10 }}>
              {/* Reason strings */}
              {data?.shap?.reason && data.shap.reason.length > 0 && (
                <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                  {data.shap.reason.slice(0, 3).map((r, i) => (
                    <div
                      key={i}
                      style={{
                        fontSize: 11,
                        color: "var(--text-secondary)",
                        padding: "4px 8px",
                        background: "rgba(0,212,255,0.04)",
                        border: "1px solid rgba(0,212,255,0.12)",
                        borderRadius: 6,
                        lineHeight: 1.4,
                      }}
                    >
                      {r}
                    </div>
                  ))}
                </div>
              )}

              {/* Feature bars */}
              <div
                style={{
                  fontFamily: "'Fira Code', monospace",
                  fontSize: 8,
                  fontWeight: 700,
                  letterSpacing: 1.5,
                  color: "var(--text-muted)",
                  textTransform: "uppercase",
                  marginTop: 2,
                }}
              >
                Top Features
              </div>
              <ShapList
                features={shapFeatures}
                contributingModels={data?.fusion_alert?.sources ?? []}
              />

              <div
                style={{
                  fontSize: 9,
                  color: "var(--text-muted)",
                  fontStyle: "italic",
                  marginTop: 4,
                }}
              >
                Red = pushes toward MALICIOUS · Green = pushes toward BENIGN
              </div>
            </div>
          </div>

          {/* Response Actions Taken */}
          <div
            style={{
              background: "linear-gradient(135deg, #0d1629, #0a1120)",
              border: "1px solid var(--border-color)",
              borderRadius: 14,
              overflow: "hidden",
              flexShrink: 0,
            }}
          >
            <div
              style={{
                padding: "10px 16px",
                borderBottom: "1px solid var(--border-color)",
                display: "flex",
                alignItems: "center",
                gap: 8,
              }}
            >
              <span style={{ fontSize: 13, color: "#22c55e" }}>&#128737;</span>
              <span
                style={{
                  fontFamily: "'Fira Code', monospace",
                  fontSize: 9,
                  fontWeight: 700,
                  letterSpacing: 1.5,
                  color: "var(--text-secondary)",
                  textTransform: "uppercase",
                  flex: 1,
                }}
              >
                Response Actions Taken
              </span>
              <span
                style={{
                  fontSize: 9,
                  fontWeight: 700,
                  color: (data?.commands?.length ?? 0) > 0 ? "#00ff88" : "#334155",
                  background: (data?.commands?.length ?? 0) > 0 ? "rgba(0,255,136,0.1)" : "#1e293b",
                  border: `1px solid ${(data?.commands?.length ?? 0) > 0 ? "rgba(0,255,136,0.3)" : "#1e293b"}`,
                  borderRadius: 10,
                  padding: "1px 7px",
                }}
              >
                {data?.commands?.length ?? 0}
              </span>
            </div>
            <ResponseActionsPanel commands={data?.commands ?? []} />
          </div>

          {/* Response Plan details — shown when plan data is available */}
          {data?.plan && (
            <div style={{ background: "linear-gradient(135deg, #0d1629, #0a1120)", border: "1px solid var(--border-color)", borderRadius: 14, overflow: "hidden", flexShrink: 0 }}>
              <div style={{ padding: "10px 16px", borderBottom: "1px solid var(--border-color)", display: "flex", alignItems: "center", gap: 8 }}>
                <span style={{ fontSize: 13, color: "var(--accent-cyan)" }}>◈</span>
                <span style={{ fontFamily: "'Fira Code', monospace", fontSize: 9, fontWeight: 700, letterSpacing: 1.5, color: "var(--text-secondary)", textTransform: "uppercase" }}>
                  Response Plan
                </span>
              </div>
              <div style={{ padding: "12px 16px", display: "flex", flexDirection: "column", gap: 8 }}>
                {/* Plan status + MITRE badges */}
                <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                  {(data.plan as any).status && (
                    <span style={{ fontSize: 10, fontWeight: 700, color: "var(--accent-cyan)", background: "rgba(0,212,255,0.1)", border: "1px solid rgba(0,212,255,0.25)", borderRadius: 6, padding: "2px 8px" }}>
                      {String((data.plan as any).status).toUpperCase()}
                    </span>
                  )}
                  {(data.plan as any).mitre_technique && (
                    <span style={{ fontSize: 10, fontWeight: 700, color: "#fb923c", background: "rgba(251,146,60,0.1)", border: "1px solid rgba(251,146,60,0.25)", borderRadius: 6, padding: "2px 8px", fontFamily: "'Fira Code', monospace" }}>
                      {(data.plan as any).mitre_technique}
                    </span>
                  )}
                  {(data.plan as any).auto_execute && (
                    <span style={{ fontSize: 10, fontWeight: 700, color: "#22c55e", background: "rgba(34,197,94,0.1)", border: "1px solid rgba(34,197,94,0.25)", borderRadius: 6, padding: "2px 8px" }}>
                      AUTO-EXECUTED
                    </span>
                  )}
                </div>
                {/* Recommended actions chips */}
                {Array.isArray((data.plan as any).recommended_actions) && (data.plan as any).recommended_actions.length > 0 && (
                  <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                    <div style={{ fontSize: 9, fontWeight: 700, letterSpacing: 1.5, color: "var(--text-muted)", textTransform: "uppercase", fontFamily: "'Fira Code', monospace" }}>
                      Recommended Actions
                    </div>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                      {(data.plan as any).recommended_actions.slice(0, 8).map((action: unknown, i: number) => (
                        <span key={i} style={{ fontSize: 10, color: "var(--text-secondary)", background: "rgba(148,163,184,0.08)", border: "1px solid rgba(148,163,184,0.15)", borderRadius: 5, padding: "2px 7px", fontFamily: "'Fira Code', monospace" }}>
                          {String(action ?? "").replace(/_/g, " ")}
                        </span>
                      ))}
                      {(data.plan as any).recommended_actions.length > 8 && (
                        <span style={{ fontSize: 10, color: "var(--text-secondary)", fontStyle: "italic" }}>
                          +{(data.plan as any).recommended_actions.length - 8} more
                        </span>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Analyst notes */}
          <div
            style={{
              background: "linear-gradient(135deg, #0d1629, #0a1120)",
              border: "1px solid var(--border-color)",
              borderRadius: 14,
              overflow: "hidden",
              flexShrink: 0,
            }}
          >
            <div
              style={{
                padding: "10px 16px",
                borderBottom: "1px solid var(--border-color)",
                display: "flex",
                alignItems: "center",
                gap: 8,
              }}
            >
              <span style={{ fontSize: 13, color: "#22c55e" }}>&#9711;</span>
              <span
                style={{
                  fontFamily: "'Fira Code', monospace",
                  fontSize: 9,
                  fontWeight: 700,
                  letterSpacing: 1.5,
                  color: "var(--text-secondary)",
                  textTransform: "uppercase",
                }}
              >
                Analyst Notes
              </span>
            </div>

            <div style={{ padding: "12px 16px", display: "flex", flexDirection: "column", gap: 8 }}>
              <textarea
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                placeholder="Add investigation notes for this incident..."
                rows={4}
                style={{
                  width: "100%",
                  padding: "10px 12px",
                  borderRadius: 8,
                  border: "1px solid var(--border-color)",
                  background: "var(--bg-primary)",
                  color: "var(--text-primary)",
                  fontSize: 12,
                  fontFamily: "inherit",
                  resize: "vertical",
                  outline: "none",
                  boxSizing: "border-box",
                  lineHeight: 1.5,
                }}
              />
              <button
                onClick={handleSaveNotes}
                disabled={!notes.trim() || notesSaving}
                style={{
                  alignSelf: "flex-end",
                  padding: "6px 16px",
                  borderRadius: 7,
                  border: "none",
                  background: notesSaved
                    ? "#15803d"
                    : notes.trim()
                    ? "#3b82f6"
                    : "#1e293b",
                  color: notes.trim() || notesSaved ? "#fff" : "#334155",
                  fontWeight: 700,
                  fontSize: 11,
                  cursor: notes.trim() && !notesSaving ? "pointer" : "not-allowed",
                  transition: "all 0.15s",
                  letterSpacing: 0.5,
                }}
              >
                {notesSaving ? "Saving..." : notesSaved ? "Saved ✓" : "Save Note"}
              </button>
            </div>
          </div>
        </motion.div>
      </div>
    </motion.div>
  );
}
