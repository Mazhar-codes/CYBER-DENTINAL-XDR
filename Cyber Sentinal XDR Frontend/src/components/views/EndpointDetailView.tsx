// EndpointDetailView.tsx
// Per-endpoint drill-down: timeline sparkline, fused alerts, SHAP, response panel
// Props supplied by NetworkMonitor.tsx; does NOT modify any existing component.

import React, { useState, useEffect, useCallback, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  EndpointInfo,
  EndpointAlert,
  EndpointCommand,
  CommandResult,
  EndpointFusionAlert,
  TimelineEntry,
  SEVERITY_COLOUR,
  fmtTime,
} from "../shared/types";
import { BACKEND_URL } from "../../config";

// ── Props ─────────────────────────────────────────────────────────────────────

export interface EndpointDetailViewProps {
  endpointId: string;
  endpointInfo: EndpointInfo | undefined;
  endpointAlerts: EndpointAlert[];
  fusionAlerts: EndpointFusionAlert[];
  onBack: () => void;
  onSendCommand: (cmd: EndpointCommand) => void;
  commandResults: CommandResult[];
  apiKey?: string;
}

// ── Constants ─────────────────────────────────────────────────────────────────

// ── Helpers ───────────────────────────────────────────────────────────────────

function timeAgo(isoTs: string): string {
  try {
    const diffMs = Date.now() - new Date(isoTs).getTime();
    const secs = Math.floor(diffMs / 1000);
    if (secs < 5)  return "just now";
    if (secs < 60) return `${secs} seconds ago`;
    const mins = Math.floor(secs / 60);
    if (mins < 60) return `${mins} minute${mins !== 1 ? "s" : ""} ago`;
    const hrs = Math.floor(mins / 60);
    return `${hrs} hour${hrs !== 1 ? "s" : ""} ago`;
  } catch {
    return isoTs;
  }
}

// ── Sparkline ─────────────────────────────────────────────────────────────────

interface SparklineProps {
  data: TimelineEntry[];
}

function ThreatSparkline({ data }: SparklineProps) {
  if (data.length === 0) {
    return (
      <div
        style={{
          height: 80,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          color: "var(--text-muted)",
          fontSize: 12,
        }}
      >
        No timeline data yet
      </div>
    );
  }

  const W = 600;
  const H = 80;
  const PAD = { top: 8, bottom: 8, left: 8, right: 8 };
  const innerW = W - PAD.left - PAD.right;
  const innerH = H - PAD.top - PAD.bottom;

  const maxScore = Math.max(...data.map((d) => d.threat_score), 0.01);
  const pts = data.map((d, i) => {
    const x = PAD.left + (i / Math.max(data.length - 1, 1)) * innerW;
    const y = PAD.top + innerH - (d.threat_score / maxScore) * innerH;
    return `${x},${y}`;
  });

  const maxTs = Math.max(...data.map((d) => d.threat_score));
  const lineColor = maxTs >= 0.7 ? "#ff3366" : maxTs >= 0.4 ? "#f59e0b" : "#00ff88";

  // Area fill path
  const first = pts[0].split(",");
  const last  = pts[pts.length - 1].split(",");
  const areaPath = [
    `M ${first[0]} ${PAD.top + innerH}`,
    `L ${pts.join(" L ")}`,
    `L ${last[0]} ${PAD.top + innerH}`,
    "Z",
  ].join(" ");

  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      style={{ width: "100%", height: 80, display: "block" }}
      preserveAspectRatio="none"
    >
      <defs>
        <linearGradient id="spark-fill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={lineColor} stopOpacity="0.25" />
          <stop offset="100%" stopColor={lineColor} stopOpacity="0.02" />
        </linearGradient>
      </defs>
      {/* Area fill */}
      <path d={areaPath} fill="url(#spark-fill)" />
      {/* Line */}
      <polyline
        points={pts.join(" ")}
        fill="none"
        stroke={lineColor}
        strokeWidth="2"
        strokeLinejoin="round"
        strokeLinecap="round"
      />
      {/* Latest dot */}
      {pts.length > 0 && (() => {
        const [cx, cy] = pts[pts.length - 1].split(",").map(Number);
        return (
          <circle cx={cx} cy={cy} r="4" fill={lineColor} opacity="0.9" />
        );
      })()}
    </svg>
  );
}

// ── Stat card ─────────────────────────────────────────────────────────────────

interface StatCardProps {
  label: string;
  value: string;
  accent: string;
}

function StatCard({ label, value, accent }: StatCardProps) {
  return (
    <div
      style={{
        background: "var(--bg-secondary)",
        border: `1px solid ${accent}33`,
        borderLeft: `3px solid ${accent}`,
        borderRadius: 8,
        padding: "10px 14px",
        flex: 1,
        minWidth: 90,
      }}
    >
      <div style={{ fontSize: 10, fontWeight: 700, color: "var(--text-secondary)", letterSpacing: 1.2, textTransform: "uppercase" }}>
        {label}
      </div>
      <div style={{ fontSize: 18, fontWeight: 800, color: "var(--text-primary)", marginTop: 3, fontFamily: "monospace" }}>
        {value}
      </div>
    </div>
  );
}

// ── Progress bar ──────────────────────────────────────────────────────────────

function ProgressBar({ value }: { value: number }) {
  const pct = Math.max(0, Math.min(100, value ?? 0));
  const color = pct > 85 ? "#ff3366" : pct > 70 ? "#f59e0b" : "#00ff88";
  return (
    <div style={{ height: 4, background: "var(--bg-primary)", borderRadius: 3, overflow: "hidden", flex: 1 }}>
      <div
        style={{
          height: "100%",
          width: `${pct}%`,
          background: color,
          borderRadius: 3,
          transition: "width 0.4s ease",
          boxShadow: `0 0 4px ${color}88`,
        }}
      />
    </div>
  );
}

// ── Action definitions (mirrors EndpointView.tsx) ─────────────────────────────

type ActionId = EndpointCommand["action"];

interface ActionDef {
  id: ActionId;
  label: string;
  color: string;
  placeholder: string;
  isConfirm?: boolean;
}

const ACTIONS: ActionDef[] = [
  { id: "kill_process",    label: "Kill Process",    color: "#ef4444", placeholder: "Process name or PID" },
  { id: "block_ip",        label: "Block IP",        color: "#f97316", placeholder: "IP address to block" },
  { id: "isolate_host",    label: "Isolate Host",    color: "#dc2626", placeholder: "Hostname", isConfirm: true },
  { id: "quarantine_file", label: "Quarantine File", color: "#a855f7", placeholder: "File path" },
  { id: "unblock_ip",      label: "Unblock IP",      color: "#22c55e", placeholder: "IP address to unblock" },
];

// ── Combined alert row ────────────────────────────────────────────────────────

interface CombinedAlertRow {
  key: string;
  timestamp: string;
  type: "endpoint" | "fusion";
  severity: string;
  attack_type: string;
  reason?: string;
  shap_explanation?: string[];
}

// ── Main component ────────────────────────────────────────────────────────────

export default function EndpointDetailView({
  endpointId,
  endpointInfo,
  endpointAlerts,
  fusionAlerts,
  onBack,
  onSendCommand,
  commandResults,
}: EndpointDetailViewProps) {

  // Timeline fetch state
  const [timeline, setTimeline] = useState<TimelineEntry[]>([]);
  const [timelineLoading, setTimelineLoading] = useState(true);

  // Response panel state (scoped to this endpoint)
  const [activeAction, setActiveAction] = useState<ActionId | null>(null);
  const [actionTarget, setActionTarget] = useState<string>("");
  const [confirmPending, setConfirmPending] = useState(false);
  const [feedbackMap, setFeedbackMap] = useState<Record<ActionId, boolean>>({} as Record<ActionId, boolean>);
  const feedbackTimers = useRef<Record<ActionId, ReturnType<typeof setTimeout>>>({} as Record<ActionId, ReturnType<typeof setTimeout>>);

  const isServer = endpointInfo?.is_server === true;
  const isOnline = endpointInfo?.status === "online";

  // ── Fetch timeline on mount ────────────────────────────────────────────────
  useEffect(() => {
    let cancelled = false;
    setTimelineLoading(true);

    const fetchTimeline = async () => {
      try {
        const token = localStorage.getItem("access_token");
        const headers: Record<string, string> = token
          ? { Authorization: `Bearer ${token}` }
          : { "X-API-Key": process.env.REACT_APP_XDR_API_KEY ?? "" };

        const res = await fetch(
          `${BACKEND_URL}/endpoint/timeline/${encodeURIComponent(endpointId)}?limit=100`,
          { headers }
        );
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        if (!cancelled) {
          // Backend returns {"timeline": [...]} with flat cpu/memory/connections/threat_score fields
          const entries = Array.isArray(data) ? data : (data?.timeline ?? []);
          setTimeline(entries);
        }
      } catch {
        if (!cancelled) setTimeline([]);
      } finally {
        if (!cancelled) setTimelineLoading(false);
      }
    };

    fetchTimeline();
    return () => { cancelled = true; };
  }, [endpointId]);

  // ── Build combined alerts ─────────────────────────────────────────────────
  const combinedAlerts: CombinedAlertRow[] = React.useMemo(() => {
    const epRows: CombinedAlertRow[] = endpointAlerts
      .filter((a) => a.endpoint_id === endpointId)
      .map((a, i) => ({
        key: `ep-${a.timestamp}-${i}`,
        timestamp: a.timestamp,
        type: "endpoint" as const,
        severity: a.severity,
        attack_type: "—",
        reason: a.reason,
        shap_explanation: undefined,
      }));

    const fusionRows: CombinedAlertRow[] = fusionAlerts
      .filter((a) => a.endpoint_id === endpointId)
      .map((a, i) => ({
        key: `fusion-${a.endpoint_id}-${i}`,
        timestamp: "",
        type: "fusion" as const,
        severity: a.severity,
        attack_type: a.attack_type ?? "—",
        reason: undefined,
        shap_explanation: a.shap_explanation,
      }));

    return [...epRows, ...fusionRows]
      .sort((a, b) => {
        if (!a.timestamp && !b.timestamp) return 0;
        if (!a.timestamp) return 1;
        if (!b.timestamp) return -1;
        return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
      })
      .slice(0, 20);
  }, [endpointAlerts, fusionAlerts, endpointId]);

  // ── Latest telemetry from timeline ────────────────────────────────────────
  const latestEntry = timeline.length > 0 ? timeline[timeline.length - 1] : null;

  // ── Response panel handlers ───────────────────────────────────────────────
  const showFeedback = useCallback((action: ActionId) => {
    setFeedbackMap((prev) => ({ ...prev, [action]: true }));
    if (feedbackTimers.current[action]) clearTimeout(feedbackTimers.current[action]);
    feedbackTimers.current[action] = setTimeout(() => {
      setFeedbackMap((prev) => ({ ...prev, [action]: false }));
    }, 2000);
  }, []);

  const handleActionClick = useCallback((action: ActionDef) => {
    if (!isOnline) return;
    if (activeAction === action.id) {
      setActiveAction(null);
      setActionTarget("");
      setConfirmPending(false);
      return;
    }
    setActiveAction(action.id);
    setActionTarget("");
    setConfirmPending(false);
  }, [activeAction, isOnline]);

  const handleSend = useCallback(() => {
    if (!activeAction) return;
    const action = ACTIONS.find((a) => a.id === activeAction)!;
    if (action.isConfirm && !confirmPending) {
      setConfirmPending(true);
      return;
    }
    const target = action.isConfirm
      ? endpointInfo?.hostname ?? endpointId
      : actionTarget.trim();
    if (!target) return;

    onSendCommand({ endpoint_id: endpointId, action: activeAction, target });
    showFeedback(activeAction);
    setActiveAction(null);
    setActionTarget("");
    setConfirmPending(false);
  }, [activeAction, actionTarget, confirmPending, endpointInfo, endpointId, onSendCommand, showFeedback]);

  const handleCancel = useCallback(() => {
    setActiveAction(null);
    setActionTarget("");
    setConfirmPending(false);
  }, []);

  // Last 10 command results for this endpoint
  const myCommandResults = commandResults
    .filter((r) => r.endpoint_id === endpointId)
    .slice(0, 10);

  // ── Shared panel style ────────────────────────────────────────────────────
  const panel: React.CSSProperties = {
    background: "linear-gradient(135deg, #1e293b 0%, #162032 100%)",
    border: "1px solid var(--border-color)",
    borderRadius: 14,
    overflow: "hidden",
  };

  const panelHeader: React.CSSProperties = {
    padding: "12px 20px",
    borderBottom: "1px solid #0a1120",
    display: "flex",
    alignItems: "center",
    gap: 10,
  };

  const panelLabel: React.CSSProperties = {
    fontSize: 12,
    fontWeight: 700,
    color: "var(--text-muted)",
    letterSpacing: 0.5,
  };

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <div style={{ padding: 24, display: "flex", flexDirection: "column", gap: 20 }}>

      {/* ── Panel 1: Header bar ──────────────────────────────────────────────── */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 14,
          background: "linear-gradient(135deg, #1e293b 0%, #162032 100%)",
          border: "1px solid var(--border-color)",
          borderRadius: 14,
          padding: "14px 20px",
        }}
      >
        {/* Back button */}
        <button
          onClick={onBack}
          title="Back to Endpoint Management"
          style={{
            display: "flex",
            alignItems: "center",
            gap: 6,
            padding: "7px 14px",
            borderRadius: 8,
            border: "1px solid var(--border-color)",
            background: "transparent",
            color: "var(--text-secondary)",
            fontWeight: 700,
            fontSize: 12,
            cursor: "pointer",
            transition: "all 0.15s",
            flexShrink: 0,
          }}
        >
          {/* Arrow-left using SVG to avoid icon library dependency */}
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="15 18 9 12 15 6" />
          </svg>
          Back
        </button>

        {/* Status dot */}
        <span
          style={{
            display: "inline-block",
            width: 10,
            height: 10,
            borderRadius: "50%",
            background: isOnline ? "#00ff88" : "#475569",
            boxShadow: isOnline ? "0 0 8px #00ff88" : "none",
            flexShrink: 0,
          }}
        />

        {/* Hostname + IP */}
        <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
          <span style={{ fontSize: 16, fontWeight: 800, color: "var(--text-primary)", letterSpacing: -0.3 }}>
            {endpointInfo?.hostname ?? endpointId}
          </span>
          <span style={{ fontSize: 11, color: "var(--text-secondary)", fontFamily: "monospace" }}>
            {endpointInfo?.ip_address ?? "—"} &nbsp;·&nbsp; {endpointInfo?.os ?? "—"} &nbsp;·&nbsp; {endpointInfo?.username ?? "—"}
          </span>
        </div>

        {/* Online/Offline badge */}
        <span
          style={{
            fontSize: 10,
            fontWeight: 800,
            letterSpacing: 1,
            textTransform: "uppercase",
            color: isOnline ? "#00ff88" : "#475569",
            background: isOnline ? "rgba(0,255,136,0.1)" : "rgba(71,85,105,0.15)",
            border: `1px solid ${isOnline ? "rgba(0,255,136,0.25)" : "rgba(71,85,105,0.3)"}`,
            borderRadius: 6,
            padding: "3px 9px",
          }}
        >
          {endpointInfo?.status ?? "unknown"}
        </span>

        {/* Server badge */}
        {isServer && (
          <span
            style={{
              fontSize: 10,
              fontWeight: 800,
              letterSpacing: 0.8,
              textTransform: "uppercase",
              color: "var(--accent-cyan)",
              background: "rgba(0,212,255,0.12)",
              border: "1px solid rgba(0,212,255,0.3)",
              borderRadius: 6,
              padding: "3px 9px",
            }}
          >
            Server (Local XDR)
          </span>
        )}

        <div style={{ flex: 1 }} />

        {/* Agent version */}
        {endpointInfo?.agent_version && (
          <span style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "monospace" }}>
            agent v{endpointInfo.agent_version}
          </span>
        )}
        <span style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "monospace" }}>
          {endpointInfo?.last_seen ? `Last seen ${timeAgo(endpointInfo.last_seen)}` : ""}
        </span>
      </div>

      {/* ── Panel 2: Timeline Sparkline ──────────────────────────────────────── */}
      <div style={panel}>
        <div style={panelHeader}>
          <span style={panelLabel}>THREAT TIMELINE</span>
          <span style={{ fontSize: 10, color: "var(--text-muted)", marginLeft: "auto" }}>last 100 entries</span>
        </div>

        <div style={{ padding: "16px 20px" }}>
          {timelineLoading ? (
            <div style={{ height: 80, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-muted)", fontSize: 12 }}>
              Loading timeline...
            </div>
          ) : (
            <ThreatSparkline data={timeline} />
          )}

          {/* Stat cards */}
          <div style={{ display: "flex", gap: 10, marginTop: 14, flexWrap: "wrap" }}>
            <StatCard
              label="CPU"
              value={endpointInfo?.cpu != null ? `${endpointInfo.cpu.toFixed(1)}%` : latestEntry != null ? `${latestEntry.cpu.toFixed(1)}%` : "—"}
              accent="#00d4ff"
            />
            <StatCard
              label="Memory"
              value={endpointInfo?.memory != null ? `${endpointInfo.memory.toFixed(1)}%` : latestEntry != null ? `${latestEntry.memory.toFixed(1)}%` : "—"}
              accent="#a855f7"
            />
            <StatCard
              label="Connections"
              value={latestEntry != null ? String(latestEntry.connections) : "—"}
              accent="#f59e0b"
            />
            <StatCard
              label="Threat Score"
              value={latestEntry != null ? `${(latestEntry.threat_score * 100).toFixed(0)}%` : "—"}
              accent={
                latestEntry == null ? "#64748b"
                  : latestEntry.threat_score >= 0.7 ? "#ff3366"
                  : latestEntry.threat_score >= 0.4 ? "#f59e0b"
                  : "#00ff88"
              }
            />
            <StatCard
              label="Severity"
              value={latestEntry?.severity ?? "—"}
              accent={SEVERITY_COLOUR[latestEntry?.severity ?? ""] ?? "#64748b"}
            />
          </div>

          {/* Inline CPU/MEM bars when data is live from endpoint_update */}
          {!latestEntry && (endpointInfo?.cpu != null || endpointInfo?.memory != null) && (
            <div style={{ marginTop: 14, display: "flex", flexDirection: "column", gap: 6, maxWidth: 340 }}>
              {endpointInfo?.cpu != null && (
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <span style={{ fontSize: 10, color: "var(--text-muted)", width: 32, flexShrink: 0 }}>CPU</span>
                  <ProgressBar value={endpointInfo.cpu} />
                  <span style={{ fontSize: 10, fontWeight: 700, fontFamily: "monospace", width: 38, textAlign: "right", color: endpointInfo.cpu > 85 ? "#ff3366" : endpointInfo.cpu > 70 ? "#f59e0b" : "#00ff88", flexShrink: 0 }}>
                    {endpointInfo.cpu.toFixed(0)}%
                  </span>
                </div>
              )}
              {endpointInfo?.memory != null && (
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <span style={{ fontSize: 10, color: "var(--text-muted)", width: 32, flexShrink: 0 }}>MEM</span>
                  <ProgressBar value={endpointInfo.memory} />
                  <span style={{ fontSize: 10, fontWeight: 700, fontFamily: "monospace", width: 38, textAlign: "right", color: endpointInfo.memory > 85 ? "#ff3366" : endpointInfo.memory > 70 ? "#f59e0b" : "#00ff88", flexShrink: 0 }}>
                    {endpointInfo.memory.toFixed(0)}%
                  </span>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* ── Panel 3: Per-endpoint Alerts + SHAP ─────────────────────────────── */}
      <div style={panel}>
        <div style={panelHeader}>
          <span style={panelLabel}>ENDPOINT ALERTS & FUSION EVENTS</span>
          <span
            style={{
              background: combinedAlerts.length > 0 ? "#7f1d1d33" : "#1e293b",
              color: combinedAlerts.length > 0 ? "#fca5a5" : "#475569",
              borderRadius: 10,
              padding: "1px 8px",
              fontSize: 10,
              fontWeight: 700,
            }}
          >
            {combinedAlerts.length}
          </span>
          <span style={{ marginLeft: "auto", fontSize: 10, color: "var(--text-muted)" }}>last 20</span>
        </div>

        {combinedAlerts.length === 0 ? (
          <div style={{ padding: "32px 20px", textAlign: "center", color: "var(--text-muted)", fontSize: 13 }}>
            No alerts recorded for this endpoint
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ background: "var(--bg-secondary)" }}>
                  {["Time", "Type", "Severity", "Attack Type", "SHAP Reasons"].map((col) => (
                    <th
                      key={col}
                      style={{
                        padding: "8px 16px",
                        textAlign: "left",
                        fontSize: 10,
                        fontWeight: 700,
                        color: "var(--text-secondary)",
                        letterSpacing: 1,
                        textTransform: "uppercase",
                        borderBottom: "1px solid var(--border-color)",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {col}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                <AnimatePresence initial={false}>
                  {combinedAlerts.map((row, idx) => {
                    const sevColor = SEVERITY_COLOUR[row.severity] ?? "#6b7280";
                    return (
                      <motion.tr
                        key={row.key}
                        initial={{ opacity: 0, x: -10 }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0 }}
                        transition={{ duration: 0.15 }}
                        style={{
                          borderBottom: "1px solid #0a1120",
                          background:
                            row.severity === "CRITICAL"
                              ? "rgba(220,38,38,0.05)"
                              : row.severity === "HIGH"
                              ? "rgba(234,88,12,0.05)"
                              : idx % 2 === 0
                              ? "#1e293b"
                              : "#192334",
                        }}
                      >
                        {/* Time */}
                        <td style={{ padding: "10px 16px", fontSize: 11, color: "var(--text-secondary)", whiteSpace: "nowrap", fontFamily: "monospace" }}>
                          {row.timestamp ? fmtTime(row.timestamp) : "—"}
                        </td>
                        {/* Type badge */}
                        <td style={{ padding: "10px 16px", whiteSpace: "nowrap" }}>
                          <span
                            style={{
                              display: "inline-block",
                              background: row.type === "fusion" ? "rgba(168,85,247,0.15)" : "rgba(0,212,255,0.1)",
                              color: row.type === "fusion" ? "#c084fc" : "#00d4ff",
                              border: `1px solid ${row.type === "fusion" ? "rgba(168,85,247,0.3)" : "rgba(0,212,255,0.25)"}`,
                              borderRadius: 6,
                              padding: "3px 8px",
                              fontSize: 10,
                              fontWeight: 700,
                              letterSpacing: 0.5,
                              textTransform: "uppercase",
                            }}
                          >
                            {row.type === "fusion" ? "Fusion" : "Endpoint"}
                          </span>
                        </td>
                        {/* Severity */}
                        <td style={{ padding: "10px 16px", whiteSpace: "nowrap" }}>
                          <span
                            style={{
                              display: "inline-block",
                              background: `${sevColor}22`,
                              color: sevColor,
                              border: `1px solid ${sevColor}55`,
                              borderRadius: 6,
                              padding: "3px 9px",
                              fontSize: 10,
                              fontWeight: 700,
                              letterSpacing: 0.5,
                            }}
                          >
                            {row.severity}
                          </span>
                        </td>
                        {/* Attack type */}
                        <td style={{ padding: "10px 16px", fontSize: 12, color: "var(--text-secondary)", whiteSpace: "nowrap" }}>
                          {row.reason ? (
                            <span style={{ color: "var(--text-muted)", fontStyle: "italic" }}>{row.reason}</span>
                          ) : (
                            row.attack_type
                          )}
                        </td>
                        {/* SHAP reasons */}
                        <td style={{ padding: "10px 16px", maxWidth: 360 }}>
                          {row.shap_explanation && row.shap_explanation.length > 0 ? (
                            <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                              {row.shap_explanation.map((reason, ri) => (
                                <span
                                  key={ri}
                                  style={{
                                    display: "inline-block",
                                    background: "rgba(0,212,255,0.1)",
                                    color: "var(--accent-cyan)",
                                    border: "1px solid rgba(0,212,255,0.2)",
                                    borderRadius: 5,
                                    padding: "2px 7px",
                                    fontSize: 10,
                                    fontWeight: 600,
                                    whiteSpace: "nowrap",
                                  }}
                                >
                                  {reason}
                                </span>
                              ))}
                            </div>
                          ) : (
                            <span style={{ fontSize: 11, color: "var(--text-muted)" }}>—</span>
                          )}
                        </td>
                      </motion.tr>
                    );
                  })}
                </AnimatePresence>
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ── Panel 4: Command Panel ───────────────────────────────────────────── */}
      <div style={panel}>
        <div style={panelHeader}>
          <span style={panelLabel}>RESPONSE ACTIONS</span>
          {!isOnline && (
            <span style={{ fontSize: 10, color: "var(--text-secondary)", fontStyle: "italic" }}>
              Endpoint is offline — commands unavailable
            </span>
          )}
          {isServer && (
            <span style={{ fontSize: 10, color: "var(--accent-amber)", fontStyle: "italic" }}>
              Isolation / IP blocking disabled for server host
            </span>
          )}
        </div>

        <div style={{ padding: 20, display: "flex", flexDirection: "column", gap: 14 }}>
          {/* Endpoint info strip */}
          <div
            style={{
              background: "var(--bg-secondary)",
              border: "1px solid var(--border-color)",
              borderRadius: 10,
              padding: "12px 16px",
              display: "flex",
              gap: 24,
              flexWrap: "wrap",
              fontSize: 11,
            }}
          >
            {[
              { k: "Endpoint", v: endpointInfo?.hostname ?? endpointId },
              { k: "IP",       v: endpointInfo?.ip_address ?? "—" },
              { k: "OS",       v: endpointInfo?.os ?? "—" },
              { k: "User",     v: endpointInfo?.username ?? "—" },
            ].map(({ k, v }) => (
              <div key={k} style={{ display: "flex", gap: 6 }}>
                <span style={{ color: "var(--text-muted)", flexShrink: 0 }}>{k}:</span>
                <span style={{ color: "var(--text-secondary)", fontFamily: "monospace" }}>{v}</span>
              </div>
            ))}
          </div>

          {/* Action buttons */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fill, minmax(140px, 1fr))",
              gap: 8,
            }}
          >
            {ACTIONS.map((action) => {
              const isActive = activeAction === action.id;
              const hasFeedback = feedbackMap[action.id];
              const isServerRestricted = isServer && (action.id === "isolate_host" || action.id === "block_ip");
              const disabled = !isOnline || isServerRestricted;

              return (
                <div key={action.id} style={{ position: "relative" }}>
                  <button
                    onClick={() => handleActionClick(action)}
                    disabled={disabled}
                    title={isServerRestricted ? "Not allowed on server host" : undefined}
                    style={{
                      width: "100%",
                      padding: "10px 14px",
                      borderRadius: 8,
                      border: isActive
                        ? `1px solid ${action.color}`
                        : `1px solid ${action.color}44`,
                      background: isActive
                        ? `${action.color}1a`
                        : hasFeedback
                        ? "rgba(0,255,136,0.08)"
                        : "transparent",
                      color: disabled
                        ? "#334155"
                        : hasFeedback
                        ? "#00ff88"
                        : isActive
                        ? action.color
                        : `${action.color}cc`,
                      fontWeight: 700,
                      fontSize: 11,
                      cursor: disabled ? "not-allowed" : "pointer",
                      letterSpacing: 0.5,
                      transition: "all 0.15s",
                      textAlign: "center",
                      position: "relative",
                    }}
                  >
                    {hasFeedback ? "Command sent ✓" : action.label}
                    {isActive && !hasFeedback && (
                      <span
                        style={{
                          position: "absolute",
                          top: -4,
                          right: -4,
                          width: 8,
                          height: 8,
                          borderRadius: "50%",
                          background: action.color,
                          boxShadow: `0 0 6px ${action.color}`,
                        }}
                      />
                    )}
                  </button>
                  {/* Tooltip for server-restricted actions */}
                  {isServerRestricted && (
                    <div
                      style={{
                        position: "absolute",
                        bottom: "110%",
                        left: "50%",
                        transform: "translateX(-50%)",
                        background: "var(--bg-secondary)",
                        border: "1px solid #f59e0b44",
                        borderRadius: 6,
                        padding: "4px 8px",
                        fontSize: 10,
                        color: "var(--accent-amber)",
                        whiteSpace: "nowrap",
                        pointerEvents: "none",
                        opacity: 0,
                        transition: "opacity 0.15s",
                        zIndex: 10,
                      }}
                      className="server-tooltip"
                    >
                      Not allowed on server host
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* Inline form for selected action */}
          <AnimatePresence>
            {activeAction && isOnline && (
              <motion.div
                key={`detail-form-${activeAction}`}
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: "auto" }}
                exit={{ opacity: 0, height: 0 }}
                transition={{ duration: 0.15 }}
                style={{
                  background: "var(--bg-secondary)",
                  border: `1px solid ${ACTIONS.find((a) => a.id === activeAction)?.color ?? "#334155"}44`,
                  borderRadius: 10,
                  padding: 14,
                  overflow: "hidden",
                }}
              >
                {(() => {
                  const action = ACTIONS.find((a) => a.id === activeAction)!;
                  return (
                    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                      <div style={{ fontSize: 11, color: "var(--text-muted)", fontWeight: 700 }}>
                        {action.label.toUpperCase()} — {endpointInfo?.hostname ?? endpointId}
                      </div>

                      {action.isConfirm ? (
                        <div
                          style={{
                            padding: "10px 12px",
                            background: "rgba(220,38,38,0.08)",
                            border: "1px solid rgba(220,38,38,0.25)",
                            borderRadius: 8,
                            fontSize: 12,
                            color: "#fca5a5",
                          }}
                        >
                          Are you sure? This will isolate{" "}
                          <strong>{endpointInfo?.hostname ?? endpointId}</strong> from the network.
                          This action requires confirmation.
                        </div>
                      ) : (
                        <input
                          autoFocus
                          value={actionTarget}
                          onChange={(e) => setActionTarget(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === "Enter") handleSend();
                            if (e.key === "Escape") handleCancel();
                          }}
                          placeholder={action.placeholder}
                          style={{
                            width: "100%",
                            padding: "8px 12px",
                            borderRadius: 8,
                            border: "1px solid var(--border-color)",
                            background: "var(--bg-primary)",
                            color: "var(--text-primary)",
                            fontSize: 12,
                            fontFamily: "'Fira Code', monospace",
                            outline: "none",
                            boxSizing: "border-box",
                          }}
                        />
                      )}

                      <div style={{ display: "flex", gap: 8 }}>
                        <button
                          onClick={handleSend}
                          disabled={!action.isConfirm && !actionTarget.trim()}
                          style={{
                            padding: "7px 18px",
                            borderRadius: 8,
                            border: "none",
                            background: confirmPending
                              ? "#dc2626"
                              : action.color === "#22c55e"
                              ? "#15803d"
                              : action.color,
                            color: "#fff",
                            fontWeight: 700,
                            fontSize: 11,
                            cursor: !action.isConfirm && !actionTarget.trim() ? "not-allowed" : "pointer",
                            opacity: !action.isConfirm && !actionTarget.trim() ? 0.5 : 1,
                            letterSpacing: 0.5,
                            transition: "all 0.15s",
                          }}
                        >
                          {confirmPending ? "Confirm Isolate" : "Send"}
                        </button>
                        <button
                          onClick={handleCancel}
                          style={{
                            padding: "7px 14px",
                            borderRadius: 8,
                            border: "1px solid var(--border-color)",
                            background: "transparent",
                            color: "var(--text-secondary)",
                            fontWeight: 700,
                            fontSize: 11,
                            cursor: "pointer",
                            transition: "all 0.15s",
                          }}
                        >
                          Cancel
                        </button>
                      </div>
                    </div>
                  );
                })()}
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Command History */}
        <div style={{ borderTop: "1px solid var(--border-color)", margin: "0 20px", paddingTop: 16, paddingBottom: 20 }}>
          <div
            style={{
              fontSize: 10,
              fontWeight: 700,
              color: "var(--text-muted)",
              letterSpacing: 1.2,
              textTransform: "uppercase",
              marginBottom: 10,
            }}
          >
            Command History (last 10 for this endpoint)
          </div>
          {myCommandResults.length === 0 ? (
            <div style={{ color: "var(--text-muted)", fontSize: 12 }}>No commands issued to this endpoint this session</div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              <AnimatePresence initial={false}>
                {myCommandResults.map((r, idx) => (
                  <motion.div
                    key={`cmd-detail-${r.command_id}-${idx}`}
                    initial={{ opacity: 0, x: -8 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0 }}
                    transition={{ duration: 0.15 }}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 10,
                      padding: "7px 10px",
                      background: r.success ? "rgba(0,255,136,0.05)" : "rgba(255,0,68,0.05)",
                      border: `1px solid ${r.success ? "rgba(0,255,136,0.15)" : "rgba(255,0,68,0.15)"}`,
                      borderRadius: 7,
                      fontSize: 11,
                    }}
                  >
                    <span
                      style={{
                        flexShrink: 0,
                        fontWeight: 800,
                        fontSize: 10,
                        letterSpacing: 0.5,
                        color: r.success ? "#00ff88" : "#ff3366",
                        background: r.success ? "rgba(0,255,136,0.1)" : "rgba(255,0,68,0.1)",
                        border: `1px solid ${r.success ? "rgba(0,255,136,0.25)" : "rgba(255,0,68,0.25)"}`,
                        borderRadius: 5,
                        padding: "1px 7px",
                      }}
                    >
                      {r.success ? "OK" : "FAIL"}
                    </span>
                    <span style={{ color: "var(--text-muted)", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {r.message}
                    </span>
                    <span style={{ color: "#1e293b", fontFamily: "monospace", fontSize: 9, flexShrink: 0 }}>
                      #{r.command_id?.slice(-6) ?? ""}
                    </span>
                  </motion.div>
                ))}
              </AnimatePresence>
            </div>
          )}
        </div>
      </div>

    </div>
  );
}
