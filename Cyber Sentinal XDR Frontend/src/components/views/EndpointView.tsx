// EndpointView.tsx
// Endpoint Management view — live endpoint grid, alert table, response panel
// Socket events consumed by parent: endpoint_update | endpoint_alert | endpoint_offline | command_result

import React, { useState, useCallback, useRef, useEffect } from "react";
import axios from "axios";
import { motion, AnimatePresence } from "framer-motion";
import { StaggerContainer, SkeletonBlock } from "../../animations/components";
import {
  EndpointInfo,
  EndpointAlert,
  EndpointCommand,
  CommandResult,
  SEVERITY_COLOUR,
  fmtTime,
} from "../shared/types";
import { ResponsePlan, IncidentReport } from "../shared/responseTypes";
import ResponseModal from "../ResponseModal";
import { getAccessToken } from "../../services/authService";
import { BACKEND_URL } from "../../config";

interface EndpointViewProps {
  endpoints: EndpointInfo[];
  endpointAlerts: EndpointAlert[];
  onSendCommand: (cmd: EndpointCommand) => void;
  commandResults: CommandResult[];
  onSelectEndpoint?: (endpointId: string) => void;
  responsePlans?: ResponsePlan[];
  incidentReports?: IncidentReport[];
  /** Current user role — hides SOAR action buttons from viewers */
  userRole?: string;
  /** Navigate to Attack Reconstruction view for a given incident */
  onInvestigateIncident?: (incidentId: string) => void;
}

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

interface ProgressBarProps {
  value: number; // 0–100
}
const ProgressBar = React.memo(function ProgressBar({ value }: ProgressBarProps) {
  const pct = Math.max(0, Math.min(100, value ?? 0));
  const color = pct > 85 ? "#ff3366" : pct > 70 ? "#f59e0b" : "#00ff88";
  return (
    <div
      style={{
        height: 4,
        background: "var(--bg-primary)",
        borderRadius: 3,
        overflow: "hidden",
        flex: 1,
      }}
    >
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
});

// ── Action types ──────────────────────────────────────────────────────────────

type ActionId = EndpointCommand["action"];

interface ActionDef {
  id: ActionId;
  label: string;
  color: string;
  placeholder: string;
  isConfirm?: boolean; // isolate_host shows confirm dialog instead of text input
}

const ACTIONS: ActionDef[] = [
  { id: "kill_process",       label: "Kill Process",     color: "#ef4444", placeholder: "Process name or PID" },
  { id: "block_ip",           label: "Block IP",         color: "#f97316", placeholder: "IP address to block" },
  { id: "isolate_host",       label: "Isolate Host",     color: "#dc2626", placeholder: "Hostname", isConfirm: true },
  { id: "unisolate_host",     label: "Unisolate Host",   color: "#0ea5e9", placeholder: "Hostname", isConfirm: true },
  { id: "quarantine_file",         label: "Quarantine File",  color: "#a855f7", placeholder: "File path" },
  { id: "restore_quarantine_file", label: "Restore File",     color: "var(--accent-green)", placeholder: "Original file path to restore to" },
  { id: "unblock_ip",              label: "Unblock IP",       color: "#22c55e", placeholder: "IP address to unblock" },
  { id: "lock_account",       label: "Lock Account",     color: "var(--accent-amber)", placeholder: "Username to lock" },
  { id: "unlock_account",     label: "Unlock Account",   color: "#06b6d4", placeholder: "Username to unlock" },
  { id: "scan_filesystem",    label: "Scan Filesystem",  color: "var(--accent-purple)", placeholder: "Leave blank to scan all" },
  { id: "monitor_persistence",label: "Monitor Persist.", color: "var(--text-muted)", placeholder: "Leave blank" },
];

/** Actions that do not require a target string — send with empty target. */
const OPTIONAL_TARGET_ACTIONS = new Set<string>(["scan_filesystem", "monitor_persistence"]);

// ── Main component ────────────────────────────────────────────────────────────

export default function EndpointView({
  endpoints,
  endpointAlerts,
  onSendCommand,
  commandResults,
  onSelectEndpoint,
  responsePlans = [],
  incidentReports = [],
  userRole,
  onInvestigateIncident,
}: EndpointViewProps) {
  // Which endpoint card is "selected" by clicking an alert row
  const [highlightedId, setHighlightedId] = useState<string | null>(null);

  // ResponseModal state for Active Threats panel
  const [responseModal, setResponseModal] = useState<{ plan: ResponsePlan } | null>(null);

  // Response panel state
  const [selectedEndpointId, setSelectedEndpointId] = useState<string>("");
  const [activeAction, setActiveAction] = useState<ActionId | null>(null);
  const [actionTarget, setActionTarget] = useState<string>("");
  const [confirmPending, setConfirmPending] = useState(false);
  const [feedbackMap, setFeedbackMap] = useState<Record<ActionId, boolean>>({} as Record<ActionId, boolean>);
  const feedbackTimers = useRef<Record<ActionId, ReturnType<typeof setTimeout>>>({} as Record<ActionId, ReturnType<typeof setTimeout>>);

  // In-flight command tracking: action → { status: 'inflight'|'completed'|'failed', target }
  type InFlightStatus = 'inflight' | 'completed' | 'failed';
  const [inFlightMap, setInFlightMap] = useState<Record<string, { status: InFlightStatus; target: string }>>({});
  const inFlightTimers = useRef<Record<string, ReturnType<typeof setTimeout>>>({});

  // Expanded command result rows (for showing result_message inline)
  const [expandedResultIdx, setExpandedResultIdx] = useState<number | null>(null);

  // Watch commandResults for completions that match in-flight commands
  useEffect(() => {
    if (commandResults.length === 0) return;
    const latest = commandResults[0];
    if (!latest.action) return;
    const actionKey = `${latest.endpoint_id}::${latest.action}`;
    const isKnown = inFlightMap[actionKey]?.status === 'inflight';
    if (!isKnown) return;

    const newStatus: InFlightStatus = (latest.success || latest.status === 'completed') ? 'completed' : 'failed';
    setInFlightMap(prev => ({ ...prev, [actionKey]: { ...prev[actionKey], status: newStatus } }));

    // Auto-reset after 3 seconds
    if (inFlightTimers.current[actionKey]) clearTimeout(inFlightTimers.current[actionKey]);
    inFlightTimers.current[actionKey] = setTimeout(() => {
      setInFlightMap(prev => {
        const next = { ...prev };
        delete next[actionKey];
        return next;
      });
    }, 3000);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [commandResults]);

  const panel: React.CSSProperties = {
    background: "var(--bg-card, #1e293b)",
    border: "1px solid var(--border-color, rgba(255,255,255,0.08))",
    borderRadius: 14,
    overflow: "hidden",
    transition: "background 0.2s ease",
  };

  // Derived data — filter out server_host (backend machine, not a remote agent)
  const remoteEndpoints = endpoints.filter(
    (e) => e.endpoint_id !== "server_host" && e.hostname !== "server_host"
  );
  const onlineEndpoints = remoteEndpoints.filter((e) => e.status === "online");
  const selectedEndpoint = remoteEndpoints.find((e) => e.endpoint_id === selectedEndpointId) ?? null;

  // Set of endpoint_ids that have an active HIGH/CRITICAL alert (remote agents only)
  const criticalEndpointIds = new Set<string>(
    endpointAlerts
      .filter((a) => (a.severity === "HIGH" || a.severity === "CRITICAL") && a.endpoint_id !== "server_host")
      .map((a) => a.endpoint_id)
  );

  const handleAlertRowClick = useCallback((alert: EndpointAlert) => {
    setHighlightedId((prev) => (prev === alert.endpoint_id ? null : alert.endpoint_id));
    // Auto-select in response panel if endpoint is online (remote agents only)
    const ep = remoteEndpoints.find((e) => e.endpoint_id === alert.endpoint_id && e.status === "online");
    if (ep) setSelectedEndpointId(ep.endpoint_id);
  }, [remoteEndpoints]);

  const showFeedback = useCallback((action: ActionId) => {
    setFeedbackMap((prev) => ({ ...prev, [action]: true }));
    if (feedbackTimers.current[action]) clearTimeout(feedbackTimers.current[action]);
    feedbackTimers.current[action] = setTimeout(() => {
      setFeedbackMap((prev) => ({ ...prev, [action]: false }));
    }, 2000);
  }, []);

  const handleActionClick = useCallback((action: ActionDef) => {
    if (!selectedEndpointId) return;
    if (activeAction === action.id) {
      // Toggle off
      setActiveAction(null);
      setActionTarget("");
      setConfirmPending(false);
      return;
    }
    setActiveAction(action.id);
    setActionTarget("");
    setConfirmPending(false);
  }, [activeAction, selectedEndpointId]);

  const handleSend = useCallback(() => {
    if (!selectedEndpointId || !activeAction) return;
    const action = ACTIONS.find((a) => a.id === activeAction)!;
    if (action.isConfirm && !confirmPending) {
      setConfirmPending(true);
      return;
    }
    const target = action.isConfirm
      ? selectedEndpoint?.hostname ?? selectedEndpointId
      : actionTarget.trim();
    // Require a target unless the action explicitly allows an empty one
    if (!target && !OPTIONAL_TARGET_ACTIONS.has(activeAction)) return;

    // Mark this action as in-flight for live button feedback
    const actionKey = `${selectedEndpointId}::${activeAction}`;
    setInFlightMap(prev => ({ ...prev, [actionKey]: { status: 'inflight', target: target || "" } }));

    onSendCommand({
      endpoint_id: selectedEndpointId,
      action: activeAction,
      target: target || "",
    });
    showFeedback(activeAction);
    setActiveAction(null);
    setActionTarget("");
    setConfirmPending(false);
  }, [selectedEndpointId, activeAction, actionTarget, confirmPending, selectedEndpoint, onSendCommand, showFeedback]);

  const handleCancel = useCallback(() => {
    setActiveAction(null);
    setActionTarget("");
    setConfirmPending(false);
  }, []);

  // Last 20 alerts — exclude server_host (backend machine, not a remote agent)
  const recentAlerts = endpointAlerts
    .filter(a => a.endpoint_id !== "server_host")
    .slice(0, 20);

  // Last 10 command results
  const recentResults = commandResults.slice(0, 10);

  // ── Compute per-plan execution status from live commandResults ────────────
  // "CONTAINED" = all completed, "PARTIAL" = any failed, "EXECUTING" = any pending/sent
  // Falls back to the plan's own status field if no command results match.
  type PlanStatus = "CONTAINED" | "PARTIAL" | "EXECUTING" | "OPEN";
  function computePlanStatus(plan: import("../shared/responseTypes").ResponsePlan): PlanStatus {
    // Match command results for this plan's endpoint
    const relatedResults = commandResults.filter(
      (r) => r.endpoint_id === plan.endpoint_id
    );

    if (relatedResults.length === 0) {
      // Fall back to plan's own status field
      if (plan.status === "executed" || plan.status === "contained") return "CONTAINED";
      if (plan.status === "partial" || plan.status === "failed") return "PARTIAL";
      if (plan.status === "executing") return "EXECUTING";
      return "OPEN";
    }

    const hasInFlight = relatedResults.some(
      (r) => r.status === "pending" || r.status === "sent"
    );
    if (hasInFlight) return "EXECUTING";

    const hasFailed = relatedResults.some(
      (r) => !r.success && r.status !== "completed"
    );
    const hasCompleted = relatedResults.some(
      (r) => r.success || r.status === "completed"
    );

    if (hasFailed && hasCompleted) return "PARTIAL";
    if (hasFailed) return "PARTIAL";
    if (hasCompleted) return "CONTAINED";
    return "OPEN";
  }

  // ── Domain helper ──────────────────────────────────────────────────────────
  function _buildDomain(sources: any[]): string {
    const set = new Set((sources || []).map((s: any) => String(s).toLowerCase()));
    const parts: string[] = [];
    if (set.has("network")) parts.push("Network");
    if (set.has("user")) parts.push("User");
    if (set.has("system")) parts.push("System");
    if (set.has("malware")) parts.push("Malware");
    return parts.length > 0 ? parts.join(" + ") : "Multi-Domain";
  }

  return (
    <div style={{ padding: 24, display: "flex", flexDirection: "column", gap: 20 }}>
      {/* Page header */}
      <div>
        <h2 style={{ margin: 0, fontSize: 20, fontWeight: 800, color: "var(--text-primary)", letterSpacing: -0.5 }}>
          Endpoint Management
        </h2>
        <p style={{ margin: "4px 0 0", color: "var(--text-secondary)", fontSize: 13 }}>
          Live endpoint status, alert mapping, and remote response actions
        </p>
      </div>

      {/* KPI bar */}
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
        {[
          { label: "Total Endpoints",   value: remoteEndpoints.length,                                                      accent: "var(--accent-cyan)" },
          { label: "Online",            value: onlineEndpoints.length,                                                      accent: "#00ff88" },
          { label: "Offline",           value: remoteEndpoints.filter((e) => e.status === "offline").length,                accent: "var(--text-muted)" },
          { label: "Isolated",          value: remoteEndpoints.filter((e) => e.status === "isolated").length,               accent: "#f97316" },
          { label: "Blocked IPs",       value: remoteEndpoints.reduce((n, e) => n + (e.blocked_ips?.length ?? 0), 0),       accent: "#ef4444" },
          { label: "Active Alerts",     value: endpointAlerts.filter(a => a.endpoint_id !== "server_host").length,          accent: "#f59e0b" },
          { label: "Critical/High",     value: criticalEndpointIds.size,                                                    accent: "#ff3366" },
        ].map(({ label, value, accent }) => (
          <div
            key={label}
            style={{
              background: "var(--bg-card, #1e293b)",
              border: `1px solid ${accent}33`,
              borderLeft: `4px solid ${accent}`,
              borderRadius: 10,
              padding: "10px 16px",
              flex: 1,
              minWidth: 110,
              transition: "background 0.2s ease",
            }}
          >
            <div style={{ color: "var(--text-muted, #64748b)", fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: 1.5 }}>
              {label}
            </div>
            <div style={{ color: "var(--text-heading, #f1f5f9)", fontSize: 24, fontWeight: 800, marginTop: 2 }}>{value}</div>
          </div>
        ))}
      </div>

      {/* ── Section 1: Endpoint Grid ─────────────────────────────────────────── */}
      <div style={panel}>
        <div
          style={{
            padding: "12px 20px",
            borderBottom: "1px solid #0a1120",
            display: "flex",
            alignItems: "center",
            gap: 10,
          }}
        >
          <span style={{ fontSize: 12, fontWeight: 700, color: "var(--text-muted)", letterSpacing: 0.5 }}>
            ENDPOINT GRID
          </span>
          <span
            style={{
              background: onlineEndpoints.length > 0 ? "rgba(0,255,136,0.12)" : "var(--bg-card)",
              color: onlineEndpoints.length > 0 ? "#00ff88" : "var(--text-secondary)",
              borderRadius: 10,
              padding: "1px 8px",
              fontSize: 10,
              fontWeight: 700,
            }}
          >
            {onlineEndpoints.length} online
          </span>
        </div>

        {endpoints.filter(ep => ep.endpoint_id !== "server_host" && ep.hostname !== "server_host").length === 0 ? (
          <div style={{ padding: 20 }}>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))",
                gap: 16,
                marginBottom: 16,
              }}
            >
              {[1, 2, 3].map((i) => (
                <SkeletonBlock key={i} height="120px" className="skeleton" rounded />
              ))}
            </div>
            <div style={{
              textAlign: "center",
              padding: "32px 24px",
              color: "rgba(0,255,255,0.4)",
              border: "1px dashed rgba(0,255,255,0.15)",
              borderRadius: "8px",
            }}>
              <div style={{ fontSize: "2.5rem", marginBottom: "12px", opacity: 0.5 }}>&#x2B21;</div>
              <div style={{ fontSize: "0.95rem", fontFamily: "monospace" }}>
                NO ENDPOINTS CONNECTED
              </div>
              <div style={{ fontSize: "0.75rem", marginTop: "8px", opacity: 0.6 }}>
                Start an endpoint agent to begin telemetry collection
              </div>
            </div>
          </div>
        ) : (
          <StaggerContainer
            style={{
              padding: 20,
              display: "grid",
              gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))",
              gap: 16,
            }}
          >
            <AnimatePresence initial={false}>
              {endpoints
                .filter(ep => !!ep.endpoint_id && ep.endpoint_id !== "server_host" && ep.hostname !== "server_host")
                .filter((ep, idx, arr) => arr.findIndex(e => e.endpoint_id === ep.endpoint_id) === idx)
                .map((ep) => {
                const isCritical = criticalEndpointIds.has(ep.endpoint_id);
                const isHighlighted = highlightedId === ep.endpoint_id;
                const isOnline = ep.status === "online";
                const isIsolated = ep.status === "isolated";
                const alertCount = endpointAlerts.filter(a => a.endpoint_id === ep.endpoint_id).length;

                const hasBlockedIps = (ep.blocked_ips?.length ?? 0) > 0;

                const cardBorder = isCritical
                  ? "1px solid rgba(255,0,68,0.65)"
                  : isIsolated
                  ? "2px solid rgba(255,80,0,0.8)"
                  : hasBlockedIps
                  ? "1px solid rgba(245,158,11,0.6)"
                  : isOnline
                  ? "1px solid rgba(0,255,136,0.2)"
                  : "1px solid var(--border-color)";

                const cardGlow = isCritical
                  ? "0 0 20px rgba(255,0,68,0.35)"
                  : isIsolated
                  ? "0 0 20px rgba(255,80,0,0.8), 0 0 40px rgba(255,80,0,0.3)"
                  : hasBlockedIps
                  ? "0 0 16px rgba(245,158,11,0.35)"
                  : isOnline
                  ? "0 0 12px rgba(0,255,136,0.15)"
                  : "none";

                const cardBackground = isIsolated
                  ? "linear-gradient(135deg, rgba(180,30,0,0.22) 0%, rgba(13,22,41,0.95) 100%)"
                  : "var(--bg-secondary)";

                const ringStyle: React.CSSProperties = isHighlighted
                  ? { outline: `2px solid #00d4ff`, outlineOffset: 2 }
                  : {};

                return (
                  <motion.div
                    key={ep.endpoint_id}
                    layout
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    exit={{ opacity: 0, scale: 0.9 }}
                    transition={{ duration: 0.2 }}
                    onClick={() => setHighlightedId((prev) => (prev === ep.endpoint_id ? null : ep.endpoint_id))}
                    style={{
                      background: cardBackground,
                      border: cardBorder,
                      borderRadius: 12,
                      padding: 16,
                      cursor: "pointer",
                      boxShadow: cardGlow,
                      transition: "box-shadow 0.3s, border-color 0.3s, background 0.3s",
                      animation: isIsolated ? "isolated-card-glow 2s ease-in-out infinite" : undefined,
                      ...ringStyle,
                    }}
                  >

                    {/* Header row */}
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        {/* Status dot — red pulsing when isolated */}
                        <span
                          style={{
                            display: "inline-block",
                            width: 9,
                            height: 9,
                            borderRadius: "50%",
                            background: isIsolated ? "#ff5000" : isOnline ? "#00ff88" : "var(--text-secondary)",
                            boxShadow: isIsolated
                              ? "0 0 10px #ff5000, 0 0 20px rgba(255,80,0,0.5)"
                              : isOnline
                              ? isCritical
                                ? "0 0 8px #ff3366"
                                : "0 0 8px #00ff88"
                              : "none",
                            flexShrink: 0,
                            animation: isIsolated
                              ? "xdr-pulse 1s ease-in-out infinite"
                              : isCritical && isOnline
                              ? "xdr-pulse 1s ease-in-out infinite"
                              : isOnline
                              ? "xdr-pulse 2s ease-in-out infinite"
                              : "none",
                          }}
                        />
                        <span style={{ fontWeight: 700, fontSize: 13, color: (isOnline || isIsolated) ? "var(--text-primary)" : "var(--text-muted)" }}>
                          {ep.hostname}
                        </span>
                      </div>
                      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                        {/* Per-card alert count badge */}
                        {alertCount > 0 && (
                          <span
                            style={{
                              fontSize: 9,
                              fontWeight: 800,
                              letterSpacing: 0.5,
                              color: isCritical ? "#ff6688" : "#fca5a5",
                              background: isCritical ? "rgba(255,0,68,0.18)" : "rgba(220,38,38,0.12)",
                              border: `1px solid ${isCritical ? "rgba(255,0,68,0.4)" : "rgba(220,38,38,0.25)"}`,
                              borderRadius: 10,
                              padding: "1px 7px",
                              minWidth: 20,
                              textAlign: "center",
                            }}
                          >
                            {alertCount}
                          </span>
                        )}
                        <span
                          style={{
                            fontSize: 9,
                            fontWeight: 800,
                            letterSpacing: 1,
                            textTransform: "uppercase",
                            color: isIsolated ? "#f97316" : isOnline ? "#00ff88" : "var(--text-secondary)",
                            background: isIsolated ? "rgba(249,115,22,0.1)" : isOnline ? "rgba(0,255,136,0.1)" : "rgba(71,85,105,0.15)",
                            border: `1px solid ${isIsolated ? "rgba(249,115,22,0.35)" : isOnline ? "rgba(0,255,136,0.25)" : "rgba(71,85,105,0.3)"}`,
                            borderRadius: 6,
                            padding: "2px 7px",
                          }}
                        >
                          {ep.status}
                        </span>
                      </div>
                    </div>

                    {/* Details */}
                    <div style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 11, color: "var(--text-secondary)" }}>
                      <div>
                        <span style={{ color: "var(--text-muted)" }}>IP: </span>
                        <span style={{ color: "var(--text-secondary)", fontFamily: "monospace" }}>{ep.ip_address}</span>
                      </div>
                      <div>
                        <span style={{ color: "var(--text-muted)" }}>OS: </span>
                        <span style={{ color: "var(--text-muted)" }}>{ep.os}</span>
                      </div>
                      <div>
                        <span style={{ color: "var(--text-muted)" }}>User: </span>
                        <span style={{ color: "#60a5fa", fontFamily: "monospace" }}>{ep.username}</span>
                      </div>
                    </div>

                    {/* Telemetry bars — replaced with NETWORK DISABLED bar when isolated */}
                    {isIsolated ? (
                      <div style={{ marginTop: 10 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                          <span style={{ fontSize: 9, color: "#f97316", fontWeight: 700, width: 32, flexShrink: 0, textTransform: "uppercase", letterSpacing: 0.5 }}>NET</span>
                          <div
                            style={{
                              flex: 1,
                              height: 8,
                              borderRadius: 4,
                              overflow: "hidden",
                              background: "rgba(255,80,0,0.15)",
                              border: "1px solid rgba(255,80,0,0.3)",
                            }}
                          >
                            <div
                              style={{
                                height: "100%",
                                width: "100%",
                                background: "repeating-linear-gradient(45deg, rgba(255,80,0,0.6) 0px, rgba(255,80,0,0.6) 4px, rgba(180,30,0,0.3) 4px, rgba(180,30,0,0.3) 8px)",
                                animation: "none",
                              }}
                            />
                          </div>
                          <span style={{ fontSize: 9, fontWeight: 800, color: "#f97316", fontFamily: "monospace", width: 34, textAlign: "right", flexShrink: 0 }}>
                            OFF
                          </span>
                        </div>
                        <div style={{ fontSize: 9, color: "#f97316", fontWeight: 700, letterSpacing: 0.8, textAlign: "center", marginTop: 3, opacity: 0.8 }}>
                          NETWORK DISABLED
                        </div>
                      </div>
                    ) : isOnline && (ep.cpu != null || ep.memory != null) ? (
                      <div style={{ marginTop: 10, display: "flex", flexDirection: "column", gap: 5 }}>
                        {ep.cpu != null && (
                          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                            <span style={{ fontSize: 10, color: "var(--text-muted)", width: 32, flexShrink: 0 }}>CPU</span>
                            <ProgressBar value={ep.cpu} />
                            <span
                              style={{
                                fontSize: 10,
                                fontWeight: 700,
                                fontFamily: "monospace",
                                width: 34,
                                textAlign: "right",
                                color: ep.cpu > 85 ? "#ff3366" : ep.cpu > 70 ? "#f59e0b" : "#00ff88",
                                flexShrink: 0,
                              }}
                            >
                              {ep.cpu.toFixed(0)}%
                            </span>
                          </div>
                        )}
                        {ep.memory != null && (
                          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                            <span style={{ fontSize: 10, color: "var(--text-muted)", width: 32, flexShrink: 0 }}>MEM</span>
                            <ProgressBar value={ep.memory} />
                            <span
                              style={{
                                fontSize: 10,
                                fontWeight: 700,
                                fontFamily: "monospace",
                                width: 34,
                                textAlign: "right",
                                color: ep.memory > 85 ? "#ff3366" : ep.memory > 70 ? "#f59e0b" : "#00ff88",
                                flexShrink: 0,
                              }}
                            >
                              {ep.memory.toFixed(0)}%
                            </span>
                          </div>
                        )}
                      </div>
                    ) : null}

                    {/* Last seen */}
                    <div
                      style={{
                        marginTop: 10,
                        fontSize: 10,
                        color: "var(--text-muted)",
                        fontFamily: "monospace",
                      }}
                    >
                      Last seen: {ep.last_seen ? timeAgo(ep.last_seen) : "unknown"}
                    </div>

                    {/* Critical alert badge */}
                    {isCritical && (
                      <div
                        style={{
                          marginTop: 8,
                          display: "flex",
                          alignItems: "center",
                          gap: 6,
                          background: "rgba(255,0,68,0.1)",
                          border: "1px solid rgba(255,0,68,0.3)",
                          borderRadius: 6,
                          padding: "4px 8px",
                        }}
                      >
                        <span
                          style={{
                            display: "inline-block",
                            width: 6,
                            height: 6,
                            borderRadius: "50%",
                            background: "#ff3366",
                            boxShadow: "0 0 6px #ff3366",
                            animation: "xdr-pulse 1s ease-in-out infinite",
                            flexShrink: 0,
                          }}
                        />
                        <span style={{ fontSize: 10, fontWeight: 700, color: "#ff6688", letterSpacing: 0.5 }}>
                          ACTIVE THREAT ALERT
                        </span>
                      </div>
                    )}

                    {/* ISOLATED badge — large, prominent, blinking */}
                    {isIsolated && (
                      <div
                        style={{
                          marginTop: 10,
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                          gap: 7,
                          background: "rgba(255,80,0,0.18)",
                          border: "1px solid rgba(255,80,0,0.65)",
                          borderRadius: 8,
                          padding: "7px 10px",
                          animation: "isolated-badge-blink 2s ease-in-out infinite",
                        }}
                      >
                        <span style={{ fontSize: 15, lineHeight: 1 }}>🔒</span>
                        <span style={{ fontSize: 13, fontWeight: 900, color: "#ff6600", letterSpacing: 1, textTransform: "uppercase" }}>
                          HOST ISOLATED
                        </span>
                      </div>
                    )}

                    {/* Blocked IPs section — amber glow + count badge */}
                    {ep.blocked_ips && ep.blocked_ips.length > 0 && (
                      <div style={{ marginTop: 8, background: "rgba(245,158,11,0.06)", border: "1px solid rgba(245,158,11,0.3)", borderRadius: 7, padding: "6px 8px" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 5 }}>
                          <span style={{ fontSize: 11 }}>🛡</span>
                          <span style={{ fontSize: 9, fontWeight: 800, color: "var(--accent-amber)", letterSpacing: 0.8, textTransform: "uppercase", flex: 1 }}>
                            Blocked IPs
                          </span>
                          <span
                            style={{
                              fontSize: 9,
                              fontWeight: 800,
                              color: "var(--accent-amber)",
                              background: "rgba(245,158,11,0.18)",
                              border: "1px solid rgba(245,158,11,0.4)",
                              borderRadius: 10,
                              padding: "1px 7px",
                            }}
                          >
                            {ep.blocked_ips.length} IP{ep.blocked_ips.length !== 1 ? "s" : ""} BLOCKED
                          </span>
                        </div>
                        <div style={{ display: "flex", flexWrap: "wrap", gap: 3 }}>
                          {ep.blocked_ips.map((ip) => (
                            <span
                              key={ip}
                              style={{
                                fontSize: 9,
                                fontFamily: "'Fira Code', monospace",
                                background: "rgba(239,68,68,0.12)",
                                color: "#ef4444",
                                border: "1px solid rgba(239,68,68,0.35)",
                                borderRadius: 4,
                                padding: "2px 6px",
                              }}
                            >
                              🚫 {ip}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* View Details link */}
                    {onSelectEndpoint && (
                      <div
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectEndpoint(ep.endpoint_id);
                        }}
                        style={{
                          marginTop: 10,
                          fontSize: 10,
                          fontWeight: 700,
                          color: "var(--accent-cyan)",
                          letterSpacing: 0.5,
                          cursor: "pointer",
                          textAlign: "right",
                          opacity: 0.8,
                          transition: "opacity 0.15s",
                        }}
                        title="Open endpoint detail view"
                      >
                        View Details →
                      </div>
                    )}
                  </motion.div>
                );
              })}
            </AnimatePresence>
          </StaggerContainer>
        )}
      </div>

      {/* ── Section 2: Endpoint Alerts ───────────────────────────────────────── */}
      <div style={panel}>
        <div
          style={{
            padding: "12px 20px",
            borderBottom: "1px solid #0a1120",
            display: "flex",
            alignItems: "center",
            gap: 10,
          }}
        >
          <span style={{ fontSize: 12, fontWeight: 700, color: "var(--text-muted)", letterSpacing: 0.5 }}>
            ENDPOINT ALERTS
          </span>
          <span
            style={{
              background: endpointAlerts.length > 0 ? "#7f1d1d33" : "var(--bg-card)",
              color: endpointAlerts.length > 0 ? "#fca5a5" : "var(--text-secondary)",
              borderRadius: 10,
              padding: "1px 8px",
              fontSize: 10,
              fontWeight: 700,
            }}
          >
            {endpointAlerts.length}
          </span>
          <span style={{ marginLeft: "auto", fontSize: 10, color: "var(--text-muted)" }}>last 20</span>
        </div>

        {recentAlerts.length === 0 ? (
          <div style={{ padding: "32px 20px", textAlign: "center", color: "var(--text-muted)", fontSize: 13 }}>
            No endpoint alerts — all endpoints appear normal
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ background: "var(--bg-secondary)" }}>
                  {["Time", "Endpoint", "Severity", "Reason"].map((col) => (
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
                  {recentAlerts.map((alert, idx) => {
                    const sevColor = SEVERITY_COLOUR[alert.severity] ?? "#6b7280";
                    const isSelected = highlightedId === alert.endpoint_id;
                    return (
                      <motion.tr
                        key={`ep-alert-${alert.timestamp}-${alert.endpoint_id}-${idx}`}
                        initial={{ opacity: 0, x: -12 }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0 }}
                        transition={{ duration: 0.15 }}
                        onClick={() => {
                          handleAlertRowClick(alert);
                          onSelectEndpoint?.(alert.endpoint_id);
                        }}
                        style={{
                          borderBottom: "1px solid #0a1120",
                          background: isSelected
                            ? "rgba(0,212,255,0.07)"
                            : alert.severity === "CRITICAL"
                            ? "rgba(220,38,38,0.05)"
                            : alert.severity === "HIGH"
                            ? "rgba(234,88,12,0.05)"
                            : idx % 2 === 0
                            ? "var(--bg-card)"
                            : "var(--bg-card)",
                          cursor: "pointer",
                          outline: isSelected ? "1px solid rgba(47,224,224,0.30)" : "none",
                          transition: "background 0.15s",
                        }}
                      >
                        <td
                          style={{
                            padding: "10px 16px",
                            fontSize: 11,
                            color: "var(--text-secondary)",
                            whiteSpace: "nowrap",
                            fontFamily: "monospace",
                          }}
                        >
                          {alert.timestamp ? fmtTime(alert.timestamp) : "—"}
                        </td>
                        <td style={{ padding: "10px 16px", whiteSpace: "nowrap" }}>
                          <span
                            style={{
                              fontSize: 12,
                              fontWeight: 700,
                              color: "#60a5fa",
                              fontFamily: "monospace",
                            }}
                          >
                            {alert.hostname}
                          </span>
                        </td>
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
                            {alert.severity}
                          </span>
                        </td>
                        <td
                          style={{
                            padding: "10px 16px",
                            fontSize: 12,
                            color: "var(--text-secondary)",
                            maxWidth: 400,
                          }}
                        >
                          {alert.reason}
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

      {/* ── Section 3: Response Panel ─────────────────────────────────────────── */}
      <div style={panel}>
        <div
          style={{
            padding: "12px 20px",
            borderBottom: "1px solid #0a1120",
            display: "flex",
            alignItems: "center",
            gap: 10,
          }}
        >
          <span style={{ fontSize: 12, fontWeight: 700, color: "var(--text-muted)", letterSpacing: 0.5 }}>
            RESPONSE ACTIONS
          </span>
          {onlineEndpoints.length === 0 && (
            <span style={{ fontSize: 10, color: "var(--text-secondary)", fontStyle: "italic" }}>
              No online endpoints available
            </span>
          )}
        </div>

        <div style={{ padding: 20, display: "flex", gap: 24, flexWrap: "wrap" }}>
          {/* Left: selector + endpoint details */}
          <div style={{ minWidth: 240, flex: "0 0 240px", display: "flex", flexDirection: "column", gap: 12 }}>
            <div>
              <label
                style={{
                  display: "block",
                  fontSize: 10,
                  fontWeight: 700,
                  color: "var(--text-secondary)",
                  letterSpacing: 1,
                  textTransform: "uppercase",
                  marginBottom: 6,
                }}
              >
                Select Endpoint
              </label>
              <select
                value={selectedEndpointId}
                onChange={(e) => {
                  setSelectedEndpointId(e.target.value);
                  setActiveAction(null);
                  setActionTarget("");
                  setConfirmPending(false);
                }}
                style={{
                  width: "100%",
                  padding: "8px 12px",
                  borderRadius: 8,
                  border: "1px solid var(--border-color)",
                  background: "var(--bg-secondary)",
                  color: "var(--text-primary)",
                  fontSize: 12,
                  fontFamily: "'Fira Code', monospace",
                  cursor: "pointer",
                  outline: "none",
                }}
              >
                <option value="">-- Choose endpoint --</option>
                {endpoints.filter((e) => e.status !== "offline" && e.endpoint_id !== "server_host" && e.hostname !== "server_host").map((ep) => (
                  <option key={ep.endpoint_id} value={ep.endpoint_id}>
                    {ep.hostname} ({ep.ip_address}){ep.status === "isolated" ? " [ISOLATED]" : ""}
                  </option>
                ))}
              </select>
            </div>

            {selectedEndpoint && (
              <motion.div
                key={selectedEndpoint.endpoint_id}
                initial={{ opacity: 0, y: 4 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.15 }}
                style={{
                  background: "var(--bg-secondary)",
                  border: "1px solid var(--border-color)",
                  borderRadius: 10,
                  padding: 14,
                  display: "flex",
                  flexDirection: "column",
                  gap: 6,
                  fontSize: 11,
                }}
              >
                <div style={{ color: "var(--accent-cyan)", fontWeight: 700, fontSize: 13, marginBottom: 4 }}>
                  {selectedEndpoint.hostname}
                </div>
                {[
                  { k: "IP",      v: selectedEndpoint.ip_address },
                  { k: "OS",      v: selectedEndpoint.os },
                  { k: "User",    v: selectedEndpoint.username },
                  { k: "Agent",   v: selectedEndpoint.agent_version },
                  { k: "Seen",    v: timeAgo(selectedEndpoint.last_seen) },
                ].map(({ k, v }) => (
                  <div key={k} style={{ display: "flex", gap: 6 }}>
                    <span style={{ color: "var(--text-muted)", width: 40, flexShrink: 0 }}>{k}:</span>
                    <span style={{ color: "var(--text-secondary)", fontFamily: "monospace" }}>{v}</span>
                  </div>
                ))}
              </motion.div>
            )}
          </div>

          {/* Right: action buttons + inline form */}
          <div style={{ flex: 1, minWidth: 260, display: "flex", flexDirection: "column", gap: 14 }}>
            {userRole === "viewer" && (
              <div
                style={{
                  padding: "10px 14px",
                  borderRadius: 8,
                  background: "rgba(71,85,105,0.1)",
                  border: "1px solid var(--border-color)",
                  fontSize: 12,
                  color: "var(--text-secondary)",
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                }}
              >
                <span>🔒</span>
                SOAR actions require analyst or admin role.
              </div>
            )}
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fill, minmax(140px, 1fr))",
                gap: 8,
              }}
            >
              {ACTIONS.filter((action) => {
                if (userRole === "viewer") return false;
                // unisolate_host — only show when selected endpoint is isolated
                if (action.id === "unisolate_host") return selectedEndpoint?.status === "isolated";
                // isolate_host — hide when endpoint is already isolated
                if (action.id === "isolate_host") return selectedEndpoint?.status !== "isolated";
                return true;
              }).map((action) => {
                const isActive = activeAction === action.id;
                const hasFeedback = feedbackMap[action.id];
                const disabled = !selectedEndpointId;
                const actionKey = `${selectedEndpointId}::${action.id}`;
                const inFlight = inFlightMap[actionKey];
                const isInFlight = inFlight?.status === 'inflight';
                const isCompleted = inFlight?.status === 'completed';
                const isFailed = inFlight?.status === 'failed';

                let btnBg = "transparent";
                let btnBorder = `1px solid ${action.color}44`;
                let btnColor = disabled ? "var(--text-muted)" : `${action.color}cc`;
                let btnLabel: React.ReactNode = action.label;

                if (isInFlight) {
                  btnBg = `${action.color}12`;
                  btnBorder = `1px solid ${action.color}88`;
                  btnColor = action.color;
                  btnLabel = (
                    <span style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 5 }}>
                      <span style={{ display: "inline-block", width: 10, height: 10, border: `2px solid ${action.color}`, borderTopColor: "transparent", borderRadius: "50%", animation: "xdr-spin 0.7s linear infinite", flexShrink: 0 }} />
                      Sending...
                    </span>
                  );
                } else if (isCompleted) {
                  btnBg = "rgba(0,255,136,0.1)";
                  btnBorder = "1px solid rgba(0,255,136,0.5)";
                  btnColor = "#00ff88";
                  btnLabel = `${action.label} ✓`;
                } else if (isFailed) {
                  btnBg = "rgba(255,51,102,0.1)";
                  btnBorder = "1px solid rgba(255,51,102,0.5)";
                  btnColor = "#ff3366";
                  btnLabel = `${action.label} ✗`;
                } else if (isActive) {
                  btnBg = `${action.color}1a`;
                  btnBorder = `1px solid ${action.color}`;
                  btnColor = action.color;
                } else if (hasFeedback) {
                  btnBg = "rgba(0,255,136,0.08)";
                  btnColor = "#00ff88";
                  btnLabel = "Queued ✓";
                }

                return (
                  <button
                    key={action.id}
                    onClick={() => !isInFlight && handleActionClick(action)}
                    disabled={disabled || isInFlight}
                    className="xdr-btn"
                    style={{
                      padding: "10px 14px",
                      borderRadius: 8,
                      border: btnBorder,
                      background: btnBg,
                      color: btnColor,
                      fontWeight: 700,
                      fontSize: 11,
                      cursor: disabled || isInFlight ? "not-allowed" : "pointer",
                      letterSpacing: 0.5,
                      transition: "all 0.2s",
                      textAlign: "center",
                      position: "relative",
                      overflow: "hidden",
                    }}
                  >
                    {btnLabel}
                    {isActive && !hasFeedback && !isInFlight && (
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
                );
              })}
            </div>

            {/* Inline form for selected action */}
            <AnimatePresence>
              {activeAction && selectedEndpointId && (
                <motion.div
                  key={`form-${activeAction}`}
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: "auto" }}
                  exit={{ opacity: 0, height: 0 }}
                  transition={{ duration: 0.15 }}
                  style={{
                    background: "var(--bg-secondary)",
                    border: `1px solid ${ACTIONS.find((a) => a.id === activeAction)?.color ?? "var(--text-muted)"}44`,
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
                          {action.label.toUpperCase()} — {selectedEndpoint?.hostname ?? selectedEndpointId}
                        </div>

                        {action.isConfirm ? (
                          <div
                            style={{
                              padding: "10px 12px",
                              background: action.id === "unisolate_host"
                                ? "rgba(14,165,233,0.08)"
                                : "rgba(220,38,38,0.08)",
                              border: action.id === "unisolate_host"
                                ? "1px solid rgba(14,165,233,0.25)"
                                : "1px solid rgba(220,38,38,0.25)",
                              borderRadius: 8,
                              fontSize: 12,
                              color: action.id === "unisolate_host" ? "#7dd3fc" : "#fca5a5",
                            }}
                          >
                            {action.id === "unisolate_host" ? (
                              <>
                                Restore network access for{" "}
                                <strong>{selectedEndpoint?.hostname ?? selectedEndpointId}</strong>?
                                This will re-enable the network interface. Confirm to proceed.
                              </>
                            ) : (
                              <>
                                Are you sure? This will isolate{" "}
                                <strong>{selectedEndpoint?.hostname ?? selectedEndpointId}</strong> from
                                the network. This action requires confirmation.
                              </>
                            )}
                          </div>
                        ) : (() => {
                          const actionKey2 = `${selectedEndpointId}::${activeAction}`;
                          const isCurrentInFlight = inFlightMap[actionKey2]?.status === 'inflight';
                          return (
                            <input
                              autoFocus
                              value={actionTarget}
                              onChange={(e) => setActionTarget(e.target.value)}
                              onKeyDown={(e) => {
                                if (e.key === "Enter") handleSend();
                                if (e.key === "Escape") handleCancel();
                              }}
                              disabled={isCurrentInFlight}
                              placeholder={action.placeholder}
                              style={{
                                width: "100%",
                                padding: "8px 12px",
                                borderRadius: 8,
                                border: "1px solid var(--border-color)",
                                background: isCurrentInFlight ? "var(--bg-primary)" : "var(--bg-primary)",
                                color: isCurrentInFlight ? "var(--text-muted)" : "var(--text-primary)",
                                fontSize: 12,
                                fontFamily: "'Fira Code', monospace",
                                outline: "none",
                                boxSizing: "border-box",
                                cursor: isCurrentInFlight ? "not-allowed" : "text",
                                opacity: isCurrentInFlight ? 0.5 : 1,
                              }}
                            />
                          );
                        })()}

                        <div style={{ display: "flex", gap: 8 }}>
                          <button
                            onClick={handleSend}
                            disabled={!action.isConfirm && !actionTarget.trim() && !OPTIONAL_TARGET_ACTIONS.has(action.id)}
                            style={{
                              padding: "7px 18px",
                              borderRadius: 8,
                              border: "none",
                              background:
                                confirmPending
                                  ? (action.id === "unisolate_host" ? "#0ea5e9" : "#dc2626")
                                  : action.color === "#22c55e"
                                  ? "#15803d"
                                  : action.color,
                              color: "#fff",
                              fontWeight: 700,
                              fontSize: 11,
                              cursor: (!action.isConfirm && !actionTarget.trim() && !OPTIONAL_TARGET_ACTIONS.has(action.id)) ? "not-allowed" : "pointer",
                              opacity: (!action.isConfirm && !actionTarget.trim() && !OPTIONAL_TARGET_ACTIONS.has(action.id)) ? 0.5 : 1,
                              letterSpacing: 0.5,
                              transition: "all 0.15s",
                            }}
                          >
                            {confirmPending
                            ? (activeAction === "unisolate_host" ? "Confirm Unisolate" : "Confirm Isolate")
                            : "Send"}
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
        </div>

        {/* Response History — inside Section 3, above Command History */}
        <div style={{ borderTop: "1px solid var(--border-color)", margin: "0 20px", paddingTop: 16, paddingBottom: 16 }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: "var(--text-muted)", letterSpacing: 1.2, textTransform: "uppercase", marginBottom: 10 }}>
            Response Plans
          </div>
          {responsePlans.length === 0 ? (
            <div style={{ color: "var(--text-muted)", fontSize: 12 }}>No response plans generated this session</div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
              {responsePlans
                .filter(p => !selectedEndpointId || p.endpoint_id === selectedEndpointId)
                .slice(0, 5)
                .map((p, idx) => {
                  const sevColor = SEVERITY_COLOUR[p.severity?.toUpperCase()] ?? "#ea580c";
                  return (
                    <div
                      key={`rph-${p.plan_id}-${idx}`}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 10,
                        padding: "7px 10px",
                        background: "var(--bg-secondary)",
                        border: "1px solid var(--border-color)",
                        borderRadius: 7,
                        fontSize: 11,
                        cursor: "pointer",
                      }}
                      onClick={() => setResponseModal({ plan: p })}
                    >
                      <span style={{ color: "#60a5fa", fontFamily: "monospace", fontSize: 9 }}>
                        {p.plan_id?.slice(-8) ?? "—"}
                      </span>
                      <span style={{ background: "#78350f22", color: "#fbbf24", borderRadius: 4, padding: "1px 6px", fontSize: 9, fontWeight: 700 }}>
                        {p.attack_type ?? "Unknown"}
                      </span>
                      <span style={{ background: `${sevColor}22`, color: sevColor, border: `1px solid ${sevColor}44`, borderRadius: 4, padding: "1px 6px", fontSize: 9, fontWeight: 700 }}>
                        {p.severity}
                      </span>
                      <span style={{ color: "var(--text-muted)", marginLeft: "auto", fontSize: 9 }}>
                        {p.created_at ? fmtTime(p.created_at) : "—"}
                      </span>
                    </div>
                  );
                })}
            </div>
          )}
        </div>

        {/* Command History */}
        <div
          style={{
            borderTop: "1px solid var(--border-color)",
            margin: "0 20px",
            paddingTop: 16,
            paddingBottom: 20,
          }}
        >
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
            Command History (last 10)
          </div>
          {recentResults.length === 0 ? (
            <div style={{ color: "var(--text-muted)", fontSize: 12 }}>No commands issued this session</div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              <AnimatePresence initial={false}>
                {recentResults.map((r, idx) => {
                  const isExpanded = expandedResultIdx === idx;
                  const isOk = r.success || r.status === "completed";
                  const isPending = r.status === "pending" || r.status === "sent";
                  const resultDetail = r.result_message ?? r.message ?? "";

                  // Badge styling by status
                  let badgeBg = "", badgeBorder = "", badgeColor = "", badgeText = "";
                  if (isPending) {
                    badgeBg = "rgba(245,158,11,0.1)"; badgeBorder = "rgba(245,158,11,0.3)";
                    badgeColor = "#f59e0b"; badgeText = r.status === "sent" ? "SENT" : "PENDING";
                  } else if (isOk) {
                    badgeBg = "rgba(0,255,136,0.1)"; badgeBorder = "rgba(0,255,136,0.3)";
                    badgeColor = "#00ff88"; badgeText = "✓ DONE";
                  } else {
                    badgeBg = "rgba(255,51,102,0.1)"; badgeBorder = "rgba(255,51,102,0.3)";
                    badgeColor = "#ff3366"; badgeText = "✗ FAIL";
                  }

                  const ACTION_LABELS: Record<string, string> = {
                    block_ip: "Block IP", unblock_ip: "Unblock IP", isolate_host: "Isolate",
                    unisolate_host: "Unisolate", kill_process: "Kill Proc", quarantine_file: "Quarantine",
                    restore_quarantine_file: "Restore", lock_account: "Lock Acct", unlock_account: "Unlock Acct",
                    scan_filesystem: "Scan FS", monitor_persistence: "Monitor Persist",
                  };
                  const actionLabel = ACTION_LABELS[r.action ?? ""] ?? (r.action ?? "Command");

                  return (
                    <motion.div
                      key={`cmd-${r.command_id}-${idx}`}
                      initial={{ opacity: 0, x: -8 }}
                      animate={{ opacity: 1, x: 0 }}
                      exit={{ opacity: 0 }}
                      transition={{ duration: 0.15 }}
                      style={{ borderRadius: 7, overflow: "hidden" }}
                    >
                      <div
                        onClick={() => setExpandedResultIdx(isExpanded ? null : idx)}
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: 10,
                          padding: "7px 10px",
                          background: isOk ? "rgba(0,255,136,0.04)" : isPending ? "rgba(245,158,11,0.04)" : "rgba(255,51,102,0.05)",
                          border: `1px solid ${isOk ? "rgba(0,255,136,0.15)" : isPending ? "rgba(245,158,11,0.15)" : "rgba(255,51,102,0.15)"}`,
                          borderRadius: isExpanded ? "7px 7px 0 0" : 7,
                          fontSize: 11,
                          cursor: resultDetail ? "pointer" : "default",
                        }}
                      >
                        {/* Status pill */}
                        <span
                          style={{
                            flexShrink: 0,
                            fontWeight: 800,
                            fontSize: 10,
                            letterSpacing: 0.5,
                            color: badgeColor,
                            background: badgeBg,
                            border: `1px solid ${badgeBorder}`,
                            borderRadius: 6,
                            padding: "2px 8px",
                            minWidth: 52,
                            textAlign: "center",
                          }}
                        >
                          {isPending && (
                            <span style={{ display: "inline-block", width: 7, height: 7, border: `1.5px solid ${badgeColor}`, borderTopColor: "transparent", borderRadius: "50%", animation: "xdr-spin 0.7s linear infinite", marginRight: 4, verticalAlign: "middle" }} />
                          )}
                          {badgeText}
                        </span>
                        {/* Action label */}
                        <span style={{ color: "var(--text-secondary)", fontWeight: 700, fontSize: 10, letterSpacing: 0.5, flexShrink: 0 }}>
                          {actionLabel}
                        </span>
                        {/* Endpoint hostname */}
                        <span style={{ color: "#60a5fa", fontFamily: "monospace", flexShrink: 0, fontSize: 11 }}>
                          {(() => {
                            const ep = endpoints.find((e) => e.endpoint_id === r.endpoint_id);
                            return ep ? ep.hostname : r.endpoint_id;
                          })()}
                        </span>
                        {/* Target (if available) */}
                        {r.target && (
                          <span style={{ color: "var(--accent-amber)", fontFamily: "monospace", fontSize: 10, flexShrink: 0 }}>
                            {r.target}
                          </span>
                        )}
                        {/* Expand indicator */}
                        {resultDetail && (
                          <span style={{ color: "var(--text-muted)", marginLeft: "auto", fontSize: 10, flexShrink: 0 }}>
                            {isExpanded ? "▲" : "▼"}
                          </span>
                        )}
                        {/* Command ID */}
                        <span style={{ color: "var(--bg-card)", fontFamily: "monospace", fontSize: 9, flexShrink: 0 }}>
                          #{r.command_id?.slice(-6) ?? ""}
                        </span>
                      </div>
                      {/* Expanded result message */}
                      <AnimatePresence>
                        {isExpanded && resultDetail && (
                          <motion.div
                            key="result-detail"
                            initial={{ opacity: 0, height: 0 }}
                            animate={{ opacity: 1, height: "auto" }}
                            exit={{ opacity: 0, height: 0 }}
                            transition={{ duration: 0.15 }}
                            style={{
                              background: "#080f1e",
                              border: `1px solid ${isOk ? "rgba(0,255,136,0.15)" : "rgba(255,51,102,0.15)"}`,
                              borderTop: "none",
                              borderRadius: "0 0 7px 7px",
                              padding: "8px 10px",
                              fontSize: 11,
                              color: "var(--text-muted)",
                              fontFamily: "monospace",
                              overflow: "hidden",
                            }}
                          >
                            {resultDetail}
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </motion.div>
                  );
                })}
              </AnimatePresence>
            </div>
          )}
        </div>
      </div>

      {/* ── Section 4: Active Threats Panel ─────────────────────────────────── */}
      <div style={panel}>
        <div
          style={{
            padding: "12px 20px",
            borderBottom: "1px solid #0a1120",
            display: "flex",
            alignItems: "center",
            gap: 10,
          }}
        >
          <span style={{ fontSize: 12, fontWeight: 700, color: "var(--text-muted)", letterSpacing: 0.5 }}>
            ACTIVE THREATS
          </span>
          <span
            style={{
              background: responsePlans.length > 0 ? "rgba(220,38,38,0.15)" : "var(--bg-card)",
              color: responsePlans.length > 0 ? "#fca5a5" : "var(--text-secondary)",
              borderRadius: 10,
              padding: "1px 8px",
              fontSize: 10,
              fontWeight: 700,
            }}
          >
            {responsePlans.length}
          </span>
          {selectedEndpointId && (
            <span style={{ marginLeft: "auto", fontSize: 10, color: "var(--text-muted)" }}>
              filtered to selected endpoint
            </span>
          )}
        </div>

        {responsePlans.length === 0 ? (
          <div style={{ padding: "32px 20px", textAlign: "center", color: "var(--text-muted)", fontSize: 13 }}>
            No active response plans — all endpoints appear normal
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ background: "var(--bg-secondary)" }}>
                  {["Plan ID", "Attack Type", "Domain", "Risk Level", "MITRE", "Score", "Status", "Created", "View", ...(onInvestigateIncident ? ["Investigate"] : [])].map((col) => (
                    <th
                      key={col}
                      style={{
                        padding: "8px 14px",
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
                {responsePlans
                  .filter((p) => !selectedEndpointId || p.endpoint_id === selectedEndpointId)
                  .map((plan, idx) => {
                    const riskColor =
                      plan.risk_level?.toUpperCase() === "CRITICAL"
                        ? "#dc2626"
                        : plan.risk_level?.toUpperCase() === "HIGH"
                        ? "#ea580c"
                        : plan.risk_level?.toUpperCase() === "MEDIUM"
                        ? "#d97706"
                        : "#22c55e";
                    return (
                      <motion.tr
                        key={`at-${plan.plan_id}-${idx}`}
                        initial={{ opacity: 0, x: -8 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ duration: 0.15 }}
                        style={{
                          borderBottom: "1px solid #0a1120",
                          background: idx % 2 === 0 ? "var(--bg-card)" : "var(--bg-card)",
                        }}
                      >
                        <td
                          style={{
                            padding: "10px 14px",
                            fontFamily: "monospace",
                            fontSize: 11,
                            color: "#60a5fa",
                            whiteSpace: "nowrap",
                          }}
                        >
                          {plan.plan_id?.slice(-10) ?? "—"}
                        </td>
                        <td style={{ padding: "10px 14px", whiteSpace: "nowrap" }}>
                          <span
                            style={{
                              background: "#78350f22",
                              color: "#fbbf24",
                              borderRadius: 5,
                              padding: "2px 8px",
                              fontSize: 10,
                              fontWeight: 700,
                              border: "1px solid #78350f44",
                            }}
                          >
                            {plan.attack_type || "Multi-Domain Threat"}
                          </span>
                        </td>
                        <td style={{ padding: "10px 14px", whiteSpace: "nowrap" }}>
                          <span style={{
                            background: "rgba(0,212,255,0.07)",
                            color: "#7dd3fc",
                            border: "1px solid rgba(0,212,255,0.2)",
                            borderRadius: 5,
                            padding: "2px 8px",
                            fontSize: 10,
                            fontWeight: 700,
                          }}>
                            {(plan as any).domain ?? _buildDomain((plan as any).sources ?? (plan as any).contributing_signals ?? [])}
                          </span>
                        </td>
                        <td style={{ padding: "10px 14px", whiteSpace: "nowrap" }}>
                          <span
                            style={{
                              display: "inline-block",
                              background: `${riskColor}22`,
                              color: riskColor,
                              border: `1px solid ${riskColor}55`,
                              borderRadius: 6,
                              padding: "3px 9px",
                              fontSize: 10,
                              fontWeight: 700,
                              letterSpacing: 0.5,
                            }}
                          >
                            {plan.risk_level ?? plan.severity}
                          </span>
                        </td>
                        <td style={{ padding: "10px 14px", whiteSpace: "nowrap" }}>
                          <span
                            style={{
                              background: "#431407",
                              color: "#fb923c",
                              border: "1px solid #7c2d1244",
                              borderRadius: 6,
                              padding: "3px 8px",
                              fontSize: 10,
                              fontWeight: 700,
                              fontFamily: "monospace",
                              letterSpacing: 0.5,
                            }}
                          >
                            {plan.mitre_technique ?? "—"}
                          </span>
                        </td>
                        <td style={{ padding: "10px 14px", whiteSpace: "nowrap" }}>
                          {(() => {
                            const rawScore = (plan as any).threat_score;
                            const displayScore = rawScore != null
                              ? (rawScore > 1 ? Math.round(rawScore) : Math.round(rawScore * 100))
                              : null;
                            const normalizedScore = rawScore != null
                              ? (rawScore > 1 ? rawScore / 100 : rawScore)
                              : null;
                            return (
                              <span style={{
                                fontFamily: "monospace",
                                fontWeight: 800,
                                fontSize: 13,
                                color: (normalizedScore ?? 0) >= 0.85 ? "#ff3366"
                                     : (normalizedScore ?? 0) >= 0.65 ? "#f59e0b"
                                     : "#00ff88",
                              }}>
                                {displayScore != null ? `${displayScore}%` : "—"}
                              </span>
                            );
                          })()}
                        </td>
                        <td style={{ padding: "10px 14px", whiteSpace: "nowrap" }}>
                          {(() => {
                            const planStatus = computePlanStatus(plan);
                            const statusCfg: Record<PlanStatus, { color: string; bg: string; border: string; label: React.ReactNode }> = {
                              CONTAINED: {
                                color: "#00ff88",
                                bg: "rgba(0,255,136,0.1)",
                                border: "rgba(0,255,136,0.35)",
                                label: "CONTAINED",
                              },
                              PARTIAL: {
                                color: "var(--accent-amber)",
                                bg: "rgba(245,158,11,0.1)",
                                border: "rgba(245,158,11,0.35)",
                                label: "PARTIAL",
                              },
                              EXECUTING: {
                                color: "var(--accent-cyan)",
                                bg: "var(--border-color)",
                                border: "rgba(47,224,224,0.35)",
                                label: (
                                  <span style={{ display: "flex", alignItems: "center", gap: 5 }}>
                                    <span style={{ display: "inline-block", width: 8, height: 8, border: "1.5px solid #00d4ff", borderTopColor: "transparent", borderRadius: "50%", animation: "xdr-spin 0.7s linear infinite" }} />
                                    EXECUTING
                                  </span>
                                ),
                              },
                              OPEN: {
                                color: "var(--text-muted)",
                                bg: "rgba(100,116,139,0.08)",
                                border: "rgba(100,116,139,0.25)",
                                label: "OPEN",
                              },
                            };
                            const cfg = statusCfg[planStatus];
                            return (
                              <span style={{
                                display: "inline-flex",
                                alignItems: "center",
                                gap: 4,
                                fontSize: 9,
                                fontWeight: 800,
                                letterSpacing: 0.8,
                                color: cfg.color,
                                background: cfg.bg,
                                border: `1px solid ${cfg.border}`,
                                borderRadius: 6,
                                padding: "3px 9px",
                              }}>
                                {cfg.label}
                              </span>
                            );
                          })()}
                        </td>
                        <td
                          style={{
                            padding: "10px 14px",
                            fontSize: 11,
                            color: "var(--text-secondary)",
                            whiteSpace: "nowrap",
                            fontFamily: "monospace",
                          }}
                        >
                          {plan.created_at ? fmtTime(plan.created_at) : "—"}
                        </td>
                        <td style={{ padding: "10px 14px" }}>
                          <button
                            onClick={() => setResponseModal({ plan })}
                            style={{
                              padding: "5px 12px",
                              borderRadius: 6,
                              border: "1px solid rgba(47,224,224,0.35)",
                              background: "rgba(0,212,255,0.07)",
                              color: "var(--accent-cyan)",
                              fontWeight: 700,
                              fontSize: 10,
                              letterSpacing: 0.5,
                              textTransform: "uppercase",
                              cursor: "pointer",
                              transition: "all 0.15s",
                              whiteSpace: "nowrap",
                            }}
                          >
                            View Response
                          </button>
                        </td>
                        {onInvestigateIncident && (
                          <td style={{ padding: "10px 14px" }}>
                            <button
                              onClick={() => onInvestigateIncident(plan.plan_id)}
                              style={{
                                padding: "5px 12px",
                                borderRadius: 6,
                                border: "1px solid rgba(168,85,247,0.35)",
                                background: "rgba(168,85,247,0.07)",
                                color: "#c084fc",
                                fontWeight: 700,
                                fontSize: 10,
                                letterSpacing: 0.5,
                                textTransform: "uppercase",
                                cursor: "pointer",
                                transition: "all 0.15s",
                                whiteSpace: "nowrap",
                              }}
                            >
                              Investigate
                            </button>
                          </td>
                        )}
                      </motion.tr>
                    );
                  })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ── Section 5: Incident Reports ──────────────────────────────────────── */}
      <div style={panel}>
        <div
          style={{
            padding: "12px 20px",
            borderBottom: "1px solid #0a1120",
            display: "flex",
            alignItems: "center",
            gap: 10,
          }}
        >
          <span style={{ fontSize: 12, fontWeight: 700, color: "var(--text-muted)", letterSpacing: 0.5 }}>
            INCIDENT REPORTS
          </span>
          <span
            style={{
              background: incidentReports.length > 0 ? "rgba(139,92,246,0.15)" : "var(--bg-card)",
              color: incidentReports.length > 0 ? "#c4b5fd" : "var(--text-secondary)",
              borderRadius: 10,
              padding: "1px 8px",
              fontSize: 10,
              fontWeight: 700,
            }}
          >
            {incidentReports.length}
          </span>
        </div>

        {incidentReports.length === 0 ? (
          <div style={{ padding: "32px 20px", textAlign: "center", color: "var(--text-muted)", fontSize: 13 }}>
            No incident reports generated yet — generate a report from a response plan to see it here.
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            {selectedEndpointId && incidentReports.some(r => r.endpoint_id !== selectedEndpointId) && (
              <div style={{ padding: "6px 14px", fontSize: 10, color: "var(--text-secondary)", background: "rgba(0,212,255,0.04)", borderBottom: "1px solid var(--border-color)", display: "flex", alignItems: "center", gap: 6 }}>
                <span style={{ color: "var(--accent-cyan)" }}>ℹ</span>
                Showing all reports across all endpoints.
                <button
                  onClick={() => {}}
                  style={{ marginLeft: "auto", fontSize: 9, color: "var(--text-muted)", background: "transparent", border: "none", cursor: "default" }}
                >
                  {incidentReports.length} total
                </button>
              </div>
            )}
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ background: "var(--bg-secondary)" }}>
                  {["Incident ID", "Endpoint", "Attack Type", "Severity", "Generated By", "Date", "Download", "Investigate"].map((col) => (
                    <th
                      key={col}
                      style={{
                        padding: "8px 14px",
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
                {incidentReports.map((report, idx) => {
                  const sevColor = SEVERITY_COLOUR[report.severity?.toUpperCase()] ?? "#ea580c";
                  return (
                    <motion.tr
                      key={`ir-${report.incident_id}-${idx}`}
                      initial={{ opacity: 0, x: -8 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ duration: 0.15 }}
                      style={{
                        borderBottom: "1px solid #0a1120",
                        background: idx % 2 === 0 ? "var(--bg-card)" : "var(--bg-card)",
                      }}
                    >
                      <td
                        style={{
                          padding: "10px 14px",
                          fontFamily: "monospace",
                          fontSize: 11,
                          color: "#818cf8",
                          whiteSpace: "nowrap",
                        }}
                      >
                        {report.incident_id?.slice(-12) ?? "—"}
                      </td>
                      <td
                        style={{
                          padding: "10px 14px",
                          fontSize: 12,
                          color: "#60a5fa",
                          fontFamily: "monospace",
                          whiteSpace: "nowrap",
                        }}
                      >
                        {report.endpoint_id}
                      </td>
                      <td style={{ padding: "10px 14px", whiteSpace: "nowrap" }}>
                        <span
                          style={{
                            background: "#78350f22",
                            color: "#fbbf24",
                            borderRadius: 5,
                            padding: "2px 8px",
                            fontSize: 10,
                            fontWeight: 700,
                            border: "1px solid #78350f44",
                          }}
                        >
                          {report.attack_type ?? "Unknown"}
                        </span>
                      </td>
                      <td style={{ padding: "10px 14px", whiteSpace: "nowrap" }}>
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
                          {report.severity}
                        </span>
                      </td>
                      <td
                        style={{
                          padding: "10px 14px",
                          fontSize: 11,
                          color: "var(--text-muted)",
                          whiteSpace: "nowrap",
                        }}
                      >
                        {report.generated_by}
                      </td>
                      <td
                        style={{
                          padding: "10px 14px",
                          fontSize: 11,
                          color: "var(--text-secondary)",
                          whiteSpace: "nowrap",
                          fontFamily: "monospace",
                        }}
                      >
                        {report.generated_at ? fmtTime(report.generated_at) : "—"}
                      </td>
                      <td style={{ padding: "10px 14px" }}>
                        {report.status === "generating" ? (
                          <span style={{ fontSize: 11, color: "var(--text-secondary)", fontStyle: "italic" }}>Generating...</span>
                        ) : userRole === "viewer" ? (
                          <span style={{ fontSize: 11, color: "var(--text-secondary)" }}>Summary only</span>
                        ) : (
                          <button
                            onClick={async () => {
                              const token = getAccessToken();
                              const url = `${BACKEND_URL}/reports/${report.incident_id}/download`;
                              try {
                                const response = await axios.get(url, {
                                  responseType: "blob",
                                  headers: token
                                    ? { Authorization: `Bearer ${token}` }
                                    : { "X-API-Key": process.env.REACT_APP_XDR_API_KEY ?? "" },
                                });
                                const blob = new Blob([response.data], { type: "application/pdf" });
                                const blobUrl = URL.createObjectURL(blob);
                                const anchor = document.createElement("a");
                                anchor.href = blobUrl;
                                anchor.download = `incident_${report.incident_id}.pdf`;
                                anchor.click();
                                setTimeout(() => URL.revokeObjectURL(blobUrl), 5000);
                              } catch (err: any) {
                                const status = err?.response?.status;
                                if (status === 403) {
                                  alert("Access denied: Analyst or Admin role required to download reports.");
                                } else {
                                  alert("Download failed. Please try again.");
                                }
                              }
                            }}
                            style={{
                              padding: "5px 12px",
                              borderRadius: 6,
                              border: "1px solid rgba(139,92,246,0.35)",
                              background: "rgba(139,92,246,0.07)",
                              color: "#c4b5fd",
                              fontWeight: 700,
                              fontSize: 10,
                              letterSpacing: 0.5,
                              textTransform: "uppercase",
                              cursor: "pointer",
                              transition: "all 0.15s",
                              whiteSpace: "nowrap",
                            }}
                          >
                            Download PDF
                          </button>
                        )}
                      </td>
                      {/* Investigate button */}
                      <td style={{ padding: "10px 14px" }}>
                        {onInvestigateIncident && (
                          <button
                            onClick={() => onInvestigateIncident(report.incident_id)}
                            style={{
                              padding: "5px 12px",
                              borderRadius: 6,
                              border: "1px solid rgba(47,224,224,0.35)",
                              background: "rgba(0,212,255,0.07)",
                              color: "var(--accent-cyan)",
                              fontWeight: 700,
                              fontSize: 10,
                              letterSpacing: 0.5,
                              textTransform: "uppercase",
                              cursor: "pointer",
                              transition: "all 0.15s",
                              whiteSpace: "nowrap",
                            }}
                          >
                            Investigate
                          </button>
                        )}
                      </td>
                    </motion.tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Response Modal — opened from Active Threats panel */}
      {responseModal && (
        <ResponseModal
          alert={null}
          plan={responseModal.plan}
          onClose={() => setResponseModal(null)}
          onExecuted={(ids) => {
            if (process.env.NODE_ENV === 'development') {
              console.log("[EndpointView] Response executed, command IDs:", ids);
            }
          }}
        />
      )}
    </div>
  );
}
