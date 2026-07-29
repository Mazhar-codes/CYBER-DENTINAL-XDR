// AttackGraphView.tsx — top-level composition for the Attack Graph SOC panel
// Converted from app.jsx; sidebar/topbar provided by NetworkMonitor.tsx

import React, { useState, useEffect, useCallback, Component, ErrorInfo } from "react";
import DualOrbitLoader from "../../shared/DualOrbitLoader";
import StatCard from "../../shared/StatCard";
import GraphControls, { GraphLegend } from "./GraphControls";
import AttackGraph from "./AttackGraph";
import NodeDetailPanel from "./NodeDetailPanel";
import RecentEvents from "./RecentEvents";
import { useAttackGraphData } from "./useAttackGraphData";
import { GraphNode, GraphData } from "./types";
import styles from "./attack-graph.module.css";
import { useAuth } from "../../../context/AuthContext";
import { authAxios } from "../../../services/authService";
import { ReplayStep } from "./ReplayTimeline";
import { BACKEND_URL } from "../../../config";

// ── Static mock graph data (used as fallback / demo until live data arrives) ──
import { MOCK_GRAPH } from "./mockData";

// ── Incident types ────────────────────────────────────────────────────────────

interface Incident {
  incident_id: string;
  title: string;
  severity: string;
  attack_type: string;
  source_layers: string[];
  mitre_techniques: string[];
  created_at: string;
  last_event_at: string;
  root_cause?: string;
  affected_assets?: string[];
}

// ── Severity helpers ──────────────────────────────────────────────────────────

const SEV_COLORS: Record<string, string> = {
  CRITICAL: "#dc2626",
  HIGH:     "#ef4444",
  MEDIUM:   "#f59e0b",
  LOW:      "#3b82f6",
};

const SOURCE_LAYER_COLORS: Record<string, string> = {
  network: "#00d4ff",
  user:    "#22c55e",
  system:  "#f59e0b",
  malware: "#dc2626",
  fusion:  "#ef4444",
  sysmon:  "#a78bfa",
  rule:    "#f97316",
};

function formatAgo(iso: string): string {
  try {
    const diff = Date.now() - new Date(iso).getTime();
    const s = Math.floor(diff / 1000);
    if (s < 60) return `${s}s ago`;
    const m = Math.floor(s / 60);
    if (m < 60) return `${m}m ago`;
    const h = Math.floor(m / 60);
    if (h < 24) return `${h}h ago`;
    return `${Math.floor(h / 24)}d ago`;
  } catch {
    return "";
  }
}

function formatTs(iso: string): string {
  try {
    return new Date(iso).toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return iso.slice(11, 19) || iso;
  }
}

// ── Error boundary for D3 graph crashes ──────────────────────────────────────

interface GraphErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

class GraphErrorBoundary extends Component<
  { children: React.ReactNode; onRetry: () => void },
  GraphErrorBoundaryState
> {
  constructor(props: { children: React.ReactNode; onRetry: () => void }) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): GraphErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    if (process.env.NODE_ENV === "development") {
      console.error("[AttackGraph] D3 crash caught by error boundary:", error, info);
    }
  }

  render() {
    if (this.state.hasError) {
      return (
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            height: "100%",
            gap: 16,
            background: "rgba(10,17,32,0.9)",
          }}
        >
          <span style={{ fontSize: 32, color: "#ef4444" }}>⚠</span>
          <div
            style={{
              color: "#ef4444",
              fontFamily: "'Fira Code', monospace",
              fontSize: 13,
              fontWeight: 700,
              textAlign: "center",
            }}
          >
            Graph unavailable — reconnecting...
          </div>
          {process.env.NODE_ENV === "development" && this.state.error && (
            <div
              style={{
                color: "var(--text-secondary)",
                fontSize: 10,
                fontFamily: "monospace",
                maxWidth: 400,
                textAlign: "center",
              }}
            >
              {this.state.error.message}
            </div>
          )}
          <button
            onClick={() => {
              this.setState({ hasError: false, error: null });
              this.props.onRetry();
            }}
            style={{
              padding: "8px 20px",
              borderRadius: 8,
              border: "1px solid rgba(59,130,246,0.35)",
              background: "rgba(59,130,246,0.1)",
              color: "#3b82f6",
              fontWeight: 700,
              fontSize: 11,
              cursor: "pointer",
              letterSpacing: 0.5,
            }}
          >
            Retry
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

interface Props {
  /** Called when alertCount changes — lets NetworkMonitor update the sidebar badge */
  onAlertCountChange?: (count: number) => void;
  /** Fusion HIGH threshold (0–1) — nodes below this score are shown as low-severity */
  fusionHighThreshold?: number;
  /** Fusion CRITICAL threshold (0–1) — nodes above this are shown as CRITICAL */
  fusionCriticalThreshold?: number;
}

export default function AttackGraphView({ onAlertCountChange, fusionHighThreshold = 0.70, fusionCriticalThreshold = 0.85 }: Props) {
  const { data: liveData, isConnected, eventsPerSec, alertCount, isLoadingSnapshot, clearGraph: clearGraphState } =
    useAttackGraphData();
  const { user } = useAuth();
  const userRole = user?.role ?? "viewer";
  const canClear = userRole === "admin" || userRole === "analyst";

  // Async wrapper: call server-side clear first, then wipe local React state.
  // If the API call fails (network error or insufficient permissions) the local
  // state is still cleared so the UI remains responsive.
  const clearGraph = useCallback(async () => {
    try {
      await authAxios.post("/attack-graph/clear");
    } catch (err) {
      if (process.env.NODE_ENV === "development") {
        console.warn("[AttackGraph] Server clear failed (may need admin role):", err);
      }
    }
    clearGraphState();
  }, [clearGraphState]);

  // Retry key — incrementing forces GraphErrorBoundary to remount AttackGraph
  const [graphRetryKey, setGraphRetryKey] = useState(0);

  // Track the last time any live node was added/updated for the status bar
  const [lastUpdatedTime, setLastUpdatedTime] = useState<Date | null>(null);
  useEffect(() => {
    if (liveData.NODES.length > 0) {
      setLastUpdatedTime(new Date());
    }
  }, [liveData.NODES.length]);

  // ── Mock data fallback ────────────────────────────────────────────────────
  const [useMock, setUseMock] = useState(false);

  useEffect(() => {
    if (isLoadingSnapshot) return;
    if (liveData.NODES.length > 0) {
      setUseMock(false);
      return;
    }
    const timer = setTimeout(() => {
      if (liveData.NODES.length === 0) setUseMock(true);
    }, 5000);
    return () => clearTimeout(timer);
  }, [isLoadingSnapshot, liveData.NODES.length]);

  const displayData: GraphData = React.useMemo(() => {
    if (liveData.NODES.length > 0) return liveData;
    if (useMock) return MOCK_GRAPH;
    return { NODES: [], EDGES: [], SHAP: {}, RESPONSES: {}, TIMELINE: [] };
  }, [liveData, useMock]);

  // ── Replay state ──────────────────────────────────────────────────────────
  const totalSteps = displayData.EDGES.filter((e) => e.malicious).length;
  const [replayStep, setReplayStep] = useState(totalSteps);
  const [paused, setPaused] = useState(true);
  const [replaySpeed, setReplaySpeed] = useState(1);

  useEffect(() => {
    setReplayStep(totalSteps);
  }, [totalSteps]);

  // Auto-replay ticker — interval adjusts to replaySpeed
  useEffect(() => {
    if (paused) return;
    const id = setInterval(() => {
      setReplayStep((s) => {
        if (s >= totalSteps) {
          setPaused(true);
          return totalSteps;
        }
        return s + 1;
      });
    }, Math.round(900 / replaySpeed));
    return () => clearInterval(id);
  }, [paused, totalSteps, replaySpeed]);

  // ── Incident list + investigation panel ──────────────────────────────────
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [replaySteps, setReplaySteps] = useState<ReplayStep[]>([]);
  const [incidentLoading, setIncidentLoading] = useState(false);

  // Fetch incident list on mount
  useEffect(() => {
    authAxios
      .get<{ incidents: Incident[]; total: number } | Incident[]>("/incidents?hours=48&limit=20")
      .then((res) => {
        // Backend returns { incidents: [...], total: N } — unwrap the array
        const raw = res.data as any;
        const list: Incident[] = Array.isArray(raw) ? raw : (raw.incidents ?? []);
        setIncidents(list);
      })
      .catch(() => {
        // Backend may not have this endpoint yet — fail silently
      });
  }, []);

  const handleSelectIncident = useCallback(async (incident: Incident) => {
    setSelectedIncident(incident);
    setReplaySteps([]);
    setReplayStep(0);
    setPaused(true);
    setIncidentLoading(true);
    try {
      const res = await authAxios.get<{ steps: ReplayStep[]; total_steps?: number; metadata?: unknown } | ReplayStep[]>(
        `/incidents/${incident.incident_id}/replay`
      );
      // Backend returns { steps: [...], total_steps: N, metadata: {...} } — unwrap
      const raw = res.data as any;
      const steps: ReplayStep[] = Array.isArray(raw) ? raw : (raw.steps ?? []);
      setReplaySteps(steps);
    } catch {
      // Endpoint may not exist yet; leave replaySteps empty
    } finally {
      setIncidentLoading(false);
    }
  }, []);

  const handleCloseInvestigation = useCallback(() => {
    setSelectedIncident(null);
    setReplaySteps([]);
  }, []);

  // ── Selected node (NodeDetailPanel) ──────────────────────────────────────
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

  const handleNodeClick = useCallback((node: GraphNode) => {
    setSelectedNode(node);
  }, []);

  const handleClosePanel = useCallback(() => {
    setSelectedNode(null);
  }, []);

  const handleJumpToStep = useCallback((step: number) => {
    setReplayStep(step);
    setPaused(true);
  }, []);

  // Start replay from step 0
  const startReplay = useCallback(() => {
    setReplayStep(0);
    setPaused(false);
  }, []);

  // Notify parent of alert count changes
  useEffect(() => {
    onAlertCountChange?.(alertCount);
  }, [alertCount, onAlertCountChange]);

  // ── ISOLATE FLEET handler ─────────────────────────────────────────────────
  const handleIsolateFleet = useCallback(async () => {
    const endpointNodes = displayData.NODES.filter((n) => n.type === "endpoint");
    if (endpointNodes.length === 0) return;

    const token = localStorage.getItem("access_token");

    try {
      await Promise.all(
        endpointNodes.map((ep) =>
          fetch(`${BACKEND_URL}/endpoint/command`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              ...(token ? { Authorization: `Bearer ${token}` } : {}),
            },
            body: JSON.stringify({
              endpoint_id: ep.endpoint_id ?? ep.id.replace("endpoint_", ""),
              action: "isolate_host",
              parameters: {},
            }),
          })
        )
      );
    } catch (err) {
      if (process.env.NODE_ENV === 'development') {
        console.error("[AttackGraph] ISOLATE FLEET failed:", err);
      }
    }
  }, [displayData.NODES]);

  // Build highlightedPath — IDs of nodes involved in chain up to replayStep
  const highlightedPath = React.useMemo<string[]>(() => {
    const ids: string[] = [];
    displayData.EDGES.forEach((e) => {
      if (e.malicious && e.chain != null && e.chain <= replayStep) {
        const sId =
          typeof e.source === "object" ? (e.source as GraphNode).id : (e.source as string);
        const tId =
          typeof e.target === "object" ? (e.target as GraphNode).id : (e.target as string);
        if (!ids.includes(sId)) ids.push(sId);
        if (!ids.includes(tId)) ids.push(tId);
      }
    });
    return ids;
  }, [displayData.EDGES, replayStep]);

  // ── Derived stats ─────────────────────────────────────────────────────────
  const criticalCount = displayData.NODES.filter((n) => n.severity === "CRITICAL").length;
  const meanRisk =
    displayData.NODES.length > 0
      ? Math.round(
          displayData.NODES.reduce((sum, n) => sum + (n.risk ?? 0), 0) /
            displayData.NODES.length
        )
      : 0;

  return (
    <div className={styles.viewRoot}>
      {/* Top bar */}
      <div className={styles.topBar}>
        <span className={styles.topBarTitle}>Attack Graph</span>
        <span className={styles.topBarSub}>/ correlation engine v3.2</span>
        <div className={styles.topBarSpacer} />

        {/* WS pill */}
        <span
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 6,
            background: isConnected ? "rgba(34,197,94,0.08)" : "rgba(71,85,105,0.12)",
            border: `1px solid ${isConnected ? "rgba(34,197,94,0.35)" : "rgba(71,85,105,0.3)"}`,
            color: isConnected ? "#22c55e" : "#475569",
            padding: "5px 12px",
            borderRadius: 20,
            fontSize: 10,
            fontWeight: 700,
            letterSpacing: 1,
          }}
          aria-label={isConnected ? "WebSocket connected" : "WebSocket disconnected"}
        >
          <span
            style={{
              width: 6,
              height: 6,
              borderRadius: "50%",
              background: isConnected ? "#22c55e" : "#475569",
              boxShadow: isConnected ? "0 0 8px #22c55e" : "none",
              animation: isConnected ? "xdr-pulse 1.5s ease-in-out infinite" : "none",
              display: "inline-block",
            }}
          />
          WSS · {isConnected ? "LIVE" : "OFFLINE"}
        </span>

        <button
          className={styles.topBarBtn}
          onClick={startReplay}
          aria-label="Replay attack chain from step 1"
        >
          ▶ REPLAY ATTACK
        </button>
        <button
          className={`${styles.topBarBtn} ${styles.topBarBtnDanger}`}
          aria-label="Isolate entire fleet"
          onClick={handleIsolateFleet}
        >
          ISOLATE FLEET
        </button>
      </div>

      {/* Stats strip */}
      <div className={styles.statsStrip}>
        <StatCard
          label="Active Attacks"
          value={alertCount > 0 ? alertCount : criticalCount}
          sub={`+${Math.max(0, criticalCount)} critical`}
          accent="#dc2626"
          glow={alertCount > 0}
          icon="⚠"
        />
        <StatCard
          label="Nodes Observed"
          value={displayData.NODES.length}
          sub="streaming"
          accent="#00d4ff"
          icon="◈"
        />
        <StatCard
          label="Mean Risk"
          value={isNaN(meanRisk) ? 0 : meanRisk}
          sub={`${displayData.EDGES.filter((e) => e.malicious).length} attack edge${displayData.EDGES.filter((e) => e.malicious).length !== 1 ? "s" : ""}`}
          accent="#ea580c"
          icon="◬"
        />
        <StatCard
          label="Events / Sec"
          value={eventsPerSec.toFixed(1)}
          sub="ML-pipeline-v3"
          accent="#a78bfa"
          icon="⬣"
        />
      </div>

      {/* Graph area + right rail */}
      <div
        className={styles.graphWrap}
        style={{ gridTemplateColumns: incidents.length > 0 ? "220px 1fr 360px" : "1fr 360px" }}
      >
        {/* ── Left sidebar: Incident list ── */}
        {incidents.length > 0 && (
          <div
            style={{
              display: "flex",
              flexDirection: "column",
              background: "rgba(5,10,20,0.85)",
              border: "1px solid rgba(0,212,255,0.12)",
              borderRadius: 12,
              overflow: "hidden",
              minHeight: 0,
            }}
          >
            {/* Header */}
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 8,
                padding: "10px 12px",
                borderBottom: "1px solid rgba(0,212,255,0.10)",
                flexShrink: 0,
              }}
            >
              <span
                style={{
                  fontSize: 9,
                  fontWeight: 800,
                  letterSpacing: 1.5,
                  color: "var(--text-muted)",
                  textTransform: "uppercase" as const,
                  fontFamily: "'Fira Code', monospace",
                }}
              >
                INCIDENTS
              </span>
              <span
                style={{
                  fontSize: 9,
                  fontWeight: 800,
                  color: "#dc2626",
                  background: "rgba(220,38,38,0.12)",
                  border: "1px solid rgba(220,38,38,0.3)",
                  borderRadius: 10,
                  padding: "1px 6px",
                  fontFamily: "'Fira Code', monospace",
                }}
              >
                {incidents.length}
              </span>
            </div>

            {/* Scrollable incident list */}
            <div style={{ flex: 1, overflowY: "auto", padding: "6px 8px" }}>
              {incidents.map((inc) => {
                const sevColor = SEV_COLORS[inc.severity?.toUpperCase()] ?? "#94a3b8";
                const isSelected = selectedIncident?.incident_id === inc.incident_id;
                return (
                  <button
                    key={inc.incident_id}
                    onClick={() => handleSelectIncident(inc)}
                    aria-pressed={isSelected}
                    style={{
                      width: "100%",
                      textAlign: "left",
                      background: isSelected
                        ? `${sevColor}14`
                        : "rgba(15,23,42,0.5)",
                      border: `1px solid ${isSelected ? sevColor + "55" : "rgba(30,41,59,0.6)"}`,
                      borderRadius: 8,
                      padding: "8px 10px",
                      marginBottom: 5,
                      cursor: "pointer",
                      transition: "border-color 0.15s, background 0.15s",
                    }}
                    onMouseEnter={(e) => {
                      if (!isSelected) {
                        (e.currentTarget as HTMLButtonElement).style.borderColor = `${sevColor}44`;
                        (e.currentTarget as HTMLButtonElement).style.background = `${sevColor}0a`;
                      }
                    }}
                    onMouseLeave={(e) => {
                      if (!isSelected) {
                        (e.currentTarget as HTMLButtonElement).style.borderColor = "rgba(30,41,59,0.6)";
                        (e.currentTarget as HTMLButtonElement).style.background = "rgba(15,23,42,0.5)";
                      }
                    }}
                  >
                    {/* Severity badge + time */}
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        marginBottom: 4,
                      }}
                    >
                      <span
                        style={{
                          fontSize: 8,
                          fontWeight: 800,
                          color: sevColor,
                          background: `${sevColor}18`,
                          border: `1px solid ${sevColor}40`,
                          borderRadius: 4,
                          padding: "1px 5px",
                          letterSpacing: 0.5,
                          textTransform: "uppercase" as const,
                        }}
                      >
                        {inc.severity}
                      </span>
                      <span
                        style={{
                          fontSize: 8,
                          color: "var(--text-muted)",
                          fontFamily: "'Fira Code', monospace",
                        }}
                      >
                        {formatAgo(inc.last_event_at || inc.created_at)}
                      </span>
                    </div>

                    {/* Title */}
                    <div
                      style={{
                        fontSize: 10,
                        fontWeight: 700,
                        color: isSelected ? "#f1f5f9" : "#94a3b8",
                        marginBottom: 4,
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                        lineHeight: 1.3,
                      }}
                    >
                      {inc.title}
                    </div>

                    {/* attack_type */}
                    <div
                      style={{
                        fontSize: 9,
                        color: "var(--text-muted)",
                        marginBottom: 4,
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {inc.attack_type}
                    </div>

                    {/* Source layer chips */}
                    <div style={{ display: "flex", gap: 3, flexWrap: "wrap" as const }}>
                      {(inc.source_layers ?? []).slice(0, 3).map((sl) => {
                        const slColor = SOURCE_LAYER_COLORS[sl.toLowerCase()] ?? "#64748b";
                        return (
                          <span
                            key={sl}
                            style={{
                              fontSize: 7,
                              fontWeight: 700,
                              color: slColor,
                              background: `${slColor}15`,
                              border: `1px solid ${slColor}30`,
                              borderRadius: 3,
                              padding: "1px 4px",
                              textTransform: "uppercase" as const,
                              letterSpacing: 0.3,
                            }}
                          >
                            {sl}
                          </span>
                        );
                      })}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {/* D3 canvas */}
        <div className={styles.graphArea} style={{ position: "relative" }}>
          {/* Status bar */}
          <div
            style={{
              position: "absolute",
              top: 10,
              left: 12,
              right: 12,
              zIndex: 5,
              display: "flex",
              alignItems: "center",
              gap: 10,
              pointerEvents: "none",
              flexWrap: "wrap",
            }}
          >
            {/* Last updated */}
            <span
              style={{
                background: "rgba(10,17,32,0.85)",
                border: "1px solid rgba(30,41,59,0.7)",
                color: "var(--text-muted)",
                padding: "4px 10px",
                borderRadius: 6,
                fontSize: 10,
                fontFamily: "'Fira Code', monospace",
                letterSpacing: 0.5,
              }}
            >
              Last updated:{" "}
              <span style={{ color: "var(--text-secondary)" }}>
                {lastUpdatedTime
                  ? lastUpdatedTime.toLocaleTimeString("en-US", { hour12: false })
                  : "—"}
              </span>
            </span>

            {/* Active node count */}
            <span
              style={{
                background: "rgba(10,17,32,0.85)",
                border: "1px solid rgba(30,41,59,0.7)",
                color: "var(--text-secondary)",
                padding: "4px 10px",
                borderRadius: 6,
                fontSize: 10,
                fontFamily: "'Fira Code', monospace",
                letterSpacing: 0.5,
              }}
            >
              {displayData.NODES.length} nodes
            </span>

            {/* Threat level badge */}
            {(() => {
              const critNodes = displayData.NODES.filter((n) => n.severity === "CRITICAL").length;
              const highNodes = displayData.NODES.filter((n) => n.severity === "HIGH").length;
              if (critNodes > 0) {
                return (
                  <span
                    style={{
                      background: "rgba(220,38,38,0.12)",
                      border: "1px solid rgba(220,38,38,0.45)",
                      color: "#ef4444",
                      padding: "4px 10px",
                      borderRadius: 6,
                      fontSize: 10,
                      fontWeight: 700,
                      fontFamily: "'Fira Code', monospace",
                      letterSpacing: 0.5,
                    }}
                  >
                    {critNodes} Critical Threat{critNodes !== 1 ? "s" : ""} Active
                  </span>
                );
              }
              if (highNodes > 0) {
                return (
                  <span
                    style={{
                      background: "rgba(245,158,11,0.12)",
                      border: "1px solid rgba(245,158,11,0.45)",
                      color: "var(--accent-amber)",
                      padding: "4px 10px",
                      borderRadius: 6,
                      fontSize: 10,
                      fontWeight: 700,
                      fontFamily: "'Fira Code', monospace",
                      letterSpacing: 0.5,
                    }}
                  >
                    {highNodes} High Severity Event{highNodes !== 1 ? "s" : ""}
                  </span>
                );
              }
              return (
                <span
                  style={{
                    background: "rgba(34,197,94,0.08)",
                    border: "1px solid rgba(34,197,94,0.35)",
                    color: "#22c55e",
                    padding: "4px 10px",
                    borderRadius: 6,
                    fontSize: 10,
                    fontWeight: 700,
                    fontFamily: "'Fira Code', monospace",
                    letterSpacing: 0.5,
                  }}
                >
                  System Normal — No Active Threats
                </span>
              );
            })()}
          </div>

          {/* Clear Graph button — top-right corner, admin/analyst only */}
          {canClear && (
            <button
              onClick={() => void clearGraph()}
              aria-label="Clear graph and reload snapshot"
              style={{
                position: "absolute",
                top: 10,
                right: 12,
                zIndex: 6,
                background: "rgba(71,85,105,0.12)",
                border: "1px solid rgba(71,85,105,0.35)",
                color: "var(--text-secondary)",
                padding: "5px 12px",
                borderRadius: 6,
                fontSize: 10,
                fontWeight: 700,
                fontFamily: "'Fira Code', monospace",
                letterSpacing: 0.5,
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                gap: 5,
                transition: "border-color 0.2s, color 0.2s",
              }}
              onMouseEnter={(e) => {
                (e.currentTarget as HTMLButtonElement).style.borderColor = "rgba(239,68,68,0.5)";
                (e.currentTarget as HTMLButtonElement).style.color = "#ef4444";
              }}
              onMouseLeave={(e) => {
                (e.currentTarget as HTMLButtonElement).style.borderColor = "rgba(71,85,105,0.35)";
                (e.currentTarget as HTMLButtonElement).style.color = "#94a3b8";
              }}
            >
              🗑 Clear
            </button>
          )}

          {/* Loading overlay */}
          {isLoadingSnapshot && displayData.NODES.length === 0 && (
            <div
              style={{
                position: "absolute",
                inset: 0,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                background: "rgba(5,10,20,0.85)",
                zIndex: 10,
              }}
            >
              <DualOrbitLoader size={56} label="Loading attack graph from backend..." />
            </div>
          )}

          <GraphErrorBoundary
            key={graphRetryKey}
            onRetry={() => setGraphRetryKey((k) => k + 1)}
          >
            <AttackGraph
              data={displayData}
              onNodeClick={handleNodeClick}
              highlightedPath={highlightedPath}
              fusionHighThreshold={fusionHighThreshold}
              fusionCriticalThreshold={fusionCriticalThreshold}
            />
          </GraphErrorBoundary>

          {/* NodeDetailPanel — overlaid inside the graph area */}
          {selectedNode && (
            <NodeDetailPanel
              node={selectedNode}
              data={displayData}
              onClose={handleClosePanel}
              onJumpToStep={handleJumpToStep}
            />
          )}

          {/* ── Investigation Panel — fixed overlay, right side of graph area ── */}
          {selectedIncident && (
            <div
              style={{
                position: "absolute",
                top: 0,
                right: 0,
                bottom: 0,
                width: 380,
                zIndex: 20,
                background: "rgba(5,10,20,0.95)",
                border: "1px solid rgba(0,212,255,0.15)",
                borderRadius: "0 14px 14px 0",
                display: "flex",
                flexDirection: "column",
                fontFamily: "'Fira Code', 'SF Mono', monospace",
                backdropFilter: "blur(12px)",
                boxShadow: "-8px 0 32px rgba(0,0,0,0.6)",
                overflow: "hidden",
              }}
            >
              {/* Panel header */}
              <div
                style={{
                  display: "flex",
                  alignItems: "flex-start",
                  gap: 10,
                  padding: "14px 16px 12px",
                  borderBottom: "1px solid rgba(0,212,255,0.10)",
                  flexShrink: 0,
                }}
              >
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 7,
                      marginBottom: 5,
                    }}
                  >
                    <span
                      style={{
                        fontSize: 8,
                        fontWeight: 800,
                        color: SEV_COLORS[selectedIncident.severity?.toUpperCase()] ?? "#94a3b8",
                        background: `${SEV_COLORS[selectedIncident.severity?.toUpperCase()] ?? "#94a3b8"}18`,
                        border: `1px solid ${SEV_COLORS[selectedIncident.severity?.toUpperCase()] ?? "#94a3b8"}40`,
                        borderRadius: 4,
                        padding: "2px 7px",
                        letterSpacing: 0.8,
                        textTransform: "uppercase" as const,
                      }}
                    >
                      {selectedIncident.severity}
                    </span>
                    <span
                      style={{
                        fontSize: 8,
                        color: "var(--text-secondary)",
                        fontFamily: "'Fira Code', monospace",
                      }}
                    >
                      {selectedIncident.incident_id.slice(-8).toUpperCase()}
                    </span>
                  </div>
                  <div
                    style={{
                      fontSize: 12,
                      fontWeight: 700,
                      color: "var(--text-primary)",
                      lineHeight: 1.4,
                    }}
                  >
                    {selectedIncident.title}
                  </div>
                </div>
                <button
                  onClick={handleCloseInvestigation}
                  aria-label="Close investigation panel"
                  style={{
                    background: "none",
                    border: "1px solid rgba(71,85,105,0.35)",
                    color: "var(--text-muted)",
                    width: 28,
                    height: 28,
                    borderRadius: 6,
                    cursor: "pointer",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    fontSize: 14,
                    flexShrink: 0,
                    transition: "color 0.15s, border-color 0.15s",
                  }}
                  onMouseEnter={(e) => {
                    (e.currentTarget as HTMLButtonElement).style.color = "#ef4444";
                    (e.currentTarget as HTMLButtonElement).style.borderColor = "rgba(239,68,68,0.4)";
                  }}
                  onMouseLeave={(e) => {
                    (e.currentTarget as HTMLButtonElement).style.color = "#64748b";
                    (e.currentTarget as HTMLButtonElement).style.borderColor = "rgba(71,85,105,0.35)";
                  }}
                >
                  ×
                </button>
              </div>

              {/* Scrollable body */}
              <div style={{ flex: 1, overflowY: "auto", padding: "12px 16px" }}>

                {/* Root Cause */}
                {selectedIncident.root_cause && (
                  <div style={{ marginBottom: 14 }}>
                    <div style={sectionHeadStyle}>ROOT CAUSE</div>
                    <div
                      style={{
                        fontSize: 12,
                        color: "var(--accent-cyan)",
                        fontFamily: "'Fira Code', monospace",
                        background: "rgba(0,212,255,0.06)",
                        border: "1px solid rgba(0,212,255,0.15)",
                        borderRadius: 6,
                        padding: "8px 10px",
                        lineHeight: 1.5,
                      }}
                    >
                      {selectedIncident.root_cause}
                    </div>
                  </div>
                )}

                {/* MITRE ATT&CK */}
                {selectedIncident.mitre_techniques && selectedIncident.mitre_techniques.length > 0 && (
                  <div style={{ marginBottom: 14 }}>
                    <div style={sectionHeadStyle}>MITRE ATT&amp;CK</div>
                    <div style={{ display: "flex", flexWrap: "wrap" as const, gap: 5 }}>
                      {selectedIncident.mitre_techniques.map((t) => (
                        <span
                          key={t}
                          style={{
                            fontSize: 9,
                            fontWeight: 700,
                            color: "#a78bfa",
                            background: "rgba(167,139,250,0.12)",
                            border: "1px solid rgba(167,139,250,0.3)",
                            borderRadius: 5,
                            padding: "3px 8px",
                            fontFamily: "'Fira Code', monospace",
                          }}
                        >
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Affected Assets */}
                {selectedIncident.affected_assets && selectedIncident.affected_assets.length > 0 && (
                  <div style={{ marginBottom: 14 }}>
                    <div style={sectionHeadStyle}>AFFECTED ASSETS</div>
                    <div style={{ display: "flex", flexWrap: "wrap" as const, gap: 5 }}>
                      {selectedIncident.affected_assets.map((a) => (
                        <span
                          key={a}
                          style={{
                            fontSize: 9,
                            fontWeight: 700,
                            color: "#3b82f6",
                            background: "rgba(59,130,246,0.10)",
                            border: "1px solid rgba(59,130,246,0.25)",
                            borderRadius: 5,
                            padding: "3px 8px",
                          }}
                        >
                          ▣ {a}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Source Layers */}
                {selectedIncident.source_layers && selectedIncident.source_layers.length > 0 && (
                  <div style={{ marginBottom: 14 }}>
                    <div style={sectionHeadStyle}>DETECTION LAYERS</div>
                    <div style={{ display: "flex", flexWrap: "wrap" as const, gap: 5 }}>
                      {selectedIncident.source_layers.map((sl) => {
                        const slColor = SOURCE_LAYER_COLORS[sl.toLowerCase()] ?? "#64748b";
                        return (
                          <span
                            key={sl}
                            style={{
                              fontSize: 9,
                              fontWeight: 700,
                              color: slColor,
                              background: `${slColor}15`,
                              border: `1px solid ${slColor}30`,
                              borderRadius: 5,
                              padding: "3px 8px",
                              textTransform: "uppercase" as const,
                              letterSpacing: 0.5,
                            }}
                          >
                            {sl}
                          </span>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* Timeline */}
                <div style={{ marginBottom: 14 }}>
                  <div
                    style={{
                      ...sectionHeadStyle,
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                    }}
                  >
                    <span>TIMELINE</span>
                    {incidentLoading && (
                      <span style={{ color: "var(--accent-cyan)", fontSize: 9 }}>Loading...</span>
                    )}
                    {!incidentLoading && replaySteps.length > 0 && (
                      <span style={{ color: "var(--text-secondary)", fontSize: 9 }}>
                        {replaySteps.length} events
                      </span>
                    )}
                  </div>

                  {replaySteps.length > 0 ? (
                    <div
                      style={{
                        maxHeight: 280,
                        overflowY: "auto",
                        borderRadius: 6,
                        border: "1px solid rgba(30,41,59,0.6)",
                        background: "rgba(5,10,20,0.5)",
                      }}
                    >
                      {replaySteps.map((rs) => {
                        const sevColor = SEV_COLORS[rs.severity?.toUpperCase()] ?? "#94a3b8";
                        const srcColor = SOURCE_LAYER_COLORS[rs.source_layer?.toLowerCase()] ?? "#64748b";
                        const isActive = rs.step === replayStep;
                        return (
                          <div
                            key={rs.step}
                            role="button"
                            tabIndex={0}
                            onClick={() => { setReplayStep(rs.step); setPaused(true); }}
                            onKeyDown={(e) => {
                              if (e.key === "Enter") { setReplayStep(rs.step); setPaused(true); }
                            }}
                            style={{
                              display: "flex",
                              gap: 8,
                              padding: "7px 10px",
                              borderBottom: "1px solid rgba(30,41,59,0.4)",
                              cursor: "pointer",
                              background: isActive ? `${sevColor}10` : "transparent",
                              borderLeft: isActive ? `2px solid ${sevColor}` : "2px solid transparent",
                              transition: "background 0.15s",
                            }}
                          >
                            {/* Step dot */}
                            <span
                              style={{
                                fontSize: 8,
                                fontWeight: 800,
                                color: sevColor,
                                minWidth: 20,
                                fontFamily: "'Fira Code', monospace",
                                paddingTop: 1,
                              }}
                            >
                              {String(rs.step + 1).padStart(2, "0")}
                            </span>
                            <div style={{ flex: 1, minWidth: 0 }}>
                              {/* Top row */}
                              <div
                                style={{
                                  display: "flex",
                                  gap: 5,
                                  alignItems: "center",
                                  marginBottom: 2,
                                  flexWrap: "wrap" as const,
                                }}
                              >
                                <span
                                  style={{
                                    fontSize: 8,
                                    color: "var(--text-muted)",
                                    fontFamily: "'Fira Code', monospace",
                                  }}
                                >
                                  {formatTs(rs.timestamp)}
                                </span>
                                <span
                                  style={{
                                    fontSize: 7,
                                    fontWeight: 800,
                                    color: sevColor,
                                    background: `${sevColor}18`,
                                    border: `1px solid ${sevColor}35`,
                                    borderRadius: 3,
                                    padding: "0 4px",
                                    textTransform: "uppercase" as const,
                                  }}
                                >
                                  {rs.severity}
                                </span>
                                <span
                                  style={{
                                    fontSize: 7,
                                    fontWeight: 700,
                                    color: srcColor,
                                    background: `${srcColor}12`,
                                    border: `1px solid ${srcColor}25`,
                                    borderRadius: 3,
                                    padding: "0 4px",
                                    textTransform: "uppercase" as const,
                                  }}
                                >
                                  {rs.source_layer}
                                </span>
                                {rs.mitre_technique && (
                                  <span
                                    style={{
                                      fontSize: 7,
                                      fontWeight: 700,
                                      color: "#a78bfa",
                                      background: "rgba(167,139,250,0.10)",
                                      border: "1px solid rgba(167,139,250,0.25)",
                                      borderRadius: 3,
                                      padding: "0 4px",
                                      fontFamily: "'Fira Code', monospace",
                                    }}
                                  >
                                    {rs.mitre_technique}
                                  </span>
                                )}
                              </div>
                              {/* Description */}
                              <div
                                style={{
                                  fontSize: 10,
                                  color: isActive ? "#cbd5e1" : "#64748b",
                                  overflow: "hidden",
                                  textOverflow: "ellipsis",
                                  whiteSpace: "nowrap",
                                }}
                              >
                                {rs.description}
                              </div>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  ) : !incidentLoading ? (
                    <div
                      style={{
                        fontSize: 10,
                        color: "var(--text-muted)",
                        fontStyle: "italic",
                        padding: "8px 0",
                      }}
                    >
                      No replay data available.
                    </div>
                  ) : null}
                </div>

                {/* Evidence summary */}
                <div style={{ marginBottom: 8 }}>
                  <div style={sectionHeadStyle}>EVIDENCE</div>
                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns: "1fr 1fr",
                      gap: 6,
                    }}
                  >
                    <div style={evidenceCardStyle}>
                      <span style={evidenceLblStyle}>EVENTS</span>
                      <span style={evidenceValStyle}>{replaySteps.length}</span>
                    </div>
                    <div style={evidenceCardStyle}>
                      <span style={evidenceLblStyle}>CONFIDENCE</span>
                      <span style={evidenceValStyle}>
                        {replaySteps.length > 0
                          ? `${Math.round(
                              (replaySteps.filter((r) =>
                                ["HIGH", "CRITICAL"].includes(r.severity?.toUpperCase())
                              ).length /
                                replaySteps.length) *
                                100
                            )}%`
                          : "—"}
                      </span>
                    </div>
                    <div style={evidenceCardStyle}>
                      <span style={evidenceLblStyle}>ATTACK TYPE</span>
                      <span
                        style={{
                          ...evidenceValStyle,
                          fontSize: 9,
                          color: "var(--accent-amber)",
                        }}
                      >
                        {selectedIncident.attack_type}
                      </span>
                    </div>
                    <div style={evidenceCardStyle}>
                      <span style={evidenceLblStyle}>LAYERS</span>
                      <span style={evidenceValStyle}>
                        {(selectedIncident.source_layers ?? []).length}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Right rail */}
        <div className={styles.rightRail}>
          <GraphControls
            replayStep={replayStep}
            totalSteps={totalSteps}
            paused={paused}
            setPaused={setPaused}
            setReplayStep={setReplayStep}
            alertCount={alertCount}
            eventsPerSec={eventsPerSec}
            isConnected={isConnected}
            replaySpeed={replaySpeed}
            onSpeedChange={setReplaySpeed}
          />
          <GraphLegend />
          <RecentEvents data={displayData} maxRows={6} />
        </div>
      </div>
    </div>
  );
}

// ── Inline style constants for investigation panel ────────────────────────────

const sectionHeadStyle: React.CSSProperties = {
  fontSize: 9,
  fontWeight: 800,
  letterSpacing: 1.5,
  color: "var(--text-secondary)",
  textTransform: "uppercase",
  marginBottom: 7,
  fontFamily: "'Fira Code', monospace",
};

const evidenceCardStyle: React.CSSProperties = {
  background: "rgba(15,23,42,0.6)",
  border: "1px solid rgba(30,41,59,0.6)",
  borderRadius: 6,
  padding: "7px 10px",
  display: "flex",
  flexDirection: "column",
  gap: 3,
};

const evidenceLblStyle: React.CSSProperties = {
  fontSize: 8,
  fontWeight: 700,
  letterSpacing: 1,
  color: "var(--text-muted)",
  textTransform: "uppercase",
  fontFamily: "'Fira Code', monospace",
};

const evidenceValStyle: React.CSSProperties = {
  fontSize: 16,
  fontWeight: 800,
  color: "var(--text-primary)",
  fontFamily: "'Fira Code', monospace",
};
