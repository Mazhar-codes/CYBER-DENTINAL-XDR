import React, { useState, useEffect, useMemo, useCallback } from "react";
import axios from "axios";
import { fmtTime, SystemAnomalyEvent } from "../shared/types";
import { BACKEND_URL } from "../../config";

type TimeRange = "1h" | "6h" | "24h" | "all";

function withinRange(ts: string | undefined, range: TimeRange): boolean {
  if (range === "all" || !ts) return true;
  try {
    const iso = ts.replace(" ", "T").replace(/(\.\d{3})\d+$/, "$1");
    const t = new Date(iso).getTime();
    if (isNaN(t)) return true;
    const hoursMs: Record<TimeRange, number> = { "1h": 3_600_000, "6h": 21_600_000, "24h": 86_400_000, "all": 0 };
    return Date.now() - t <= hoursMs[range];
  } catch {
    return true;
  }
}

function Pill({
  label, active, accent, onClick,
}: { label: string; active: boolean; accent: string; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      style={{
        padding: "4px 11px",
        borderRadius: 20,
        border: active ? `1px solid ${accent}` : "1px solid var(--border-color)",
        cursor: "pointer",
        background: active ? `${accent}1a` : "var(--bg-secondary)",
        color: active ? accent : "var(--text-secondary)",
        fontWeight: active ? 700 : 400,
        fontSize: 11,
        transition: "all 0.15s",
        whiteSpace: "nowrap",
      }}
    >
      {label}
    </button>
  );
}

interface SysmonAgentHealth {
  running: boolean;
  model_loaded: boolean;
  log_path: string;
  last_score: number;
  total_events: number;
  total_alerts: number;
}

interface SysmonFusion {
  threat_score: number;
  severity: string;
  should_respond?: boolean;
  contributing_models?: string[];
}

export interface SysmonIndicator {
  indicator: string;
  weight: number;
  field: string;
  value: string;
}

export interface SysmonBehaviorAlert {
  anomaly_score: number;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  label: string;
  process_name: string;
  pid: string;
  confidence: number;
  high_risk: boolean;
  ts: string;
  source: "sysmon_behavior";
  fusion?: SysmonFusion;
  // SHAP indicator analysis fields (present on anomaly alerts only)
  shap_reasons?: string[];
  shap_mitre?: string[];
  shap_indicators?: SysmonIndicator[];
}

interface SysmonRawLog {
  event_id: string;
  event_name: string;
  process_name: string;
  pid: string;
  commandline: string;
  high_risk: boolean;
  is_anomaly: boolean;
  ts: string;
  source: string;
}

interface SysmonBehaviorViewProps {
  isMonitoring: boolean;
  alerts: SysmonBehaviorAlert[];
  sysmonLogs?: SysmonRawLog[];
  systemAnomalies?: SystemAnomalyEvent[];
  /** Current user role — gates SHAP/indicator columns */
  userRole?: string;
  /** True when the behavioral (rule-based) detector is loaded alongside LSTM */
  behavioralDetectorLoaded?: boolean;
}

export default function SysmonBehaviorView({ isMonitoring, alerts, sysmonLogs = [], systemAnomalies = [], userRole, behavioralDetectorLoaded }: SysmonBehaviorViewProps) {
  const [sysmonHealth, setSysmonHealth] = useState<SysmonAgentHealth | null>(null);

  // ── Sysmon process events filters ──────────────────────────────────────────
  const [sysmonSearch, setSysmonSearch] = useState("");
  const [sysmonTimeRange, setSysmonTimeRange] = useState<TimeRange>("all");
  const [sysmonRiskFilter, setSysmonRiskFilter] = useState<"ALL" | "HIGH RISK" | "NORMAL">("ALL");

  // ── System telemetry filters ────────────────────────────────────────────────
  const [sysSearch, setSysSearch] = useState("");
  const [sysSeverity, setSysSeverity] = useState<string>("ALL");
  const [sysStatusFilter, setSysStatusFilter] = useState<"ALL" | "ANOMALOUS" | "NORMAL">("ALL");
  const [sysTimeRange, setSysTimeRange] = useState<TimeRange>("all");

  const clearSysmonFilters = useCallback(() => {
    setSysmonSearch(""); setSysmonTimeRange("all"); setSysmonRiskFilter("ALL");
  }, []);

  const clearSysFilters = useCallback(() => {
    setSysSearch(""); setSysSeverity("ALL"); setSysStatusFilter("ALL"); setSysTimeRange("all");
  }, []);

  const filteredSysmonLogs = useMemo(() => {
    const q = sysmonSearch.toLowerCase().trim();
    return sysmonLogs.filter((log) => {
      if (!withinRange(log.ts, sysmonTimeRange)) return false;
      if (sysmonRiskFilter === "HIGH RISK" && !log.high_risk) return false;
      if (sysmonRiskFilter === "NORMAL" && log.high_risk) return false;
      if (q) {
        const s = [log.process_name, log.event_name, log.commandline, log.pid]
          .filter(Boolean).join(" ").toLowerCase();
        if (!s.includes(q)) return false;
      }
      return true;
    });
  }, [sysmonLogs, sysmonSearch, sysmonTimeRange, sysmonRiskFilter]);

  // Build a PID-keyed lookup of the most recent SHAP data from behavioral alerts.
  // This lets us overlay indicator pills onto matching rows in the raw log table.
  const shapByPid = useMemo(() => {
    const map = new Map<string, { reasons: string[]; mitre: string[] }>();
    for (const alert of alerts) {
      const reasons = alert.shap_reasons ?? [];
      const mitre   = alert.shap_mitre   ?? [];
      if (reasons.length > 0 || mitre.length > 0) {
        // Keep the most recent alert per PID (alerts are appended newest-last)
        map.set(alert.pid, { reasons, mitre });
      }
    }
    return map;
  }, [alerts]);

  // Only show the Indicators column when at least one row has SHAP data AND user is admin or analyst
  const hasAnySHAP = useMemo(
    () => shapByPid.size > 0 && userRole !== "viewer",
    [shapByPid, userRole]
  );

  const filteredSystemAnomalies = useMemo(() => {
    const q = sysSearch.toLowerCase().trim();
    return systemAnomalies.filter((entry) => {
      const isAnomalous = entry.is_genuinely_anomalous === true
        || entry.severity === "HIGH"
        || entry.severity === "CRITICAL";
      if (!withinRange(entry.ts, sysTimeRange)) return false;
      if (sysSeverity !== "ALL" && entry.severity !== sysSeverity) return false;
      if (sysStatusFilter === "ANOMALOUS" && !isAnomalous) return false;
      if (sysStatusFilter === "NORMAL" && isAnomalous) return false;
      if (q) {
        const behavioralType = entry.behavioral_attack_type ?? "";
        const s = [entry.source, entry.severity, isAnomalous ? "anomalous" : "normal", behavioralType]
          .filter(Boolean).join(" ").toLowerCase();
        if (!s.includes(q)) return false;
      }
      return true;
    });
  }, [systemAnomalies, sysSearch, sysSeverity, sysStatusFilter, sysTimeRange]);

  useEffect(() => {
    const fetchHealth = () => {
      axios
        .get(`${BACKEND_URL}/health`)
        .then((res) => {
          const agent = res.data?.sysmon_agent ?? null;
          setSysmonHealth(agent);
        })
        .catch(() => setSysmonHealth(null));
    };
    fetchHealth();
    const healthTimer = setInterval(fetchHealth, 30000);
    return () => clearInterval(healthTimer);
  }, []);

  const highCriticalCount = alerts.filter(
    (a) => a.severity === "HIGH" || a.severity === "CRITICAL"
  ).length;

  const panel: React.CSSProperties = {
    background: "var(--bg-card)",
    border: "1px solid var(--border-color)",
    borderRadius: 14,
  };

  return (
    <div style={{ padding: 24, display: "flex", flexDirection: "column", gap: 18 }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div>
          <h2
            style={{
              margin: 0,
              fontSize: 20,
              fontWeight: 800,
              color: "var(--text-primary)",
              letterSpacing: -0.5,
              display: "flex",
              alignItems: "center",
              gap: 10,
            }}
          >
            Sysmon Behavior
            {highCriticalCount > 0 && (
              <span
                style={{
                  background: "#dc2626",
                  color: "#fff",
                  borderRadius: 20,
                  padding: "2px 10px",
                  fontSize: 10,
                  fontWeight: 700,
                  letterSpacing: 1,
                  animation: "xdr-pulse 0.5s ease-in-out 3",
                }}
              >
                {highCriticalCount} HIGH+CRITICAL
              </span>
            )}
          </h2>
          <p style={{ margin: "4px 0 0", color: "var(--text-secondary)", fontSize: 13 }}>
            Real-time process behavior anomaly detection via Sysmon event telemetry
          </p>
        </div>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            background: "var(--bg-card)",
            border: "1px solid var(--border-color)",
            borderRadius: 20,
            padding: "6px 14px",
          }}
        >
          <span
            style={{
              display: "inline-block",
              width: 7,
              height: 7,
              borderRadius: "50%",
              background: isMonitoring ? "#22c55e" : "var(--text-secondary)",
              boxShadow: isMonitoring ? "0 0 8px #22c55e" : "none",
              animation: isMonitoring ? "xdr-pulse 1.4s ease-in-out infinite" : "none",
            }}
          />
          <span
            style={{
              fontSize: 10,
              fontWeight: 700,
              color: isMonitoring ? "#22c55e" : "var(--text-secondary)",
              letterSpacing: 1,
              textTransform: "uppercase",
            }}
          >
            {isMonitoring ? "Listening" : "Idle"}
          </span>
        </div>
      </div>

      {/* Agent status bar */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 20,
          background: "var(--bg-card)",
          border: `1px solid ${sysmonHealth?.running ? "#22c55e33" : "var(--text-muted)"}`,
          borderLeft: `4px solid ${sysmonHealth?.running ? "#22c55e" : "var(--text-secondary)"}`,
          borderRadius: 12,
          padding: "10px 18px",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span
            style={{
              display: "inline-block",
              width: 8,
              height: 8,
              borderRadius: "50%",
              background: sysmonHealth?.running ? "#22c55e" : "var(--text-secondary)",
              boxShadow: sysmonHealth?.running ? "0 0 8px #22c55e" : "none",
              animation: sysmonHealth?.running ? "xdr-pulse 1.4s ease-in-out infinite" : "none",
              flexShrink: 0,
            }}
          />
          <span
            style={{
              fontSize: 11,
              fontWeight: 700,
              color: sysmonHealth?.running ? "#22c55e" : "var(--text-secondary)",
              letterSpacing: 0.8,
              textTransform: "uppercase",
            }}
          >
            {sysmonHealth?.running ? "Monitoring Active" : "Agent not running"}
          </span>
        </div>
        {sysmonHealth && (
          <>
            <span style={{ color: "var(--text-muted)", fontSize: 11 }}>|</span>
            <span style={{ fontSize: 11, color: "var(--text-secondary)" }}>
              Events processed:{" "}
              <span style={{ color: "#15803d", fontWeight: 700, fontFamily: "monospace" }}>
                {sysmonHealth.total_events.toLocaleString()}
              </span>
            </span>
            <span style={{ color: "var(--text-muted)", fontSize: 11 }}>|</span>
            <span style={{ fontSize: 11, color: "var(--text-secondary)" }}>
              Alerts fired:{" "}
              <span
                style={{
                  color: sysmonHealth.total_alerts > 0 ? "#f87171" : "#15803d",
                  fontWeight: 700,
                  fontFamily: "monospace",
                }}
              >
                {sysmonHealth.total_alerts}
              </span>
            </span>
          </>
        )}
      </div>

      {/* Sysmon Process Events filter bar */}
      <div
        style={{
          background: "var(--bg-card)",
          border: "1px solid var(--border-color)",
          borderRadius: 12,
          padding: "12px 16px",
          display: "flex",
          flexDirection: "column",
          gap: 10,
        }}
      >
        <div style={{ fontSize: 10, fontWeight: 700, color: "var(--accent-amber)", letterSpacing: 1, textTransform: "uppercase", marginBottom: 2 }}>
          Process Events Filters
        </div>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
          {/* Search */}
          <div style={{ flex: "1 1 220px", position: "relative" }}>
            <span style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)", color: "var(--text-muted)", fontSize: 12, pointerEvents: "none" }}>&#128269;</span>
            <input
              type="text"
              placeholder="Search process name, event type..."
              value={sysmonSearch}
              onChange={(e) => setSysmonSearch(e.target.value)}
              style={{ width: "100%", padding: "6px 10px 6px 30px", borderRadius: 8, border: "1px solid var(--border-color)", background: "var(--bg-primary)", color: "var(--text-primary)", fontSize: 12, outline: "none", boxSizing: "border-box" }}
            />
          </div>
          {/* Risk filter */}
          <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
            <span style={{ color: "var(--text-muted)", fontSize: 10, fontWeight: 700, letterSpacing: 1, whiteSpace: "nowrap" }}>RISK:</span>
            {(["ALL", "HIGH RISK", "NORMAL"] as const).map((r) => (
              <Pill key={r} label={r} active={sysmonRiskFilter === r} accent={r === "HIGH RISK" ? "#ef4444" : r === "NORMAL" ? "#22c55e" : "#3b82f6"} onClick={() => setSysmonRiskFilter(r)} />
            ))}
          </div>
          {/* Time range */}
          <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
            <span style={{ color: "var(--text-muted)", fontSize: 10, fontWeight: 700, letterSpacing: 1, whiteSpace: "nowrap" }}>TIME:</span>
            {(["1h", "6h", "24h", "all"] as TimeRange[]).map((r) => (
              <Pill key={r} label={r === "all" ? "All" : `Last ${r}`} active={sysmonTimeRange === r} accent="#3b82f6" onClick={() => setSysmonTimeRange(r)} />
            ))}
          </div>
          <span style={{ marginLeft: "auto", color: "var(--text-muted)", fontSize: 11, whiteSpace: "nowrap" }}>
            Showing <span style={{ color: "var(--text-secondary)", fontWeight: 700 }}>{filteredSysmonLogs.length}</span> of <span style={{ color: "var(--text-secondary)", fontWeight: 700 }}>{sysmonLogs.length}</span>
          </span>
          {(sysmonSearch || sysmonTimeRange !== "all" || sysmonRiskFilter !== "ALL") && (
            <button onClick={clearSysmonFilters} style={{ padding: "3px 10px", borderRadius: 8, border: "1px solid var(--border-color)", background: "transparent", color: "var(--text-secondary)", fontSize: 10, cursor: "pointer", fontWeight: 700 }}>Clear</button>
          )}
        </div>
      </div>

      {/* Live Sysmon Process Events — ALL events, not just anomalies */}
      <div style={{ ...panel, overflow: "hidden" }}>
        <div
          style={{
            padding: "12px 20px",
            borderBottom: "1px solid var(--border-color)",
            display: "flex",
            alignItems: "center",
            gap: 10,
          }}
        >
          <span style={{ fontSize: 12, fontWeight: 700, color: "var(--text-muted)", letterSpacing: 0.5 }}>
            LIVE PROCESS EVENTS
          </span>
          <span
            style={{
              background: "var(--bg-secondary)",
              color: "var(--text-secondary)",
              borderRadius: 20,
              padding: "2px 10px",
              fontSize: 10,
              fontWeight: 700,
            }}
          >
            {filteredSysmonLogs.length} shown
          </span>
          <span style={{ color: "var(--text-muted)", fontSize: 10 }}>last 200 · normal + anomalous</span>
        </div>

        {sysmonLogs.length === 0 ? (
          <div
            style={{
              padding: "32px 24px",
              textAlign: "center",
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              gap: 8,
            }}
          >
            <span style={{ fontSize: 28, opacity: 0.3, color: "var(--text-muted)" }}>&#9632;</span>
            <span style={{ color: "var(--text-muted)", fontSize: 13 }}>
              Waiting for Sysmon events
            </span>
            <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
              Ensure Sysmon + Winlogbeat are running and writing to C:\winlogbeat\logs\
            </span>
          </div>
        ) : filteredSysmonLogs.length === 0 ? (
          <div style={{ padding: "24px", textAlign: "center", color: "var(--text-muted)", fontSize: 13 }}>
            No events match current filters.
          </div>
        ) : (
          <div style={{ maxHeight: 320, overflowY: "auto", overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
              <thead>
                <tr style={{ background: "var(--bg-primary)", position: "sticky", top: 0, zIndex: 1 }}>
                  {["Time", "Process", "PID", "Event ID", "Event Name", "Risk", "Command",
                    ...(hasAnySHAP ? ["Indicators"] : [])
                  ].map((col) => (
                    <th
                      key={col}
                      style={{
                        padding: "8px 12px",
                        textAlign: "left",
                        color: col === "Indicators" ? "#f59e0b" : "var(--text-muted)",
                        fontWeight: 700,
                        fontSize: 10,
                        letterSpacing: 0.8,
                        textTransform: "uppercase",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {col}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filteredSysmonLogs.map((log, idx) => {
                  const rowBg = log.high_risk
                    ? "rgba(220,38,38,0.08)"
                    : idx % 2 === 0
                    ? "var(--bg-card)"
                    : "var(--bg-secondary)";
                  const shapData = shapByPid.get(log.pid);
                  return (
                    <tr
                      key={`log-${log.ts}-${log.pid}-${idx}`}
                      style={{ borderBottom: "1px solid var(--border-color)", background: rowBg }}
                    >
                      <td style={{ padding: "7px 12px", color: "var(--text-secondary)", whiteSpace: "nowrap", fontFamily: "monospace", fontSize: 11 }}>
                        {fmtTime(log.ts)}
                      </td>
                      <td style={{ padding: "7px 12px", fontFamily: "monospace", color: log.high_risk ? "#f87171" : "var(--text-secondary)", whiteSpace: "nowrap", fontWeight: log.high_risk ? 700 : 400 }}>
                        {log.process_name}
                      </td>
                      <td style={{ padding: "7px 12px", color: "var(--text-secondary)", fontFamily: "monospace", fontSize: 11 }}>
                        {log.pid}
                      </td>
                      <td style={{ padding: "7px 12px", color: "var(--text-muted)", fontFamily: "monospace", fontSize: 11 }}>
                        {log.event_id}
                      </td>
                      <td style={{ padding: "7px 12px", whiteSpace: "nowrap" }}>
                        <span
                          style={{
                            display: "inline-block",
                            background: "var(--accent-cyan-dim)",
                            color: "var(--accent-cyan)",
                            borderRadius: 4,
                            padding: "1px 7px",
                            fontSize: 10,
                            fontWeight: 600,
                            border: "1px solid var(--border-color-strong)",
                          }}
                        >
                          {log.event_name}
                        </span>
                      </td>
                      <td style={{ padding: "7px 12px", textAlign: "center" }}>
                        {log.high_risk ? (
                          <span
                            style={{
                              display: "inline-block",
                              background: "rgba(220,38,38,0.15)",
                              color: "var(--accent-red)",
                              borderRadius: 4,
                              padding: "1px 7px",
                              fontSize: 9,
                              fontWeight: 700,
                              letterSpacing: 0.5,
                              textTransform: "uppercase",
                            }}
                          >
                            HIGH RISK
                          </span>
                        ) : (
                          <span style={{ color: "#22c55e", fontSize: 10 }}>✓</span>
                        )}
                      </td>
                      <td
                        style={{
                          padding: "7px 12px",
                          color: "var(--text-muted)",
                          fontFamily: "monospace",
                          fontSize: 10,
                          maxWidth: 260,
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                        }}
                        title={log.commandline}
                      >
                        {log.commandline || "—"}
                      </td>
                      {hasAnySHAP && (
                        <td style={{ padding: "7px 12px", maxWidth: 320 }}>
                          {shapData ? (
                            <div style={{ display: "flex", flexWrap: "wrap", gap: 4, alignItems: "center" }}>
                              {/* Reason pills — amber/orange, Sysmon theme */}
                              {shapData.reasons.slice(0, 2).map((reason, i) => (
                                <span
                                  key={`r-${i}`}
                                  title={reason}
                                  style={{
                                    display: "inline-block",
                                    background: "#451a03",
                                    color: "#fb923c",
                                    border: "1px solid #78350f",
                                    borderRadius: 10,
                                    padding: "1px 8px",
                                    fontSize: 10,
                                    fontWeight: 600,
                                    whiteSpace: "nowrap",
                                    maxWidth: 150,
                                    overflow: "hidden",
                                    textOverflow: "ellipsis",
                                  }}
                                >
                                  {reason}
                                </span>
                              ))}
                              {/* MITRE technique chips — dark purple */}
                              {shapData.mitre.slice(0, 2).map((tid, i) => (
                                <span
                                  key={`m-${i}`}
                                  title={`MITRE ATT&CK: ${tid}`}
                                  style={{
                                    display: "inline-block",
                                    background: "#2e1065",
                                    color: "#c4b5fd",
                                    border: "1px solid #4c1d95",
                                    borderRadius: 10,
                                    padding: "1px 7px",
                                    fontSize: 9,
                                    fontWeight: 700,
                                    whiteSpace: "nowrap",
                                    letterSpacing: 0.3,
                                  }}
                                >
                                  {tid}
                                </span>
                              ))}
                              {/* Overflow badge */}
                              {(shapData.reasons.length + shapData.mitre.length) > 4 && (
                                <span
                                  style={{
                                    display: "inline-block",
                                    background: "var(--bg-secondary)",
                                    color: "var(--text-secondary)",
                                    border: "1px solid var(--border-color)",
                                    borderRadius: 10,
                                    padding: "1px 7px",
                                    fontSize: 10,
                                    fontWeight: 600,
                                  }}
                                >
                                  +{(shapData.reasons.length + shapData.mitre.length) - 4} more
                                </span>
                              )}
                            </div>
                          ) : (
                            <span style={{ color: "var(--text-muted)", fontSize: 11 }}>—</span>
                          )}
                        </td>
                      )}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* System Telemetry filter bar */}
      <div
        style={{
          background: "var(--bg-card)",
          border: "1px solid var(--border-color)",
          borderRadius: 12,
          padding: "12px 16px",
          display: "flex",
          flexDirection: "column",
          gap: 10,
        }}
      >
        <div style={{ fontSize: 10, fontWeight: 700, color: "var(--accent-amber)", letterSpacing: 1, textTransform: "uppercase", marginBottom: 2 }}>
          System Telemetry Filters
        </div>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
          {/* Search */}
          <div style={{ flex: "1 1 200px", position: "relative" }}>
            <span style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)", color: "var(--text-muted)", fontSize: 12, pointerEvents: "none" }}>&#128269;</span>
            <input
              type="text"
              placeholder="Search source, severity..."
              value={sysSearch}
              onChange={(e) => setSysSearch(e.target.value)}
              style={{ width: "100%", padding: "6px 10px 6px 30px", borderRadius: 8, border: "1px solid var(--border-color)", background: "var(--bg-primary)", color: "var(--text-primary)", fontSize: 12, outline: "none", boxSizing: "border-box" }}
            />
          </div>
          {/* Severity */}
          <div style={{ display: "flex", gap: 4, alignItems: "center", flexWrap: "wrap" }}>
            <span style={{ color: "var(--text-muted)", fontSize: 10, fontWeight: 700, letterSpacing: 1, whiteSpace: "nowrap" }}>SEV:</span>
            {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => {
              const SCOLOR: Record<string,string> = { CRITICAL:"#dc2626", HIGH:"#ea580c", MEDIUM:"#d97706", LOW:"#22c55e" };
              return <Pill key={s} label={s} active={sysSeverity === s} accent={SCOLOR[s] ?? "#3b82f6"} onClick={() => setSysSeverity(s)} />;
            })}
          </div>
          {/* Status */}
          <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
            <span style={{ color: "var(--text-muted)", fontSize: 10, fontWeight: 700, letterSpacing: 1, whiteSpace: "nowrap" }}>STATUS:</span>
            {(["ALL", "ANOMALOUS", "NORMAL"] as const).map((s) => (
              <Pill key={s} label={s} active={sysStatusFilter === s} accent={s === "ANOMALOUS" ? "#ef4444" : s === "NORMAL" ? "#22c55e" : "#3b82f6"} onClick={() => setSysStatusFilter(s)} />
            ))}
          </div>
          {/* Time range */}
          <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
            <span style={{ color: "var(--text-muted)", fontSize: 10, fontWeight: 700, letterSpacing: 1, whiteSpace: "nowrap" }}>TIME:</span>
            {(["1h", "6h", "24h", "all"] as TimeRange[]).map((r) => (
              <Pill key={r} label={r === "all" ? "All" : `Last ${r}`} active={sysTimeRange === r} accent="#3b82f6" onClick={() => setSysTimeRange(r)} />
            ))}
          </div>
          <span style={{ marginLeft: "auto", color: "var(--text-muted)", fontSize: 11, whiteSpace: "nowrap" }}>
            Showing <span style={{ color: "var(--text-secondary)", fontWeight: 700 }}>{filteredSystemAnomalies.length}</span> of <span style={{ color: "var(--text-secondary)", fontWeight: 700 }}>{systemAnomalies.length}</span>
          </span>
          {(sysSearch || sysSeverity !== "ALL" || sysStatusFilter !== "ALL" || sysTimeRange !== "all") && (
            <button onClick={clearSysFilters} style={{ padding: "3px 10px", borderRadius: 8, border: "1px solid var(--border-color)", background: "transparent", color: "var(--text-secondary)", fontSize: 10, cursor: "pointer", fontWeight: 700 }}>Clear</button>
          )}
        </div>
      </div>

      {/* System Telemetry Logs */}
      <div style={{ ...panel, padding: 20 }}>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            marginBottom: 16,
            flexWrap: "wrap",
            gap: 8,
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ fontSize: 12, fontWeight: 700, color: "var(--text-muted)", letterSpacing: 0.5 }}>
              SYSTEM TELEMETRY LOGS
            </span>
            {/* Model status indicator */}
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 5,
                background: "var(--bg-secondary)",
                border: `1px solid ${behavioralDetectorLoaded ? "#0d948840" : "#d9780640"}`,
                borderRadius: 12,
                padding: "2px 9px",
              }}
            >
              <span
                style={{
                  display: "inline-block",
                  width: 6,
                  height: 6,
                  borderRadius: "50%",
                  flexShrink: 0,
                  background: behavioralDetectorLoaded ? "#2dd4bf" : "#f59e0b",
                  boxShadow: behavioralDetectorLoaded ? "0 0 6px #2dd4bf" : "0 0 6px #f59e0b",
                }}
              />
              <span
                style={{
                  fontSize: 10,
                  fontWeight: 700,
                  color: behavioralDetectorLoaded ? "#2dd4bf" : "#f59e0b",
                  letterSpacing: 0.5,
                  whiteSpace: "nowrap",
                }}
              >
                {behavioralDetectorLoaded ? "LSTM + Behavioral" : "LSTM only"}
              </span>
            </div>
          </div>
          <span
            style={{
              background: "var(--bg-secondary)",
              color: "var(--text-secondary)",
              borderRadius: 20,
              padding: "2px 10px",
              fontSize: 10,
              fontWeight: 700,
            }}
          >
            {filteredSystemAnomalies.length} shown
          </span>
        </div>

        {systemAnomalies.length === 0 ? (
          <div style={{ color: "var(--text-secondary)", fontSize: 13, padding: "12px 0" }}>
            No system telemetry collected yet — monitoring will populate this log automatically.
          </div>
        ) : filteredSystemAnomalies.length === 0 ? (
          <div style={{ color: "var(--text-secondary)", fontSize: 13, padding: "12px 0" }}>
            No entries match current filters.
          </div>
        ) : (
          <div style={{ maxHeight: 320, overflowY: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
              <thead>
                <tr style={{ background: "var(--bg-primary)", position: "sticky", top: 0, zIndex: 1 }}>
                  {(["Time", "Status", "Severity", "Score", "CPU %", "Mem %", "Source"] as string[])
                    .concat(userRole !== "viewer" ? ["SHAP Reasons"] : ["Detection Reason"])
                    .map((col) => (
                    <th
                      key={col}
                      style={{
                        padding: "8px 12px",
                        textAlign: "left",
                        color: "var(--text-muted)",
                        fontWeight: 700,
                        fontSize: 10,
                        letterSpacing: 0.8,
                        textTransform: "uppercase",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {col}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filteredSystemAnomalies.map((entry, idx) => {
                  const isAnomalous = entry.is_genuinely_anomalous === true
                    || entry.severity === "HIGH"
                    || entry.severity === "CRITICAL";
                  const hasBehavioral = entry.behavioral_is_anomaly === true;
                  const severityColor: Record<string, string> = {
                    LOW: "var(--text-secondary)",
                    MEDIUM: "#d97706",
                    HIGH: "#ea580c",
                    CRITICAL: "#dc2626",
                  };
                  const sevColor = severityColor[entry.severity ?? ""] ?? "var(--text-secondary)";

                  const statusBadgeStyle: React.CSSProperties = {
                    display: "inline-block",
                    padding: "2px 8px",
                    borderRadius: 10,
                    fontSize: 10,
                    fontWeight: 700,
                    letterSpacing: 0.5,
                    background: isAnomalous ? "rgba(220,38,38,0.12)" : "rgba(34,197,94,0.08)",
                    color: isAnomalous ? "var(--accent-red)" : "var(--accent-green)",
                    border: `1px solid ${isAnomalous ? "rgba(220,38,38,0.35)" : "rgba(34,197,94,0.25)"}`,
                  };

                  const severityBadgeStyle: React.CSSProperties = {
                    display: "inline-block",
                    padding: "2px 8px",
                    borderRadius: 10,
                    fontSize: 10,
                    fontWeight: 700,
                    letterSpacing: 0.5,
                    background: "var(--bg-secondary)",
                    color: sevColor,
                    border: `1px solid ${sevColor}44`,
                  };

                  // Behavioral badge — cyan/teal, shown only when behavioral detector fired
                  const behavioralBadgeStyle: React.CSSProperties = {
                    display: "inline-block",
                    padding: "2px 7px",
                    borderRadius: 10,
                    fontSize: 9,
                    fontWeight: 700,
                    letterSpacing: 0.6,
                    background: "rgba(45,212,191,0.12)",
                    color: "#2dd4bf",
                    border: "1px solid rgba(13,148,136,0.45)",
                    fontFamily: "monospace",
                    whiteSpace: "nowrap",
                  };

                  return (
                    <tr
                      key={idx}
                      style={{
                        background: isAnomalous ? "rgba(220,38,38,0.07)" : idx % 2 === 0 ? "var(--bg-card)" : "var(--bg-secondary)",
                        borderBottom: "1px solid var(--border-color)",
                      }}
                    >
                      <td style={{ padding: "7px 12px", fontSize: 11, color: "var(--text-secondary)", whiteSpace: "nowrap", fontFamily: "monospace" }}>
                        {entry.ts ? new Date(entry.ts).toLocaleTimeString() : "—"}
                      </td>
                      <td style={{ padding: "7px 12px" }}>
                        <span style={statusBadgeStyle}>
                          {isAnomalous ? "ANOMALOUS" : "NORMAL"}
                        </span>
                      </td>
                      <td style={{ padding: "7px 12px" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 5, flexWrap: "wrap" }}>
                          {entry.severity ? (
                            <span style={severityBadgeStyle}>{entry.severity}</span>
                          ) : (
                            <span style={{ color: "var(--text-muted)", fontSize: 12 }}>—</span>
                          )}
                          {hasBehavioral && (
                            <span
                              style={behavioralBadgeStyle}
                              title={
                                entry.behavioral_attack_type
                                  ? `Behavioral: ${entry.behavioral_attack_type} — confidence ${entry.behavioral_confidence != null ? Math.round(entry.behavioral_confidence) + "%" : "n/a"}`
                                  : "Behavioral detector flagged this event"
                              }
                            >
                              BEHAVIORAL
                            </span>
                          )}
                        </div>
                        {hasBehavioral && entry.behavioral_attack_type && (
                          <div style={{ marginTop: 3, display: "flex", alignItems: "center", gap: 5 }}>
                            <span
                              style={{
                                fontFamily: "monospace",
                                fontSize: 10,
                                color: "#5eead4",
                                maxWidth: 160,
                                overflow: "hidden",
                                textOverflow: "ellipsis",
                                whiteSpace: "nowrap",
                                display: "inline-block",
                              }}
                              title={entry.behavioral_attack_type}
                            >
                              {entry.behavioral_attack_type}
                            </span>
                            {entry.behavioral_score != null && (
                              <span
                                style={{
                                  fontFamily: "monospace",
                                  fontSize: 10,
                                  color: "var(--text-secondary)",
                                  whiteSpace: "nowrap",
                                }}
                              >
                                {Math.round(entry.behavioral_score * 100)}%
                              </span>
                            )}
                          </div>
                        )}
                      </td>
                      <td style={{ padding: "7px 12px", fontSize: 12, color: isAnomalous ? "var(--accent-red)" : "var(--accent-green)", fontWeight: 700, fontFamily: "monospace" }}>
                        {(entry.anomaly_score * 100).toFixed(1)}%
                      </td>
                      <td style={{ padding: "7px 12px", fontSize: 11, color: "var(--text-secondary)", fontFamily: "monospace" }}>
                        {entry.features_snapshot?.[0] != null
                          ? entry.features_snapshot[0].toFixed(1) + "%"
                          : "—"}
                      </td>
                      <td style={{ padding: "7px 12px", fontSize: 11, color: "var(--text-secondary)", fontFamily: "monospace" }}>
                        {entry.features_snapshot?.[1] != null
                          ? entry.features_snapshot[1].toFixed(1) + "%"
                          : "—"}
                      </td>
                      <td style={{ padding: "7px 12px", fontSize: 11, color: "var(--text-secondary)" }}>
                        {entry.source ?? "—"}
                      </td>
                      <td style={{ padding: "7px 12px", maxWidth: 300 }}>
                        {userRole === "viewer" ? (
                          /* Viewer: plain human-readable text only — no raw SHAP feature names */
                          <span style={{ color: "var(--text-secondary)", fontSize: 12, fontStyle: "italic" }}>
                            {isAnomalous
                              ? "Elevated system resource anomaly detected."
                              : "Normal system behavior."}
                          </span>
                        ) : (
                          (() => {
                            const reasons: string[] = entry.shap_reasons ?? entry.shap_explanation ?? [];
                            if (!Array.isArray(reasons) || reasons.length === 0) {
                              return <span style={{ color: "var(--text-muted)", fontSize: 11 }}>—</span>;
                            }
                            const MAX_PILLS = 4;
                            const visible = reasons.slice(0, MAX_PILLS);
                            const overflow = reasons.length - MAX_PILLS;
                            return (
                              <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                                {visible.map((r: string, i: number) => {
                                  const isBehavioral = r.startsWith("Behavioral:");
                                  return (
                                    <span
                                      key={i}
                                      title={r}
                                      style={{
                                        display: "inline-block",
                                        background: isBehavioral ? "rgba(45,212,191,0.12)" : "rgba(167,139,250,0.12)",
                                        color: isBehavioral ? "#2dd4bf" : "#a78bfa",
                                        border: `1px solid ${isBehavioral ? "rgba(13,148,136,0.4)" : "rgba(76,29,149,0.4)"}`,
                                        borderRadius: 10,
                                        padding: "1px 8px",
                                        fontSize: 10,
                                        fontWeight: 600,
                                        whiteSpace: "nowrap",
                                        maxWidth: 160,
                                        overflow: "hidden",
                                        textOverflow: "ellipsis",
                                      }}
                                    >
                                      {r}
                                    </span>
                                  );
                                })}
                                {overflow > 0 && (
                                  <span
                                    style={{
                                      display: "inline-block",
                                      background: "var(--bg-secondary)",
                                      color: "var(--text-secondary)",
                                      border: "1px solid var(--border-color)",
                                      borderRadius: 10,
                                      padding: "1px 7px",
                                      fontSize: 10,
                                      fontWeight: 600,
                                    }}
                                  >
                                    +{overflow} more
                                  </span>
                                )}
                              </div>
                            );
                          })()
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

    </div>
  );
}
