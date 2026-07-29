import React, { useMemo, useState, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import SeverityBadge from "../shared/SeverityBadge";
import { FlowResult, UserAnomalyRow, MalwareAlert, SocAlert, SEVERITY_COLOUR, ATTACK_COLOURS, fmtTime } from "../shared/types";
import ResponseModal from "../ResponseModal";
import { ResponsePlan } from "../shared/responseTypes";

// ── Time-range helper ─────────────────────────────────────────────────────────
type TimeRange = "1h" | "6h" | "24h" | "all";

function withinRange(ts: string | undefined, range: TimeRange): boolean {
  if (range === "all" || !ts) return true;
  try {
    const iso = ts.replace(" ", "T").replace(/(\.\d{3})\d+$/, "$1");
    const t = new Date(iso).getTime();
    if (isNaN(t)) return true;
    const now = Date.now();
    const hoursMs: Record<TimeRange, number> = { "1h": 3_600_000, "6h": 21_600_000, "24h": 86_400_000, "all": 0 };
    return now - t <= hoursMs[range];
  } catch {
    return true;
  }
}

// ── Neon pill button ─────────────────────────────────────────────────────────
function Pill({
  label,
  active,
  accent,
  onClick,
}: {
  label: string;
  active: boolean;
  accent: string;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      style={{
        padding: "4px 12px",
        borderRadius: 20,
        border: active ? `1px solid ${accent}` : "1px solid var(--border-color)",
        cursor: "pointer",
        background: active ? `${accent}1a` : "var(--bg-secondary)",
        color: active ? accent : "var(--text-muted)",
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

function alertToFlowResult(a: Alert): FlowResult {
  return {
    timestamp: a.time,
    src_ip: a.srcIp ?? "server_host",
    dest_ip: a.dstIp ?? "",
    prediction: "ATTACK",
    confidence: a.confidence ?? 0,
    severity: a.severity as FlowResult["severity"],
    traffic_label: a.attackType ?? a.description,
    traffic_description: a.detail ?? "",
    attack_type: a.attackType ?? "Network Attack",
  } as FlowResult;
}

function socAlertToFlowResult(sa: SocAlert): FlowResult {
  const attackType = sa.attack_type || sa.correlation?.attack_type || "Unknown";
  const sev = (sa.final_severity ?? "HIGH") as FlowResult["severity"];
  const conf = Math.round((sa.confidence ?? sa.correlation?.confidence ?? 0) * 100);
  const sevColor = SEVERITY_COLOUR[sa.final_severity] ?? "#ef4444";
  return {
    cycle: 0,
    timestamp: sa.timestamp ?? "",
    src_ip: "server_host",
    dest_ip: sa.host || "local",
    src_port: 0,
    dest_port: 0,
    protocol: "—",
    bytes_sent: 0,
    bytes_received: 0,
    packets_sent: 0,
    packets_received: 0,
    flow_duration: 0,
    flow_bytes_per_s: 0,
    prediction: "ATTACK",
    attack_type: attackType,
    confidence: conf,
    severity: sev,
    color: ATTACK_COLOURS[attackType] ?? sevColor,
    icon: "🚨",
    description: sa.correlation?.attack_type || "Correlated attack",
    top3: [],
    traffic_label: attackType,
    traffic_icon: "🚨",
    traffic_description: `${sa.correlation?.mitre_tactic || ""} ${attackType}`.trim(),
    traffic_category: "ATTACK",
  };
}

interface Alert {
  id: string;
  time: string;
  source: "Network" | "User";
  severity: string;
  description: string;
  detail?: string;
  attackType?: string;
  user?: string;
  srcIp?: string;
  dstIp?: string;
  confidence?: number;
}

interface AlertsViewProps {
  flows: FlowResult[];
  userAnomalies: UserAnomalyRow[];
  malwareAlerts?: MalwareAlert[];
  socAlerts?: SocAlert[];
  responsePlans?: ResponsePlan[];
  /** Current user role — hides Respond column for viewers */
  userRole?: string;
}

export default function AlertsView({ flows, userAnomalies, malwareAlerts, socAlerts = [], responsePlans = [], userRole }: AlertsViewProps) {
  const [sourceFilter, setSourceFilter] = useState<"ALL" | "Network" | "User">("ALL");
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");

  // Extended filter state
  const [searchQuery, setSearchQuery] = useState("");
  const [attackTypeFilter, setAttackTypeFilter] = useState<string>("ALL");
  const [timeRange, setTimeRange] = useState<TimeRange>("all");

  // Response modal state
  const [responseModal, setResponseModal] = useState<{
    alert: FlowResult | null;
    plan: ResponsePlan | null;
  } | null>(null);

  const clearAllFilters = useCallback(() => {
    setSearchQuery("");
    setSourceFilter("ALL");
    setSeverityFilter("ALL");
    setAttackTypeFilter("ALL");
    setTimeRange("all");
  }, []);

  const allAlerts: Alert[] = useMemo(() => {
    const netAlerts: Alert[] = flows
      .filter((f) => f.prediction === "ATTACK")
      .map((f, i) => ({
        id: `net-${f.timestamp}-${f.src_ip}-${i}`,
        time: fmtTime(f.timestamp),
        source: "Network" as const,
        severity: f.severity,
        description: `${f.traffic_label} detected`,
        detail: f.traffic_description,
        attackType: f.attack_type,
        srcIp: f.src_ip,
        dstIp: f.dest_ip,
        confidence: f.confidence,
      }));

    const userAlerts: Alert[] = userAnomalies
      .filter((u) => u.prediction_label === "ANOMALY")
      .map((u, i) => ({
        id: `usr-${u.ts ?? i}-${u.user}`,
        time: u.ts ? fmtTime(u.ts) : "—",
        source: "User" as const,
        severity: u.fusion?.severity ?? "HIGH",
        description: `Anomalous behavior detected`,
        detail: [
          u.after_hours_logins ? `${u.after_hours_logins} after-hours logins` : null,
          u.usb_connects ? `${u.usb_connects} USB events` : null,
          u.files_accessed ? `${u.files_accessed} files accessed` : null,
        ]
          .filter(Boolean)
          .join(", ") || "Unusual user activity pattern",
        user: u.user,
        confidence: u.anomaly_score != null ? u.anomaly_score * 100 : undefined,
      }));

    return [...netAlerts, ...userAlerts];
  }, [flows, userAnomalies]);

  // Unique attack types from network alerts for dropdown
  const uniqueAttackTypes = useMemo(
    () => Array.from(new Set(allAlerts.map((a) => a.attackType).filter(Boolean) as string[])),
    [allAlerts]
  );

  const filteredAlerts = useMemo(() => {
    const q = searchQuery.toLowerCase().trim();
    return allAlerts.filter((a) => {
      if (sourceFilter !== "ALL" && a.source !== sourceFilter) return false;
      if (severityFilter !== "ALL" && a.severity !== severityFilter) return false;
      if (attackTypeFilter !== "ALL" && a.attackType !== attackTypeFilter) return false;
      if (!withinRange(undefined, timeRange)) return false; // time filter applied below on raw ts
      if (q) {
        const searchable = [a.srcIp, a.dstIp, a.attackType, a.user, a.description, a.detail]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        if (!searchable.includes(q)) return false;
      }
      return true;
    });
  }, [allAlerts, sourceFilter, severityFilter, attackTypeFilter, timeRange, searchQuery]);

  const counts = {
    Network: allAlerts.filter((a) => a.source === "Network").length,
    User: allAlerts.filter((a) => a.source === "User").length,
  };

  const severityCounts = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].reduce(
    (acc, s) => ({ ...acc, [s]: allAlerts.filter((a) => a.severity === s).length }),
    {} as Record<string, number>
  );

  const panel: React.CSSProperties = {
    background: "var(--bg-card, #1e293b)",
    border: "1px solid var(--border-color, rgba(255,255,255,0.08))",
    borderRadius: 14,
  };

  return (
    <div style={{ padding: 24, display: "flex", flexDirection: "column", gap: 18 }}>
      {/* Header */}
      <div>
        <h2 style={{ margin: 0, fontSize: 20, fontWeight: 800, color: "var(--text-heading)", letterSpacing: -0.5 }}>
          Alerts & Incidents
        </h2>
        <p style={{ margin: "4px 0 0", color: "var(--text-secondary)", fontSize: 13 }}>
          Combined alert stream from network detection and user behavior analysis
        </p>
      </div>

      {/* Summary row */}
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
        {[
          { label: "Total Alerts", value: allAlerts.length, accent: "#3b82f6" },
          { label: "Network", value: counts.Network, accent: "#60a5fa" },
          { label: "User Behavior", value: counts.User, accent: "#a78bfa" },
          { label: "Critical", value: severityCounts.CRITICAL ?? 0, accent: "#dc2626" },
          { label: "High", value: severityCounts.HIGH ?? 0, accent: "#ea580c" },
          { label: "Medium", value: severityCounts.MEDIUM ?? 0, accent: "#d97706" },
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
              minWidth: 90,
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

      {/* Filter bar */}
      <div
        style={{
          background: "var(--bg-card, #1e293b)",
          border: "1px solid var(--border-color, rgba(255,255,255,0.08))",
          borderRadius: 12,
          padding: "14px 18px",
          display: "flex",
          flexDirection: "column",
          gap: 12,
        }}
      >
        {/* Row 1: Search + attack type + time range */}
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
          {/* Search */}
          <div style={{ flex: "1 1 220px", position: "relative" }}>
            <span
              style={{
                position: "absolute",
                left: 10,
                top: "50%",
                transform: "translateY(-50%)",
                color: "var(--text-muted)",
                fontSize: 12,
                pointerEvents: "none",
              }}
            >
              &#128269;
            </span>
            <input
              type="text"
              placeholder="Search IP, attack type, user..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                width: "100%",
                padding: "6px 10px 6px 30px",
                borderRadius: 8,
                border: "1px solid var(--border-color)",
                background: "var(--bg-primary)",
                color: "var(--text-primary)",
                fontSize: 12,
                outline: "none",
                boxSizing: "border-box",
              }}
            />
          </div>

          {/* Attack type dropdown */}
          <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
            <span style={{ color: "var(--text-muted)", fontSize: 10, fontWeight: 700, letterSpacing: 1, whiteSpace: "nowrap" }}>
              ATTACK:
            </span>
            <select
              value={attackTypeFilter}
              onChange={(e) => setAttackTypeFilter(e.target.value)}
              style={{
                padding: "5px 10px",
                borderRadius: 8,
                border: attackTypeFilter !== "ALL" ? "1px solid #f59e0b" : "1px solid var(--border-color)",
                background: "var(--bg-primary)",
                color: attackTypeFilter !== "ALL" ? "var(--accent-amber)" : "var(--text-muted)",
                fontSize: 11,
                outline: "none",
                cursor: "pointer",
                fontWeight: attackTypeFilter !== "ALL" ? 700 : 400,
              }}
            >
              <option value="ALL">All Types</option>
              {uniqueAttackTypes.map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>

          {/* Time range */}
          <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
            <span style={{ color: "var(--text-muted)", fontSize: 10, fontWeight: 700, letterSpacing: 1, whiteSpace: "nowrap" }}>
              TIME:
            </span>
            {(["1h", "6h", "24h", "all"] as TimeRange[]).map((r) => (
              <Pill
                key={r}
                label={r === "all" ? "All" : `Last ${r}`}
                active={timeRange === r}
                accent="#3b82f6"
                onClick={() => setTimeRange(r)}
              />
            ))}
          </div>
        </div>

        {/* Row 2: Source + Severity + result count */}
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
          <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
            <span style={{ color: "var(--text-muted)", fontSize: 10, fontWeight: 700, letterSpacing: 1 }}>SOURCE:</span>
            {(["ALL", "Network", "User"] as const).map((s) => (
              <Pill
                key={s}
                label={s}
                active={sourceFilter === s}
                accent="#3b82f6"
                onClick={() => setSourceFilter(s)}
              />
            ))}
          </div>

          <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
            <span style={{ color: "var(--text-muted)", fontSize: 10, fontWeight: 700, letterSpacing: 1 }}>SEVERITY:</span>
            {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => (
              <Pill
                key={s}
                label={s}
                active={severityFilter === s}
                accent={SEVERITY_COLOUR[s] ?? "#3b82f6"}
                onClick={() => setSeverityFilter(s)}
              />
            ))}
          </div>

          <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ color: "var(--text-muted)", fontSize: 11 }}>
              Showing{" "}
              <span style={{ color: "var(--text-secondary)", fontWeight: 700 }}>{filteredAlerts.length}</span>
              {" of "}
              <span style={{ color: "var(--text-secondary)", fontWeight: 700 }}>{allAlerts.length}</span>
              {" alerts"}
            </span>
            {(searchQuery || sourceFilter !== "ALL" || severityFilter !== "ALL" || attackTypeFilter !== "ALL" || timeRange !== "all") && (
              <button
                onClick={clearAllFilters}
                style={{
                  padding: "3px 10px",
                  borderRadius: 8,
                  border: "1px solid var(--border-color)",
                  background: "transparent",
                  color: "var(--text-secondary)",
                  fontSize: 10,
                  cursor: "pointer",
                  fontWeight: 700,
                }}
              >
                Clear filters
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Correlated Attacks section */}
      <div style={{ ...panel, overflow: "hidden" }}>
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
            CORRELATED ATTACKS
          </span>
          <span
            style={{
              background: socAlerts.length > 0 ? "#1c3a1c" : "var(--bg-card)",
              color: socAlerts.length > 0 ? "#4ade80" : "var(--text-secondary)",
              borderRadius: 10,
              padding: "1px 8px",
              fontSize: 10,
              fontWeight: 700,
            }}
          >
            {socAlerts.length}
          </span>
        </div>

        {socAlerts.length === 0 ? (
          <div style={{ padding: "32px 20px", textAlign: "center", color: "var(--text-muted)", fontSize: 13 }}>
            No correlated attacks detected — system monitoring all domains
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ background: "var(--bg-secondary)" }}>
                  {(["Severity", "MITRE", "Attack Chain", "Sources", "Confidence"] as string[])
                    .concat(userRole !== "viewer" ? ["Response"] : [])
                    .concat(["Time"])
                    .map((col) => (
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
                {socAlerts.map((alert, idx) => {
                  const sevColor = SEVERITY_COLOUR[alert.final_severity] ?? "#6b7280";
                  const confPct = Math.round((alert.correlation?.confidence ?? alert.confidence) * 100);
                  const suggestions = alert.correlation?.response_suggestions ?? [];
                  return (
                    <tr
                      key={`soc-${alert.timestamp}-${idx}`}
                      style={{
                        borderBottom: "1px solid #0a1120",
                        background:
                          alert.final_severity === "CRITICAL"
                            ? "#dc262608"
                            : alert.final_severity === "HIGH"
                            ? "#ea580c08"
                            : idx % 2 === 0
                            ? "var(--bg-card)"
                            : "var(--bg-card)",
                      }}
                    >
                      {/* Severity */}
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
                          {alert.final_severity}
                        </span>
                      </td>

                      {/* MITRE ID */}
                      <td style={{ padding: "10px 14px", whiteSpace: "nowrap" }}>
                        <span
                          style={{
                            display: "inline-block",
                            background: "#431407",
                            color: "#fb923c",
                            border: "1px solid #7c2d1244",
                            borderRadius: 6,
                            padding: "3px 9px",
                            fontSize: 10,
                            fontWeight: 700,
                            letterSpacing: 0.5,
                            fontFamily: "monospace",
                          }}
                        >
                          {alert.mitre_id || alert.correlation?.mitre_id || "—"}
                        </span>
                      </td>

                      {/* Attack Chain */}
                      <td style={{ padding: "10px 14px", maxWidth: 220 }}>
                        <div style={{ fontSize: 12, color: "var(--text-primary)", fontWeight: 600 }}>
                          {alert.attack_type || alert.correlation?.attack_type || "—"}
                        </div>
                        {alert.correlation?.mitre_tactic && (
                          <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 2 }}>
                            {alert.correlation.mitre_tactic}
                          </div>
                        )}
                        {alert.correlation?.attack_chain && (
                          <span
                            style={{
                              display: "inline-block",
                              background: "#1a1040",
                              color: "#818cf8",
                              borderRadius: 4,
                              padding: "1px 6px",
                              fontSize: 9,
                              fontWeight: 700,
                              marginTop: 3,
                              letterSpacing: 0.5,
                            }}
                          >
                            CHAIN
                          </span>
                        )}
                      </td>

                      {/* Sources */}
                      <td style={{ padding: "10px 14px" }}>
                        <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                          {(alert.involved_sources ?? alert.correlation?.involved_sources ?? []).map((src) => (
                            <span
                              key={src}
                              style={{
                                background: "var(--bg-card)",
                                color: "var(--text-secondary)",
                                border: "1px solid var(--border-color)",
                                borderRadius: 4,
                                padding: "2px 6px",
                                fontSize: 9,
                                fontWeight: 700,
                                letterSpacing: 0.5,
                                textTransform: "uppercase",
                                whiteSpace: "nowrap",
                              }}
                            >
                              {src}
                            </span>
                          ))}
                        </div>
                      </td>

                      {/* Confidence */}
                      <td style={{ padding: "10px 14px", whiteSpace: "nowrap" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                          <div
                            style={{
                              width: 64,
                              height: 5,
                              background: "var(--bg-secondary)",
                              borderRadius: 3,
                              overflow: "hidden",
                              flexShrink: 0,
                            }}
                          >
                            <div
                              style={{
                                height: "100%",
                                width: `${confPct}%`,
                                background: sevColor,
                                borderRadius: 3,
                              }}
                            />
                          </div>
                          <span
                            style={{
                              fontSize: 11,
                              fontWeight: 700,
                              fontFamily: "monospace",
                              color: sevColor,
                            }}
                          >
                            {confPct}%
                          </span>
                        </div>
                      </td>

                      {/* Response suggestions + Respond button */}
                      <td style={{ padding: "10px 14px", maxWidth: 240 }}>
                        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                          {suggestions.length > 0 && (
                            <div style={{ display: "flex", flexWrap: "wrap", gap: 3 }}>
                              {suggestions.slice(0, 3).map((s, i) => (
                                <span
                                  key={i}
                                  style={{
                                    background: "var(--bg-card)",
                                    color: "var(--text-muted)",
                                    border: "1px solid var(--border-color)",
                                    borderRadius: 4,
                                    padding: "2px 6px",
                                    fontSize: 9,
                                    whiteSpace: "nowrap",
                                  }}
                                >
                                  {s}
                                </span>
                              ))}
                            </div>
                          )}
                          {userRole !== "viewer" && (alert.final_severity === "MEDIUM" || alert.final_severity === "HIGH" || alert.final_severity === "CRITICAL") && (() => {
                            const matchingPlan =
                              responsePlans.find(
                                (p) =>
                                  p.endpoint_id === "server_host" &&
                                  (p.attack_type === alert.attack_type ||
                                    p.attack_type === alert.correlation?.attack_type)
                              ) ??
                              responsePlans.find((p) => p.endpoint_id === "server_host") ??
                              null;
                            return (
                              <button
                                onClick={() =>
                                  setResponseModal({
                                    alert: socAlertToFlowResult(alert),
                                    plan: matchingPlan,
                                  })
                                }
                                style={{
                                  padding: "5px 12px",
                                  borderRadius: 6,
                                  border: "1px solid rgba(220,38,38,0.45)",
                                  background: "rgba(220,38,38,0.1)",
                                  color: "#fca5a5",
                                  fontWeight: 700,
                                  fontSize: 10,
                                  letterSpacing: 0.5,
                                  textTransform: "uppercase",
                                  cursor: "pointer",
                                  transition: "all 0.15s",
                                  whiteSpace: "nowrap",
                                  alignSelf: "flex-start",
                                }}
                                onMouseEnter={(e) => {
                                  (e.currentTarget as HTMLButtonElement).style.background = "rgba(220,38,38,0.22)";
                                  (e.currentTarget as HTMLButtonElement).style.borderColor = "rgba(220,38,38,0.7)";
                                }}
                                onMouseLeave={(e) => {
                                  (e.currentTarget as HTMLButtonElement).style.background = "rgba(220,38,38,0.1)";
                                  (e.currentTarget as HTMLButtonElement).style.borderColor = "rgba(220,38,38,0.45)";
                                }}
                              >
                                Respond
                              </button>
                            );
                          })()}
                          {suggestions.length === 0 && alert.final_severity !== "MEDIUM" && alert.final_severity !== "HIGH" && alert.final_severity !== "CRITICAL" && (
                            <span style={{ color: "var(--text-muted)", fontSize: 11 }}>—</span>
                          )}
                        </div>
                      </td>

                      {/* Time */}
                      <td
                        style={{
                          padding: "10px 14px",
                          fontSize: 11,
                          color: "var(--text-secondary)",
                          whiteSpace: "nowrap",
                          fontFamily: "monospace",
                        }}
                      >
                        {alert.timestamp ? fmtTime(alert.timestamp) : "—"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Malware Detections section */}
      <div style={{ ...panel, overflow: "hidden" }}>
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
            MALWARE DETECTIONS
          </span>
          <span
            style={{
              background: "#7f1d1d33",
              color: "#fca5a5",
              borderRadius: 10,
              padding: "1px 8px",
              fontSize: 10,
              fontWeight: 700,
            }}
          >
            {(malwareAlerts ?? []).filter((a) => !a.trusted && (a.label === "malicious" || a.label === "suspicious" || a.prediction === "MALWARE")).length}
          </span>
        </div>

        {!malwareAlerts || malwareAlerts.length === 0 ? (
          <div style={{ padding: "32px 20px", textAlign: "center", color: "var(--text-muted)", fontSize: 13 }}>
            No malware detections
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ background: "var(--bg-secondary)" }}>
                  {["Timestamp", "File Path", "Score", "Label", "Trusted", "Host", "Fusion Score", "SHAP Reasons"].map((col) => (
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
                {malwareAlerts.map((alert, idx) => {
                  const score = Math.min(100, Math.max(0, alert.score * 100));
                  const scoreColor =
                    score >= 75
                      ? "#ef4444"
                      : score >= 50
                      ? "#f97316"
                      : score >= 25
                      ? "#d97706"
                      : "#22c55e";

                  // Derive display label: prefer new `label` field, fall back to old `prediction`
                  const effectiveLabel = alert.label
                    ?? (alert.prediction === "MALWARE" ? "malicious"
                      : alert.prediction === "BENIGN" ? "benign"
                      : alert.prediction === "SUSPICIOUS" ? "suspicious"
                      : "unknown");

                  const labelBg =
                    effectiveLabel === "malicious"
                      ? "#7f1d1d"
                      : effectiveLabel === "suspicious"
                      ? "#78350f"
                      : effectiveLabel === "benign"
                      ? "#14532d"
                      : "var(--bg-card)";
                  const labelColor =
                    effectiveLabel === "malicious"
                      ? "#fca5a5"
                      : effectiveLabel === "suspicious"
                      ? "#fbbf24"
                      : effectiveLabel === "benign"
                      ? "#86efac"
                      : "var(--text-secondary)";

                  const isTrusted = alert.trusted === true;
                  const fusionScore = alert.fusion?.threat_score;
                  const fusionAttackType = alert.fusion?.attack_type;
                  const truncatedPath =
                    alert.file_path && alert.file_path.length > 40
                      ? "..." + alert.file_path.slice(-37)
                      : alert.file_path;

                  return (
                    <tr
                      key={`malware-${alert.ts}-${alert.file_path}-${idx}`}
                      style={{
                        borderBottom: "1px solid #0a1120",
                        background: idx % 2 === 0 ? "var(--bg-card)" : "var(--bg-card)",
                        opacity: isTrusted ? 0.55 : 1,
                      }}
                    >
                      {/* Timestamp */}
                      <td
                        style={{
                          padding: "10px 14px",
                          fontSize: 11,
                          color: "var(--text-secondary)",
                          whiteSpace: "nowrap",
                          fontFamily: "monospace",
                        }}
                      >
                        {fmtTime(alert.ts)}
                      </td>

                      {/* File Path */}
                      <td
                        style={{
                          padding: "10px 14px",
                          fontSize: 11,
                          color: "var(--text-secondary)",
                          maxWidth: 280,
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                          fontFamily: "monospace",
                        }}
                        title={alert.file_path}
                      >
                        {truncatedPath}
                      </td>

                      {/* Score bar */}
                      <td style={{ padding: "10px 14px", whiteSpace: "nowrap" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                          <div
                            style={{
                              width: 72,
                              height: 5,
                              background: "var(--bg-secondary)",
                              borderRadius: 3,
                              overflow: "hidden",
                              flexShrink: 0,
                            }}
                          >
                            <div
                              style={{
                                height: "100%",
                                width: `${score}%`,
                                background: scoreColor,
                                borderRadius: 3,
                              }}
                            />
                          </div>
                          <span style={{ fontSize: 11, color: scoreColor, fontWeight: 700, fontFamily: "monospace" }}>
                            {score.toFixed(0)}%
                          </span>
                        </div>
                      </td>

                      {/* Label badge */}
                      <td style={{ padding: "10px 14px" }}>
                        <span
                          style={{
                            display: "inline-block",
                            background: labelBg,
                            color: labelColor,
                            borderRadius: 6,
                            padding: "3px 9px",
                            fontSize: 10,
                            fontWeight: 700,
                            letterSpacing: 0.5,
                            textTransform: "uppercase",
                          }}
                        >
                          {effectiveLabel}
                        </span>
                        {fusionAttackType && (
                          <span
                            style={{
                              display: "inline-block",
                              marginLeft: 6,
                              background: "var(--bg-card)",
                              color: "var(--text-secondary)",
                              borderRadius: 4,
                              padding: "2px 6px",
                              fontSize: 9,
                              border: "1px solid var(--border-color)",
                              whiteSpace: "nowrap",
                            }}
                          >
                            {fusionAttackType}
                          </span>
                        )}
                      </td>

                      {/* Trusted */}
                      <td style={{ padding: "10px 14px", whiteSpace: "nowrap" }}>
                        {isTrusted ? (
                          <span
                            style={{
                              display: "inline-flex",
                              alignItems: "center",
                              gap: 4,
                              background: "#1c3a1c",
                              color: "#4ade80",
                              borderRadius: 6,
                              padding: "3px 8px",
                              fontSize: 10,
                              fontWeight: 700,
                              letterSpacing: 0.5,
                            }}
                            title={alert.trust_reason ?? "Trusted source"}
                          >
                            &#128737; Yes
                          </span>
                        ) : (
                          <span style={{ color: "var(--text-secondary)", fontSize: 11 }}>No</span>
                        )}
                      </td>

                      {/* Host */}
                      <td
                        style={{
                          padding: "10px 14px",
                          fontSize: 12,
                          color: "#60a5fa",
                          fontFamily: "monospace",
                          whiteSpace: "nowrap",
                        }}
                      >
                        {alert.host}
                      </td>

                      {/* Fusion Score */}
                      <td style={{ padding: "10px 14px" }}>
                        {fusionScore != null ? (
                          <span
                            style={{
                              fontSize: 12,
                              fontWeight: 700,
                              fontFamily: "monospace",
                              color:
                                fusionScore >= 75
                                  ? "#ef4444"
                                  : fusionScore >= 50
                                  ? "#f97316"
                                  : fusionScore >= 25
                                  ? "#d97706"
                                  : "#22c55e",
                            }}
                          >
                            {fusionScore.toFixed(1)}
                          </span>
                        ) : (
                          <span style={{ color: "var(--text-muted)", fontSize: 11 }}>—</span>
                        )}
                      </td>

                      {/* SHAP Reasons */}
                      <td style={{ padding: "10px 14px", maxWidth: 220 }}>
                        {alert.shap_explanation?.reason?.length ? (
                          <div style={{ display: "flex", flexWrap: "wrap", gap: 3 }}>
                            {alert.shap_explanation.reason.slice(0, 3).map((r, i) => (
                              <span
                                key={i}
                                style={{
                                  background: "#3b1f6e",
                                  color: "#c4b5fd",
                                  borderRadius: 4,
                                  padding: "2px 6px",
                                  fontSize: 9,
                                  whiteSpace: "nowrap",
                                }}
                              >
                                {r}
                              </span>
                            ))}
                          </div>
                        ) : (
                          <span style={{ color: "var(--text-muted)", fontSize: 11 }}>—</span>
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

      {/* Network Anomalies table — with Respond column */}
      {(() => {
        const netAttacks = flows.filter(
          (f) => f.prediction === "ATTACK" && (f.severity === "HIGH" || f.severity === "CRITICAL")
        );
        return netAttacks.length > 0 ? (
          <div style={{ ...panel, overflow: "hidden" }}>
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
                NETWORK ANOMALIES
              </span>
              <span
                style={{
                  background: "#7f1d1d33",
                  color: "#fca5a5",
                  borderRadius: 10,
                  padding: "1px 8px",
                  fontSize: 10,
                  fontWeight: 700,
                }}
              >
                {netAttacks.length}
              </span>
              <span style={{ marginLeft: "auto", fontSize: 10, color: "var(--text-muted)" }}>HIGH / CRITICAL only</span>
            </div>
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ background: "var(--bg-secondary)" }}>
                    {(["Time", "Src IP", "Dst IP", "Attack Type", "Severity", "Confidence"] as string[])
                      .concat(userRole !== "viewer" ? ["Respond"] : [])
                      .map((col) => (
                      <th
                        key={col}
                        style={{
                          padding: "8px 14px",
                          textAlign: col === "Respond" ? "center" : "left",
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
                  {netAttacks.slice(0, 50).map((flow, idx) => {
                    const sevColor = SEVERITY_COLOUR[flow.severity] ?? "#6b7280";
                    // Find a pre-loaded plan for this flow's endpoint if available.
                    // Response plans are generated with endpoint_id = "server_host" (the
                    // protected host), never the attacker's src_ip.  Match by attack_type
                    // first, then fall back to severity so the modal always gets a plan.
                    const matchingPlan =
                      responsePlans.find(
                        (p) =>
                          p.endpoint_id === "server_host" &&
                          p.attack_type === flow.attack_type
                      ) ??
                      responsePlans.find(
                        (p) =>
                          p.endpoint_id === "server_host" &&
                          p.severity === flow.severity
                      ) ??
                      null;
                    return (
                      <tr
                        key={`na-${flow.timestamp}-${flow.src_ip}-${idx}`}
                        style={{
                          borderBottom: "1px solid #0a1120",
                          background:
                            flow.severity === "CRITICAL"
                              ? "#dc262608"
                              : flow.severity === "HIGH"
                              ? "#ea580c08"
                              : idx % 2 === 0
                              ? "var(--bg-card)"
                              : "var(--bg-card)",
                        }}
                      >
                        <td style={{ padding: "10px 14px", fontSize: 11, color: "var(--text-secondary)", whiteSpace: "nowrap", fontFamily: "monospace" }}>
                          {fmtTime(flow.timestamp)}
                        </td>
                        <td style={{ padding: "10px 14px", fontSize: 11, color: "#60a5fa", fontFamily: "monospace", whiteSpace: "nowrap" }}>
                          {flow.src_ip}
                        </td>
                        <td style={{ padding: "10px 14px", fontSize: 11, color: "#818cf8", fontFamily: "monospace", whiteSpace: "nowrap" }}>
                          {flow.dest_ip}
                        </td>
                        <td style={{ padding: "10px 14px", whiteSpace: "nowrap" }}>
                          <span
                            style={{
                              background: "var(--bg-card)",
                              color: "#fbbf24",
                              borderRadius: 5,
                              padding: "2px 8px",
                              fontSize: 10,
                              fontWeight: 700,
                              border: "1px solid #78350f44",
                            }}
                          >
                            {flow.attack_type}
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
                            {flow.severity}
                          </span>
                        </td>
                        <td style={{ padding: "10px 14px", whiteSpace: "nowrap" }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
                            <div
                              style={{
                                width: 60,
                                height: 4,
                                background: "var(--bg-secondary)",
                                borderRadius: 2,
                                overflow: "hidden",
                                flexShrink: 0,
                              }}
                            >
                              <div
                                style={{
                                  height: "100%",
                                  width: `${Math.min(100, flow.confidence)}%`,
                                  background: sevColor,
                                  borderRadius: 2,
                                }}
                              />
                            </div>
                            <span style={{ fontSize: 11, color: sevColor, fontWeight: 700, fontFamily: "monospace" }}>
                              {flow.confidence.toFixed(1)}%
                            </span>
                          </div>
                        </td>
                        {userRole !== "viewer" && (
                          <td style={{ padding: "10px 14px", textAlign: "center" }}>
                            <button
                              onClick={() => setResponseModal({ alert: flow, plan: matchingPlan })}
                              style={{
                                padding: "5px 12px",
                                borderRadius: 6,
                                border: "1px solid rgba(220,38,38,0.45)",
                                background: "rgba(220,38,38,0.1)",
                                color: "#fca5a5",
                                fontWeight: 700,
                                fontSize: 10,
                                letterSpacing: 0.5,
                                textTransform: "uppercase",
                                cursor: "pointer",
                                transition: "all 0.15s",
                                whiteSpace: "nowrap",
                              }}
                              onMouseEnter={(e) => {
                                (e.currentTarget as HTMLButtonElement).style.background = "rgba(220,38,38,0.22)";
                                (e.currentTarget as HTMLButtonElement).style.borderColor = "rgba(220,38,38,0.7)";
                              }}
                              onMouseLeave={(e) => {
                                (e.currentTarget as HTMLButtonElement).style.background = "rgba(220,38,38,0.1)";
                                (e.currentTarget as HTMLButtonElement).style.borderColor = "rgba(220,38,38,0.45)";
                              }}
                            >
                              Respond
                            </button>
                          </td>
                        )}
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        ) : null;
      })()}

      {/* Response Modal */}
      {responseModal && (
        <ResponseModal
          alert={responseModal.alert}
          plan={responseModal.plan}
          onClose={() => setResponseModal(null)}
          onExecuted={(ids) => {
            if (process.env.NODE_ENV === 'development') {
              console.log("[AlertsView] Response executed, command IDs:", ids);
            }
          }}
        />
      )}

      {/* Alert list */}
      <div style={{ ...panel, overflow: "hidden" }}>
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
            ALERT STREAM
          </span>
        </div>

        {filteredAlerts.length === 0 ? (
          <div style={{ padding: 48, textAlign: "center", color: "var(--text-muted)", fontSize: 13 }}>
            {allAlerts.length === 0
              ? "No alerts detected — start monitoring to see live threats."
              : "No alerts match current filters."}
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column" }}>
            <AnimatePresence mode="popLayout" initial={false}>
            {filteredAlerts.map((alert, idx) => {
              const sevColor = SEVERITY_COLOUR[alert.severity] ?? "#6b7280";
              const isHighSev = alert.severity === "CRITICAL" || alert.severity === "HIGH";
              return (
                <motion.div
                  key={alert.id}
                  initial={{ opacity: 0, x: -16 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: 16 }}
                  transition={{ duration: 0.25, ease: "easeOut" }}
                  className={
                    "xdr-table-row" +
                    (alert.severity === "CRITICAL"
                      ? " alert-critical-pulse"
                      : alert.severity === "HIGH"
                      ? " alert-high-pulse"
                      : "")
                  }
                  style={{
                    padding: "14px 20px",
                    borderBottom: "1px solid #0a1120",
                    background:
                      alert.severity === "CRITICAL"
                        ? "#dc262608"
                        : alert.severity === "HIGH"
                        ? "#ea580c08"
                        : idx % 2 === 0
                        ? "var(--bg-card)"
                        : "var(--bg-card)",
                    display: "flex",
                    alignItems: "flex-start",
                    gap: 14,
                  }}
                >
                  {/* Severity indicator line */}
                  <div
                    style={{
                      width: 3,
                      minHeight: 40,
                      borderRadius: 2,
                      background: sevColor,
                      boxShadow: `0 0 6px ${sevColor}44`,
                      flexShrink: 0,
                      alignSelf: "stretch",
                    }}
                  />

                  {/* Source badge */}
                  <div style={{ flexShrink: 0, paddingTop: 2 }}>
                    <span
                      style={{
                        display: "inline-block",
                        background: alert.source === "Network" ? "#1e3a5f" : "#1e1040",
                        color: alert.source === "Network" ? "#60a5fa" : "#a78bfa",
                        borderRadius: 6,
                        padding: "3px 9px",
                        fontSize: 9,
                        fontWeight: 700,
                        letterSpacing: 1,
                        textTransform: "uppercase",
                      }}
                    >
                      {alert.source}
                    </span>
                  </div>

                  {/* Content */}
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                      <SeverityBadge severity={alert.severity} size="sm" />
                      {alert.attackType && alert.attackType !== "BENIGN" && (
                        <span
                          style={{
                            background: "var(--bg-card)",
                            color: "var(--text-secondary)",
                            borderRadius: 4,
                            padding: "1px 7px",
                            fontSize: 10,
                            border: "1px solid var(--border-color)",
                          }}
                        >
                          {alert.attackType}
                        </span>
                      )}
                      <span style={{ color: "var(--text-primary)", fontWeight: 600, fontSize: 13 }}>
                        {alert.description}
                      </span>
                    </div>
                    <div style={{ color: "var(--text-secondary)", fontSize: 12 }}>
                      {alert.user && (
                        <span style={{ color: "#818cf8", fontFamily: "monospace", marginRight: 10 }}>
                          {alert.user}
                        </span>
                      )}
                      {alert.srcIp && (
                        <span style={{ fontFamily: "monospace", color: "#60a5fa", marginRight: 6 }}>
                          {alert.srcIp}
                        </span>
                      )}
                      {alert.dstIp && (
                        <span style={{ color: "var(--text-secondary)", marginRight: 6 }}>
                          → <span style={{ fontFamily: "monospace", color: "#818cf8" }}>{alert.dstIp}</span>
                        </span>
                      )}
                      {alert.detail && <span style={{ color: "var(--text-secondary)" }}>{alert.detail}</span>}
                    </div>
                    {alert.confidence != null && (
                      <div style={{ marginTop: 6, display: "flex", alignItems: "center", gap: 8 }}>
                        <div
                          style={{
                            height: 3,
                            width: 80,
                            background: "var(--bg-secondary)",
                            borderRadius: 2,
                            overflow: "hidden",
                          }}
                        >
                          <div
                            style={{
                              height: "100%",
                              width: `${Math.min(100, alert.confidence)}%`,
                              background: sevColor,
                              borderRadius: 2,
                            }}
                          />
                        </div>
                        <span style={{ color: "var(--text-muted)", fontSize: 10 }}>
                          {alert.confidence.toFixed(1)}% confidence
                        </span>
                      </div>
                    )}
                  </div>

                  {/* Respond button — HIGH/CRITICAL only, hidden for viewers */}
                  {isHighSev && userRole !== "viewer" && (() => {
                    const matchingPlan =
                      responsePlans.find(
                        (p) =>
                          p.endpoint_id === "server_host" &&
                          p.attack_type === alert.attackType
                      ) ??
                      responsePlans.find(
                        (p) =>
                          p.endpoint_id === "server_host" &&
                          p.severity === alert.severity
                      ) ??
                      null;
                    return (
                      <button
                        onClick={() =>
                          setResponseModal({
                            alert: alertToFlowResult(alert),
                            plan: matchingPlan,
                          })
                        }
                        style={{
                          padding: "5px 12px",
                          borderRadius: 6,
                          border: "1px solid rgba(220,38,38,0.45)",
                          background: "rgba(220,38,38,0.1)",
                          color: "#fca5a5",
                          fontWeight: 700,
                          fontSize: 10,
                          letterSpacing: 0.5,
                          textTransform: "uppercase" as const,
                          cursor: "pointer",
                          transition: "all 0.15s",
                          whiteSpace: "nowrap" as const,
                          flexShrink: 0,
                          alignSelf: "center",
                        }}
                        onMouseEnter={(e) => {
                          (e.currentTarget as HTMLButtonElement).style.background =
                            "rgba(220,38,38,0.22)";
                          (e.currentTarget as HTMLButtonElement).style.borderColor =
                            "rgba(220,38,38,0.7)";
                        }}
                        onMouseLeave={(e) => {
                          (e.currentTarget as HTMLButtonElement).style.background =
                            "rgba(220,38,38,0.1)";
                          (e.currentTarget as HTMLButtonElement).style.borderColor =
                            "rgba(220,38,38,0.45)";
                        }}
                      >
                        Respond
                      </button>
                    );
                  })()}

                  {/* Timestamp */}
                  <div style={{ color: "var(--text-muted)", fontSize: 11, flexShrink: 0, paddingTop: 2 }}>
                    {alert.time}
                  </div>
                </motion.div>
              );
            })}
            </AnimatePresence>
          </div>
        )}
      </div>
    </div>
  );
}
