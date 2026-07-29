import React, { useState, useEffect, useRef, useMemo, useCallback } from "react";
import ReactECharts from "echarts-for-react";
import SeverityBadge from "../shared/SeverityBadge";
import LiveIndicator from "../shared/LiveIndicator";
import { UserAnomalyRow, UserBehaviorSummary, SEVERITY_COLOUR, fmtTime } from "../shared/types";
import { useThemeContext } from "../../context/ThemeContext";

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
        padding: "4px 12px",
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

interface UserBehaviorViewProps {
  userAnomalies: UserAnomalyRow[];
  userSummary: UserBehaviorSummary | null;
  isMonitoring: boolean;
}

export default function UserBehaviorView({
  userAnomalies,
  userSummary,
  isMonitoring,
}: UserBehaviorViewProps) {
  const { colors } = useThemeContext();
  const [filter, setFilter] = useState<"ALL" | "ANOMALY" | "NORMAL">("ALL");
  const [pulse, setPulse] = useState(false);
  const prevCountRef = useRef(0);

  // Extended filter state
  const [searchQuery, setSearchQuery] = useState("");
  const [timeRange, setTimeRange] = useState<TimeRange>("all");

  const clearFilters = useCallback(() => {
    setSearchQuery(""); setFilter("ALL"); setTimeRange("all");
  }, []);

  // Trigger anomaly pulse when new anomalies arrive
  useEffect(() => {
    const anomalyCount = userAnomalies.filter((r) => r.prediction_label === "ANOMALY").length;
    if (anomalyCount > prevCountRef.current) {
      setPulse(true);
      const timer = setTimeout(() => setPulse(false), 2000);
      prevCountRef.current = anomalyCount;
      return () => clearTimeout(timer);
    }
    prevCountRef.current = anomalyCount;
  }, [userAnomalies]);

  const filteredRows = useMemo(() => {
    const q = searchQuery.toLowerCase().trim();
    return userAnomalies.filter((r) => {
      if (filter !== "ALL") {
        if (filter === "ANOMALY" && r.prediction_label !== "ANOMALY") return false;
        if (filter === "NORMAL" && r.prediction_label === "ANOMALY") return false;
      }
      if (!withinRange(r.ts, timeRange)) return false;
      if (q) {
        const s = [r.user, r.hostname, r.endpoint_id].filter(Boolean).join(" ").toLowerCase();
        if (!s.includes(q)) return false;
      }
      return true;
    });
  }, [userAnomalies, filter, timeRange, searchQuery]);

  const anomalyCount = userAnomalies.filter((r) => r.prediction_label === "ANOMALY").length;
  const normalCount = userAnomalies.filter((r) => r.prediction_label !== "ANOMALY").length;

  // Risk score distribution chart
  const riskChartOption = {
    backgroundColor: "transparent",
    tooltip: {
      trigger: "item",
      backgroundColor: colors.bgCard,
      borderColor: colors.borderColor,
      textStyle: { color: "var(--text-primary)", fontSize: 12 },
    },
    series: [
      {
        type: "pie",
        radius: ["45%", "70%"],
        center: ["50%", "50%"],
        data: [
          { name: "Normal", value: normalCount, itemStyle: { color: "#22c55e" } },
          { name: "Anomaly", value: anomalyCount, itemStyle: { color: "var(--accent-amber)" } },
        ],
        label: { show: false },
        itemStyle: { borderRadius: 4, borderWidth: 2, borderColor: "var(--bg-primary)" },
      },
    ],
  };

  // Score bar chart
  const topUsers = userAnomalies.slice(0, 10);
  const scoreBarOption = {
    backgroundColor: "transparent",
    tooltip: {
      trigger: "axis",
      backgroundColor: colors.bgCard,
      borderColor: colors.borderColor,
      textStyle: { color: "var(--text-primary)", fontSize: 12 },
    },
    grid: { left: 80, right: 16, top: 8, bottom: 8 },
    xAxis: {
      type: "value",
      max: 100,
      axisLabel: { color: "var(--text-secondary)", fontSize: 9 },
      splitLine: { lineStyle: { color: colors.borderColor } },
    },
    yAxis: {
      type: "category",
      data: topUsers.map((u) => u.user).reverse(),
      axisLabel: { color: "var(--text-muted)", fontSize: 10, fontFamily: "monospace" },
      axisLine: { lineStyle: { color: colors.borderColor } },
    },
    series: [
      {
        type: "bar",
        data: topUsers
          .map((u) => ({
            value: Math.round((u.anomaly_score ?? 0) * 100),
            itemStyle: {
              color:
                u.prediction_label === "ANOMALY"
                  ? (u.fusion?.severity === "CRITICAL"
                      ? "#dc2626"
                      : u.fusion?.severity === "HIGH"
                      ? "#ea580c"
                      : "#d97706")
                  : "#22c55e",
              borderRadius: [0, 4, 4, 0],
            },
          }))
          .reverse(),
        barMaxWidth: 16,
      },
    ],
  };

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
            User Behavior Analysis
            {pulse && (
              <span
                style={{
                  background: "#ea580c",
                  color: "#fff",
                  borderRadius: 20,
                  padding: "2px 10px",
                  fontSize: 10,
                  fontWeight: 700,
                  letterSpacing: 1,
                  animation: "xdr-pulse 0.5s ease-in-out 3",
                }}
              >
                NEW ANOMALY
              </span>
            )}
          </h2>
          <p style={{ margin: "4px 0 0", color: "var(--text-secondary)", fontSize: 13 }}>
            One-Class SVM insider threat detection — CERT r4.2 baseline
          </p>
        </div>
        <LiveIndicator active={(userSummary?.total_users ?? 0) > 0} label="UBA LIVE" />
      </div>

      {/* Summary cards */}
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
        {[
          {
            label: "Total Users",
            value: userSummary?.total_users ?? 0,
            sub: "monitored this cycle",
            accent: "#3b82f6",
          },
          {
            label: "Normal Users",
            value: userSummary?.normal_users ?? normalCount,
            sub: "clean behavior",
            accent: "#22c55e",
          },
          {
            label: "Anomalies",
            value: userSummary?.anomaly_users ?? anomalyCount,
            sub: "flagged users",
            accent: "#ea580c",
            glow: (userSummary?.anomaly_users ?? anomalyCount) > 0,
          },
          {
            label: "Avg Risk Score",
            value: userSummary?.avg_score != null
              ? `${(userSummary.avg_score * 100).toFixed(1)}%`
              : userAnomalies.length > 0
              ? `${(
                  (userAnomalies.reduce((s, r) => s + (r.anomaly_score ?? 0), 0) /
                    userAnomalies.length) *
                  100
                ).toFixed(1)}%`
              : "—",
            sub: "across all users",
            accent: "#f59e0b",
          },
          {
            label: "Last Cycle",
            value: userSummary?.cycle_ts
              ? (() => {
                  try {
                    return new Date(userSummary.cycle_ts).toLocaleTimeString();
                  } catch {
                    return userSummary.cycle_ts ?? "—";
                  }
                })()
              : "—",
            sub: userSummary?.cycle_ts
              ? (() => {
                  try {
                    return new Date(userSummary.cycle_ts).toLocaleDateString();
                  } catch {
                    return "";
                  }
                })()
              : "awaiting first cycle",
            accent: "var(--text-secondary)",
          },
        ].map(({ label, value, sub, accent, glow }) => (
          <div
            key={label}
            style={{
              background: "var(--bg-card)",
              border: `1px solid ${accent}33`,
              borderLeft: `4px solid ${accent}`,
              borderRadius: 12,
              padding: "16px 20px",
              flex: 1,
              minWidth: 130,
              boxShadow: glow ? `0 0 18px ${accent}22` : "none",
              transition: "box-shadow 0.3s",
            }}
          >
            <div style={{ color: "var(--accent-green)", fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: 1.5 }}>
              {label}
            </div>
            <div style={{ color: accent, fontSize: 26, fontWeight: 800, marginTop: 4, letterSpacing: -0.5 }}>
              {value}
            </div>
            {sub && <div style={{ color: "var(--accent-green)", fontSize: 11, marginTop: 4 }}>{sub}</div>}
          </div>
        ))}
      </div>

      {/* Charts row */}
      {userAnomalies.length > 0 && (
        <div style={{ display: "grid", gridTemplateColumns: "160px 1fr", gap: 14 }}>
          <div style={{ ...panel, padding: 16, display: "flex", flexDirection: "column", alignItems: "center" }}>
            <div style={{ fontSize: 10, fontWeight: 700, color: "var(--text-secondary)", letterSpacing: 1.5, textTransform: "uppercase", marginBottom: 8 }}>
              Risk Split
            </div>
            <ReactECharts option={riskChartOption} style={{ height: 120, width: "100%" }} />
            <div style={{ display: "flex", gap: 12, marginTop: 4 }}>
              <span style={{ color: "#22c55e", fontSize: 10, fontWeight: 700 }}>◆ {normalCount} Normal</span>
              <span style={{ color: "var(--accent-amber)", fontSize: 10, fontWeight: 700 }}>◆ {anomalyCount} Flagged</span>
            </div>
          </div>
          <div style={{ ...panel, padding: 16 }}>
            <div style={{ fontSize: 10, fontWeight: 700, color: "var(--text-secondary)", letterSpacing: 1.5, textTransform: "uppercase", marginBottom: 8 }}>
              User Risk Scores
            </div>
            <ReactECharts
              option={scoreBarOption}
              style={{ height: Math.max(120, topUsers.length * 22) }}
            />
          </div>
        </div>
      )}

      {/* Filter bar */}
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
        {/* Row 1: Search + Time range */}
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
          {/* Search */}
          <div style={{ flex: "1 1 220px", position: "relative" }}>
            <span style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)", color: "var(--text-muted)", fontSize: 12, pointerEvents: "none" }}>&#128269;</span>
            <input
              type="text"
              placeholder="Search username, hostname..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{ width: "100%", padding: "6px 10px 6px 30px", borderRadius: 8, border: "1px solid var(--border-color)", background: "var(--bg-primary)", color: "var(--text-primary)", fontSize: 12, outline: "none", boxSizing: "border-box" }}
            />
          </div>

          {/* Time range */}
          <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
            <span style={{ color: "var(--text-muted)", fontSize: 10, fontWeight: 700, letterSpacing: 1, whiteSpace: "nowrap" }}>TIME:</span>
            {(["1h", "6h", "24h", "all"] as TimeRange[]).map((r) => (
              <Pill key={r} label={r === "all" ? "All" : `Last ${r}`} active={timeRange === r} accent="#3b82f6" onClick={() => setTimeRange(r)} />
            ))}
          </div>
        </div>

        {/* Row 2: Anomaly level tabs + count */}
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
          <span style={{ color: "var(--text-muted)", fontSize: 10, fontWeight: 700, letterSpacing: 1, whiteSpace: "nowrap" }}>ANOMALY:</span>
          {(["ALL", "ANOMALY", "NORMAL"] as const).map((f) => {
            const accents: Record<string, string> = { ALL: "#3b82f6", ANOMALY: "#ea580c", NORMAL: "#22c55e" };
            const rawCounts: Record<string, number> = { ALL: userAnomalies.length, ANOMALY: anomalyCount, NORMAL: normalCount };
            return (
              <button
                key={f}
                onClick={() => setFilter(f)}
                style={{
                  padding: "4px 14px",
                  borderRadius: 20,
                  border: filter === f ? `1px solid ${accents[f]}` : "1px solid var(--border-color)",
                  cursor: "pointer",
                  background: filter === f ? `${accents[f]}1a` : "var(--bg-secondary)",
                  color: filter === f ? accents[f] : "var(--text-secondary)",
                  fontWeight: filter === f ? 700 : 400,
                  fontSize: 11,
                  transition: "all 0.15s",
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                }}
              >
                {f}
                <span
                  style={{
                    background: filter === f ? accents[f] : "var(--text-muted)",
                    color: filter === f ? "#fff" : "var(--text-muted)",
                    borderRadius: 10,
                    padding: "0 6px",
                    fontSize: 9,
                    fontWeight: 700,
                  }}
                >
                  {rawCounts[f]}
                </span>
              </button>
            );
          })}

          <span style={{ marginLeft: "auto", color: "var(--text-muted)", fontSize: 11, whiteSpace: "nowrap" }}>
            Showing{" "}
            <span style={{ color: "var(--text-secondary)", fontWeight: 700 }}>{filteredRows.length}</span>
            {" of "}
            <span style={{ color: "var(--text-secondary)", fontWeight: 700 }}>{userAnomalies.length}</span>
            {" users"}
          </span>
          {(searchQuery || filter !== "ALL" || timeRange !== "all") && (
            <button onClick={clearFilters} style={{ padding: "3px 10px", borderRadius: 8, border: "1px solid var(--border-color)", background: "transparent", color: "var(--text-secondary)", fontSize: 10, cursor: "pointer", fontWeight: 700 }}>Clear</button>
          )}
        </div>
      </div>

      {/* User table */}
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
            USER BEHAVIOR LOG
          </span>
          <span
            style={{
              background: "var(--bg-secondary)",
              color: "var(--text-muted)",
              borderRadius: 20,
              padding: "2px 10px",
              fontSize: 10,
            }}
          >
            {filteredRows.length} / {userAnomalies.length} users
          </span>
          {anomalyCount > 0 && (
            <span
              style={{
                background: "rgba(234,88,12,0.10)",
                color: "var(--accent-amber)",
                borderRadius: 20,
                padding: "2px 10px",
                fontSize: 10,
                fontWeight: 700,
                border: "1px solid #7f2d1e",
              }}
            >
              {anomalyCount} flagged
            </span>
          )}
        </div>

        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
            <thead>
              <tr style={{ background: "var(--bg-primary)" }}>
                {(
                [
                  { label: "User" },
                  { label: "Source" },
                  { label: "Score" },
                  { label: "Status" },
                  { label: "Severity" },
                  { label: "Sessions", title: "Concurrent sessions (endpoint)" },
                  { label: "After Hours", title: "After-hours activity flag (endpoint) or after-hours logins count (Winlogbeat)" },
                  { label: "Remote", title: "Remote session detected (endpoint) or USB events (Winlogbeat)" },
                  { label: "Time" },
                ] as { label: string; title?: string }[]
              ).map(({ label, title }) => (
                  <th
                    key={label}
                    title={title}
                    style={{
                      padding: "10px 14px",
                      textAlign: "left",
                      color: title ? "var(--text-secondary)" : "var(--text-muted)",
                      fontWeight: 700,
                      fontSize: 10,
                      letterSpacing: 0.8,
                      textTransform: "uppercase",
                      whiteSpace: "nowrap",
                      cursor: title ? "help" : "default",
                    }}
                  >
                    {label}{title ? " ⓘ" : ""}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filteredRows.length === 0 ? (
                <tr>
                  <td colSpan={9} style={{ padding: 48, textAlign: "center", color: "var(--text-muted)", fontSize: 13 }}>
                    {userAnomalies.length === 0
                      ? "No user behavior data yet — endpoint agents or Winlogbeat must be sending logs."
                      : `No ${filter.toLowerCase()} users in current view.`}
                  </td>
                </tr>
              ) : (
                filteredRows.map((row, idx) => {
                  const isAnomaly = row.prediction_label === "ANOMALY";
                  const sev = row.fusion?.severity ?? (isAnomaly ? "HIGH" : "");
                  const sevColor = SEVERITY_COLOUR[sev] ?? "#6b7280";

                  // Determine display score: prefer explicit user_score, then anomaly_score
                  const rawScore = row.user_score ?? row.anomaly_score ?? 0;
                  const score = rawScore > 1 ? rawScore : rawScore * 100;

                  const isEndpoint = row.source === "endpoint";
                  const isMachineAccount = (row.is_machine_account ?? 0) >= 1;

                  const rowBg =
                    isMachineAccount
                      ? idx % 2 === 0 ? "var(--bg-secondary)" : "var(--bg-card)"
                      : sev === "CRITICAL"
                      ? "#dc262610"
                      : sev === "HIGH"
                      ? "#ea580c0e"
                      : isAnomaly
                      ? "#d9770609"
                      : idx % 2 === 0
                      ? "var(--bg-card)"
                      : "var(--bg-card)";

                  // Effective username: prefer current_user, then user field
                  const displayUser = row.current_user ?? row.user;

                  return (
                    <tr
                      key={`${row.user}-${idx}`}
                      style={{
                        borderBottom: "1px solid #0a1120",
                        background: rowBg,
                        opacity: isMachineAccount ? 0.6 : 1,
                        transition: "background 0.1s",
                      }}
                    >
                      {/* User column */}
                      <td style={{ padding: "10px 14px", fontFamily: "monospace", color: "var(--accent-cyan)", whiteSpace: "nowrap", fontWeight: 600 }}>
                        {isAnomaly && !isMachineAccount && (
                          <span
                            style={{
                              display: "inline-block",
                              width: 6,
                              height: 6,
                              borderRadius: "50%",
                              background: sevColor,
                              boxShadow: `0 0 6px ${sevColor}`,
                              marginRight: 6,
                              animation: "xdr-pulse 1.4s ease-in-out infinite",
                            }}
                          />
                        )}
                        {displayUser}
                        {isMachineAccount && (
                          <span
                            style={{
                              marginLeft: 6,
                              background: "rgba(100,116,139,0.15)",
                              color: "var(--text-muted)",
                              border: "1px solid rgba(100,116,139,0.3)",
                              borderRadius: 4,
                              padding: "1px 6px",
                              fontSize: 9,
                              fontWeight: 700,
                              letterSpacing: 0.5,
                            }}
                          >
                            MACHINE ACCOUNT
                          </span>
                        )}
                        {row.hostname && (
                          <span style={{
                            display: "block",
                            fontSize: 10,
                            fontWeight: 400,
                            color: "var(--text-secondary)",
                            fontFamily: "monospace",
                            marginTop: 2,
                          }}>
                            {row.hostname}
                          </span>
                        )}
                        {/* SHAP explanation chips */}
                        {row.shap_explanation && row.shap_explanation.length > 0 && (
                          <div style={{ marginTop: 5, display: "flex", flexWrap: "wrap", gap: 3 }}>
                            <span style={{ fontSize: 9, color: "var(--text-muted)", fontWeight: 700, letterSpacing: 0.5, marginRight: 2 }}>Reasons:</span>
                            {row.shap_explanation.slice(0, 3).map((reason, ri) => (
                              <span
                                key={ri}
                                style={{
                                  fontSize: 9,
                                  fontFamily: "sans-serif",
                                  background: "var(--accent-cyan-dim)",
                                  color: "var(--accent-cyan)",
                                  border: "1px solid var(--border-color-strong)",
                                  borderRadius: 4,
                                  padding: "1px 6px",
                                  fontWeight: 600,
                                  whiteSpace: "normal",
                                  maxWidth: 180,
                                  overflow: "hidden",
                                  textOverflow: "ellipsis",
                                }}
                                title={reason}
                              >
                                {reason}
                              </span>
                            ))}
                            {row.shap_explanation.length > 3 && (
                              <span style={{ fontSize: 9, color: "var(--text-muted)" }}>
                                +{row.shap_explanation.length - 3}
                              </span>
                            )}
                          </div>
                        )}
                      </td>

                      {/* Source column */}
                      <td style={{ padding: "10px 14px", whiteSpace: "nowrap" }}>
                        {isEndpoint ? (
                          <span
                            style={{
                              background: "var(--border-color)",
                              color: "var(--accent-cyan)",
                              border: "1px solid var(--border-color-strong)",
                              borderRadius: 4,
                              padding: "2px 7px",
                              fontSize: 9,
                              fontWeight: 700,
                              letterSpacing: 0.5,
                            }}
                          >
                            ENDPOINT
                          </span>
                        ) : (
                          <span
                            style={{
                              background: "rgba(139,92,246,0.1)",
                              color: "#a78bfa",
                              border: "1px solid rgba(139,92,246,0.25)",
                              borderRadius: 4,
                              padding: "2px 7px",
                              fontSize: 9,
                              fontWeight: 700,
                              letterSpacing: 0.5,
                            }}
                          >
                            WINLOGBEAT
                          </span>
                        )}
                      </td>

                      {/* Score column */}
                      <td style={{ padding: "10px 14px" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                          <div
                            style={{
                              flex: 1,
                              height: 6,
                              background: "var(--bg-secondary)",
                              borderRadius: 3,
                              overflow: "hidden",
                              minWidth: 60,
                            }}
                          >
                            <div
                              style={{
                                height: "100%",
                                width: `${score}%`,
                                background:
                                  score >= 75
                                    ? "#dc2626"
                                    : score >= 50
                                    ? "#ea580c"
                                    : score >= 25
                                    ? "#d97706"
                                    : "#22c55e",
                                borderRadius: 3,
                                transition: "width 0.3s ease",
                              }}
                            />
                          </div>
                          <span
                            style={{
                              color:
                                score >= 75
                                  ? "#dc2626"
                                  : score >= 50
                                  ? "#ea580c"
                                  : score >= 25
                                  ? "#d97706"
                                  : "#22c55e",
                              fontWeight: 700,
                              fontSize: 11,
                              minWidth: 38,
                              textAlign: "right",
                            }}
                          >
                            {score.toFixed(1)}%
                          </span>
                        </div>
                      </td>

                      {/* Status (ANOMALY/NORMAL) */}
                      <td style={{ padding: "10px 14px" }}>
                        <span
                          style={{
                            display: "inline-flex",
                            alignItems: "center",
                            gap: 4,
                            background: isAnomaly ? "#ea580c1a" : "#22c55e1a",
                            color: isAnomaly ? "#ea580c" : "#22c55e",
                            border: `1px solid ${isAnomaly ? "#ea580c44" : "#22c55e44"}`,
                            borderRadius: 20,
                            padding: "2px 10px",
                            fontWeight: 700,
                            fontSize: 10,
                            letterSpacing: 0.5,
                          }}
                        >
                          {isAnomaly ? "ANOMALY" : "NORMAL"}
                        </span>
                      </td>

                      {/* Severity */}
                      <td style={{ padding: "10px 14px" }}>
                        {sev ? <SeverityBadge severity={sev} size="sm" /> : <span style={{ color: "var(--text-muted)" }}>—</span>}
                      </td>

                      {/* Sessions (endpoint) or login count (Winlogbeat) */}
                      <td style={{ padding: "10px 14px", textAlign: "right", color: "var(--text-secondary)", fontFamily: "monospace" }}>
                        {isEndpoint
                          ? (row.concurrent_sessions != null
                              ? <span style={{ color: (row.concurrent_sessions ?? 0) > 1 ? "#f59e0b" : "var(--text-secondary)", fontWeight: (row.concurrent_sessions ?? 0) > 1 ? 700 : 400 }}>
                                  {row.concurrent_sessions}
                                </span>
                              : <span style={{ color: "var(--text-muted)" }}>—</span>
                            )
                          : (row.total_logins ?? 0)}
                      </td>

                      {/* After Hours: endpoint flag or Winlogbeat after-hours count */}
                      <td style={{ padding: "10px 14px", textAlign: "center" }}>
                        {isEndpoint
                          ? (row.unusual_hour != null
                              ? (row.unusual_hour >= 1.0
                                  ? <span style={{ background: "rgba(245,158,11,0.12)", color: "var(--accent-amber)", border: "1px solid rgba(245,158,11,0.3)", borderRadius: 4, padding: "2px 8px", fontSize: 10, fontWeight: 700 }}>YES</span>
                                  : <span style={{ background: "rgba(34,197,94,0.08)", color: "#22c55e", border: "1px solid rgba(34,197,94,0.2)", borderRadius: 4, padding: "2px 8px", fontSize: 10, fontWeight: 700 }}>NO</span>
                                )
                              : <span style={{ color: "var(--text-muted)" }}>—</span>
                            )
                          : <span style={{ color: (row.after_hours_logins ?? 0) > 0 ? "#f59e0b" : "var(--text-secondary)", fontWeight: (row.after_hours_logins ?? 0) > 0 ? 700 : 400 }}>
                              {row.after_hours_logins ?? 0}
                            </span>
                        }
                      </td>

                      {/* Remote (endpoint) or USB events (Winlogbeat) */}
                      <td style={{ padding: "10px 14px", textAlign: "center" }}>
                        {isEndpoint
                          ? (row.has_remote_session != null
                              ? (row.has_remote_session >= 1.0
                                  ? <span style={{ background: "rgba(239,68,68,0.1)", color: "#ef4444", border: "1px solid rgba(239,68,68,0.3)", borderRadius: 4, padding: "2px 8px", fontSize: 10, fontWeight: 700 }}>YES</span>
                                  : <span style={{ background: "rgba(34,197,94,0.08)", color: "#22c55e", border: "1px solid rgba(34,197,94,0.2)", borderRadius: 4, padding: "2px 8px", fontSize: 10, fontWeight: 700 }}>NO</span>
                                )
                              : <span style={{ color: "var(--text-muted)" }}>—</span>
                            )
                          : <span style={{ color: (row.usb_connects ?? 0) > 0 ? "#ea580c" : "var(--text-secondary)", fontWeight: (row.usb_connects ?? 0) > 0 ? 700 : 400 }}>
                              {row.usb_connects ?? 0}
                            </span>
                        }
                      </td>

                      {/* Timestamp */}
                      <td style={{ padding: "10px 14px", color: "var(--text-secondary)", whiteSpace: "nowrap" }}>
                        {row.ts ? fmtTime(row.ts) : "—"}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
