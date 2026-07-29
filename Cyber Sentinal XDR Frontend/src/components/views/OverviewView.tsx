import React, { useMemo, useState, useEffect } from "react";
import ReactECharts from "echarts-for-react";
import { useThemeContext } from "../../context/ThemeContext";
import StatCard from "../shared/StatCard";
import SeverityBadge from "../shared/SeverityBadge";
import LiveIndicator from "../shared/LiveIndicator";
import { StaggerContainer, StaggerItem, AnimatedNumber, SkeletonBlock } from "../../animations/components";
import {
  FlowResult,
  UserAnomalyRow,
  UserBehaviorSummary,
  MalwareSummary,
  SocAlert,
  Stats,
  ATTACK_COLOURS,
  SEVERITY_COLOUR,
  fmtTime,
} from "../shared/types";
import { authAxios } from "../../services/authService";
import { BACKEND_URL } from "../../config";

interface OverviewViewProps {
  flows: FlowResult[];
  stats: Stats;
  isMonitoring: boolean;
  userAnomalies: UserAnomalyRow[];
  userSummary: UserBehaviorSummary | null;
  timelineData: { time: string; attacks: number; normal: number }[];
  attackTypeData: Record<string, number>;
  malwareSummary?: MalwareSummary;
  mongoOk?: boolean;
  fusionScore?: number;
  socAlerts?: SocAlert[];
  // Fix C2 — live fusion score + data-arrived gate
  hasFusionData?: boolean;
  // Fix H2 — real socket connection state
  socketConnected?: boolean;
  // Fix H1 — multi-source active threat count
  activeThreatCount?: number;
  // Fix M1 — endpoints online StatCard
  endpoints?: any[];
  // Fix M2 — system + endpoint sources in recent alerts
  systemAnomalies?: any[];
  endpointAlerts?: any[];
  // Activity Log — admin only
  userRole?: string;
  socket?: any;
}

export default function OverviewView({
  flows,
  stats,
  isMonitoring,
  userAnomalies,
  userSummary,
  timelineData,
  attackTypeData,
  malwareSummary,
  mongoOk,
  fusionScore,
  socAlerts,
  hasFusionData,
  socketConnected,
  activeThreatCount,
  endpoints,
  systemAnomalies,
  endpointAlerts,
  userRole,
  socket,
}: OverviewViewProps) {
  const { colors } = useThemeContext();
  const attackRate = stats.total > 0 ? (stats.attacks / stats.total) * 100 : 0;

  // Fix C2 — use live fusionScore; fall back to 0 only for colour computation
  const globalThreatScore = fusionScore ?? 0;

  const threatColor = !hasFusionData
    ? "var(--text-secondary)"
    : globalThreatScore >= 75
    ? "#dc2626"
    : globalThreatScore >= 50
    ? "#ea580c"
    : globalThreatScore >= 25
    ? "#d97706"
    : "#22c55e";

  // Fix C2/L2 — grey gauge arc when awaiting first telemetry
  const gaugeAxisColors: [number, string][] = hasFusionData
    ? [
        [0.25, "#22c55e"],
        [0.5,  "#d97706"],
        [0.75, "#ea580c"],
        [1,    "#dc2626"],
      ]
    : [
        [1, colors.bgCard],
      ];

  const gaugeOption = {
    backgroundColor: "transparent",
    series: [
      {
        type: "gauge",
        startAngle: 200,
        endAngle: -20,
        min: 0,
        max: 100,
        radius: "90%",
        center: ["50%", "60%"],
        axisLine: {
          lineStyle: {
            width: 18,
            color: gaugeAxisColors,
          },
        },
        pointer: {
          length: "60%",
          width: 4,
          itemStyle: { color: threatColor },
        },
        axisTick: { show: false },
        splitLine: { show: false },
        axisLabel: { show: false },
        detail: {
          valueAnimation: true,
          // Fix L2 — suppress numeric value until first data arrives
          formatter: hasFusionData ? "{value}" : "",
          color: threatColor,
          fontSize: 32,
          fontWeight: 800,
          offsetCenter: [0, "20%"],
        },
        data: [{ value: Math.round(globalThreatScore) }],
      },
    ],
  };

  const timelineOption = {
    backgroundColor: "transparent",
    tooltip: {
      trigger: "axis",
      backgroundColor: colors.bgCard,
      borderColor: colors.borderColor,
      textStyle: { color: colors.textPrimary, fontSize: 12 },
    },
    legend: {
      data: ["Normal", "Attack"],
      textStyle: { color: colors.textMuted, fontSize: 11 },
      top: 0,
    },
    grid: { left: 36, right: 12, top: 30, bottom: 30 },
    xAxis: {
      type: "category",
      data: timelineData.map((d) => d.time),
      axisLabel: { color: colors.textSecondary, fontSize: 9, rotate: 30 },
      axisLine: { lineStyle: { color: colors.borderColor } },
    },
    yAxis: {
      type: "value",
      minInterval: 1,
      axisLabel: { color: colors.textSecondary, fontSize: 10 },
      splitLine: { lineStyle: { color: colors.borderColor } },
    },
    series: [
      {
        name: "Normal",
        type: "line",
        smooth: true,
        data: timelineData.map((d) => d.normal),
        itemStyle: { color: "#22c55e" },
        lineStyle: { color: "#22c55e", width: 2 },
        areaStyle: { color: "#22c55e1a" },
        symbol: "none",
      },
      {
        name: "Attack",
        type: "line",
        smooth: true,
        data: timelineData.map((d) => d.attacks),
        itemStyle: { color: "#ef4444" },
        lineStyle: { color: "#ef4444", width: 2 },
        areaStyle: { color: "#ef44441a" },
        symbol: "none",
      },
    ],
  };

  const donutOption = {
    backgroundColor: "transparent",
    tooltip: {
      trigger: "item",
      backgroundColor: colors.bgCard,
      borderColor: colors.borderColor,
      textStyle: { color: colors.textPrimary, fontSize: 12 },
    },
    legend: {
      orient: "vertical" as const,
      right: 0,
      top: "center",
      textStyle: { color: colors.textMuted, fontSize: 10 },
    },
    series: [
      {
        type: "pie",
        radius: ["45%", "70%"],
        center: ["38%", "50%"],
        data:
          Object.keys(attackTypeData).length > 0
            ? Object.entries(attackTypeData).map(([name, value]) => ({
                name,
                value,
                itemStyle: { color: ATTACK_COLOURS[name] ?? "#6b7280" },
              }))
            : [{ name: "No Data", value: 1, itemStyle: { color: colors.bgCard } }],
        label: { show: false },
        itemStyle: { borderRadius: 4, borderWidth: 2, borderColor: colors.bgPrimary },
      },
    ],
  };

  // Recent 10 alerts — Fix M2: includes system anomalies + endpoint alerts
  const recentAlerts = useMemo(() => {
    const netAlerts = flows
      .filter((f) => f.prediction === "ATTACK")
      .slice(0, 10)
      .map((f) => ({
        id: `net-${f.timestamp}-${f.src_ip}`,
        time: fmtTime(f.timestamp),
        source: "Network" as const,
        severity: f.severity,
        description: `${f.traffic_label} — ${f.src_ip} → ${f.dest_ip}`,
      }));

    const userAlerts = userAnomalies
      .filter((u) => u.prediction_label === "ANOMALY")
      .slice(0, 5)
      .map((u, i) => ({
        id: `usr-${u.ts ?? i}-${u.user}`,
        time: u.ts ? fmtTime(u.ts) : "—",
        source: "User" as const,
        severity: (u.fusion?.severity ?? "HIGH") as string,
        description: `Anomalous behavior — ${u.user}`,
      }));

    const socAlertItems = (socAlerts ?? []).slice(0, 5).map((a, i) => ({
      id: `soc-${a.timestamp}-${i}`,
      time: a.timestamp ? fmtTime(a.timestamp) : "—",
      source: "Correlated" as const,
      severity: a.final_severity,
      description: `${a.attack_type} — ${a.mitre_id} (${(a.involved_sources ?? []).join("+")})`,
    }));

    // Fix M2 — system anomalies (HIGH/CRITICAL only)
    const sysItems = (systemAnomalies ?? [])
      .filter((s: any) => s.severity === 'HIGH' || s.severity === 'CRITICAL')
      .slice(0, 5)
      .map((s: any) => {
        const cpuIdx = s.feature_names?.indexOf('cpu_percent') ?? 0;
        const memIdx = s.feature_names?.indexOf('mem_percent') ?? 1;
        const cpu = s.features_snapshot?.[cpuIdx];
        const mem = s.features_snapshot?.[memIdx];
        return {
          id: s.ts ?? String(Math.random()),
          time: s.ts ? new Date(s.ts).toLocaleTimeString() : 'Now',
          source: 'System' as const,
          severity: s.severity,
          description: `System anomaly — CPU: ${cpu != null ? cpu.toFixed(1) : '?'}% | MEM: ${mem != null ? mem.toFixed(1) : '?'}%`,
        };
      });

    // Fix M2 — endpoint alerts (HIGH/CRITICAL only)
    const epItems = (endpointAlerts ?? [])
      .filter((a: any) => a.severity === 'HIGH' || a.severity === 'CRITICAL')
      .slice(0, 5)
      .map((a: any) => ({
        id: a.timestamp ?? String(Math.random()),
        time: a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : 'Now',
        source: 'Endpoint' as const,
        severity: a.severity,
        description: `${a.hostname ?? a.endpoint_id}: ${a.reason ?? 'Alert'}`,
      }));

    return [...netAlerts, ...userAlerts, ...socAlertItems, ...sysItems, ...epItems]
      .sort((x, y) => (x.time < y.time ? 1 : -1))
      .slice(0, 10);
  }, [flows, userAnomalies, socAlerts, systemAnomalies, endpointAlerts]);

  // ── Activity Log (admin only) ─────────────────────────────────────────────────
  interface AuditEntry {
    _id?: string;
    action: string;
    user?: string;
    user_id?: string;
    ip?: string;
    timestamp?: string;
    ts?: string;
    detail?: string;
  }

  const ACTION_LABELS: Record<string, string> = {
    // Auth
    login:                      "User Login",
    logout:                     "User Logout",
    register:                   "User Registered",
    password_changed:           "Password Changed",
    password_reset_requested:   "Password Reset Req.",
    password_reset_completed:   "Password Reset Done",
    // 2FA (backend uses these exact action names)
    "2fa_setup_initiated":      "2FA Setup Started",
    "2fa_enabled":              "2FA Enabled",
    "2fa_disabled":             "2FA Disabled",
    "2fa_verify_failed":        "2FA Verify Failed",
    // keep legacy keys in case old events exist
    enable_2fa:                 "2FA Enabled",
    disable_2fa:                "2FA Disabled",
    // Admin user management
    admin_create_user:          "User Created",
    user_deleted:               "User Deleted",
    role_changed:               "Role Changed",
    force_logout:               "Force Logout",
    mfa_recovery_approved:      "MFA Recovery Approved",
    mfa_recovery_denied:        "MFA Recovery Denied",
    // Monitoring
    monitoring_started:         "Monitoring Started",
    monitoring_stopped:         "Monitoring Stopped",
    // Investigation & response
    investigation_started:      "Incident Investigated",
    response_plan_created:      "Response Plan Created",
    response_plan_executed:     "Response Executed",
    response_plan_contained:    "Threat Contained",
    // SOAR
    command_result:             "SOAR Command",
    // Reports
    report_generated:           "Report Generated",
    // Settings
    thresholds_updated:         "Thresholds Updated",
    sound_alerts_enabled:       "Sound Alerts ON",
    sound_alerts_disabled:      "Sound Alerts OFF",
    // Fallback
    client_event:               "Client Action",
  };

  const ACTION_COLOUR = (action: string): { bg: string; fg: string } => {
    const a = (action ?? "").toLowerCase();
    if (a.includes("fail") || a.includes("delete") || a.includes("denied") || a === "logout" || a === "user logout")
      return { bg: "#3b0d0d", fg: "#f87171" };
    if (a.includes("response") || a.includes("soar") || a.includes("command") || a.includes("threshold") || a.includes("contained"))
      return { bg: "#2d1d02", fg: "#fbbf24" };
    if (a.includes("invest") || a.includes("role") || a.includes("2fa") || a.includes("mfa") || a.includes("recovery") || a.includes("force"))
      return { bg: "#0c1f3d", fg: "#60a5fa" };
    if (a.includes("monitor") || a.includes("sound") || a.includes("report") || a.includes("created") || a.includes("register"))
      return { bg: "#1a1040", fg: "#a78bfa" };
    return { bg: "#0d2618", fg: "#4ade80" };
  };

  const [activityLog, setActivityLog] = useState<AuditEntry[]>([]);

  // Fetch recent audit logs on mount (admin only)
  useEffect(() => {
    if (userRole !== "admin") return;
    authAxios
      .get(`${BACKEND_URL}/audit-logs`, { params: { limit: 30 }, timeout: 6000 })
      .then((res) => {
        const entries: AuditEntry[] = res.data?.logs ?? res.data ?? [];
        if (Array.isArray(entries)) setActivityLog(entries.slice(0, 50));
      })
      .catch(() => {
        // Audit log endpoint unavailable — socket events will populate
      });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [userRole]);

  // Subscribe to real-time audit_event socket events
  useEffect(() => {
    if (!socket || userRole !== "admin") return;
    const handler = (entry: AuditEntry) => {
      setActivityLog((prev) => [entry, ...prev].slice(0, 50));
    };
    socket.on("audit_event", handler);
    return () => {
      socket.off("audit_event", handler);
    };
  }, [socket, userRole]);

  const panel: React.CSSProperties = {
    background: "var(--bg-card, #1e293b)",
    border: "1px solid var(--border-color, rgba(255,255,255,0.08))",
    borderRadius: 14,
    padding: 20,
    transition: "background 0.2s ease",
  };

  return (
    <div style={{ padding: 24, display: "flex", flexDirection: "column", gap: 20 }}>
      {/* Page header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div>
          <h2 style={{ margin: 0, fontSize: 20, fontWeight: 800, color: "var(--text-heading)", letterSpacing: -0.5 }}>
            Security Overview
          </h2>
          <p style={{ margin: "4px 0 0", color: "var(--text-secondary)", fontSize: 13 }}>
            Real-time threat intelligence dashboard
          </p>
        </div>
        <LiveIndicator active={isMonitoring} />
      </div>

      {/* KPI row */}
      <StaggerContainer style={{ display: "flex", gap: 14, flexWrap: "wrap" }}>
        <StaggerItem style={{ flex: "1 1 160px" }}>
          <StatCard
            label="Active Threats"
            value={activeThreatCount ?? stats.attacks}
            sub="network + user + malware"
            accent="#ef4444"
            glow={(activeThreatCount ?? stats.attacks) > 0}
            icon="🚨"
          />
        </StaggerItem>
        <StaggerItem style={{ flex: "1 1 160px" }}>
          <StatCard
            label="Network Flows"
            value={stats.total}
            sub="this session"
            accent="#3b82f6"
            icon="⬡"
          />
        </StaggerItem>
        <StaggerItem style={{ flex: "1 1 160px" }}>
          <StatCard
            label="Users Monitored"
            value={userSummary?.total_users ?? 0}
            sub={`${userSummary?.anomaly_users ?? 0} flagged`}
            accent="#8b5cf6"
            glow={(userSummary?.anomaly_users ?? 0) > 0}
            icon="◉"
          />
        </StaggerItem>
        <StaggerItem style={{ flex: "1 1 160px" }}>
          <StatCard
            label="Capture Cycles"
            value={stats.cycles}
            sub="10s intervals"
            accent="#06b6d4"
            icon="◎"
          />
        </StaggerItem>
        <StaggerItem style={{ flex: "1 1 160px" }}>
          <StatCard
            label="Attack Rate"
            value={stats.total > 0 ? `${attackRate.toFixed(1)}%` : "—"}
            sub="of all flows"
            accent="#f59e0b"
            glow={attackRate > 20}
            icon="◬"
          />
        </StaggerItem>
        <StaggerItem style={{ flex: "1 1 160px" }}>
          <StatCard
            label="Endpoints Online"
            value={endpoints?.filter((e: any) => e.status === 'online').length ?? 0}
            sub="monitored hosts"
            accent="#06b6d4"
            icon="▣"
          />
        </StaggerItem>
      </StaggerContainer>

      {/* Malware Summary card row */}
      <div style={{ display: "flex", gap: 14, flexWrap: "wrap", alignItems: "stretch" }}>
        <div
          style={{
            ...panel,
            flex: 1,
            minWidth: 180,
            display: "flex",
            flexDirection: "column",
            gap: 4,
          }}
        >
          <div style={{ fontSize: 10, fontWeight: 700, color: "var(--text-muted)", letterSpacing: 1.5, textTransform: "uppercase", marginBottom: 6 }}>
            Malware Summary
          </div>
          <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
            {/* Malware Scanned */}
            <div style={{ flex: 1, minWidth: 110 }}>
              <div style={{ color: "var(--accent-green)", fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: 1 }}>
                Malware Scanned
              </div>
              <div style={{ color: "var(--text-primary)", fontSize: 24, fontWeight: 800, marginTop: 2 }}>
                {malwareSummary?.total_scanned ?? 0}
              </div>
            </div>
            {/* Threats Detected */}
            <div style={{ flex: 1, minWidth: 110 }}>
              <div style={{ color: "var(--accent-green)", fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: 1 }}>
                Threats Detected
              </div>
              <div
                style={{
                  fontSize: 24,
                  fontWeight: 800,
                  marginTop: 2,
                  color: (malwareSummary?.malware_count ?? 0) > 0 ? "#ef4444" : "var(--text-primary)",
                }}
              >
                {malwareSummary?.malware_count ?? 0}
              </div>
            </div>
            {/* Detection Rate */}
            <div style={{ flex: 1, minWidth: 110 }}>
              <div style={{ color: "var(--accent-green)", fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: 1 }}>
                Detection Rate
              </div>
              {(() => {
                const total = malwareSummary?.total_scanned ?? 0;
                const malware = malwareSummary?.malware_count ?? 0;
                const rate = total > 0 ? (malware / total) * 100 : 0;
                return (
                  <div
                    style={{
                      fontSize: 24,
                      fontWeight: 800,
                      marginTop: 2,
                      color: rate > 5 ? "#d97706" : "var(--text-primary)",
                    }}
                  >
                    {total > 0 ? `${rate.toFixed(1)}%` : "—"}
                  </div>
                );
              })()}
            </div>
            {/* Last Scan */}
            <div style={{ flex: 1, minWidth: 130 }}>
              <div style={{ color: "var(--accent-green)", fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: 1 }}>
                Last Scan
              </div>
              <div style={{ color: "var(--text-secondary)", fontSize: 13, fontWeight: 600, marginTop: 6, fontFamily: "monospace" }}>
                {malwareSummary?.last_scan_ts
                  ? fmtTime(malwareSummary.last_scan_ts)
                  : "Never"}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Main grid: gauge + timeline + donut */}
      <div style={{ display: "grid", gridTemplateColumns: "220px 1fr 260px", gap: 16 }}>
        {/* Threat Gauge */}
        <div style={{ ...panel, display: "flex", flexDirection: "column", alignItems: "center" }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: "var(--text-secondary)", letterSpacing: 1.5, textTransform: "uppercase", marginBottom: 4 }}>
            Global Threat Score
          </div>
          {/* Fix L2 — grey opacity until first fusion_alert arrives */}
          <div style={{ width: "100%", opacity: hasFusionData ? 1 : 0.3, transition: "opacity 0.4s ease", position: "relative" }}>
            <ReactECharts option={gaugeOption} style={{ height: 160, width: "100%" }} />
            {/* Fix L2 — "Awaiting telemetry…" overlay when no data */}
            {!hasFusionData && (
              <div style={{
                position: "absolute",
                inset: 0,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                pointerEvents: "none",
              }}>
                <span style={{ fontSize: 11, color: "var(--text-muted)", fontStyle: "italic" }}>
                  Awaiting telemetry…
                </span>
              </div>
            )}
          </div>
          <div
            style={{
              fontSize: 11,
              fontWeight: 700,
              color: threatColor,
              letterSpacing: 1,
              textTransform: "uppercase",
              marginTop: -8,
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              gap: 2,
            }}
          >
            {hasFusionData && (
              <span style={{ fontSize: 22, fontWeight: 900, letterSpacing: 0 }}>
                <AnimatedNumber value={globalThreatScore} decimals={0} suffix="%" />
              </span>
            )}
            {hasFusionData
              ? (globalThreatScore >= 75
                  ? "CRITICAL"
                  : globalThreatScore >= 50
                  ? "HIGH"
                  : globalThreatScore >= 25
                  ? "MEDIUM"
                  : "LOW")
              : "—"}
          </div>
        </div>

        {/* Timeline */}
        <div style={panel}>
          <div style={{ fontSize: 11, fontWeight: 700, color: "var(--text-muted)", letterSpacing: 1, textTransform: "uppercase", marginBottom: 10 }}>
            Threat Timeline
          </div>
          <ReactECharts option={timelineOption} style={{ height: 150 }} />
        </div>

        {/* Attack donut */}
        <div style={panel}>
          <div style={{ fontSize: 11, fontWeight: 700, color: "var(--text-muted)", letterSpacing: 1, textTransform: "uppercase", marginBottom: 10 }}>
            Attack Distribution
          </div>
          <ReactECharts option={donutOption} style={{ height: 150 }} />
        </div>
      </div>

      {/* Recent alerts + activity log row */}
      <div style={{ display: "grid", gridTemplateColumns: userRole === "admin" ? "1fr 400px" : "1fr", gap: 16 }}>
        {/* Recent alerts */}
        <div style={panel}>
          <div style={{ fontSize: 11, fontWeight: 700, color: "var(--text-muted)", letterSpacing: 1, textTransform: "uppercase", marginBottom: 14 }}>
            Recent Alerts
          </div>
          {recentAlerts.length === 0 && !isMonitoring ? (
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {[80, 65, 75, 60].map((w, i) => (
                <SkeletonBlock key={i} height="36px" className="skeleton" />
              ))}
            </div>
          ) : recentAlerts.length === 0 ? (
            <div style={{ color: "var(--text-muted)", fontSize: 13, textAlign: "center", padding: "24px 0" }}>
              No alerts — system is monitoring
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {recentAlerts.map((alert) => (
                <div
                  key={alert.id}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 10,
                    padding: "8px 12px",
                    background: "var(--bg-secondary)",
                    borderRadius: 8,
                    border: `1px solid ${SEVERITY_COLOUR[alert.severity] ?? "var(--border-color)"}22`,
                  }}
                >
                  <SeverityBadge severity={alert.severity} size="sm" />
                  {(() => {
                    const badgeColor =
                      alert.source === "Network"
                        ? { bg: "#1e3a5f", fg: "#60a5fa" }
                        : alert.source === "User"
                        ? { bg: "#1e1040", fg: "#a78bfa" }
                        : { bg: "#1a2a1a", fg: "#4ade80" };
                    return (
                      <span
                        style={{
                          background: badgeColor.bg,
                          color: badgeColor.fg,
                          borderRadius: 4,
                          padding: "1px 7px",
                          fontSize: 9,
                          fontWeight: 700,
                          letterSpacing: 0.5,
                          flexShrink: 0,
                        }}
                      >
                        {alert.source.toUpperCase()}
                      </span>
                    );
                  })()}
                  <span style={{ flex: 1, fontSize: 12, color: "var(--text-secondary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {alert.description}
                  </span>
                  <span style={{ color: "var(--text-muted)", fontSize: 11, flexShrink: 0 }}>{alert.time}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Activity Log — admin only */}
        {userRole === "admin" && (
          <div style={panel}>
            {/* Panel heading with pulsing green dot */}
            <div style={{ display: "flex", alignItems: "center", gap: 7, marginBottom: 14 }}>
              <span
                style={{
                  width: 7,
                  height: 7,
                  borderRadius: "50%",
                  background: "#22c55e",
                  boxShadow: "0 0 6px #22c55e",
                  display: "inline-block",
                  animation: "xdr-pulse 1.8s ease-in-out infinite",
                  flexShrink: 0,
                }}
              />
              <span style={{ fontSize: 11, fontWeight: 700, color: "var(--text-muted)", letterSpacing: 1, textTransform: "uppercase"}}>
                Activity Log
              </span>
            </div>

            {/* Scrollable entry list */}
            <div style={{ maxHeight: 360, overflowY: "auto", display: "flex", flexDirection: "column", gap: 5 }}>
              {activityLog.length === 0 ? (
                <div style={{ color: "var(--text-muted)", fontSize: 12, textAlign: "center", padding: "20px 0" }}>
                  No activity yet
                </div>
              ) : (
                activityLog.map((entry, idx) => {
                  const colour = ACTION_COLOUR(entry.action);
                  const label = ACTION_LABELS[entry.action] ?? entry.action;
                  const actor = entry.user ?? entry.user_id ?? "system";
                  const ts = entry.timestamp ?? entry.ts;
                  const timeStr = ts ? fmtTime(ts) : "—";
                  return (
                    <div
                      key={entry._id ?? `${entry.action}-${idx}`}
                      style={{
                        display: "flex",
                        alignItems: "flex-start",
                        gap: 8,
                        padding: "6px 8px",
                        background: "var(--bg-secondary)",
                        borderRadius: 7,
                        border: "1px solid var(--border-color)",
                      }}
                    >
                      {/* Action badge */}
                      <span
                        style={{
                          background: colour.bg,
                          color: colour.fg,
                          borderRadius: 4,
                          padding: "1px 6px",
                          fontSize: 9,
                          fontWeight: 700,
                          letterSpacing: 0.4,
                          flexShrink: 0,
                          whiteSpace: "nowrap",
                        }}
                      >
                        {label}
                      </span>

                      {/* User + IP + detail */}
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div
                          style={{
                            fontSize: 11,
                            color: "var(--text-secondary)",
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                          }}
                        >
                          {actor}
                        </div>
                        {entry.ip && (
                          <div style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "monospace" }}>
                            {entry.ip}
                          </div>
                        )}
                        {entry.detail && (
                          <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2, paddingLeft: 4, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                            {entry.detail}
                          </div>
                        )}
                      </div>

                      {/* Timestamp */}
                      <span style={{ fontSize: 10, color: "var(--text-muted)", flexShrink: 0, paddingTop: 1 }}>
                        {timeStr}
                      </span>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
