import React, { useState, useEffect, useCallback } from "react";
import { authAxios } from "../../services/authService";
import { BACKEND_URL } from "../../config";
import DualOrbitLoader from "../shared/DualOrbitLoader";

interface AgentStatus {
  name: string;
  key: string;
  description: string;
}

const AGENTS: AgentStatus[] = [
  { name: "Network Detection Agent",  key: "network_agent",  description: "Rule + Hybrid ML pipeline" },
  { name: "User Behavior Agent",       key: "user_agent",     description: "OC-SVM insider threat detection" },
  { name: "Fusion Engine",             key: "fusion_agent",   description: "Threat score aggregator" },
  { name: "SHAP Explainability",       key: "shap_agent",     description: "Feature importance explainer" },
  { name: "Malware Detection Agent",   key: "malware_agent",  description: "LightGBM EMBER file scanner" },
  { name: "System Monitor Agent",      key: "system_agent",   description: "LSTM + Behavioral (Process Behavior) system anomaly" },
  { name: "Sysmon Behavior Agent",     key: "sysmon_agent",   description: "Process behavior anomaly detector" },
];

interface HealthData {
  status?: string;
  mongo?: boolean;
  network_agent?: boolean | null;
  user_agent?: { running?: boolean; runtime_available?: boolean; interval_seconds?: number; last_result_summary?: unknown } | null;
  shap_agent?: boolean | null;
  monitoring?: boolean | null;
  ts?: string;
  [key: string]: unknown;
}

interface StorageData {
  mongo_ok?: boolean;
  collections?: Record<string, { count: number; cap: number; pct_full: number }>;
  [key: string]: unknown;
}

export default function SystemStatusView({ isMonitoring }: { isMonitoring: boolean }) {
  const [health, setHealth] = useState<HealthData | null>(null);
  const [storage, setStorage] = useState<StorageData | null>(null);
  const [healthError, setHealthError] = useState(false);
  const [storageError, setStorageError] = useState(false);
  const [lastPoll, setLastPoll] = useState<Date | null>(null);
  const [polling, setPolling] = useState(false);

  const fetchStatus = useCallback(async () => {
    setPolling(true);
    try {
      const res = await authAxios.get(`${BACKEND_URL}/health`, { timeout: 12000 });
      setHealth(res.data);
      setHealthError(false);
    } catch {
      setHealthError(true);
    }
    try {
      const res = await authAxios.get(`${BACKEND_URL}/storage-status`, { timeout: 8000 });
      setStorage(res.data);
      setStorageError(false);
    } catch {
      setStorageError(true);
    }
    setLastPoll(new Date());
    setPolling(false);
  }, []);

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 30000);
    return () => clearInterval(interval);
  }, [fetchStatus]);

  const coerceToDisplay = (val: unknown): string => {
    if (val === null || val === undefined) return "unknown";
    if (typeof val === "boolean") return val ? "ok" : "error";
    if (typeof val === "object") {
      const obj = val as Record<string, unknown>;
      if ("running" in obj) return obj.running ? "running" : "stopped";
      return "active";
    }
    return String(val);
  };

  const getStatusColor = (val: unknown): string => {
    const v = coerceToDisplay(val).toLowerCase();
    if (v === "ok" || v === "connected" || v === "running" || v === "online" || v === "active") return "#22c55e";
    if (v === "error" || v === "disconnected" || v === "down" || v === "stopped") return "#dc2626";
    if (v === "degraded" || v === "warning") return "#d97706";
    return "var(--text-secondary)";
  };

  const panel: React.CSSProperties = {
    background: "var(--bg-card)",
    border: "1px solid var(--border-color)",
    borderRadius: 14,
    padding: 20,
  };

  const COLLECTIONS = [
    "logs", "features", "predictions", "alerts",
    "shap_explanations", "commands", "endpoints",
  ];

  return (
    <div style={{ padding: 24, display: "flex", flexDirection: "column", gap: 18 }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div>
          <h2 style={{ margin: 0, fontSize: 20, fontWeight: 800, color: "var(--text-primary)", letterSpacing: -0.5 }}>
            System Status
          </h2>
          <p style={{ margin: "4px 0 0", color: "var(--text-secondary)", fontSize: 13 }}>
            Backend health, agent status, and MongoDB storage
          </p>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          {lastPoll && (
            <span style={{ color: "var(--text-muted)", fontSize: 11 }}>
              Last polled: {lastPoll.toLocaleTimeString()}
            </span>
          )}
          <button
            onClick={fetchStatus}
            disabled={polling}
            style={{
              padding: "7px 18px",
              borderRadius: 8,
              border: "1px solid var(--border-color)",
              background: polling ? "var(--bg-card)" : "var(--bg-secondary)",
              color: polling ? "var(--text-muted)" : "var(--text-muted)",
              fontSize: 12,
              cursor: polling ? "not-allowed" : "pointer",
              fontWeight: 600,
              transition: "all 0.15s",
            }}
          >
            {polling ? "Polling..." : "Refresh"}
          </button>
        </div>
      </div>

      {/* Backend + Core grid */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
        {/* Backend Health */}
        <div style={panel}>
          <div style={{ fontSize: 11, fontWeight: 700, color: "var(--accent-amber)", letterSpacing: 1.5, textTransform: "uppercase", marginBottom: 16 }}>
            Backend Health
          </div>
          {healthError ? (
            <div
              style={{
                background: "rgba(220,38,38,0.10)",
                border: "1px solid rgba(220,38,38,0.35)",
                borderRadius: 8,
                padding: "12px 16px",
                color: "#ef4444",
                fontSize: 13,
              }}
            >
              Could not reach backend at {BACKEND_URL}/health — ensure the FastAPI server is running.
            </div>
          ) : health ? (
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {Object.entries(health).map(([key, val]) => {
                const display = coerceToDisplay(val);
                const color = getStatusColor(val);
                return (
                  <div
                    key={key}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      padding: "8px 12px",
                      background: "var(--bg-secondary)",
                      borderRadius: 8,
                    }}
                  >
                    <span style={{ fontSize: 12, color: "var(--text-muted)", textTransform: "capitalize" }}>
                      {key.replace(/_/g, " ")}
                    </span>
                    <span
                      style={{
                        display: "inline-flex",
                        alignItems: "center",
                        gap: 6,
                        fontSize: 11,
                        fontWeight: 700,
                        color,
                        letterSpacing: 0.5,
                        textTransform: "uppercase",
                      }}
                    >
                      <span
                        style={{
                          width: 7,
                          height: 7,
                          borderRadius: "50%",
                          background: color,
                          boxShadow: `0 0 5px ${color}88`,
                          display: "inline-block",
                        }}
                      />
                      {display}
                    </span>
                  </div>
                );
              })}
            </div>
          ) : (
            <div style={{ display: "flex", justifyContent: "center", padding: "24px 0" }}>
              <DualOrbitLoader size={40} label="Loading system status..." />
            </div>
          )}
        </div>

        {/* Agent Status */}
        <div style={panel}>
          <div style={{ fontSize: 11, fontWeight: 700, color: "var(--accent-amber)", letterSpacing: 1.5, textTransform: "uppercase", marginBottom: 16 }}>
            Detection Agents
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {AGENTS.map((agent) => {
              const backendVal = health?.[agent.key];
              const backendDisplay = coerceToDisplay(backendVal);
              const isOk = backendVal !== undefined && backendVal !== null
                ? ["ok", "running", "online", "active"].includes(backendDisplay.toLowerCase())
                : agent.key === "network_agent" || agent.key === "user_agent" || agent.key === "fusion_agent"
                ? isMonitoring
                : false;
              const color = isOk ? "#22c55e" : "var(--text-muted)";

              return (
                <div
                  key={agent.key}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 12,
                    padding: "10px 14px",
                    background: "var(--bg-secondary)",
                    borderRadius: 8,
                    border: `1px solid ${isOk ? "#22c55e1a" : "var(--bg-card)"}`,
                  }}
                >
                  <span
                    style={{
                      width: 8,
                      height: 8,
                      borderRadius: "50%",
                      background: color,
                      boxShadow: isOk ? `0 0 8px ${color}` : "none",
                      animation: isOk ? "xdr-pulse 2s ease-in-out infinite" : "none",
                      display: "inline-block",
                      flexShrink: 0,
                    }}
                  />
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 12, fontWeight: 600, color: isOk ? "var(--text-primary)" : "var(--text-secondary)" }}>
                      {agent.name}
                    </div>
                    <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 1 }}>{agent.description}</div>
                  </div>
                  <span
                    style={{
                      fontSize: 10,
                      fontWeight: 700,
                      color,
                      letterSpacing: 0.5,
                      textTransform: "uppercase",
                    }}
                  >
                    {backendVal !== undefined && backendVal !== null ? backendDisplay : (isOk ? "RUNNING" : "IDLE")}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* External Tools */}
      <div style={panel}>
        <div style={{ fontSize: 11, fontWeight: 700, color: "var(--accent-amber)", letterSpacing: 1.5, textTransform: "uppercase", marginBottom: 16 }}>
          External Capture Tools
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: 10 }}>
          {[
            {
              name: "Suricata IDS",
              status: coerceToDisplay(health?.suricata ?? "unknown"),
              description: "Network traffic capture & IDS alerts",
              note: "Requires admin privileges",
            },
            {
              name: "Winlogbeat",
              status: coerceToDisplay(health?.winlogbeat ?? "unknown"),
              description: "Windows event log shipper",
              note: "Writes to C:\\XDR_Logs\\",
            },
            {
              name: "MongoDB Atlas",
              status: coerceToDisplay(health?.mongo ?? "unknown"),
              description: "Central storage — all collections",
              note: "cloud.mongodb.com",
            },
            {
              name: "TShark / Zeek",
              status: "unknown",
              description: "Protocol-level packet analysis",
              note: "Optional capture tool",
            },
            {
              name: "Sysmon",
              status: coerceToDisplay(health?.sysmon_agent ?? "unknown"),
              description: "Process/DLL/Registry event capture",
              note: "Install: sysmon64.exe -accepteula -i sysmonconfig.xml",
            },
          ].map(({ name, status, description, note }) => {
            const color = getStatusColor(status);
            return (
              <div
                key={name}
                style={{
                  background: "var(--bg-secondary)",
                  borderRadius: 10,
                  padding: "14px 16px",
                  border: `1px solid ${color}22`,
                  borderTop: `3px solid ${color}`,
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                  <span
                    style={{
                      width: 7,
                      height: 7,
                      borderRadius: "50%",
                      background: color,
                      boxShadow: color !== "var(--text-secondary)" ? `0 0 6px ${color}` : "none",
                      display: "inline-block",
                    }}
                  />
                  <span style={{ fontSize: 13, fontWeight: 700, color: "var(--text-primary)" }}>{name}</span>
                </div>
                <div style={{ fontSize: 11, color: "var(--text-secondary)", marginBottom: 4 }}>{description}</div>
                <div style={{ fontSize: 10, color: "var(--text-muted)" }}>{note}</div>
                <div style={{ marginTop: 8, fontSize: 10, fontWeight: 700, color, textTransform: "uppercase", letterSpacing: 0.5 }}>
                  {status === "unknown" ? "STATUS UNKNOWN" : status.toUpperCase()}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* MongoDB Storage */}
      <div style={panel}>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            marginBottom: 16,
          }}
        >
          <div style={{ fontSize: 11, fontWeight: 700, color: "var(--accent-amber)", letterSpacing: 1.5, textTransform: "uppercase" }}>
            MongoDB Collections
          </div>
          {storage?.storage_full ? (
            <span
              style={{
                background: "rgba(220,38,38,0.10)",
                color: "#ef4444",
                borderRadius: 20,
                padding: "3px 12px",
                fontSize: 10,
                fontWeight: 700,
                border: "1px solid rgba(220,38,38,0.35)",
              }}
            >
              STORAGE FULL — Auto-trim active
            </span>
          ) : null}
        </div>

        {storageError ? (
          <div style={{ color: "var(--text-secondary)", fontSize: 13 }}>
            Could not reach /storage-status endpoint.
          </div>
        ) : storage ? (
          <div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(160px, 1fr))", gap: 8 }}>
              {COLLECTIONS.map((col) => {
                const colData = storage.collections?.[col];
                const count = colData?.count ?? 0;
                const cap = colData?.cap ?? 0;
                const pct = colData?.pct_full ?? 0;
                return (
                  <div
                    key={col}
                    style={{
                      background: "var(--bg-secondary)",
                      borderRadius: 8,
                      padding: "10px 14px",
                      border: "1px solid var(--border-color)",
                    }}
                  >
                    <div style={{ fontSize: 11, fontWeight: 600, color: "var(--text-muted)", marginBottom: 6 }}>
                      {col}
                    </div>
                    <div style={{ fontSize: 18, fontWeight: 800, color: "var(--text-primary)", marginBottom: 2 }}>
                      {count.toLocaleString()}
                    </div>
                    <div style={{ fontSize: 11, color: "var(--text-secondary)", marginBottom: 4 }}>
                      cap: {cap > 0 ? cap.toLocaleString() : "—"}
                    </div>
                    <div
                      style={{
                        height: 3,
                        background: "var(--bg-card)",
                        borderRadius: 2,
                        overflow: "hidden",
                      }}
                    >
                      <div
                        style={{
                          height: "100%",
                          width: `${Math.min(100, pct)}%`,
                          background: pct > 80 ? "#ef4444" : pct > 50 ? "#f59e0b" : "#3b82f6",
                          borderRadius: 2,
                        }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        ) : (
          <div style={{ color: "var(--text-muted)", fontSize: 13 }}>Loading storage data...</div>
        )}
      </div>

    </div>
  );
}
