// SettingsView.tsx
// Settings panel — General, Security, Integration Status, Detection Thresholds, Alert Settings.
// Visible only to admin and analyst roles.

import React, { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { authAxios } from "../../services/authService";
import { useAuth } from "../../context/AuthContext";
import { BACKEND_URL } from "../../config";

// ── Shared styles ─────────────────────────────────────────────────────────────
const SECTION_LABEL: React.CSSProperties = {
  fontFamily: "'Fira Code', monospace",
  fontSize: 9,
  fontWeight: 700,
  letterSpacing: 1.8,
  textTransform: "uppercase",
  color: "var(--text-secondary)",
};

function Panel({
  children,
  accent = "#3b82f6",
}: {
  children: React.ReactNode;
  accent?: string;
}) {
  return (
    <div
      style={{
        background: "var(--bg-card)",
        borderLeft: `4px solid ${accent}`,
        borderRadius: 12,
        padding: "20px 24px",
        position: "relative",
        overflow: "hidden",
      }}
    >
      <div
        style={{
          position: "absolute",
          top: -20,
          right: -20,
          width: 80,
          height: 80,
          borderRadius: "50%",
          background: `${accent}0d`,
          pointerEvents: "none",
        }}
      />
      {children}
    </div>
  );
}

// ── Accordion Section ─────────────────────────────────────────────────────────
function AccordionSection({
  title,
  accent,
  icon,
  defaultOpen = false,
  children,
}: {
  title: string;
  accent: string;
  icon: string;
  defaultOpen?: boolean;
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <div
      style={{
        background: "var(--bg-card)",
        borderLeft: `4px solid ${open ? accent : "var(--border-color)"}`,
        borderRadius: 12,
        overflow: "hidden",
        transition: "border-color 0.2s",
      }}
    >
      {/* Header */}
      <button
        onClick={() => setOpen((o) => !o)}
        style={{
          width: "100%",
          display: "flex",
          alignItems: "center",
          gap: 12,
          padding: "18px 24px",
          background: "transparent",
          border: "none",
          cursor: "pointer",
          textAlign: "left",
        }}
      >
        <span style={{ fontSize: 18, color: open ? accent : "var(--text-secondary)", transition: "color 0.2s" }}>
          {icon}
        </span>
        <span
          style={{
            flex: 1,
            fontSize: 13,
            fontWeight: 700,
            color: open ? "var(--text-primary)" : "var(--text-muted)",
            transition: "color 0.2s",
          }}
        >
          {title}
        </span>
        <span
          style={{
            fontSize: 14,
            color: "var(--text-secondary)",
            transition: "transform 0.22s",
            display: "inline-block",
            transform: open ? "rotate(90deg)" : "rotate(0deg)",
          }}
        >
          ▶
        </span>
      </button>

      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            key="body"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.22 }}
            style={{ overflow: "hidden" }}
          >
            <div
              style={{
                padding: "0 24px 20px",
                borderTop: "1px solid var(--border-color)",
                paddingTop: 16,
              }}
            >
              {children}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// ── Toggle switch ─────────────────────────────────────────────────────────────
function Toggle({
  value,
  onChange,
  label,
  sub,
  accent = "#3b82f6",
}: {
  value: boolean;
  onChange: (v: boolean) => void;
  label: string;
  sub?: string;
  accent?: string;
}) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        gap: 16,
        padding: "12px 0",
        borderBottom: "1px solid var(--border-color)",
      }}
    >
      <div>
        <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text-primary)" }}>{label}</div>
        {sub && <div style={{ fontSize: 11, color: "var(--text-secondary)", marginTop: 2 }}>{sub}</div>}
      </div>
      <button
        onClick={() => onChange(!value)}
        style={{
          width: 44,
          height: 24,
          borderRadius: 12,
          border: "none",
          background: value ? accent : "var(--bg-secondary)",
          cursor: "pointer",
          position: "relative",
          transition: "background 0.2s",
          flexShrink: 0,
          boxShadow: value ? `0 0 8px ${accent}55` : `inset 0 0 0 1px var(--border-color)`,
        }}
      >
        <span
          style={{
            position: "absolute",
            top: 3,
            left: value ? 23 : 3,
            width: 18,
            height: 18,
            borderRadius: "50%",
            background: "#fff",
            transition: "left 0.2s",
            display: "block",
          }}
        />
      </button>
    </div>
  );
}

// ── Threshold slider row ──────────────────────────────────────────────────────
function SliderRow({
  label,
  value,
  min,
  max,
  step,
  onChange,
  accent,
  disabled,
}: {
  label: string;
  value: number;
  min: number;
  max: number;
  step: number;
  onChange: (v: number) => void;
  accent: string;
  disabled?: boolean;
}) {
  return (
    <div
      style={{
        padding: "12px 0",
        borderBottom: "1px solid var(--border-color)",
        opacity: disabled ? 0.5 : 1,
      }}
    >
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          marginBottom: 8,
        }}
      >
        <span style={{ fontSize: 12, fontWeight: 600, color: "var(--text-primary)" }}>{label}</span>
        <span
          style={{
            fontFamily: "'Fira Code', monospace",
            fontSize: 12,
            fontWeight: 700,
            color: accent,
          }}
        >
          {value.toFixed(2)}
        </span>
      </div>
      <input
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        disabled={disabled}
        onChange={(e) => onChange(parseFloat(e.target.value))}
        style={{
          width: "100%",
          accentColor: accent,
          cursor: disabled ? "not-allowed" : "pointer",
        }}
      />
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          marginTop: 4,
        }}
      >
        <span style={{ fontSize: 10, color: "var(--text-secondary)" }}>{min}</span>
        <span style={{ fontSize: 10, color: "var(--text-secondary)" }}>{max}</span>
      </div>
    </div>
  );
}

// ── Integration status card ───────────────────────────────────────────────────
interface HealthData {
  monitoring?: boolean;
  mongo?: boolean;
  // Flat boolean keys (legacy shape — kept for backward compat)
  suricata_ok?: boolean;
  sysmon_ok?: boolean;
  winlogbeat_ok?: boolean;
  // Nested agent status objects returned by the current backend /health endpoint
  suricata?: { status?: string; running?: boolean };
  sysmon_agent?: { status?: string; running?: boolean };
  winlogbeat?: { status?: string; running?: boolean };
  network_agent?: { status?: string; running?: boolean };
  user_agent?: { status?: string; running?: boolean };
  system_agent?: { status?: string; running?: boolean };
  malware_agent?: { status?: string; running?: boolean };
  [key: string]: unknown;
}

function StatusBadge({ value }: { value: boolean | undefined }) {
  if (value === undefined)
    return (
      <span
        style={{
          padding: "3px 10px",
          borderRadius: 12,
          background: "rgba(245,158,11,0.12)",
          color: "var(--accent-amber)",
          border: "1px solid rgba(245,158,11,0.3)",
          fontSize: 11,
          fontWeight: 700,
        }}
      >
        UNKNOWN ?
      </span>
    );
  return value ? (
    <span
      style={{
        padding: "3px 10px",
        borderRadius: 12,
        background: "rgba(34,197,94,0.12)",
        color: "#22c55e",
        border: "1px solid rgba(34,197,94,0.3)",
        fontSize: 11,
        fontWeight: 700,
      }}
    >
      RUNNING
    </span>
  ) : (
    <span
      style={{
        padding: "3px 10px",
        borderRadius: 12,
        background: "rgba(239,68,68,0.12)",
        color: "#ef4444",
        border: "1px solid rgba(239,68,68,0.3)",
        fontSize: 11,
        fontWeight: 700,
      }}
    >
      STOPPED
    </span>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
interface SettingsViewProps {
  audioEnabled: boolean;
  onEnableAudio: () => void;
  onDisableAudio?: () => void;
}

export default function SettingsView({ audioEnabled, onEnableAudio, onDisableAudio }: SettingsViewProps) {
  const { user } = useAuth();

  // ── Role guard ──────────────────────────────────────────────────────────────
  if (user?.role === "viewer") {
    return (
      <div style={{ padding: 32, display: "flex", justifyContent: "center" }}>
        <Panel accent="#ef4444">
          <div
            style={{
              textAlign: "center",
              padding: "24px 0",
              maxWidth: 400,
              margin: "0 auto",
            }}
          >
            <span style={{ fontSize: 36 }}>🔒</span>
            <h3
              style={{
                color: "#ef4444",
                margin: "12px 0 8px",
                fontWeight: 800,
                letterSpacing: 1,
              }}
            >
              ACCESS RESTRICTED
            </h3>
            <p style={{ color: "var(--text-secondary)", fontSize: 13 }}>
              Settings are available to admin and analyst roles only. Contact your
              administrator if you require elevated access.
            </p>
          </div>
        </Panel>
      </div>
    );
  }

  return <SettingsContent audioEnabled={audioEnabled} onEnableAudio={onEnableAudio} onDisableAudio={onDisableAudio} />;
}

// ── Inner content (only rendered for admin/analyst) ───────────────────────────
function SettingsContent({
  audioEnabled,
  onEnableAudio,
  onDisableAudio,
}: SettingsViewProps) {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  // ── A. General Settings ─────────────────────────────────────────────────────
  const [animations, setAnimations] = useState(() => {
    const stored = localStorage.getItem("xdr_animations");
    return stored === null ? true : stored === "true";
  });

  const handleAnimationsToggle = useCallback((v: boolean) => {
    setAnimations(v);
    localStorage.setItem("xdr_animations", String(v));
  }, []);

  // Sound alerts audit helper — fire-and-forget, never blocks the toggle
  const auditSoundToggle = useCallback((enabled: boolean) => {
    authAxios.post(`${BACKEND_URL}/audit/client-event`, {
      action: enabled ? "sound_alerts_enabled" : "sound_alerts_disabled",
      detail: `Sound alerts ${enabled ? "enabled" : "disabled"} by user`,
      status: "success",
    }).catch(() => {});
  }, []);

  // ── B. Security Settings ─────────────────────────────────────────────────────
  const [showPasswordForm, setShowPasswordForm] = useState(false);
  const [pwCurrent, setPwCurrent] = useState("");
  const [pwNew, setPwNew] = useState("");
  const [pwConfirm, setPwConfirm] = useState("");
  const [pwMsg, setPwMsg] = useState<{ type: "success" | "error" | "info"; text: string } | null>(
    null
  );

  const handleChangePassword = useCallback(async () => {
    if (pwNew !== pwConfirm) {
      setPwMsg({ type: "error", text: "New passwords do not match." });
      return;
    }
    try {
      await authAxios.post("/auth/change-password", {
        current_password: pwCurrent,
        new_password: pwNew,
      });
      setPwMsg({ type: "success", text: "Password changed successfully." });
      setPwCurrent("");
      setPwNew("");
      setPwConfirm("");
      setShowPasswordForm(false);
    } catch {
      setPwMsg({ type: "info", text: "Feature coming soon — endpoint not yet implemented." });
    }
    setTimeout(() => setPwMsg(null), 4000);
  }, [pwCurrent, pwNew, pwConfirm]);

  // ── C. Integration Status ────────────────────────────────────────────────────
  const [health, setHealth] = useState<HealthData | null>(null);
  const [healthLoading, setHealthLoading] = useState(false);

  const fetchHealth = useCallback(async () => {
    setHealthLoading(true);
    try {
      const res = await authAxios.get(`${BACKEND_URL}/health`, { timeout: 12000 });
      setHealth(res.data);
    } catch {
      setHealth(null);
    } finally {
      setHealthLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchHealth();
    const interval = setInterval(fetchHealth, 30000);
    return () => clearInterval(interval);
  }, [fetchHealth]);

  // ── D. Detection Thresholds ──────────────────────────────────────────────────
  const [thresholds, setThresholds] = useState({
    network: 0.7,
    system: 0.5,
    fusionCritical: 0.85,
    fusionHigh: 0.7,
    malware: 0.70,
    userBehavior: 0.80,
  });
  const [thresholdMsg, setThresholdMsg] = useState<{
    type: "success" | "error";
    text: string;
  } | null>(null);
  const [thresholdLoading, setThresholdLoading] = useState(false);
  // autoResponse declared here (before handleApplyThresholds) to avoid TDZ error
  const [autoResponse, setAutoResponse] = useState(
    () => localStorage.getItem("xdr_auto_response") === "true"
  );

  // Hydrate sliders and toggles from persisted backend values on mount (admin only).
  useEffect(() => {
    if (!isAdmin) return;
    authAxios.get("/settings").then((res) => {
      const t = res.data?.thresholds;
      if (!t) return;
      setThresholds({
        network: t.network_anomaly_threshold ?? 0.7,
        system: t.system_anomaly_threshold ?? 0.5,
        fusionCritical: t.fusion_critical_threshold ?? 0.85,
        fusionHigh: t.fusion_high_threshold ?? 0.7,
        malware: t.malware_threshold ?? 0.70,
        userBehavior: t.user_behavior_threshold ?? 0.80,
      });
      // After existing threshold loading:
      if (t.auto_response_enabled !== undefined) {
        setAutoResponse(Boolean(t.auto_response_enabled));
      }
    }).catch(() => {
      // Silently ignore — sliders fall back to defaults if endpoint is unavailable.
    });
  }, [isAdmin]);

  const handleApplyThresholds = useCallback(async () => {
    setThresholdLoading(true);
    try {
      await authAxios.post("/settings/thresholds", {
        network_anomaly_threshold: thresholds.network,
        system_anomaly_threshold: thresholds.system,
        fusion_critical_threshold: thresholds.fusionCritical,
        fusion_high_threshold: thresholds.fusionHigh,
        malware_threshold: thresholds.malware,
        user_behavior_threshold: thresholds.userBehavior,
        auto_response_enabled: autoResponse,
      });
      setThresholdMsg({ type: "success", text: "Thresholds applied successfully." });
    } catch {
      setThresholdMsg({ type: "error", text: "Failed to apply thresholds. Check permissions or backend status." });
    } finally {
      setThresholdLoading(false);
      setTimeout(() => setThresholdMsg(null), 4000);
    }
  }, [thresholds, autoResponse]);

  // ── E. Alert Settings ────────────────────────────────────────────────────────
  const [minSeverity, setMinSeverity] = useState(
    () => localStorage.getItem("xdr_min_severity") ?? "LOW"
  );

  const handleMinSeverityChange = useCallback((v: string) => {
    setMinSeverity(v);
    localStorage.setItem("xdr_min_severity", v);
  }, []);

  const handleAutoResponseToggle = useCallback((v: boolean) => {
    setAutoResponse(v);
    localStorage.setItem("xdr_auto_response", String(v));
    // Sync to backend so the server respects this setting
    authAxios.post(`${BACKEND_URL}/settings/thresholds`, {
      network_anomaly_threshold: thresholds.network,
      system_anomaly_threshold:  thresholds.system,
      fusion_critical_threshold: thresholds.fusionCritical,
      fusion_high_threshold:     thresholds.fusionHigh,
      malware_threshold:         thresholds.malware,
      user_behavior_threshold:   thresholds.userBehavior,
      auto_response_enabled:     v,
    }).catch(() => {});
  }, [thresholds]);

  const SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
  const SEV_COLORS: Record<string, string> = {
    LOW: "#22c55e",
    MEDIUM: "#f59e0b",
    HIGH: "#ef4444",
    CRITICAL: "#dc2626",
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.28 }}
      style={{
        padding: 24,
        maxWidth: 800,
        margin: "0 auto",
        display: "flex",
        flexDirection: "column",
        gap: 16,
      }}
    >
      {/* Page header */}
      <div style={{ marginBottom: 8 }}>
        <h2
          style={{
            margin: 0,
            fontSize: 20,
            fontWeight: 800,
            color: "var(--text-primary)",
            letterSpacing: -0.5,
          }}
        >
          Settings
        </h2>
        <p style={{ margin: "4px 0 0", color: "var(--text-secondary)", fontSize: 13 }}>
          System configuration — changes take effect immediately unless otherwise noted.
        </p>
      </div>

      {/* A. General Settings */}
      <AccordionSection
        title="General Settings"
        accent="#3b82f6"
        icon="◈"
        defaultOpen
      >
        <Toggle
          value={animations}
          onChange={handleAnimationsToggle}
          label="UI Animations"
          sub="Framer Motion entry/exit animations across all views"
          accent="#3b82f6"
        />

        {/* Sound Alerts row */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: 16,
            padding: "12px 0",
            borderBottom: "1px solid var(--border-color)",
          }}
        >
          <div>
            <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text-primary)" }}>Sound Alerts</div>
            <div style={{ fontSize: 11, color: "var(--text-secondary)", marginTop: 2 }}>
              Siren audio on HIGH/CRITICAL threats — browser consent required
            </div>
          </div>
          {audioEnabled ? (
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span
                style={{
                  padding: "3px 10px",
                  borderRadius: 12,
                  background: "rgba(34,197,94,0.12)",
                  color: "#22c55e",
                  border: "1px solid rgba(34,197,94,0.3)",
                  fontSize: 11,
                  fontWeight: 700,
                }}
              >
                ENABLED
              </span>
              <button
                onClick={() => { onDisableAudio?.(); auditSoundToggle(false); }}
                style={{
                  padding: "6px 14px",
                  borderRadius: 8,
                  border: "1px solid rgba(239,68,68,0.3)",
                  background: "rgba(239,68,68,0.08)",
                  color: "#ef4444",
                  fontSize: 11,
                  fontWeight: 700,
                  cursor: "pointer",
                  letterSpacing: 0.5,
                }}
              >
                Disable
              </button>
            </div>
          ) : (
            <button
              onClick={() => { onEnableAudio(); auditSoundToggle(true); }}
              style={{
                padding: "7px 16px",
                borderRadius: 8,
                border: "1px solid rgba(245,158,11,0.4)",
                background: "rgba(245,158,11,0.1)",
                color: "var(--accent-amber)",
                fontSize: 12,
                fontWeight: 700,
                cursor: "pointer",
                letterSpacing: 0.5,
              }}
            >
              Enable Sound
            </button>
          )}
        </div>
      </AccordionSection>

      {/* B. Security Settings */}
      <AccordionSection title="Security Settings" accent="#a78bfa" icon="◉">
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            gap: 0,
          }}
        >
          <div
            style={{
              padding: "12px 0",
              borderBottom: "1px solid var(--border-color)",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>MFA Status</span>
            <span
              style={{
                padding: "3px 10px",
                borderRadius: 12,
                background: user?.two_factor_enabled
                  ? "rgba(34,197,94,0.12)"
                  : "rgba(239,68,68,0.12)",
                color: user?.two_factor_enabled ? "#22c55e" : "#ef4444",
                border: `1px solid ${user?.two_factor_enabled ? "rgba(34,197,94,0.3)" : "rgba(239,68,68,0.3)"}`,
                fontSize: 11,
                fontWeight: 700,
              }}
            >
              {user?.two_factor_enabled ? "Enabled" : "Disabled"}
            </span>
          </div>

          <div
            style={{
              padding: "12px 0",
              borderBottom: "1px solid var(--border-color)",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>Last Login</span>
            <span
              style={{
                fontFamily: "'Fira Code', monospace",
                fontSize: 11,
                color: "var(--text-muted)",
              }}
            >
              {user?.last_login
                ? new Date(user.last_login).toLocaleString()
                : "Not available"}
            </span>
          </div>

          <div
            style={{
              padding: "12px 0",
              borderBottom: "1px solid var(--border-color)",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>Session Tokens</span>
            <span style={{ fontSize: 11, color: "var(--text-secondary)" }}>
              Access: 15 min / Refresh: 7 days
            </span>
          </div>

          <div style={{ padding: "14px 0" }}>
            <button
              onClick={() => setShowPasswordForm((v) => !v)}
              style={{
                padding: "8px 16px",
                borderRadius: 8,
                border: "1px solid #a78bfa44",
                background: "rgba(167,139,250,0.07)",
                color: "#a78bfa",
                fontSize: 12,
                fontWeight: 700,
                cursor: "pointer",
                letterSpacing: 0.5,
              }}
            >
              {showPasswordForm ? "Cancel" : "Change Password"}
            </button>

            <AnimatePresence>
              {showPasswordForm && (
                <motion.div
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: "auto", opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  transition={{ duration: 0.2 }}
                  style={{ overflow: "hidden", marginTop: 14 }}
                >
                  <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                    {[
                      { label: "Current Password", value: pwCurrent, set: setPwCurrent },
                      { label: "New Password", value: pwNew, set: setPwNew },
                      { label: "Confirm New Password", value: pwConfirm, set: setPwConfirm },
                    ].map(({ label, value, set }) => (
                      <div key={label}>
                        <label
                          style={{ fontSize: 11, color: "var(--text-muted)", display: "block", marginBottom: 4 }}
                        >
                          {label}
                        </label>
                        <input
                          type="password"
                          value={value}
                          onChange={(e) => set(e.target.value)}
                          style={{
                            width: "100%",
                            padding: "9px 12px",
                            borderRadius: 8,
                            border: "1px solid var(--border-color)",
                            background: "var(--bg-primary)",
                            color: "var(--text-primary)",
                            fontSize: 13,
                            boxSizing: "border-box",
                            outline: "none",
                          }}
                        />
                      </div>
                    ))}
                    <button
                      onClick={handleChangePassword}
                      style={{
                        padding: "9px 20px",
                        borderRadius: 8,
                        border: "none",
                        background: "linear-gradient(135deg, #a78bfa, #7c3aed)",
                        color: "#fff",
                        fontSize: 12,
                        fontWeight: 700,
                        cursor: "pointer",
                        alignSelf: "flex-start",
                      }}
                    >
                      Update Password
                    </button>
                  </div>
                  {pwMsg && (
                    <div
                      style={{
                        marginTop: 10,
                        padding: "8px 12px",
                        borderRadius: 8,
                        background:
                          pwMsg.type === "success"
                            ? "rgba(34,197,94,0.1)"
                            : pwMsg.type === "error"
                            ? "rgba(239,68,68,0.1)"
                            : "rgba(59,130,246,0.1)",
                        color:
                          pwMsg.type === "success"
                            ? "#22c55e"
                            : pwMsg.type === "error"
                            ? "#ef4444"
                            : "#3b82f6",
                        fontSize: 12,
                        fontWeight: 600,
                      }}
                    >
                      {pwMsg.text}
                    </div>
                  )}
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </AccordionSection>

      {/* C. Integration Status */}
      <AccordionSection title="Integration Status" accent="#22c55e" icon="◫">
        <div
          style={{
            display: "flex",
            justifyContent: "flex-end",
            marginBottom: 12,
          }}
        >
          <button
            onClick={fetchHealth}
            disabled={healthLoading}
            style={{
              padding: "6px 14px",
              borderRadius: 8,
              border: "1px solid var(--border-color)",
              background: "var(--bg-primary)",
              color: "var(--text-muted)",
              fontSize: 11,
              fontWeight: 700,
              cursor: healthLoading ? "not-allowed" : "pointer",
            }}
          >
            {healthLoading ? "Refreshing..." : "Refresh"}
          </button>
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(180px, 1fr))",
            gap: 10,
          }}
        >
          {[
            { label: "Suricata",   icon: "◬", resolve: (h: HealthData) => h.suricata?.running ?? h.suricata_ok },
            { label: "Sysmon",     icon: "◫", resolve: (h: HealthData) => h.sysmon_agent?.running ?? h.sysmon_ok },
            { label: "Winlogbeat", icon: "⬡", resolve: (h: HealthData) => h.winlogbeat?.running ?? h.winlogbeat_ok },
            { label: "MongoDB",    icon: "▣", resolve: (h: HealthData) => h.mongo as boolean | undefined },
          ].map(({ label, icon, resolve }) => {
            const val = health ? resolve(health) : undefined;
            return (
              <div
                key={label}
                style={{
                  background: "var(--bg-primary)",
                  border: "1px solid var(--border-color)",
                  borderRadius: 10,
                  padding: "14px 16px",
                  display: "flex",
                  flexDirection: "column",
                  gap: 10,
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ fontSize: 16, color: "var(--text-secondary)" }}>{icon}</span>
                  <span style={{ fontSize: 12, fontWeight: 700, color: "var(--text-primary)" }}>
                    {label}
                  </span>
                </div>
                <StatusBadge value={val} />
              </div>
            );
          })}
        </div>
      </AccordionSection>

      {/* D. Detection Thresholds */}
      <AccordionSection title="Detection Thresholds" accent="#f59e0b" icon="◈">
        {!isAdmin && (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              padding: "10px 14px",
              borderRadius: 8,
              background: "rgba(245,158,11,0.07)",
              border: "1px solid rgba(245,158,11,0.2)",
              marginBottom: 16,
              fontSize: 12,
              color: "var(--accent-amber)",
              fontWeight: 600,
            }}
          >
            <span>🔒</span>
            Read-only — Admin privileges required to adjust thresholds.
          </div>
        )}

        <SliderRow
          label="Network Anomaly Threshold"
          value={thresholds.network}
          min={0.4}
          max={0.9}
          step={0.05}
          onChange={(v) => setThresholds((t) => ({ ...t, network: v }))}
          accent="#3b82f6"
          disabled={!isAdmin}
        />
        <SliderRow
          label="System Anomaly Threshold"
          value={thresholds.system}
          min={0.35}
          max={0.85}
          step={0.05}
          onChange={(v) => setThresholds((t) => ({ ...t, system: v }))}
          accent="#a78bfa"
          disabled={!isAdmin}
        />
        <SliderRow
          label="Fusion CRITICAL Threshold"
          value={thresholds.fusionCritical}
          min={0.7}
          max={0.95}
          step={0.05}
          onChange={(v) => setThresholds((t) => ({ ...t, fusionCritical: v }))}
          accent="#ef4444"
          disabled={!isAdmin}
        />
        <SliderRow
          label="Fusion HIGH Threshold"
          value={thresholds.fusionHigh}
          min={0.5}
          max={0.85}
          step={0.05}
          onChange={(v) => setThresholds((t) => ({ ...t, fusionHigh: v }))}
          accent="#f59e0b"
          disabled={!isAdmin}
        />
        <SliderRow
          label="Malware Detection Threshold"
          value={thresholds.malware}
          min={0.30}
          max={0.95}
          step={0.05}
          onChange={(v) => setThresholds((t) => ({ ...t, malware: v }))}
          accent="#dc2626"
          disabled={!isAdmin}
        />
        <div style={{ fontSize: 11, color: "var(--text-secondary)", marginTop: -8, paddingBottom: 4 }}>
          Minimum confidence score to flag a file as malicious
        </div>
        <SliderRow
          label="User Behavior Anomaly Threshold"
          value={thresholds.userBehavior}
          min={0.30}
          max={0.95}
          step={0.05}
          onChange={(v) => setThresholds((t) => ({ ...t, userBehavior: v }))}
          accent="#f97316"
          disabled={!isAdmin}
        />
        <div style={{ fontSize: 11, color: "var(--text-secondary)", marginTop: -8, paddingBottom: 4 }}>
          Minimum anomaly score to flag user activity
        </div>

        {isAdmin && (
          <div style={{ marginTop: 16, display: "flex", alignItems: "center", gap: 12 }}>
            <button
              onClick={handleApplyThresholds}
              disabled={thresholdLoading}
              style={{
                padding: "9px 22px",
                borderRadius: 8,
                border: "none",
                background: thresholdLoading
                  ? "var(--bg-card)"
                  : "linear-gradient(135deg, #f59e0b, #d97706)",
                color: thresholdLoading ? "var(--text-muted)" : "#000",
                fontSize: 12,
                fontWeight: 800,
                cursor: thresholdLoading ? "not-allowed" : "pointer",
                letterSpacing: 0.5,
              }}
            >
              {thresholdLoading ? "Applying..." : "Apply Thresholds"}
            </button>

            {thresholdMsg && (
              <span
                style={{
                  fontSize: 12,
                  fontWeight: 600,
                  color: thresholdMsg.type === "success" ? "#22c55e" : "#ef4444",
                }}
              >
                {thresholdMsg.text}
              </span>
            )}
          </div>
        )}
      </AccordionSection>

      {/* E. Alert Settings */}
      <AccordionSection title="Alert Settings" accent="#ef4444" icon="◬">
        <div style={{ marginBottom: 16 }}>
          <div
            style={{
              ...SECTION_LABEL,
              display: "block",
              marginBottom: 10,
            }}
          >
            Minimum Severity to Display
          </div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            {SEVERITIES.map((sev) => (
              <label
                key={sev}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                  cursor: "pointer",
                  padding: "7px 14px",
                  borderRadius: 8,
                  border: `1px solid ${minSeverity === sev ? SEV_COLORS[sev] + "66" : "var(--border-color)"}`,
                  background:
                    minSeverity === sev ? `${SEV_COLORS[sev]}14` : "var(--bg-primary)",
                  transition: "all 0.15s",
                }}
              >
                <input
                  type="radio"
                  name="min-severity"
                  value={sev}
                  checked={minSeverity === sev}
                  onChange={() => handleMinSeverityChange(sev)}
                  style={{ accentColor: SEV_COLORS[sev] }}
                />
                <span
                  style={{
                    fontSize: 11,
                    fontWeight: 700,
                    color: minSeverity === sev ? SEV_COLORS[sev] : "var(--text-muted)",
                  }}
                >
                  {sev}
                </span>
              </label>
            ))}
          </div>
        </div>

        <Toggle
          value={autoResponse}
          onChange={handleAutoResponseToggle}
          label="Auto-Response on HIGH/CRITICAL"
          sub="When enabled, HIGH and CRITICAL threats automatically trigger SOAR response, generate an incident report, and notify you — no manual 'Respond' click needed."
          accent="#ef4444"
        />
        {autoResponse && (
          <div style={{ marginTop: 8, padding: "8px 14px", background: "rgba(239,68,68,0.08)", borderRadius: 8, border: "1px solid rgba(239,68,68,0.2)", fontSize: 13, color: "#fca5a5" }}>
            <span style={{ fontWeight: 600 }}>Active:</span> SOAR actions will execute automatically. You will receive a toast notification and the incident report will be auto-downloaded when a HIGH/CRITICAL threat is detected.
          </div>
        )}
      </AccordionSection>
    </motion.div>
  );
}
