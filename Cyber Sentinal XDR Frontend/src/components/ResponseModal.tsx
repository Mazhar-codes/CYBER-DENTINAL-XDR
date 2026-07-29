// ResponseModal.tsx
// Full-screen incident response modal — plan viewer, action selector, execution, PDF report
// Role-gated: admin/analyst can execute; viewer sees read-only badge

import React, { useState, useEffect, useCallback, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { authAxios } from "../services/authService";
import { useAuth } from "../context/AuthContext";
import { FlowResult, SEVERITY_COLOUR } from "./shared/types";
import { ResponsePlan, ResponseAction, IncidentReport } from "./shared/responseTypes";
import { BACKEND_URL } from "../config";
import DualOrbitLoader from "./shared/DualOrbitLoader";

// ── Helpers ────────────────────────────────────────────────────────────────────

function formatActionLabel(action: string): string {
  return action
    .split("_")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

function severityGlow(severity: string): string {
  switch (severity?.toUpperCase()) {
    case "CRITICAL": return "0 0 32px rgba(220,38,38,0.45), 0 0 64px rgba(220,38,38,0.18)";
    case "HIGH":     return "0 0 28px rgba(234,88,12,0.40), 0 0 56px rgba(234,88,12,0.15)";
    case "MEDIUM":   return "0 0 20px rgba(217,119,6,0.35)";
    default:         return "0 0 14px rgba(34,197,94,0.20)";
  }
}

function severityBorder(severity: string): string {
  switch (severity?.toUpperCase()) {
    case "CRITICAL": return "1px solid rgba(220,38,38,0.5)";
    case "HIGH":     return "1px solid rgba(234,88,12,0.45)";
    case "MEDIUM":   return "1px solid rgba(217,119,6,0.4)";
    default:         return "1px solid rgba(34,197,94,0.25)";
  }
}

// ── Types ──────────────────────────────────────────────────────────────────────

interface ActionStatus {
  action: string;
  target?: string;
  state: "pending" | "running" | "success" | "failed";
}

export interface ResponseModalProps {
  alert: FlowResult | null;
  plan: ResponsePlan | null;
  onClose: () => void;
  onExecuted: (commandIds: string[]) => void;
}

// ── Spinner ────────────────────────────────────────────────────────────────────

function Spinner({ size = 16, color = "var(--accent-cyan)" }: { size?: number; color?: string }) {
  return (
    <span
      style={{
        display: "inline-block",
        width: size,
        height: size,
        border: `2px solid ${color}33`,
        borderTop: `2px solid ${color}`,
        borderRadius: "50%",
        animation: "rm-spin 0.7s linear infinite",
        flexShrink: 0,
      }}
    />
  );
}

// ── SHAP Bar Chart ─────────────────────────────────────────────────────────────

interface ShapFeature {
  feature: string;
  shap_value: number;
  feature_value: number;
}

// Admin: full bar chart with feature names + raw SHAP values
function ShapChartFull({ features }: { features: ShapFeature[] }) {
  if (!features || features.length === 0) {
    return <div style={{ color: "var(--text-muted)", fontSize: 12, padding: "12px 0" }}>No SHAP data available.</div>;
  }

  const maxAbs = Math.max(...features.map((f) => Math.abs(f.shap_value)), 0.0001);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
      {features.slice(0, 8).map((f, i) => {
        const pct = Math.min(100, (Math.abs(f.shap_value) / maxAbs) * 100);
        const positive = f.shap_value >= 0;
        const barColor = positive ? "#ef4444" : "#22c55e";
        return (
          <div key={i} style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div
              style={{
                width: 160,
                fontSize: 10,
                color: "var(--text-secondary)",
                textAlign: "right",
                flexShrink: 0,
                fontFamily: "monospace",
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
              title={f.feature}
            >
              {f.feature}
            </div>
            <div
              style={{
                flex: 1,
                height: 12,
                background: "var(--bg-primary)",
                borderRadius: 3,
                overflow: "hidden",
                position: "relative",
              }}
            >
              <div
                style={{
                  position: "absolute",
                  left: positive ? "50%" : `calc(50% - ${pct / 2}%)`,
                  width: `${pct / 2}%`,
                  height: "100%",
                  background: barColor,
                  borderRadius: 3,
                  boxShadow: `0 0 4px ${barColor}66`,
                  transition: "width 0.35s ease",
                }}
              />
              {/* Center line */}
              <div
                style={{
                  position: "absolute",
                  left: "50%",
                  top: 0,
                  width: 1,
                  height: "100%",
                  background: "var(--bg-card)",
                }}
              />
            </div>
            {/* Admin only: raw SHAP value */}
            <span
              style={{
                width: 54,
                textAlign: "right",
                fontSize: 10,
                fontFamily: "monospace",
                color: barColor,
                fontWeight: 700,
                flexShrink: 0,
              }}
            >
              {f.shap_value >= 0 ? "+" : ""}{f.shap_value.toFixed(3)}
            </span>
          </div>
        );
      })}
      <div style={{ fontSize: 9, color: "var(--text-muted)", marginTop: 4, textAlign: "right" }}>
        Red = increases threat score &nbsp;|&nbsp; Green = reduces threat score
      </div>
    </div>
  );
}

// Analyst: bar chart only, no raw feature values shown
function ShapChartSummarized({ features }: { features: ShapFeature[] }) {
  if (!features || features.length === 0) {
    return <div style={{ color: "var(--text-muted)", fontSize: 12, padding: "12px 0" }}>No SHAP data available.</div>;
  }

  const maxAbs = Math.max(...features.map((f) => Math.abs(f.shap_value)), 0.0001);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
      {features.slice(0, 8).map((f, i) => {
        const pct = Math.min(100, (Math.abs(f.shap_value) / maxAbs) * 100);
        const positive = f.shap_value >= 0;
        const barColor = positive ? "#ef4444" : "#22c55e";
        return (
          <div key={i} style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div
              style={{
                width: 160,
                fontSize: 10,
                color: "var(--text-secondary)",
                textAlign: "right",
                flexShrink: 0,
                fontFamily: "monospace",
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
              title={f.feature}
            >
              {f.feature}
            </div>
            <div
              style={{
                flex: 1,
                height: 12,
                background: "var(--bg-primary)",
                borderRadius: 3,
                overflow: "hidden",
                position: "relative",
              }}
            >
              <div
                style={{
                  position: "absolute",
                  left: positive ? "50%" : `calc(50% - ${pct / 2}%)`,
                  width: `${pct / 2}%`,
                  height: "100%",
                  background: barColor,
                  borderRadius: 3,
                  boxShadow: `0 0 4px ${barColor}66`,
                  transition: "width 0.35s ease",
                }}
              />
              <div
                style={{
                  position: "absolute",
                  left: "50%",
                  top: 0,
                  width: 1,
                  height: "100%",
                  background: "var(--bg-card)",
                }}
              />
            </div>
            {/* No raw SHAP value for analyst — show impact direction only */}
            <span
              style={{
                width: 54,
                textAlign: "right",
                fontSize: 10,
                color: barColor,
                fontWeight: 700,
                flexShrink: 0,
              }}
            >
              {positive ? "HIGH" : "LOW"}
            </span>
          </div>
        );
      })}
      <div style={{ fontSize: 9, color: "var(--text-muted)", marginTop: 4, textAlign: "right" }}>
        Red = increases threat score &nbsp;|&nbsp; Green = reduces threat score
      </div>
    </div>
  );
}

// Role-gated SHAP dispatcher
function ShapChart({ features, role }: { features: ShapFeature[]; role: string }) {
  if (role === "viewer") {
    // Viewer: plain text only — no chart
    return (
      <div
        style={{
          padding: "14px 18px",
          background: "rgba(71,85,105,0.08)",
          border: "1px solid var(--border-color)",
          borderRadius: 10,
          fontSize: 13,
          color: "var(--text-secondary)",
          lineHeight: 1.6,
          fontStyle: "italic",
        }}
      >
        Suspicious process behavior detected. Contact an analyst or admin for detailed
        feature attribution.
      </div>
    );
  }

  if (role === "analyst") {
    return <ShapChartSummarized features={features} />;
  }

  // Admin (default): full chart with raw values
  return <ShapChartFull features={features} />;
}

// ── Main Component ─────────────────────────────────────────────────────────────

export default function ResponseModal({ alert, plan: initialPlan, onClose, onExecuted }: ResponseModalProps) {
  const { user } = useAuth();
  const role = user?.role ?? "viewer";
  const canExecute = role === "admin" || role === "analyst";

  const [plan, setPlan] = useState<ResponsePlan | null>(initialPlan);
  const [planLoading, setPlanLoading] = useState(false);
  const [planError, setPlanError] = useState<string | null>(null);

  const [checkedActions, setCheckedActions] = useState<Set<number>>(new Set());
  const [executing, setExecuting] = useState(false);
  const [actionStatuses, setActionStatuses] = useState<ActionStatus[]>([]);
  const [executionDone, setExecutionDone] = useState(false);
  const [executionError, setExecutionError] = useState<string | null>(null);
  const [commandIds, setCommandIds] = useState<string[]>([]);

  const [reportLoading, setReportLoading] = useState(false);
  const [reportError, setReportError] = useState<string | null>(null);
  const [report, setReport] = useState<IncidentReport | null>(null);

  // ── Load plan if not provided ────────────────────────────────────────────────
  useEffect(() => {
    if (initialPlan) {
      setPlan(initialPlan);
      return;
    }
    if (!alert) return;

    setPlanLoading(true);
    setPlanError(null);

    const body = {
      endpoint_id: alert.src_ip ?? "unknown",
      severity: alert.severity,
      attack_type: alert.attack_type,
      contributing_signals: [alert.attack_type],
      shap_explanation: null,
      threat_score: (() => { const c = alert.confidence ?? 0; return c > 1 ? c / 100 : c; })(),
    };

    authAxios
      .post<ResponsePlan>(`${BACKEND_URL}/response/plan`, body)
      .then((res) => {
        setPlan(res.data);
      })
      .catch((err) => {
        const msg =
          err?.response?.data?.detail ??
          err?.message ??
          "Failed to load response plan";
        setPlanError(typeof msg === "string" ? msg : JSON.stringify(msg));
      })
      .finally(() => setPlanLoading(false));
  }, [alert, initialPlan]);

  // ── Pre-check all actions when plan loads ────────────────────────────────────
  useEffect(() => {
    if (plan?.recommended_actions) {
      setCheckedActions(new Set(plan.recommended_actions.map((_, i) => i)));
    }
  }, [plan]);

  // ── Keyboard close (Escape) ──────────────────────────────────────────────────
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onClose]);

  // ── Execute handler ───────────────────────────────────────────────────────────
  const handleExecute = useCallback(async () => {
    if (!plan || !canExecute) return;
    const selectedActions: ResponseAction[] = plan.recommended_actions.filter((_, i) =>
      checkedActions.has(i)
    );
    if (selectedActions.length === 0) return;

    setExecuting(true);
    setExecutionError(null);
    setActionStatuses(
      selectedActions.map((a) => ({ action: a.action, target: a.target, state: "running" }))
    );

    try {
      const payload = {
        endpoint_id: plan.endpoint_id,
        actions: selectedActions,
        plan_id: plan.plan_id,
        issued_by: user?.email ?? user?.username ?? "analyst",
      };
      const res = await authAxios.post<{ success: boolean; command_ids: string[] }>(
        `${BACKEND_URL}/response/execute`,
        payload
      );

      const ids = res.data.command_ids ?? [];
      setCommandIds(ids);

      setActionStatuses(
        selectedActions.map((a) => ({ action: a.action, target: a.target, state: "success" }))
      );
      setExecutionDone(true);
      onExecuted(ids);
    } catch (err: unknown) {
      const anyErr = err as { response?: { data?: { detail?: string } }; message?: string };
      const msg =
        anyErr?.response?.data?.detail ??
        anyErr?.message ??
        "Execution failed";
      setExecutionError(typeof msg === "string" ? msg : JSON.stringify(msg));
      setActionStatuses((prev) =>
        prev.map((s) => ({ ...s, state: "failed" as const }))
      );
    } finally {
      setExecuting(false);
    }
  }, [plan, checkedActions, canExecute, user, onExecuted]);

  // ── Download Report ───────────────────────────────────────────────────────────
  const handleDownloadReport = useCallback(async () => {
    if (!plan) return;
    setReportLoading(true);
    setReportError(null);

    try {
      const payload = {
        plan_id: plan.plan_id,
        admin_name: user?.email ?? user?.username ?? "analyst",
        incident_id: report?.incident_id ?? undefined,
      };
      const res = await authAxios.post<IncidentReport>(
        `${BACKEND_URL}/reports/generate`,
        payload
      );
      setReport(res.data);

      // Backend embeds the PDF as base64 in the generate response — use it
      // directly so no second HTTP request (and no CORS issues) are needed.
      const b64: string = (res.data as any).pdf_content_b64 ?? "";
      if (!b64) {
        throw new Error("PDF content not returned by server. Check reportlab is installed.");
      }
      const binaryStr = atob(b64);
      const bytes = new Uint8Array(binaryStr.length);
      for (let i = 0; i < binaryStr.length; i++) {
        bytes[i] = binaryStr.charCodeAt(i);
      }
      const blob = new Blob([bytes], { type: "application/pdf" });
      const blobUrl = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = blobUrl;
      link.setAttribute("download", `incident_${res.data.incident_id}.pdf`);
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(blobUrl);
    } catch (err: unknown) {
      const anyErr = err as { response?: { data?: { detail?: string } }; message?: string };
      const msg =
        anyErr?.response?.data?.detail ?? anyErr?.message ?? "Report generation failed";
      setReportError(typeof msg === "string" ? msg : JSON.stringify(msg));
    } finally {
      setReportLoading(false);
    }
  }, [plan, user, report]);

  // ── Derived display values ────────────────────────────────────────────────────
  const displaySeverity = plan?.severity ?? alert?.severity ?? "HIGH";
  const sevColor = SEVERITY_COLOUR[displaySeverity?.toUpperCase()] ?? "#ea580c";

  // SHAP data: extracted from plan.shap_explanation when the backend includes it
  const shapFeatures = useMemo(() => {
    const raw = (plan as any)?.shap_explanation ?? [];
    if (!Array.isArray(raw) || raw.length === 0) return [];
    // Backend often sends string reason arrays: ["high packet rate", "suspicious IP"]
    if (typeof raw[0] === "string") {
      return (raw as string[]).map((reason, i) => ({
        feature: reason,
        shap_value: Math.max(0.1, 1 - i * 0.15),
        feature_value: 0,
      }));
    }
    // Structured SHAP objects from tree explainer
    return raw
      .filter((item: any) => item && typeof item === "object" && ("feature" in item || "name" in item))
      .map((item: any) => ({
        feature: item.feature ?? item.name ?? "unknown",
        shap_value: item.shap_value ?? item.importance ?? 0,
        feature_value: item.feature_value ?? 0,
      }));
  }, [plan]);

  if (!alert && !initialPlan) return null;

  return (
    <AnimatePresence>
      <motion.div
        key="rm-backdrop"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        transition={{ duration: 0.18 }}
        onClick={onClose}
        style={{
          position: "fixed",
          inset: 0,
          background: "rgba(0,0,0,0.72)",
          backdropFilter: "blur(4px)",
          zIndex: 2000,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          padding: 24,
        }}
      >
        <motion.div
          key="rm-panel"
          initial={{ opacity: 0, scale: 0.95, y: 20 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 20 }}
          transition={{ duration: 0.22, ease: "easeOut" }}
          onClick={(e) => e.stopPropagation()}
          style={{
            width: "100%",
            maxWidth: 860,
            maxHeight: "90vh",
            overflowY: "auto",
            background: "linear-gradient(145deg, #0d1629 0%, #0a1120 100%)",
            border: severityBorder(displaySeverity),
            borderRadius: 18,
            boxShadow: severityGlow(displaySeverity),
            display: "flex",
            flexDirection: "column",
            gap: 0,
          }}
        >
          {/* ── Header ─────────────────────────────────────────────────────────── */}
          <div
            style={{
              padding: "18px 24px",
              borderBottom: "1px solid var(--border-color)",
              display: "flex",
              alignItems: "center",
              gap: 14,
              flexShrink: 0,
            }}
          >
            <div
              style={{
                width: 10,
                height: 10,
                borderRadius: "50%",
                background: sevColor,
                boxShadow: `0 0 10px ${sevColor}`,
                animation: "rm-pulse 1.2s ease-in-out infinite",
                flexShrink: 0,
              }}
            />
            <span
              style={{
                fontSize: 15,
                fontWeight: 800,
                color: "var(--text-primary)",
                letterSpacing: 1.5,
                textTransform: "uppercase",
                flex: 1,
              }}
            >
              Incident Response
            </span>
            <span
              style={{
                background: `${sevColor}22`,
                color: sevColor,
                border: `1px solid ${sevColor}55`,
                borderRadius: 8,
                padding: "4px 12px",
                fontSize: 11,
                fontWeight: 800,
                letterSpacing: 1,
                textTransform: "uppercase",
              }}
            >
              {displaySeverity}
            </span>
            <button
              onClick={onClose}
              title="Close (Esc)"
              style={{
                width: 32,
                height: 32,
                borderRadius: 8,
                border: "1px solid var(--border-color)",
                background: "transparent",
                color: "var(--text-secondary)",
                fontSize: 16,
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                flexShrink: 0,
                transition: "all 0.15s",
              }}
            >
              &#x2715;
            </button>
          </div>

          <div style={{ padding: 24, display: "flex", flexDirection: "column", gap: 24 }}>
            {/* ── Section 1 — Attack Summary ─────────────────────────────────── */}
            <section>
              <SectionTitle>Attack Summary</SectionTitle>
              {plan ? (
                <div
                  style={{
                    background: "#0f1c2e",
                    border: "1px solid var(--border-color)",
                    borderRadius: 12,
                    padding: 18,
                    display: "flex",
                    flexDirection: "column",
                    gap: 14,
                  }}
                >
                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns: "repeat(auto-fill, minmax(180px, 1fr))",
                      gap: 12,
                    }}
                  >
                    {[
                      { label: "Attack Type",    value: plan.attack_type ?? "Unknown" },
                      { label: "Severity",       value: plan.severity },
                      { label: "Risk Level",     value: plan.risk_level },
                      { label: "Endpoint",       value: plan.endpoint_id },
                      { label: "MITRE Technique", value: plan.mitre_technique },
                      { label: "Threat Score",   value: alert ? (() => { const c = alert.confidence ?? 0; const pct = c > 1 ? c / 100 : c * 100; return `${pct.toFixed(1)}%`; })() : "—" },
                    ].map(({ label, value }) => (
                      <div key={label}>
                        <div
                          style={{
                            fontSize: 9,
                            fontWeight: 700,
                            letterSpacing: 1.5,
                            color: "var(--text-muted)",
                            textTransform: "uppercase",
                            marginBottom: 4,
                          }}
                        >
                          {label}
                        </div>
                        <div
                          style={{
                            fontSize: 13,
                            fontWeight: 700,
                            color:
                              label === "Attack Type"
                                ? "#fbbf24"
                                : label === "Severity"
                                ? sevColor
                                : label === "MITRE Technique"
                                ? "#fb923c"
                                : label === "Endpoint"
                                ? "#60a5fa"
                                : "var(--text-primary)",
                            fontFamily:
                              label === "MITRE Technique" || label === "Endpoint"
                                ? "monospace"
                                : "inherit",
                          }}
                        >
                          {value ?? "—"}
                        </div>
                      </div>
                    ))}
                  </div>

                  {plan.summary && (
                    <div
                      style={{
                        padding: "10px 14px",
                        background: "rgba(0,0,0,0.3)",
                        border: "1px solid var(--border-color)",
                        borderRadius: 8,
                        fontSize: 13,
                        color: "var(--text-secondary)",
                        lineHeight: 1.6,
                      }}
                    >
                      {plan.summary}
                    </div>
                  )}

                  {plan.auto_execute && (
                    <div
                      style={{
                        display: "inline-flex",
                        alignItems: "center",
                        gap: 6,
                        background: "rgba(239,68,68,0.1)",
                        border: "1px solid rgba(239,68,68,0.3)",
                        borderRadius: 6,
                        padding: "4px 10px",
                        fontSize: 10,
                        fontWeight: 700,
                        color: "#fca5a5",
                        letterSpacing: 0.5,
                        alignSelf: "flex-start",
                      }}
                    >
                      <span
                        style={{
                          width: 6,
                          height: 6,
                          borderRadius: "50%",
                          background: "#ef4444",
                          boxShadow: "0 0 6px #ef4444",
                          display: "inline-block",
                          animation: "rm-pulse 1s ease-in-out infinite",
                        }}
                      />
                      AUTO-EXECUTE RECOMMENDED
                    </div>
                  )}
                </div>
              ) : planLoading ? (
                <div style={{ display: "flex", justifyContent: "center", padding: "24px 0" }}>
                  <DualOrbitLoader size={40} label="Loading attack summary..." />
                </div>
              ) : planError ? (
                <ErrorBox message={planError} />
              ) : alert ? (
                <div
                  style={{
                    background: "#0f1c2e",
                    border: "1px solid var(--border-color)",
                    borderRadius: 12,
                    padding: 18,
                    display: "grid",
                    gridTemplateColumns: "repeat(auto-fill, minmax(180px, 1fr))",
                    gap: 12,
                  }}
                >
                  {[
                    { label: "Attack Type", value: alert.attack_type },
                    { label: "Severity",    value: alert.severity },
                    { label: "Source IP",   value: alert.src_ip },
                    { label: "Dest IP",     value: alert.dest_ip },
                    { label: "Confidence",  value: `${alert.confidence.toFixed(1)}%` },
                    { label: "Protocol",    value: alert.protocol },
                  ].map(({ label, value }) => (
                    <div key={label}>
                      <div
                        style={{
                          fontSize: 9,
                          fontWeight: 700,
                          letterSpacing: 1.5,
                          color: "var(--text-muted)",
                          textTransform: "uppercase",
                          marginBottom: 4,
                        }}
                      >
                        {label}
                      </div>
                      <div
                        style={{
                          fontSize: 13,
                          fontWeight: 700,
                          color: "var(--text-primary)",
                          fontFamily: label === "Source IP" || label === "Dest IP" ? "monospace" : "inherit",
                        }}
                      >
                        {value ?? "—"}
                      </div>
                    </div>
                  ))}
                </div>
              ) : null}
            </section>

            {/* ── Section 2 — SHAP Explanation ──────────────────────────────── */}
            <section>
              <SectionTitle>SHAP Explanation</SectionTitle>
              <div
                style={{
                  background: "#0f1c2e",
                  border: "1px solid var(--border-color)",
                  borderRadius: 12,
                  padding: 18,
                }}
              >
                <ShapChart features={shapFeatures} role={role} />
              </div>
            </section>

            {/* ── Section 3 — Suggested Actions ─────────────────────────────── */}
            <section>
              <SectionTitle>Suggested Actions</SectionTitle>
              {planLoading ? (
                <div style={{ display: "flex", justifyContent: "center", padding: "24px 0" }}>
                  <DualOrbitLoader size={40} label="Loading response plan..." />
                </div>
              ) : planError ? (
                <ErrorBox message={planError} />
              ) : plan?.recommended_actions && plan.recommended_actions.length > 0 ? (
                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  {plan.recommended_actions.map((action, i) => {
                    const isChecked = checkedActions.has(i);
                    const status = actionStatuses.find((s) => s.action === action.action && s.target === action.target);
                    return (
                      <motion.label
                        key={i}
                        initial={{ opacity: 0, x: -8 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ duration: 0.15, delay: i * 0.04 }}
                        style={{
                          display: "flex",
                          alignItems: "flex-start",
                          gap: 12,
                          padding: "12px 16px",
                          background: isChecked ? "rgba(239,68,68,0.06)" : "#0f1c2e",
                          border: isChecked ? "1px solid rgba(239,68,68,0.25)" : "1px solid var(--border-color)",
                          borderRadius: 10,
                          cursor: executing || executionDone ? "default" : "pointer",
                          transition: "all 0.15s",
                        }}
                      >
                        <div style={{ paddingTop: 1 }}>
                          {status ? (
                            status.state === "running" ? (
                              <Spinner size={16} color="var(--accent-cyan)" />
                            ) : status.state === "success" ? (
                              <span style={{ fontSize: 16, color: "#22c55e" }}>&#10003;</span>
                            ) : (
                              <span style={{ fontSize: 16, color: "#ef4444" }}>&#10007;</span>
                            )
                          ) : (
                            <input
                              type="checkbox"
                              checked={isChecked}
                              disabled={executing || executionDone}
                              onChange={() => {
                                setCheckedActions((prev) => {
                                  const next = new Set(prev);
                                  if (next.has(i)) next.delete(i);
                                  else next.add(i);
                                  return next;
                                });
                              }}
                              style={{ width: 15, height: 15, accentColor: "#ef4444", cursor: "pointer" }}
                            />
                          )}
                        </div>
                        <div style={{ flex: 1 }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                            <span style={{ fontSize: 13, fontWeight: 700, color: "var(--text-primary)" }}>
                              {formatActionLabel(action.action)}
                            </span>
                            {action.target && (
                              <span
                                style={{
                                  fontFamily: "monospace",
                                  fontSize: 11,
                                  color: "#60a5fa",
                                  background: "rgba(96,165,250,0.1)",
                                  border: "1px solid rgba(96,165,250,0.2)",
                                  borderRadius: 5,
                                  padding: "1px 7px",
                                }}
                              >
                                {action.target}
                              </span>
                            )}
                          </div>
                          {action.reason && (
                            <div style={{ marginTop: 4, fontSize: 11, color: "var(--text-secondary)", fontStyle: "italic" }}>
                              {action.reason}
                            </div>
                          )}
                          {status?.state === "failed" && (
                            <div style={{ marginTop: 4, fontSize: 11, color: "#ef4444" }}>
                              Execution failed
                            </div>
                          )}
                        </div>
                      </motion.label>
                    );
                  })}
                </div>
              ) : plan ? (
                <div style={{ padding: 16, color: "var(--text-muted)", fontSize: 13 }}>
                  No recommended actions for this incident.
                </div>
              ) : (
                <div style={{ padding: 16, color: "var(--text-muted)", fontSize: 13 }}>
                  Waiting for response plan...
                </div>
              )}
            </section>

            {/* ── Execution Error ────────────────────────────────────────────── */}
            {executionError && <ErrorBox message={executionError} />}
            {reportError && <ErrorBox message={`Report: ${reportError}`} />}

            {/* ── Footer buttons ─────────────────────────────────────────────── */}
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 12,
                paddingTop: 8,
                borderTop: "1px solid var(--border-color)",
                flexWrap: "wrap",
              }}
            >
              {canExecute ? (
                <>
                  {!executionDone ? (
                    <button
                      onClick={handleExecute}
                      disabled={
                        executing ||
                        planLoading ||
                        !plan ||
                        checkedActions.size === 0
                      }
                      style={{
                        padding: "10px 28px",
                        borderRadius: 10,
                        border: "none",
                        background:
                          executing || planLoading || !plan || checkedActions.size === 0
                            ? "var(--bg-card)"
                            : "linear-gradient(135deg, #dc2626 0%, #b91c1c 100%)",
                        color:
                          executing || planLoading || !plan || checkedActions.size === 0
                            ? "var(--text-muted)"
                            : "#fff",
                        fontWeight: 800,
                        fontSize: 12,
                        letterSpacing: 1,
                        textTransform: "uppercase",
                        cursor:
                          executing || planLoading || !plan || checkedActions.size === 0
                            ? "not-allowed"
                            : "pointer",
                        display: "flex",
                        alignItems: "center",
                        gap: 8,
                        transition: "all 0.15s",
                        boxShadow:
                          !executing && plan && checkedActions.size > 0
                            ? "0 0 16px rgba(220,38,38,0.35)"
                            : "none",
                      }}
                    >
                      {executing && <Spinner size={13} color="#ffffff" />}
                      {executing ? "Executing..." : "Execute Response"}
                    </button>
                  ) : (
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 8,
                        padding: "8px 16px",
                        background: "rgba(34,197,94,0.1)",
                        border: "1px solid rgba(34,197,94,0.3)",
                        borderRadius: 10,
                        fontSize: 12,
                        fontWeight: 700,
                        color: "#22c55e",
                      }}
                    >
                      <span>&#10003;</span>
                      Response Executed — {commandIds.length} command{commandIds.length !== 1 ? "s" : ""} issued
                    </div>
                  )}

                  {executionDone && (
                    <button
                      onClick={handleDownloadReport}
                      disabled={reportLoading}
                      style={{
                        padding: "10px 20px",
                        borderRadius: 10,
                        border: "1px solid rgba(0,212,255,0.4)",
                        background: "var(--accent-cyan-dim)",
                        color: "var(--accent-cyan)",
                        fontWeight: 700,
                        fontSize: 12,
                        letterSpacing: 0.5,
                        cursor: reportLoading ? "not-allowed" : "pointer",
                        display: "flex",
                        alignItems: "center",
                        gap: 8,
                        transition: "all 0.15s",
                      }}
                    >
                      {reportLoading && <Spinner size={13} color="var(--accent-cyan)" />}
                      {reportLoading ? "Generating..." : "Download Incident Report (PDF)"}
                    </button>
                  )}
                </>
              ) : (
                <div
                  style={{
                    padding: "9px 18px",
                    background: "var(--bg-card)",
                    border: "1px solid var(--border-color)",
                    borderRadius: 10,
                    fontSize: 12,
                    fontWeight: 700,
                    color: "var(--text-secondary)",
                    letterSpacing: 0.5,
                  }}
                >
                  View Only — Contact Admin to Execute Response
                </div>
              )}

              <button
                onClick={onClose}
                style={{
                  marginLeft: "auto",
                  padding: "9px 18px",
                  borderRadius: 10,
                  border: "1px solid var(--border-color)",
                  background: "transparent",
                  color: "var(--text-secondary)",
                  fontWeight: 700,
                  fontSize: 12,
                  cursor: "pointer",
                  letterSpacing: 0.5,
                  transition: "all 0.15s",
                }}
              >
                Close
              </button>
            </div>
          </div>
        </motion.div>
      </motion.div>

      {/* Keyframe styles */}
      <style>{`
        @keyframes rm-spin {
          from { transform: rotate(0deg); }
          to   { transform: rotate(360deg); }
        }
        @keyframes rm-pulse {
          0%, 100% { opacity: 1; transform: scale(1); }
          50%       { opacity: 0.45; transform: scale(0.82); }
        }
      `}</style>
    </AnimatePresence>
  );
}

// ── Sub-components ─────────────────────────────────────────────────────────────

function SectionTitle({ children }: { children: React.ReactNode }) {
  return (
    <div
      style={{
        fontSize: 10,
        fontWeight: 700,
        color: "var(--text-muted)",
        letterSpacing: 2,
        textTransform: "uppercase",
        marginBottom: 10,
        display: "flex",
        alignItems: "center",
        gap: 8,
      }}
    >
      <div style={{ flex: 1, height: 1, background: "var(--bg-card)" }} />
      {children}
      <div style={{ flex: 1, height: 1, background: "var(--bg-card)" }} />
    </div>
  );
}

function ErrorBox({ message }: { message: string }) {
  return (
    <div
      style={{
        padding: "10px 14px",
        background: "rgba(220,38,38,0.08)",
        border: "1px solid rgba(220,38,38,0.3)",
        borderRadius: 8,
        fontSize: 12,
        color: "#fca5a5",
      }}
    >
      {message}
    </div>
  );
}
