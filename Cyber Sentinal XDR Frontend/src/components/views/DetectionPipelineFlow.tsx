// DetectionPipelineFlow.tsx
// Visual detection pipeline diagram for the Investigate / Attack Reconstruction view.
// Shows the full chain: Endpoint Telemetry → Detection Models → Fusion Engine → Alert → Response
// Data source: /replay/{incident_id} response (fusion_alert + timeline events)

import React, { useMemo } from "react";
import { motion } from "framer-motion";

// ── Types ─────────────────────────────────────────────────────────────────────

interface ModelScore {
  name: string;
  label: string;
  score: number;        // 0–1
  weight: number;       // 0–1 (fusion weight)
  severity: string;
  color: string;
  icon: string;
  active: boolean;      // true if this model contributed
}

interface FusionAlertLike {
  threat_score?: number;
  severity?: string;
  attack_type?: string;
  sources?: string[];
  components?: {
    network?: { score: number; weight: number; contribution: number };
    user?:    { score: number; weight: number; contribution: number };
    system?:  { score: number; weight: number; contribution: number };
    malware?: { score: number; weight: number; contribution: number };
  };
  mitre_technique?: string;
}

interface TimelineEventLike {
  event_type?: string;
  data?: Record<string, unknown>;
  score?: number;
  [key: string]: unknown;
}

export interface DetectionPipelineFlowProps {
  fusionAlert?: FusionAlertLike | null;
  timeline?: TimelineEventLike[];
  attackType?: string;
  severity?: string;
  commands?: Array<{ action: string }>;
  fusionHighThreshold?: number;
  fusionCriticalThreshold?: number;
}

// ── Constants ─────────────────────────────────────────────────────────────────

const MODEL_WEIGHTS: Record<string, number> = {
  network: 0.35,
  user:    0.30,
  system:  0.15,
  malware: 0.20,
};

const MODEL_META: Record<string, { label: string; color: string; icon: string }> = {
  network: { label: "Network",  color: "var(--accent-cyan)", icon: "◆" },
  user:    { label: "User",     color: "#f97316", icon: "◉" },
  system:  { label: "System",   color: "var(--accent-purple)", icon: "▲" },
  malware: { label: "Malware",  color: "#dc2626", icon: "☣" },
};

const SEV_COLORS: Record<string, string> = {
  CRITICAL: "#dc2626",
  HIGH:     "#ef4444",
  MEDIUM:   "#f59e0b",
  LOW:      "#3b82f6",
  NORMAL:   "#22c55e",
};

function sevColor(s?: string): string {
  return SEV_COLORS[(s ?? "").toUpperCase()] ?? "#64748b";
}

function scoreToSeverity(score: number): string {
  if (score >= 0.85) return "CRITICAL";
  if (score >= 0.70) return "HIGH";
  if (score >= 0.40) return "MEDIUM";
  if (score > 0)    return "LOW";
  return "NORMAL";
}

// ── Flow arrow with animated dashes ──────────────────────────────────────────

function FlowArrow({ active = true }: { active?: boolean }) {
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        padding: "2px 0",
        flexShrink: 0,
      }}
    >
      <div
        style={{
          width: 2,
          height: 28,
          background: active
            ? "linear-gradient(180deg, #00d4ff, #3b82f6)"
            : "#1e293b",
          borderRadius: 1,
          position: "relative",
          overflow: "hidden",
        }}
      >
        {active && (
          <div
            style={{
              position: "absolute",
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              background:
                "repeating-linear-gradient(180deg, transparent 0px, transparent 4px, rgba(0,212,255,0.6) 4px, rgba(0,212,255,0.6) 8px)",
              animation: "pipeline-flow 1.2s linear infinite",
            }}
          />
        )}
      </div>
      <div
        style={{
          width: 0,
          height: 0,
          borderLeft: "5px solid transparent",
          borderRight: "5px solid transparent",
          borderTop: `7px solid ${active ? "#3b82f6" : "#1e293b"}`,
        }}
      />
    </div>
  );
}

// ── Single model score card ───────────────────────────────────────────────────

function ModelCard({ model, isPrimary }: { model: ModelScore; isPrimary: boolean }) {
  const barWidth = Math.round(model.score * 100);
  const sc = sevColor(model.severity);
  const barColor =
    model.severity === "CRITICAL" || model.severity === "HIGH"
      ? sc
      : model.severity === "MEDIUM"
      ? "#f59e0b"
      : "#22c55e";

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.22 }}
      style={{
        flex: 1,
        minWidth: 0,
        background: model.active
          ? `linear-gradient(135deg, ${model.color}08, #0d1629)`
          : "linear-gradient(135deg, #0d1629, #0a1120)",
        border: isPrimary
          ? `1.5px solid ${model.color}60`
          : model.active
          ? `1px solid ${model.color}30`
          : "1px solid #1e293b",
        borderRadius: 10,
        padding: "12px 14px",
        position: "relative",
        overflow: "hidden",
        boxShadow: isPrimary ? `0 0 16px ${model.color}20` : "none",
      }}
    >
      {/* Primary indicator pulse ring */}
      {isPrimary && (
        <div
          style={{
            position: "absolute",
            inset: -2,
            borderRadius: 11,
            border: `1.5px solid ${model.color}`,
            opacity: 0.4,
            animation: "pipeline-pulse 1.8s ease-out infinite",
            pointerEvents: "none",
          }}
        />
      )}

      {/* Header */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 6,
          marginBottom: 10,
        }}
      >
        <span style={{ fontSize: 14, color: model.color }}>{model.icon}</span>
        <span
          style={{
            fontSize: 10,
            fontWeight: 800,
            color: model.active ? "#e2e8f0" : "#475569",
            fontFamily: "'Fira Code', monospace",
            letterSpacing: 0.8,
            textTransform: "uppercase",
          }}
        >
          {model.label}
        </span>
        {isPrimary && (
          <span
            style={{
              marginLeft: "auto",
              fontSize: 8,
              fontWeight: 800,
              letterSpacing: 1,
              color: model.color,
              background: `${model.color}18`,
              border: `1px solid ${model.color}40`,
              borderRadius: 4,
              padding: "1px 5px",
              textTransform: "uppercase",
            }}
          >
            PRIMARY
          </span>
        )}
      </div>

      {/* Score display */}
      {model.active ? (
        <>
          <div
            style={{
              fontFamily: "'Fira Code', monospace",
              fontSize: 20,
              fontWeight: 800,
              color: sc,
              lineHeight: 1,
              marginBottom: 6,
            }}
          >
            {(model.score * 100).toFixed(0)}
            <span style={{ fontSize: 11, color: "var(--text-muted)", fontWeight: 400, marginLeft: 2 }}>
              /100
            </span>
          </div>

          {/* Progress bar */}
          <div
            style={{
              height: 5,
              background: "var(--bg-primary)",
              border: "1px solid var(--border-color)",
              borderRadius: 3,
              overflow: "hidden",
              marginBottom: 6,
            }}
          >
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${barWidth}%` }}
              transition={{ duration: 0.6, ease: "easeOut" }}
              style={{
                height: "100%",
                background: barColor,
                boxShadow: `0 0 6px ${barColor}55`,
                borderRadius: 3,
              }}
            />
          </div>

          {/* Severity badge */}
          <span
            style={{
              fontSize: 9,
              fontWeight: 800,
              letterSpacing: 1,
              color: sc,
              background: `${sc}18`,
              border: `1px solid ${sc}40`,
              borderRadius: 4,
              padding: "1px 6px",
              textTransform: "uppercase",
              display: "inline-block",
            }}
          >
            {model.severity}
          </span>
        </>
      ) : (
        <div
          style={{
            fontSize: 11,
            color: "var(--text-muted)",
            fontStyle: "italic",
            marginTop: 4,
          }}
        >
          N/A
        </div>
      )}

      {/* Weight badge bottom-right */}
      <div
        style={{
          position: "absolute",
          bottom: 8,
          right: 10,
          fontSize: 8,
          fontFamily: "'Fira Code', monospace",
          color: "var(--text-muted)",
          fontWeight: 700,
        }}
      >
        w={model.weight.toFixed(2)}
      </div>
    </motion.div>
  );
}

// ── Fusion Engine breakdown panel ─────────────────────────────────────────────

function FusionBreakdown({
  models,
  totalScore,
  severity,
  fusionHighThreshold,
  fusionCriticalThreshold,
}: {
  models: ModelScore[];
  totalScore: number;
  severity: string;
  fusionHighThreshold: number;
  fusionCriticalThreshold: number;
}) {
  const sc = sevColor(severity);
  const thresholdMet =
    severity === "CRITICAL"
      ? `>= ${(fusionCriticalThreshold * 100).toFixed(0)} CRITICAL`
      : `>= ${(fusionHighThreshold * 100).toFixed(0)} HIGH`;

  return (
    <div
      style={{
        background: "linear-gradient(135deg, #0d1629, #0a1120)",
        border: `1px solid ${sc}30`,
        borderLeft: `3px solid ${sc}`,
        borderRadius: 10,
        padding: "14px 16px",
      }}
    >
      {/* Title row */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          marginBottom: 12,
        }}
      >
        <span style={{ fontSize: 14, color: sc }}>⚡</span>
        <span
          style={{
            fontFamily: "'Fira Code', monospace",
            fontSize: 9,
            fontWeight: 800,
            letterSpacing: 1.8,
            color: "var(--text-secondary)",
            textTransform: "uppercase",
          }}
        >
          Fusion Engine
        </span>
        <span
          style={{
            marginLeft: "auto",
            fontFamily: "'Fira Code', monospace",
            fontSize: 14,
            fontWeight: 800,
            color: sc,
          }}
        >
          {(totalScore * 100).toFixed(1)}%
        </span>
      </div>

      {/* Per-model weighted contributions */}
      <div style={{ display: "flex", flexDirection: "column", gap: 6, marginBottom: 10 }}>
        {models
          .filter((m) => m.active)
          .map((m) => {
            const contribution = m.score * m.weight;
            const pct = Math.round(contribution * 100);
            return (
              <div
                key={m.name}
                style={{
                  display: "grid",
                  gridTemplateColumns: "70px 28px 28px 16px 1fr 36px",
                  gap: 6,
                  alignItems: "center",
                  fontSize: 10,
                  fontFamily: "'Fira Code', monospace",
                }}
              >
                <span style={{ color: m.color, fontWeight: 700 }}>{m.label}</span>
                <span style={{ color: "var(--text-muted)" }}>{(m.score * 100).toFixed(0)}</span>
                <span style={{ color: "var(--text-muted)" }}>x{m.weight.toFixed(2)}</span>
                <span style={{ color: "var(--text-muted)" }}>=</span>
                <div
                  style={{
                    height: 4,
                    background: "var(--bg-primary)",
                    border: "1px solid var(--border-color)",
                    borderRadius: 2,
                    overflow: "hidden",
                  }}
                >
                  <div
                    style={{
                      height: "100%",
                      width: `${Math.min(pct / (totalScore * 100) * 100, 100)}%`,
                      background: m.color,
                      borderRadius: 2,
                    }}
                  />
                </div>
                <span style={{ color: m.color, fontWeight: 700, textAlign: "right" }}>
                  +{pct}
                </span>
              </div>
            );
          })}
      </div>

      {/* Threshold comparison */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          padding: "6px 10px",
          background: `${sc}0a`,
          border: `1px solid ${sc}22`,
          borderRadius: 6,
          fontSize: 10,
          fontFamily: "'Fira Code', monospace",
        }}
      >
        <span style={{ color: "var(--text-muted)" }}>Score</span>
        <span style={{ color: sc, fontWeight: 700 }}>
          {(totalScore * 100).toFixed(1)}
        </span>
        <span style={{ color: "var(--text-muted)" }}>{thresholdMet}</span>
        <span
          style={{
            marginLeft: "auto",
            fontWeight: 800,
            color: "#22c55e",
            background: "rgba(34,197,94,0.1)",
            border: "1px solid rgba(34,197,94,0.3)",
            borderRadius: 4,
            padding: "1px 7px",
          }}
        >
          TRIGGERED
        </span>
      </div>
    </div>
  );
}

// ── Alert generated box ───────────────────────────────────────────────────────

function AlertBox({
  attackType,
  severity,
  mitre,
}: {
  attackType?: string;
  severity?: string;
  mitre?: string;
}) {
  const sc = sevColor(severity);
  return (
    <div
      style={{
        background: `linear-gradient(135deg, ${sc}0a, #0d1629)`,
        border: `1px solid ${sc}30`,
        borderRadius: 10,
        padding: "12px 16px",
        display: "flex",
        alignItems: "center",
        gap: 12,
        flexWrap: "wrap",
      }}
    >
      <span style={{ fontSize: 14, color: sc }}>◈</span>
      <div>
        <div
          style={{
            fontFamily: "'Fira Code', monospace",
            fontSize: 9,
            fontWeight: 700,
            letterSpacing: 1.5,
            color: "var(--text-secondary)",
            textTransform: "uppercase",
            marginBottom: 4,
          }}
        >
          Alert Generated
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          {attackType && (
            <span
              style={{
                fontSize: 11,
                fontWeight: 700,
                color: "#fbbf24",
                background: "#78350f22",
                border: "1px solid #78350f44",
                borderRadius: 5,
                padding: "2px 8px",
              }}
            >
              {attackType}
            </span>
          )}
          {severity && (
            <span
              style={{
                fontSize: 10,
                fontWeight: 800,
                color: sc,
                background: `${sc}18`,
                border: `1px solid ${sc}40`,
                borderRadius: 5,
                padding: "2px 8px",
                letterSpacing: 0.8,
              }}
            >
              {severity.toUpperCase()}
            </span>
          )}
          {mitre && (
            <span
              style={{
                fontSize: 10,
                fontWeight: 700,
                color: "#a78bfa",
                background: "#4c1d9520",
                border: "1px solid #4c1d9540",
                borderRadius: 5,
                padding: "2px 8px",
                fontFamily: "'Fira Code', monospace",
              }}
            >
              {mitre}
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Response triggered box ────────────────────────────────────────────────────

function ResponseBox({ actions }: { actions: string[] }) {
  if (actions.length === 0) return null;
  return (
    <div
      style={{
        background: "linear-gradient(135deg, rgba(34,197,94,0.06), #0d1629)",
        border: "1px solid rgba(34,197,94,0.25)",
        borderRadius: 10,
        padding: "12px 16px",
        display: "flex",
        alignItems: "flex-start",
        gap: 10,
        flexWrap: "wrap",
      }}
    >
      <span style={{ fontSize: 14, color: "#22c55e", flexShrink: 0 }}>&#128737;</span>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div
          style={{
            fontFamily: "'Fira Code', monospace",
            fontSize: 9,
            fontWeight: 700,
            letterSpacing: 1.5,
            color: "var(--text-secondary)",
            textTransform: "uppercase",
            marginBottom: 6,
          }}
        >
          Response Triggered
        </div>
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          {actions.slice(0, 5).map((a, i) => (
            <span
              key={i}
              style={{
                fontSize: 10,
                fontWeight: 600,
                color: "#22c55e",
                background: "rgba(34,197,94,0.08)",
                border: "1px solid rgba(34,197,94,0.25)",
                borderRadius: 5,
                padding: "2px 8px",
                fontFamily: "'Fira Code', monospace",
              }}
            >
              {a}
            </span>
          ))}
          {actions.length > 5 && (
            <span style={{ fontSize: 10, color: "var(--text-secondary)" }}>
              +{actions.length - 5} more
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function DetectionPipelineFlow({
  fusionAlert,
  timeline = [],
  attackType,
  severity,
  commands = [],
  fusionHighThreshold = 0.70,
  fusionCriticalThreshold = 0.85,
}: DetectionPipelineFlowProps) {

  // Derive per-model scores from fusion alert components or timeline events
  const models = useMemo<ModelScore[]>(() => {
    const comps = fusionAlert?.components;
    const sources = fusionAlert?.sources ?? [];

    return Object.entries(MODEL_META).map(([key, meta]) => {
      const comp = comps?.[key as keyof typeof comps];
      const isActive = !!comp || sources.includes(key);

      // Try to get score from components first, then scan timeline events
      let score = 0;
      if (comp?.score != null) {
        score = comp.score > 1 ? comp.score / 100 : comp.score;
      } else if (isActive) {
        // Derive from timeline: find events with matching type and take max score
        const typeMap: Record<string, string[]> = {
          network: ["network_anomaly", "network"],
          user: ["user_anomaly", "fusion_alert"],
          system: ["system_anomaly", "sysmon_alert"],
          malware: ["malware_alert"],
        };
        const matchTypes = typeMap[key] ?? [];
        const scores = timeline
          .filter((e) => matchTypes.includes(String(e.event_type ?? "")))
          .map((e) => {
            const s =
              (e.score as number | undefined) ??
              (e.data?.threat_score as number | undefined) ??
              (e.data?.anomaly_score as number | undefined) ??
              0;
            return s > 1 ? s / 100 : s;
          });
        score = scores.length > 0 ? Math.max(...scores) : 0.5;
      }

      const sev = scoreToSeverity(score);

      return {
        name: key,
        label: meta.label,
        score,
        weight: MODEL_WEIGHTS[key] ?? 0.25,
        severity: isActive ? sev : "NORMAL",
        color: meta.color,
        icon: meta.icon,
        active: isActive,
      };
    });
  }, [fusionAlert, timeline]);

  // Identify primary detection source (highest weighted contribution)
  const primaryModel = useMemo(() => {
    const active = models.filter((m) => m.active);
    if (active.length === 0) return null;
    return active.reduce((best, m) =>
      m.score * m.weight > best.score * best.weight ? m : best
    );
  }, [models]);

  const totalScore = fusionAlert?.threat_score ?? 0;
  const effectiveSeverity = severity ?? fusionAlert?.severity ?? scoreToSeverity(totalScore);
  const effectiveAttackType = attackType ?? fusionAlert?.attack_type;
  const responseTaken = commands.map((c) => c.action);
  const hasAnyData = models.some((m) => m.active) || totalScore > 0;

  if (!hasAnyData) return null;

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      style={{
        background: "linear-gradient(135deg, #080f1e, #0a1120)",
        border: "1px solid rgba(0,212,255,0.12)",
        borderRadius: 14,
        overflow: "hidden",
        flexShrink: 0,
      }}
    >
      {/* CSS animations */}
      <style>{`
        @keyframes pipeline-flow {
          from { transform: translateY(-100%); }
          to   { transform: translateY(100%);  }
        }
        @keyframes pipeline-pulse {
          0%   { transform: scale(1);    opacity: 0.4; }
          60%  { transform: scale(1.04); opacity: 0.15; }
          100% { transform: scale(1);    opacity: 0.4; }
        }
      `}</style>

      {/* Header */}
      <div
        style={{
          padding: "10px 16px",
          borderBottom: "1px solid rgba(0,212,255,0.1)",
          display: "flex",
          alignItems: "center",
          gap: 8,
        }}
      >
        <span style={{ fontSize: 13, color: "var(--accent-cyan)" }}>◈</span>
        <span
          style={{
            fontFamily: "'Fira Code', monospace",
            fontSize: 9,
            fontWeight: 700,
            letterSpacing: 1.8,
            color: "var(--text-secondary)",
            textTransform: "uppercase",
          }}
        >
          Detection Pipeline
        </span>
        <span
          style={{
            marginLeft: "auto",
            fontSize: 9,
            fontWeight: 700,
            letterSpacing: 0.8,
            color: "var(--text-muted)",
            fontFamily: "'Fira Code', monospace",
          }}
        >
          How This Was Detected
        </span>
      </div>

      <div style={{ padding: "14px 16px", display: "flex", flexDirection: "column", gap: 4 }}>

        {/* Stage 1: Endpoint Telemetry */}
        <div
          style={{
            background: "rgba(59,130,246,0.06)",
            border: "1px solid rgba(59,130,246,0.2)",
            borderRadius: 8,
            padding: "8px 14px",
            display: "flex",
            alignItems: "center",
            gap: 8,
          }}
        >
          <span style={{ fontSize: 12, color: "#3b82f6" }}>▣</span>
          <span
            style={{
              fontSize: 11,
              fontWeight: 700,
              color: "#60a5fa",
              fontFamily: "'Fira Code', monospace",
            }}
          >
            Endpoint Telemetry
          </span>
          <span style={{ fontSize: 10, color: "var(--text-muted)", marginLeft: "auto" }}>
            Network · System · User · Process
          </span>
        </div>

        <FlowArrow active />

        {/* Stage 2: Detection Models — 4 cards */}
        <div
          style={{
            background: "rgba(0,0,0,0.2)",
            border: "1px solid var(--border-color)",
            borderRadius: 10,
            padding: "12px",
          }}
        >
          <div
            style={{
              fontFamily: "'Fira Code', monospace",
              fontSize: 8,
              fontWeight: 700,
              letterSpacing: 1.5,
              color: "var(--text-muted)",
              textTransform: "uppercase",
              marginBottom: 10,
            }}
          >
            Detection Models
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            {models.map((m) => (
              <ModelCard
                key={m.name}
                model={m}
                isPrimary={m.name === primaryModel?.name && m.active}
              />
            ))}
          </div>
        </div>

        <FlowArrow active={totalScore > 0} />

        {/* Stage 3: Fusion Engine */}
        <FusionBreakdown
          models={models}
          totalScore={totalScore}
          severity={effectiveSeverity}
          fusionHighThreshold={fusionHighThreshold}
          fusionCriticalThreshold={fusionCriticalThreshold}
        />

        <FlowArrow active />

        {/* Stage 4: Alert Generated */}
        <AlertBox
          attackType={effectiveAttackType}
          severity={effectiveSeverity}
          mitre={fusionAlert?.mitre_technique}
        />

        {responseTaken.length > 0 && (
          <>
            <FlowArrow active />
            <ResponseBox actions={responseTaken} />
          </>
        )}
      </div>
    </motion.div>
  );
}
