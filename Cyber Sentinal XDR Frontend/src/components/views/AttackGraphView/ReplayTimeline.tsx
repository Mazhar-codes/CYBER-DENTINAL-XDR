// ReplayTimeline.tsx — vertical scrollable event log for attack reconstruction
// Shows each timeline event step with type-colored icons; auto-scrolls to current step.

import React, { useEffect, useRef } from "react";

export interface TimelineEvent {
  ts: string;                // ISO timestamp
  event_type:
    | "network_anomaly"
    | "system_anomaly"
    | "fusion_alert"
    | "malware_alert"
    | "sysmon_alert"
    | "response_action"
    | "user_anomaly";
  data: Record<string, unknown>;
  step: number;              // sequential 0-based index
  /** Human-readable source label shown as a chip in the timeline row */
  source_label?: string;
  /** Normalised score 0–1 or 0–100; displayed as a percentage badge */
  score?: number;
}

/** Incident replay step from GET /incidents/{id}/replay */
export interface ReplayStep {
  step: number;
  timestamp: string;
  kind: string;
  event_type: string;
  attack_type: string;
  severity: string;
  mitre_technique: string;
  tactic: string;
  description: string;
  source_layer: string;
}

interface ReplayTimelineProps {
  events: TimelineEvent[];
  currentStep: number;
  onStepClick: (step: number) => void;
  /** When provided and non-empty, renders from incident replay API instead of events */
  replaySteps?: ReplayStep[];
}

// ── Event type → visual config ────────────────────────────────────────────────

interface EventConfig {
  icon: string;
  color: string;
  label: string;
}

const EVENT_CONFIG: Record<TimelineEvent["event_type"], EventConfig> = {
  network_anomaly: { icon: "🌐", color: "var(--accent-cyan)",  label: "Network Anomaly"  },
  system_anomaly:  { icon: "💻", color: "var(--accent-amber)",  label: "System Anomaly"   },
  fusion_alert:    { icon: "⚡", color: "#ef4444",  label: "Fusion Alert"     },
  malware_alert:   { icon: "🦠", color: "#dc2626",  label: "Malware Alert"    },
  sysmon_alert:    { icon: "🔍", color: "#a78bfa",  label: "Sysmon Alert"     },
  response_action: { icon: "🛡️", color: "#22c55e",  label: "Response Action"  },
  user_anomaly:    { icon: "👤", color: "var(--accent-amber)",  label: "User Anomaly"     },
};

// Severity colors for fusion_alert color override
const SEV_COLORS: Record<string, string> = {
  CRITICAL: "#dc2626",
  HIGH:     "#ef4444",
  MEDIUM:   "#f59e0b",
  LOW:      "#3b82f6",
};

// Source layer chip colors
const SOURCE_LAYER_COLORS: Record<string, string> = {
  network:   "#00d4ff",
  user:      "#22c55e",
  system:    "#f59e0b",
  malware:   "#dc2626",
  fusion:    "#ef4444",
  sysmon:    "#a78bfa",
  rule:      "#f97316",
};

// ── Helpers ───────────────────────────────────────────────────────────────────

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

function buildDescription(event: TimelineEvent): string {
  const d = event.data;
  switch (event.event_type) {
    case "network_anomaly":
      return `${d.attack_type ?? "Attack"} from ${d.source_ip ?? d.src_ip ?? "unknown"} → port ${d.destination_port ?? d.dest_port ?? "?"}`;
    case "system_anomaly":
      return `System anomaly — CPU ${d.cpu ?? "?"}% MEM ${d.memory ?? "?"}%`;
    case "fusion_alert":
      return `Fusion: ${d.attack_type ?? "Threat"} score ${d.threat_score != null ? `${Math.round((d.threat_score as number) * 100)}%` : "?"}`;
    case "malware_alert":
      return `Malware: ${d.label ?? d.prediction ?? "detected"} — ${d.file_path ?? d.process_name ?? "unknown file"}`;
    case "sysmon_alert":
      return `Sysmon: ${d.event_type ?? d.action ?? "behavioral event"}`;
    case "user_anomaly":
      return `User: ${d.username ?? d.user ?? "unknown"} — score ${d.score != null ? `${Math.round((d.score as number) * 100)}%` : "?"}`;
    case "response_action":
      return `Response: ${d.action ?? "action"} → ${d.target ?? "target"}`;
    default:
      return JSON.stringify(d).slice(0, 80);
  }
}

// ── ReplayStep row sub-component ──────────────────────────────────────────────

function ReplayStepRow({
  step,
  currentStep,
  onStepClick,
  activeRef,
}: {
  step: ReplayStep;
  currentStep: number;
  onStepClick: (s: number) => void;
  activeRef: React.RefObject<HTMLDivElement | null>;
}) {
  const isActive = step.step === currentStep;
  const isPast   = step.step < currentStep;
  const opacity  = isActive ? 1 : isPast ? 0.6 : 0.35;

  const sevColor = SEV_COLORS[step.severity?.toUpperCase()] ?? "#94a3b8";
  const srcColor = SOURCE_LAYER_COLORS[step.source_layer?.toLowerCase()] ?? "#64748b";

  const borderLeft = isActive ? `3px solid ${sevColor}` : "3px solid transparent";
  const rowBg      = isActive ? `${sevColor}14` : "transparent";

  return (
    <div
      ref={isActive ? (activeRef as React.RefObject<HTMLDivElement>) : undefined}
      role="button"
      tabIndex={0}
      aria-label={`Step ${step.step + 1}: ${step.event_type} at ${formatTs(step.timestamp)}`}
      onClick={() => onStepClick(step.step)}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onStepClick(step.step);
        }
      }}
      style={{
        display: "flex",
        alignItems: "flex-start",
        gap: 12,
        padding: "9px 10px 9px 0",
        cursor: "pointer",
        opacity,
        borderLeft,
        background: rowBg,
        borderRadius: isActive ? "0 8px 8px 0" : 0,
        transition: "opacity 0.2s, background 0.2s, border-color 0.2s",
        position: "relative",
      }}
    >
      {/* Dot */}
      <div
        style={{
          width: 30,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          flexShrink: 0,
          paddingLeft: isActive ? 3 : 0,
        }}
      >
        <div
          style={{
            width: 24,
            height: 24,
            borderRadius: "50%",
            background: `${sevColor}22`,
            border: `2px solid ${sevColor}${isActive ? "cc" : "55"}`,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: 9,
            fontWeight: 800,
            color: sevColor,
            flexShrink: 0,
            boxShadow: isActive ? `0 0 10px ${sevColor}55` : "none",
            transition: "box-shadow 0.2s",
            fontFamily: "'Fira Code', monospace",
          }}
        >
          {String(step.step + 1).padStart(2, "0")}
        </div>
      </div>

      {/* Content */}
      <div style={{ flex: 1, minWidth: 0 }}>
        {/* Top row: time + severity + source_layer */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 5,
            marginBottom: 3,
            flexWrap: "wrap" as const,
          }}
        >
          {/* Time pill */}
          <span
            style={{
              fontFamily: "'Fira Code', 'SF Mono', monospace",
              fontSize: 9,
              fontWeight: 700,
              letterSpacing: 0.8,
              color: "var(--text-secondary)",
              background: "var(--bg-secondary)",
              border: "1px solid var(--border-color)",
              borderRadius: 5,
              padding: "1px 6px",
              flexShrink: 0,
            }}
          >
            {formatTs(step.timestamp)}
          </span>

          {/* Severity chip */}
          <span
            style={{
              fontSize: 8,
              fontWeight: 800,
              letterSpacing: 0.8,
              color: sevColor,
              background: `${sevColor}18`,
              border: `1px solid ${sevColor}40`,
              borderRadius: 4,
              padding: "1px 5px",
              flexShrink: 0,
              textTransform: "uppercase" as const,
            }}
          >
            {step.severity}
          </span>

          {/* Source layer chip */}
          <span
            style={{
              fontSize: 8,
              fontWeight: 700,
              letterSpacing: 0.5,
              color: srcColor,
              background: `${srcColor}15`,
              border: `1px solid ${srcColor}30`,
              borderRadius: 4,
              padding: "1px 5px",
              flexShrink: 0,
              textTransform: "uppercase" as const,
            }}
          >
            {step.source_layer}
          </span>

          {/* MITRE badge */}
          {step.mitre_technique && (
            <span
              style={{
                fontSize: 8,
                fontWeight: 700,
                letterSpacing: 0.3,
                color: "#a78bfa",
                background: "rgba(167,139,250,0.12)",
                border: "1px solid rgba(167,139,250,0.3)",
                borderRadius: 4,
                padding: "1px 5px",
                flexShrink: 0,
                fontFamily: "'Fira Code', monospace",
              }}
            >
              {step.mitre_technique}
            </span>
          )}

          {/* Step index */}
          <span
            style={{
              marginLeft: "auto",
              fontFamily: "'Fira Code', monospace",
              fontSize: 9,
              color: "var(--text-muted)",
              flexShrink: 0,
            }}
          >
            #{String(step.step + 1).padStart(2, "0")}
          </span>
        </div>

        {/* Description */}
        <div
          style={{
            fontSize: 11,
            color: isActive ? "#cbd5e1" : "#64748b",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            transition: "color 0.2s",
          }}
        >
          {step.description}
        </div>

        {/* Active step extra detail */}
        {isActive && (step.tactic || step.attack_type) && (
          <div
            style={{
              marginTop: 4,
              display: "flex",
              gap: 5,
              flexWrap: "wrap" as const,
            }}
          >
            {step.attack_type && (
              <span
                style={{
                  fontSize: 9,
                  color: "var(--accent-amber)",
                  fontFamily: "'Fira Code', monospace",
                }}
              >
                {step.attack_type}
              </span>
            )}
            {step.tactic && (
              <span
                style={{
                  fontSize: 9,
                  color: "var(--text-muted)",
                  fontStyle: "italic",
                }}
              >
                {step.tactic}
              </span>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function ReplayTimeline({
  events,
  currentStep,
  onStepClick,
  replaySteps,
}: ReplayTimelineProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const activeRef    = useRef<HTMLDivElement | null>(null);

  // Auto-scroll to keep active step visible
  useEffect(() => {
    if (activeRef.current && containerRef.current) {
      activeRef.current.scrollIntoView({
        block: "nearest",
        behavior: "smooth",
      });
    }
  }, [currentStep]);

  // ── Render from ReplayStep[] when provided ──────────────────────────────────
  if (replaySteps && replaySteps.length > 0) {
    return (
      <div
        ref={containerRef}
        style={{
          flex: 1,
          overflowY: "auto",
          display: "flex",
          flexDirection: "column",
          position: "relative",
          paddingRight: 4,
        }}
      >
        {/* Vertical connecting line */}
        <div
          style={{
            position: "absolute",
            left: 29,
            top: 0,
            bottom: 0,
            width: 2,
            background:
              "linear-gradient(180deg, #1e293b 0%, rgba(0,212,255,0.15) 50%, #1e293b 100%)",
            pointerEvents: "none",
          }}
        />
        {replaySteps.map((rs) => (
          <ReplayStepRow
            key={rs.step}
            step={rs}
            currentStep={currentStep}
            onStepClick={onStepClick}
            activeRef={activeRef}
          />
        ))}
      </div>
    );
  }

  // ── Fallback: render from TimelineEvent[] ───────────────────────────────────

  if (events.length === 0) {
    return (
      <div
        style={{
          flex: 1,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          color: "var(--text-muted)",
          fontSize: 13,
          fontStyle: "italic",
          padding: 24,
        }}
      >
        No timeline events recorded for this incident.
      </div>
    );
  }

  return (
    <div
      ref={containerRef}
      style={{
        flex: 1,
        overflowY: "auto",
        display: "flex",
        flexDirection: "column",
        position: "relative",
        paddingRight: 4,
      }}
    >
      {/* Vertical connecting line */}
      <div
        style={{
          position: "absolute",
          left: 29,
          top: 0,
          bottom: 0,
          width: 2,
          background: "linear-gradient(180deg, #1e293b 0%, rgba(0,212,255,0.15) 50%, #1e293b 100%)",
          pointerEvents: "none",
        }}
      />

      {events.map((ev) => {
        const cfg = EVENT_CONFIG[ev.event_type] ?? { icon: "●", color: "var(--text-muted)", label: ev.event_type };

        // Override fusion_alert color by severity
        let dotColor = cfg.color;
        if (ev.event_type === "fusion_alert" && ev.data.severity) {
          dotColor = SEV_COLORS[String(ev.data.severity).toUpperCase()] ?? cfg.color;
        }

        const isActive = ev.step === currentStep;
        const isPast   = ev.step < currentStep;

        const opacity = isActive ? 1 : isPast ? 0.6 : 0.35;
        const borderLeft = isActive
          ? `3px solid ${dotColor}`
          : "3px solid transparent";
        const rowBg = isActive
          ? `${dotColor}14`
          : "transparent";

        // Source layer from data
        const srcLayer = ev.data.source_layer as string | undefined ?? ev.source_label;
        const srcColor = srcLayer
          ? SOURCE_LAYER_COLORS[srcLayer.toLowerCase()] ?? "#64748b"
          : "#64748b";

        // MITRE technique from data
        const mitreTag = ev.data.mitre_technique as string | undefined;

        return (
          <div
            key={ev.step}
            ref={isActive ? (activeRef as React.RefObject<HTMLDivElement>) : undefined}
            role="button"
            tabIndex={0}
            aria-label={`Step ${ev.step + 1}: ${cfg.label} at ${formatTs(ev.ts)}`}
            onClick={() => onStepClick(ev.step)}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                onStepClick(ev.step);
              }
            }}
            style={{
              display: "flex",
              alignItems: "flex-start",
              gap: 12,
              padding: "9px 10px 9px 0",
              marginLeft: 0,
              cursor: "pointer",
              opacity,
              borderLeft,
              background: rowBg,
              borderRadius: isActive ? "0 8px 8px 0" : 0,
              transition: "opacity 0.2s, background 0.2s, border-color 0.2s",
              position: "relative",
            }}
          >
            {/* Dot on the timeline line */}
            <div
              style={{
                width: 30,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                flexShrink: 0,
                paddingLeft: isActive ? 3 : 0,
              }}
            >
              <div
                style={{
                  width: 24,
                  height: 24,
                  borderRadius: "50%",
                  background: `${dotColor}22`,
                  border: `2px solid ${dotColor}${isActive ? "cc" : "55"}`,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  fontSize: 11,
                  flexShrink: 0,
                  boxShadow: isActive ? `0 0 10px ${dotColor}55` : "none",
                  transition: "box-shadow 0.2s",
                }}
              >
                {cfg.icon}
              </div>
            </div>

            {/* Content */}
            <div style={{ flex: 1, minWidth: 0 }}>
              {/* Top row: time pill + type label + source chip + MITRE + score */}
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 7,
                  marginBottom: 3,
                  flexWrap: "wrap" as const,
                }}
              >
                {/* Time pill */}
                <span
                  style={{
                    fontFamily: "'Fira Code', 'SF Mono', monospace",
                    fontSize: 9,
                    fontWeight: 700,
                    letterSpacing: 0.8,
                    color: "var(--text-secondary)",
                    background: "var(--bg-secondary)",
                    border: "1px solid var(--border-color)",
                    borderRadius: 5,
                    padding: "1px 6px",
                    flexShrink: 0,
                  }}
                >
                  {formatTs(ev.ts)}
                </span>

                {/* Type label */}
                <span
                  style={{
                    fontSize: 9,
                    fontWeight: 800,
                    letterSpacing: 1,
                    textTransform: "uppercase" as const,
                    color: dotColor,
                    flexShrink: 0,
                  }}
                >
                  {cfg.label}
                </span>

                {/* Source layer chip */}
                {srcLayer && (
                  <span
                    style={{
                      fontSize: 8,
                      fontWeight: 700,
                      letterSpacing: 0.5,
                      color: srcColor,
                      background: `${srcColor}15`,
                      border: `1px solid ${srcColor}30`,
                      borderRadius: 4,
                      padding: "1px 5px",
                      flexShrink: 0,
                      textTransform: "uppercase" as const,
                    }}
                  >
                    {srcLayer}
                  </span>
                )}

                {/* MITRE technique badge */}
                {mitreTag && (
                  <span
                    style={{
                      fontSize: 8,
                      fontWeight: 700,
                      letterSpacing: 0.3,
                      color: "#a78bfa",
                      background: "rgba(167,139,250,0.12)",
                      border: "1px solid rgba(167,139,250,0.3)",
                      borderRadius: 4,
                      padding: "1px 5px",
                      flexShrink: 0,
                      fontFamily: "'Fira Code', monospace",
                    }}
                  >
                    {mitreTag}
                  </span>
                )}

                {/* Score badge */}
                {ev.score != null && (
                  <span
                    style={{
                      fontSize: 8,
                      fontWeight: 800,
                      fontFamily: "'Fira Code', monospace",
                      color: ev.score >= 0.85 ? "#ff3366" : ev.score >= 0.65 ? "#f59e0b" : "#00ff88",
                      background: "rgba(0,0,0,0.3)",
                      border: `1px solid ${ev.score >= 0.85 ? "rgba(255,51,102,0.3)" : ev.score >= 0.65 ? "rgba(245,158,11,0.3)" : "rgba(0,255,136,0.3)"}`,
                      borderRadius: 4,
                      padding: "1px 5px",
                      flexShrink: 0,
                    }}
                  >
                    {Math.round(ev.score > 1 ? ev.score : ev.score * 100)}%
                  </span>
                )}

                {/* Step index */}
                <span
                  style={{
                    marginLeft: "auto",
                    fontFamily: "'Fira Code', monospace",
                    fontSize: 9,
                    color: "var(--text-muted)",
                    flexShrink: 0,
                  }}
                >
                  #{String(ev.step + 1).padStart(2, "0")}
                </span>
              </div>

              {/* Description */}
              <div
                style={{
                  fontSize: 11,
                  color: isActive ? "#cbd5e1" : "#64748b",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                  fontFamily: ev.event_type === "malware_alert" || ev.event_type === "sysmon_alert"
                    ? "'Fira Code', monospace"
                    : "inherit",
                  transition: "color 0.2s",
                }}
              >
                {buildDescription(ev)}
              </div>

              {/* Active step — extra detail line */}
              {isActive && (ev.data.severity != null || ev.data.prediction != null) ? (
                <div
                  style={{
                    marginTop: 4,
                    display: "flex",
                    gap: 6,
                    flexWrap: "wrap" as const,
                  }}
                >
                  {ev.data.severity != null ? (
                    <span
                      style={{
                        fontSize: 9,
                        fontWeight: 800,
                        letterSpacing: 0.8,
                        color: SEV_COLORS[String(ev.data.severity).toUpperCase()] ?? "#94a3b8",
                        background: `${SEV_COLORS[String(ev.data.severity).toUpperCase()] ?? "#94a3b8"}18`,
                        border: `1px solid ${SEV_COLORS[String(ev.data.severity).toUpperCase()] ?? "#94a3b8"}40`,
                        borderRadius: 5,
                        padding: "1px 7px",
                      }}
                    >
                      {String(ev.data.severity).toUpperCase()}
                    </span>
                  ) : null}
                  {ev.data.confidence != null ? (
                    <span
                      style={{
                        fontSize: 9,
                        color: "var(--text-secondary)",
                        fontFamily: "monospace",
                      }}
                    >
                      conf: {Math.round(Number(ev.data.confidence))}%
                    </span>
                  ) : null}
                </div>
              ) : null}
            </div>
          </div>
        );
      })}
    </div>
  );
}
