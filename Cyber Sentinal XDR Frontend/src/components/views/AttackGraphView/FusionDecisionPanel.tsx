// FusionDecisionPanel.tsx — per-model breakdown of a fusion threat score
// Shows WHY the fusion engine raised severity with visual bar charts per model.

import React from "react";

interface ModelContribution {
  score: number;       // 0–1
  weight: number;      // 0–1 (e.g. 0.35)
  contribution: number; // score × weight, 0–1
}

interface FusionAlertData {
  threat_score: number;
  severity: string;
  attack_type: string;
  sources?: string[];
  components?: {
    network?: ModelContribution;
    user?: ModelContribution;
    system?: ModelContribution;
    malware?: ModelContribution;
  };
  mitre_technique?: string;
}

export interface FusionDecisionPanelProps {
  fusionAlert: FusionAlertData | null;
}

// ── Color maps ────────────────────────────────────────────────────────────────

const SEV_COLORS: Record<string, { bg: string; text: string; glow: string }> = {
  CRITICAL: { bg: "#dc2626",  text: "#fca5a5",  glow: "0 0 18px rgba(220,38,38,0.6)"   },
  HIGH:     { bg: "#ea580c",  text: "#fdba74",  glow: "0 0 18px rgba(234,88,12,0.5)"   },
  MEDIUM:   { bg: "#d97706",  text: "#fde68a",  glow: "0 0 14px rgba(217,119,6,0.45)"  },
  LOW:      { bg: "#3b82f6",  text: "#93c5fd",  glow: "0 0 14px rgba(59,130,246,0.4)"  },
};

const MODEL_COLORS: Record<string, string> = {
  network: "#00d4ff",
  user:    "#a78bfa",
  system:  "#f59e0b",
  malware: "#ef4444",
};

const MODEL_ICONS: Record<string, string> = {
  network: "⬡",
  user:    "◉",
  system:  "◫",
  malware: "⬣",
};

const MODEL_ORDER = ["network", "user", "system", "malware"] as const;
type ModelKey = typeof MODEL_ORDER[number];

// Default weights when backend omits components
const DEFAULT_WEIGHTS: Record<ModelKey, number> = {
  network: 0.35,
  user:    0.30,
  system:  0.15,
  malware: 0.20,
};

// ── Gauge ring ────────────────────────────────────────────────────────────────

interface GaugeProps {
  pct: number;       // 0–100
  color: string;
  glow: string;
}

function ArcGauge({ pct, color, glow }: GaugeProps) {
  const R = 52;
  const cx = 68;
  const cy = 68;

  // SVG: start at 135° (bottom-left), sweep 270° clockwise
  const startAngle = 135;

  function polarToXY(cx: number, cy: number, r: number, deg: number) {
    const rad = ((deg - 90) * Math.PI) / 180;
    return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) };
  }

  // Track arc (grey) — 270° from 135° to 405° = 45°
  const trackD = describeArc(cx, cy, R, startAngle, startAngle + 270);
  // Filled arc
  const filledDeg = pct * 2.7; // 270° total for 100%
  const fillD = filledDeg > 0
    ? describeArc(cx, cy, R, startAngle, startAngle + filledDeg)
    : "";

  function describeArc(cx: number, cy: number, r: number, startDeg: number, endDeg: number): string {
    const s = polarToXY(cx, cy, r, startDeg);
    const e = polarToXY(cx, cy, r, endDeg);
    const large = endDeg - startDeg > 180 ? 1 : 0;
    return `M ${s.x} ${s.y} A ${r} ${r} 0 ${large} 1 ${e.x} ${e.y}`;
  }

  return (
    <svg width={136} height={136} viewBox="0 0 136 136" style={{ overflow: "visible" }}>
      {/* Drop shadow filter */}
      <defs>
        <filter id="gauge-glow">
          <feGaussianBlur stdDeviation="3" result="blur" />
          <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
      </defs>

      {/* Track */}
      <path d={trackD} fill="none" stroke="#1e293b" strokeWidth={10} strokeLinecap="round" />

      {/* Filled arc */}
      {fillD && (
        <path
          d={fillD}
          fill="none"
          stroke={color}
          strokeWidth={10}
          strokeLinecap="round"
          filter="url(#gauge-glow)"
          style={{ filter: `drop-shadow(0 0 6px ${color})` }}
        />
      )}

      {/* Center text */}
      <text
        x={cx}
        y={cy - 6}
        textAnchor="middle"
        fill={color}
        fontSize={24}
        fontWeight={800}
        fontFamily="'Fira Code', 'SF Mono', monospace"
      >
        {pct}
      </text>
      <text
        x={cx}
        y={cy + 14}
        textAnchor="middle"
        fill="#475569"
        fontSize={9}
        fontWeight={700}
        letterSpacing={1.5}
        fontFamily="'Fira Code', monospace"
      >
        THREAT %
      </text>
    </svg>
  );
}

// ── Skeleton placeholder ──────────────────────────────────────────────────────

function Skeleton() {
  return (
    <div style={{ padding: "24px 16px", display: "flex", flexDirection: "column", gap: 16 }}>
      {[120, 80, 100, 90].map((w, i) => (
        <div
          key={i}
          style={{
            height: 14,
            width: `${w}%`,
            maxWidth: w,
            background: "linear-gradient(90deg, #1e293b 25%, #273348 50%, #1e293b 75%)",
            backgroundSize: "200% 100%",
            borderRadius: 6,
            animation: "shimmer 1.5s ease-in-out infinite",
          }}
        />
      ))}
      <style>{`
        @keyframes shimmer {
          0%   { background-position: 200% 0; }
          100% { background-position: -200% 0; }
        }
      `}</style>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function FusionDecisionPanel({ fusionAlert }: FusionDecisionPanelProps) {
  if (!fusionAlert) {
    return (
      <div
        style={{
          background: "linear-gradient(135deg, #0d1629, #0a1120)",
          border: "1px solid var(--border-color)",
          borderRadius: 14,
          overflow: "hidden",
        }}
      >
        {/* Header */}
        <div
          style={{
            padding: "12px 16px",
            borderBottom: "1px solid var(--border-color)",
            display: "flex",
            alignItems: "center",
            gap: 8,
          }}
        >
          <span style={{ fontSize: 13, color: "#ea580c" }}>⚡</span>
          <span
            style={{
              fontFamily: "'Fira Code', monospace",
              fontSize: 10,
              fontWeight: 700,
              letterSpacing: 1.5,
              color: "var(--text-secondary)",
              textTransform: "uppercase",
            }}
          >
            Fusion Decision
          </span>
        </div>
        <Skeleton />
      </div>
    );
  }

  const pct = Math.round(fusionAlert.threat_score * 100);
  const sevKey = (fusionAlert.severity ?? "MEDIUM").toUpperCase();
  const sevStyle = SEV_COLORS[sevKey] ?? SEV_COLORS.MEDIUM;
  const sourceSet = new Set((fusionAlert.sources ?? []).map((s) => s.toLowerCase()));

  return (
    <div
      style={{
        background: "linear-gradient(135deg, #0d1629, #0a1120)",
        border: "1px solid var(--border-color)",
        borderRadius: 14,
        overflow: "hidden",
        display: "flex",
        flexDirection: "column",
      }}
    >
      {/* ── Header ── */}
      <div
        style={{
          padding: "12px 16px",
          borderBottom: "1px solid var(--border-color)",
          display: "flex",
          alignItems: "center",
          gap: 8,
        }}
      >
        <span style={{ fontSize: 14, color: "#ea580c" }}>⚡</span>
        <span
          style={{
            fontFamily: "'Fira Code', monospace",
            fontSize: 10,
            fontWeight: 700,
            letterSpacing: 1.5,
            color: "var(--text-secondary)",
            textTransform: "uppercase",
            flex: 1,
          }}
        >
          Fusion Decision
        </span>

        {/* Severity pill */}
        <span
          style={{
            background: `${sevStyle.bg}22`,
            color: sevStyle.text,
            border: `1px solid ${sevStyle.bg}55`,
            borderRadius: 6,
            padding: "3px 9px",
            fontSize: 9,
            fontWeight: 800,
            letterSpacing: 1,
            textTransform: "uppercase",
            boxShadow: sevStyle.glow,
          }}
        >
          {sevKey}
        </span>
      </div>

      {/* ── Gauge + attack type ── */}
      <div
        style={{
          padding: "16px 16px 8px",
          display: "flex",
          alignItems: "center",
          gap: 14,
        }}
      >
        <ArcGauge pct={pct} color={sevStyle.bg} glow={sevStyle.glow} />

        <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 8 }}>
          {/* Attack type */}
          <div>
            <div
              style={{
                fontFamily: "'Fira Code', monospace",
                fontSize: 8,
                fontWeight: 700,
                letterSpacing: 1.5,
                color: "var(--text-muted)",
                textTransform: "uppercase",
                marginBottom: 3,
              }}
            >
              Attack Type
            </div>
            <span
              style={{
                background: "#78350f22",
                color: "#fbbf24",
                border: "1px solid #78350f44",
                borderRadius: 6,
                padding: "3px 9px",
                fontSize: 11,
                fontWeight: 700,
              }}
            >
              {fusionAlert.attack_type || "Unknown"}
            </span>
          </div>

          {/* MITRE tag */}
          {fusionAlert.mitre_technique && (
            <div>
              <div
                style={{
                  fontFamily: "'Fira Code', monospace",
                  fontSize: 8,
                  fontWeight: 700,
                  letterSpacing: 1.5,
                  color: "var(--text-muted)",
                  textTransform: "uppercase",
                  marginBottom: 3,
                }}
              >
                MITRE
              </div>
              <span
                style={{
                  background: "#431407",
                  color: "#fb923c",
                  border: "1px solid #7c2d1244",
                  borderRadius: 6,
                  padding: "3px 9px",
                  fontSize: 10,
                  fontWeight: 700,
                  fontFamily: "'Fira Code', monospace",
                  letterSpacing: 0.5,
                }}
              >
                {fusionAlert.mitre_technique}
              </span>
            </div>
          )}

          {/* Active sources chips */}
          <div style={{ display: "flex", flexWrap: "wrap", gap: 5 }}>
            {MODEL_ORDER.filter((m) => sourceSet.has(m)).map((m) => (
              <span
                key={m}
                style={{
                  fontSize: 9,
                  fontWeight: 700,
                  letterSpacing: 0.8,
                  color: MODEL_COLORS[m],
                  background: `${MODEL_COLORS[m]}18`,
                  border: `1px solid ${MODEL_COLORS[m]}40`,
                  borderRadius: 5,
                  padding: "2px 7px",
                }}
              >
                {MODEL_ICONS[m]} {m.charAt(0).toUpperCase() + m.slice(1)}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* ── Per-model breakdown ── */}
      <div
        style={{
          padding: "0 16px 16px",
          display: "flex",
          flexDirection: "column",
          gap: 10,
        }}
      >
        <div
          style={{
            fontFamily: "'Fira Code', monospace",
            fontSize: 8,
            fontWeight: 700,
            letterSpacing: 1.8,
            color: "var(--text-muted)",
            textTransform: "uppercase",
            marginBottom: 2,
          }}
        >
          Model Contributions
        </div>

        {MODEL_ORDER.map((modelKey) => {
          const isActive = sourceSet.has(modelKey);
          const comp = fusionAlert.components?.[modelKey];
          const weight = comp?.weight ?? DEFAULT_WEIGHTS[modelKey];
          const score = comp?.score ?? 0;
          const contribution = comp?.contribution ?? (isActive ? score * weight : 0);
          const color = MODEL_COLORS[modelKey];
          const barPct = Math.min(Math.round(score * 100), 100);
          const contribPct = Math.min(Math.round(contribution * 100), 100);

          return (
            <div
              key={modelKey}
              style={{ opacity: isActive ? 1 : 0.35 }}
            >
              {/* Label row */}
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                  marginBottom: 4,
                }}
              >
                <span style={{ fontSize: 12, lineHeight: 1, color }}>{MODEL_ICONS[modelKey]}</span>
                <span
                  style={{
                    fontSize: 11,
                    fontWeight: 700,
                    color: isActive ? "#cbd5e1" : "#334155",
                    flex: 1,
                  }}
                >
                  {modelKey.charAt(0).toUpperCase() + modelKey.slice(1)}
                </span>

                {/* Weight badge */}
                <span
                  style={{
                    fontFamily: "'Fira Code', monospace",
                    fontSize: 8,
                    fontWeight: 700,
                    letterSpacing: 0.5,
                    color: "var(--text-secondary)",
                    background: "var(--bg-card)",
                    border: "1px solid var(--border-color)",
                    borderRadius: 4,
                    padding: "1px 5px",
                  }}
                >
                  w={weight.toFixed(2)}
                </span>

                {/* Score */}
                <span
                  style={{
                    fontFamily: "'Fira Code', monospace",
                    fontSize: 10,
                    fontWeight: 800,
                    color: isActive ? color : "#334155",
                    minWidth: 32,
                    textAlign: "right",
                  }}
                >
                  {barPct}%
                </span>
              </div>

              {/* Score bar */}
              <div
                style={{
                  height: 5,
                  background: "var(--bg-secondary)",
                  border: "1px solid var(--border-color)",
                  borderRadius: 3,
                  overflow: "hidden",
                  marginBottom: 2,
                }}
              >
                <div
                  style={{
                    height: "100%",
                    width: `${barPct}%`,
                    background: isActive
                      ? `linear-gradient(90deg, ${color}99, ${color})`
                      : "#1e293b",
                    borderRadius: 3,
                    boxShadow: isActive ? `0 0 6px ${color}55` : "none",
                    transition: "width 0.4s ease",
                  }}
                />
              </div>

              {/* Contribution line */}
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                }}
              >
                <div
                  style={{
                    fontFamily: "'Fira Code', monospace",
                    fontSize: 8,
                    color: "var(--text-muted)",
                    letterSpacing: 0.5,
                    flexShrink: 0,
                  }}
                >
                  contribution
                </div>
                <div
                  style={{
                    flex: 1,
                    height: 3,
                    background: "var(--bg-primary)",
                    borderRadius: 2,
                    overflow: "hidden",
                  }}
                >
                  <div
                    style={{
                      height: "100%",
                      width: `${contribPct * 4}%`, // ×4 to make contributions visible
                      maxWidth: "100%",
                      background: isActive ? `${color}66` : "#1e293b",
                      borderRadius: 2,
                      transition: "width 0.4s ease",
                    }}
                  />
                </div>
                <div
                  style={{
                    fontFamily: "'Fira Code', monospace",
                    fontSize: 8,
                    color: isActive ? color : "#334155",
                    fontWeight: 800,
                    minWidth: 28,
                    textAlign: "right",
                  }}
                >
                  {contribPct}%
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* ── Footer: total score reconfirmation ── */}
      <div
        style={{
          borderTop: "1px solid var(--border-color)",
          padding: "10px 16px",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
        }}
      >
        <span
          style={{
            fontFamily: "'Fira Code', monospace",
            fontSize: 9,
            fontWeight: 700,
            letterSpacing: 1.2,
            color: "var(--text-muted)",
            textTransform: "uppercase",
          }}
        >
          Combined Threat Score
        </span>
        <span
          style={{
            fontFamily: "'Fira Code', monospace",
            fontSize: 18,
            fontWeight: 800,
            color: sevStyle.bg,
            textShadow: `0 0 12px ${sevStyle.bg}`,
          }}
        >
          {pct}%
        </span>
      </div>
    </div>
  );
}
