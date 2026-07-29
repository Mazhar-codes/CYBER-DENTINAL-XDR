// GraphControls.tsx — replay scrubber + stats + legend
// Converted from GraphControls.jsx

import React from "react";
import LiveIndicator from "../../shared/LiveIndicator";
import styles from "./attack-graph.module.css";

// ── Legend ────────────────────────────────────────────────────────────────────

const LEGEND_NODES = [
  { k: "alert",        g: "⚠", c: "#dc2626", l: "Active Threat"  },
  { k: "threat_actor", g: "☠", c: "#dc2626", l: "Threat Actor"   },
  { k: "endpoint",     g: "▣", c: "#3b82f6", l: "Endpoint"       },
  { k: "ip",           g: "◈", c: "#00d4ff", l: "IP / Domain"    },
  { k: "process",      g: "⬣", c: "#a78bfa", l: "Process"        },
  { k: "technique",    g: "⬡", c: "#a78bfa", l: "MITRE Technique"},
  { k: "user",         g: "◉", c: "#22c55e", l: "User Session"   },
  { k: "file",         g: "◬", c: "#f97316", l: "File / Malware" },
];

const LEGEND_SEVERITY = [
  { label: "CRITICAL", color: "#dc2626" },
  { label: "HIGH",     color: "#ef4444" },
  { label: "MEDIUM",   color: "var(--accent-amber)" },
  { label: "LOW",      color: "#3b82f6" },
];

const SPEED_OPTIONS = [1, 2, 5, 10];

export function GraphLegend() {
  return (
    <div className={styles.legend}>
      <div className={styles.legendHead}>NODE TYPES</div>
      <div className={styles.legendList}>
        {LEGEND_NODES.map((item) => (
          <div key={item.k} className={styles.legendItem}>
            <span
              className={styles.legendDot}
              style={{
                color: item.c,
                borderColor: item.c + "55",
                background: item.c + "1a",
              }}
            >
              {item.g}
            </span>
            <span className={styles.legendLbl}>{item.l}</span>
          </div>
        ))}
      </div>

      <div className={styles.legendHead} style={{ marginTop: 12 }}>SEVERITY</div>
      <div className={styles.legendList}>
        {LEGEND_SEVERITY.map((s) => (
          <div key={s.label} className={styles.legendItem}>
            <span
              style={{
                width: 24, height: 24, borderRadius: "50%",
                border: `2px solid ${s.color}55`,
                background: s.color + "22",
                display: "flex", alignItems: "center", justifyContent: "center",
                flexShrink: 0,
              }}
            />
            <span className={styles.legendLbl} style={{ color: s.color }}>{s.label}</span>
          </div>
        ))}
      </div>

      <div className={styles.legendHead} style={{ marginTop: 12 }}>EDGES</div>
      <div className={styles.legendEdges}>
        <div className={styles.legendEdge}>
          <span className={`${styles.edgeLine} ${styles.edgeMal}`} />
          <span>Attack chain (lit)</span>
        </div>
        <div className={styles.legendEdge}>
          <span className={`${styles.edgeLine} ${styles.edgePot}`} />
          <span>Potential malicious</span>
        </div>
        <div className={styles.legendEdge}>
          <span className={`${styles.edgeLine} ${styles.edgeNorm}`} />
          <span>Normal activity</span>
        </div>
      </div>
    </div>
  );
}

// ── Controls ──────────────────────────────────────────────────────────────────

interface GraphControlsProps {
  replayStep: number;
  totalSteps: number;
  paused: boolean;
  setPaused: (p: boolean | ((prev: boolean) => boolean)) => void;
  setReplayStep: (s: number | ((prev: number) => number)) => void;
  alertCount: number;
  eventsPerSec: number;
  isConnected: boolean;
  /** Playback speed multiplier (1 | 2 | 5 | 10) */
  replaySpeed: number;
  onSpeedChange: (speed: number) => void;
}

export default function GraphControls({
  replayStep,
  totalSteps,
  paused,
  setPaused,
  setReplayStep,
  alertCount,
  eventsPerSec,
  isConnected,
  replaySpeed,
  onSpeedChange,
}: GraphControlsProps) {

  const secondsRemaining =
    totalSteps > 0 && replaySpeed > 0
      ? Math.ceil((totalSteps - replayStep) / replaySpeed)
      : 0;

  const handlePlay = () => {
    if (replayStep >= totalSteps) {
      setReplayStep(0);
    }
    setPaused(false);
  };

  const handlePause = () => {
    setPaused(true);
  };

  const handleReset = () => {
    setReplayStep(0);
    setPaused(true);
  };

  return (
    <div className={styles.controls}>
      {/* ── Section header ── */}
      <div
        style={{
          fontSize: 9,
          fontWeight: 800,
          letterSpacing: 1.5,
          color: "var(--text-secondary)",
          textTransform: "uppercase" as const,
          marginBottom: 8,
        }}
      >
        REPLAY CONTROLS
      </div>

      {/* ── Play / Pause / Reset row ── */}
      <div className={styles.controlsRow}>
        <button
          className={`${styles.ctlBtn} ${styles.ctlPlay}`}
          onClick={handlePlay}
          disabled={!paused}
          aria-label="Start replay"
          title="Play"
        >
          ▶
        </button>

        <button
          className={styles.ctlBtn}
          onClick={handlePause}
          disabled={paused}
          aria-label="Pause replay"
          title="Pause"
        >
          ⏸
        </button>

        <button
          className={styles.ctlBtn}
          onClick={handleReset}
          aria-label="Reset replay to start"
          title="Reset"
        >
          ↺
        </button>

        {/* Step forward */}
        <button
          className={styles.ctlBtn}
          onClick={() => setReplayStep((s) => Math.min(s + 1, totalSteps))}
          aria-label="Step forward one chain step"
          title="Step"
        >
          <span style={{ fontSize: 13 }}>▷|</span>
        </button>
      </div>

      {/* ── Seek scrubber ── */}
      <div style={{ marginTop: 8 }}>
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginBottom: 4,
          }}
        >
          <span
            style={{
              fontSize: 9,
              fontWeight: 700,
              letterSpacing: 1,
              color: "var(--text-secondary)",
              textTransform: "uppercase" as const,
            }}
          >
            STEP{" "}
            <span style={{ color: "var(--text-primary)" }}>
              {String(replayStep).padStart(2, "0")}
            </span>
            <span style={{ color: "var(--text-secondary)" }}>
              {" "}/ {String(totalSteps).padStart(2, "0")}
            </span>
          </span>
          {!paused && secondsRemaining > 0 && (
            <span
              style={{
                fontSize: 9,
                color: "var(--text-secondary)",
                fontFamily: "'Fira Code', monospace",
              }}
            >
              ~{secondsRemaining}s remaining
            </span>
          )}
        </div>
        <input
          type="range"
          min={0}
          max={totalSteps}
          value={replayStep}
          onChange={(e) => {
            setReplayStep(Number(e.target.value));
            setPaused(true);
          }}
          aria-label={`Seek to step (current: ${replayStep} of ${totalSteps})`}
          style={{
            width: "100%",
            accentColor: "#00d4ff",
            cursor: "pointer",
          }}
        />
      </div>

      {/* ── Speed selector ── */}
      <div style={{ marginTop: 10 }}>
        <div
          style={{
            fontSize: 9,
            fontWeight: 700,
            letterSpacing: 1,
            color: "var(--text-secondary)",
            textTransform: "uppercase" as const,
            marginBottom: 5,
          }}
        >
          SPEED
        </div>
        <div style={{ display: "flex", gap: 5 }}>
          {SPEED_OPTIONS.map((speed) => {
            const isActive = replaySpeed === speed;
            return (
              <button
                key={speed}
                onClick={() => onSpeedChange(speed)}
                aria-pressed={isActive}
                aria-label={`Set replay speed to ${speed}x`}
                style={{
                  flex: 1,
                  padding: "4px 0",
                  borderRadius: 5,
                  border: `1px solid ${isActive ? "rgba(0,212,255,0.55)" : "rgba(71,85,105,0.3)"}`,
                  background: isActive
                    ? "rgba(0,212,255,0.12)"
                    : "rgba(15,23,42,0.5)",
                  color: isActive ? "#00d4ff" : "#475569",
                  fontSize: 10,
                  fontWeight: 700,
                  fontFamily: "'Fira Code', monospace",
                  cursor: "pointer",
                  letterSpacing: 0.5,
                  transition: "border-color 0.15s, color 0.15s, background 0.15s",
                }}
              >
                {speed}x
              </button>
            );
          })}
        </div>
      </div>

      {/* ── Stats row ── */}
      <div
        className={styles.controlsRow}
        style={{ justifyContent: "space-between", marginTop: 12 }}
      >
        <div className={styles.ctlStat}>
          <span className={styles.ctlStatLbl}>ACTIVE ALERTS</span>
          <span className={styles.ctlStatVal} style={{ color: "#dc2626" }}>
            {alertCount}
          </span>
        </div>

        <div className={styles.ctlStat}>
          <span className={styles.ctlStatLbl}>EVENTS / SEC</span>
          <span
            className={styles.ctlStatVal}
            style={{
              color: "var(--color-primary)",
              fontFamily: "'Fira Code', monospace",
            }}
          >
            {eventsPerSec.toFixed(1)}
          </span>
        </div>

        <div className={styles.ctlStat}>
          <span className={styles.ctlStatLbl}>WS</span>
          {isConnected ? (
            <span
              className={styles.ctlStatVal}
              style={{
                color: "#22c55e",
                display: "inline-flex",
                alignItems: "center",
                gap: 5,
              }}
            >
              <span className={styles.liveDot} aria-hidden="true" />
              CONNECTED
            </span>
          ) : (
            <span className={styles.ctlStatVal} style={{ color: "var(--text-secondary)" }}>
              OFFLINE
            </span>
          )}
        </div>
      </div>

      {/* LiveIndicator — second visual cue for connection status */}
      {isConnected && (
        <div style={{ display: "flex", justifyContent: "flex-end" }}>
          <LiveIndicator active={isConnected} label="WSS · LIVE" />
        </div>
      )}
    </div>
  );
}
