// RecentEvents.tsx — live event feed side rail panel

import React from "react";
import styles from "./attack-graph.module.css";
import { GraphData, TimelineEntry } from "./types";

interface Props {
  data: GraphData;
  /** Maximum rows to display (default 5) */
  maxRows?: number;
}

function nodeLabel(data: GraphData, id: string): string {
  const n = data.NODES.find((x) => x.id === id);
  return n ? n.label : id;
}

export default function RecentEvents({ data, maxRows = 5 }: Props) {
  const events: TimelineEntry[] = data.TIMELINE.slice().reverse().slice(0, maxRows);

  return (
    <div className={styles.recentEvents}>
      <div
        className={styles.legendHead}
        style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}
      >
        <span>RECENT EVENTS</span>
        <span
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 4,
            color: "#22c55e",
          }}
        >
          <span className={styles.liveDot} aria-hidden="true" />
          live
        </span>
      </div>

      {events.length === 0 && (
        <div className={styles.empty}>No attack chain events recorded.</div>
      )}

      <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>
        {events.map((e, i) => (
          <div
            key={i}
            className={`${styles.eventRow} ${i < events.length - 1 ? styles.eventRowBorder : ""}`}
          >
            <span
              style={{
                fontFamily: "'Fira Code', monospace",
                fontSize: 9,
                color: "var(--text-muted)",
              }}
            >
              {e.ts}
            </span>
            <span style={{ fontSize: 10, color: "#cbd5e1" }}>
              <span
                style={{
                  color: "#fca5a5",
                  textTransform: "capitalize",
                  fontWeight: 700,
                }}
              >
                {e.action}
              </span>
              <span
                style={{
                  fontFamily: "'Fira Code', monospace",
                  color: "var(--text-muted)",
                  marginLeft: 6,
                  fontSize: 9,
                }}
              >
                {nodeLabel(data, e.src)} → {nodeLabel(data, e.dst)}
              </span>
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
