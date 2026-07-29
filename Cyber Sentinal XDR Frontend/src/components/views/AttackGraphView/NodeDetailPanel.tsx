// NodeDetailPanel.tsx — slide-in side panel: Overview / SHAP / Timeline / Info / Suggested Response
// Converted from NodeDetailPanel.jsx with full TypeScript + accessibility

import React, { useState, useEffect, useRef, useCallback } from "react";
import SeverityBadge from "../../shared/SeverityBadge";
import styles from "./attack-graph.module.css";
import { GraphNode, GraphData, NODE_STYLE, SEV_COLOR } from "./types";
import { useAuth } from "../../../context/AuthContext";

interface Props {
  node: GraphNode | null;
  data: GraphData;
  onClose: () => void;
  onJumpToStep: (step: number) => void;
  onExecuteResponse?: (action: string, target: string) => void;
  onDismissResponse?: (action: string) => void;
}

type TabKey = "overview" | "shap" | "tl" | "resp" | "info";

function idLabel(data: GraphData, id: string): string {
  const n = data.NODES.find((x) => x.id === id);
  return n ? n.label : id;
}

/** Format a Date.now()-style ms timestamp or ISO string into a human-readable string */
function formatTimestamp(ts: string | undefined): string {
  if (!ts) return "—";
  try {
    return new Date(ts).toLocaleString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
      hour: "numeric",
      minute: "2-digit",
      hour12: true,
    });
  } catch {
    return ts;
  }
}

export default function NodeDetailPanel({
  node,
  data,
  onClose,
  onJumpToStep,
  onExecuteResponse,
  onDismissResponse,
}: Props) {
  const [tab, setTab] = useState<TabKey>("overview");
  const panelRef = useRef<HTMLDivElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);
  const { user } = useAuth();
  const role = user?.role ?? "viewer";

  // Reset to overview tab whenever the selected node changes
  useEffect(() => {
    setTab("overview");
  }, [node?.id]);

  // Focus trap — focus the close button when panel opens
  useEffect(() => {
    if (node && closeRef.current) {
      closeRef.current.focus();
    }
  }, [node]);

  // Esc key closes the panel
  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && node) {
        onClose();
      }
    };
    document.addEventListener("keydown", handleKey);
    return () => document.removeEventListener("keydown", handleKey);
  }, [node, onClose]);

  // Tab key focus trap within panel
  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key !== "Tab" || !panelRef.current) return;
      const focusable = panelRef.current.querySelectorAll<HTMLElement>(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
      );
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (e.shiftKey) {
        if (document.activeElement === first) {
          e.preventDefault();
          last.focus();
        }
      } else {
        if (document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    },
    []
  );

  if (!node) return null;

  const sev = SEV_COLOR[node.severity] ?? "#6b7280";
  const style = NODE_STYLE[node.type] ?? NODE_STYLE["endpoint"];
  const shap = data.SHAP[node.id] ?? [];
  const responses = data.RESPONSES[node.id] ?? [];

  const TABS: { k: TabKey; l: string }[] = [
    { k: "overview", l: "Overview"          },
    { k: "shap",     l: "SHAP"              },
    { k: "tl",       l: "Timeline"          },
    { k: "info",     l: "Info"              },
    { k: "resp",     l: "Response"          },
  ];

  // ── Overview tab data ──────────────────────────────────────────────────────
  // Build contributing model sources from node metadata fields
  const sourceChips: string[] = [];
  if (node.attack_type && node.attack_type !== "Endpoint Alert") {
    // Infer model from attack type
    const at = node.attack_type.toLowerCase();
    if (["dos", "ddos", "portscan", "bruteforce", "heartbleed", "botnet"].some((k) => at.includes(k))) {
      sourceChips.push("Network");
    } else if (at.includes("malware") || at.includes("ransomware")) {
      sourceChips.push("Malware");
    } else if (at.includes("insider") || at.includes("user")) {
      sourceChips.push("User");
    }
  }
  if (node.type === "user") sourceChips.push("User");
  if (node.type === "process" || node.hash) sourceChips.push("Malware");
  if (node.type === "endpoint" && sourceChips.length === 0) sourceChips.push("Network");
  if (sourceChips.length === 0) sourceChips.push("ML Detector");

  // ── Info tab data — collect all non-null metadata fields ──────────────────
  const metaEntries: Array<[string, string]> = [];
  const metaKeys: Array<keyof GraphNode> = [
    "id", "type", "severity", "risk", "attack_type", "src_ip", "dst_ip", "ip",
    "os", "dept", "department", "pid", "cmd", "command", "country", "geo",
    "asn", "path", "hash", "timestamp", "endpoint_id", "mitre_technique",
    "prediction", "score",
  ];
  for (const key of metaKeys) {
    const val = node[key];
    if (val == null || val === "" || (val === 0 && key === "risk")) continue;
    // Skip duplicates between ip/src_ip
    if (key === "ip" && metaEntries.some(([k]) => k === "src_ip")) continue;
    const display =
      typeof val === "number"
        ? Number.isInteger(val)
          ? String(val)
          : val.toFixed(3)
        : String(val);
    metaEntries.push([key, display]);
  }

  return (
    <div
      ref={panelRef}
      role="dialog"
      aria-modal="true"
      aria-label={`Node detail: ${node.label}`}
      className={styles.panel}
      onKeyDown={handleKeyDown}
    >
      {/* ── Header ── */}
      <div className={styles.panelHead} style={{ borderColor: sev + "44" }}>
        <div className={styles.panelHeadRow}>
          <span
            className={styles.panelGlyph}
            style={{
              background: style.color + "22",
              color: style.color,
              borderColor: style.color + "55",
            }}
          >
            {style.glyph}
          </span>
          <div className={styles.panelTitles}>
            <div className={styles.panelEyebrow} style={{ color: sev }}>
              {node.severity} · {style.label}
              {node.mitre_technique && (
                <span style={{ color: "#a78bfa", marginLeft: 8 }}>
                  [{node.mitre_technique}]
                </span>
              )}
            </div>
            <div className={styles.panelTitle}>
              {/* Never show bare "Unknown" in the panel title */}
              {node.attack_type
                ? node.attack_type
                : node.label && node.label.toLowerCase() !== "unknown"
                ? node.label
                : node.src_ip || node.ip || `${node.severity} Event`}
            </div>
          </div>
          <button
            ref={closeRef}
            className={styles.panelClose}
            onClick={onClose}
            aria-label="Close panel"
          >
            ×
          </button>
        </div>

        {/* Meta chips */}
        <div className={styles.panelMeta}>
          {node.attack_type && (
            <span
              className={styles.metaChip}
              style={{ background: `${sev}20`, borderColor: `${sev}55`, color: sev }}
            >
              {node.attack_type}
            </span>
          )}
          {(node.src_ip || node.ip) && (
            <span className={styles.metaChip}>src: {node.src_ip || node.ip}</span>
          )}
          {node.dst_ip && <span className={styles.metaChip}>dst: {node.dst_ip}</span>}
          {node.pid    && <span className={styles.metaChip}>PID {node.pid}</span>}
          {node.dept   && <span className={styles.metaChip}>{node.dept}</span>}
          {node.country && <span className={styles.metaChip}>{node.country}</span>}
          {node.hash   && <span className={styles.metaChip}>SHA {node.hash}</span>}
          {node.mitre_technique && (
            <span
              className={styles.metaChip}
              style={{ background: "rgba(167,139,250,0.12)", borderColor: "rgba(167,139,250,0.4)", color: "#a78bfa" }}
            >
              {node.mitre_technique}
            </span>
          )}
          {node.severity && <SeverityBadge severity={node.severity} size="sm" />}
        </div>

        {/* Threat score as percentage if available */}
        {node.score != null && (
          <div style={{ marginTop: 8, fontSize: 11, color: "var(--text-muted)", fontFamily: "'Fira Code', monospace" }}>
            Threat score:{" "}
            <span style={{ color: sev, fontWeight: 700 }}>{node.score}%</span>
          </div>
        )}

        {/* SHAP reason pills (brief) */}
        {node.shap_reasons && node.shap_reasons.length > 0 && (
          <div style={{ display: "flex", flexWrap: "wrap", gap: 5, marginTop: 8 }}>
            {node.shap_reasons.map((r, i) => (
              <span
                key={i}
                style={{
                  background: "rgba(220,38,38,0.1)",
                  border: "1px solid rgba(220,38,38,0.3)",
                  color: "#fca5a5",
                  padding: "2px 7px",
                  borderRadius: 4,
                  fontSize: 9,
                  fontFamily: "'Fira Code', monospace",
                  fontWeight: 600,
                }}
              >
                {r}
              </span>
            ))}
          </div>
        )}

        {/* Risk bar */}
        <div className={styles.panelRisk}>
          <span className={styles.panelRiskLbl}>RISK SCORE</span>
          <div className={styles.panelRiskBar}>
            <div
              className={styles.panelRiskFill}
              style={{
                width: `${node.risk ?? 0}%`,
                background: `linear-gradient(90deg, ${sev}, ${sev}aa)`,
                boxShadow: `0 0 12px ${sev}`,
              }}
            />
          </div>
          <span className={styles.panelRiskVal} style={{ color: sev }}>
            {node.risk ?? 0}
            <span style={{ opacity: 0.5, fontSize: 11 }}>/100</span>
          </span>
        </div>
      </div>

      {/* ── Tab bar ── */}
      <div className={styles.panelTabs} role="tablist">
        {TABS.map((t) => (
          <button
            key={t.k}
            role="tab"
            aria-selected={tab === t.k}
            className={`${styles.panelTab} ${tab === t.k ? styles.panelTabActive : ""}`}
            onClick={() => setTab(t.k)}
          >
            {t.l}
          </button>
        ))}
      </div>

      {/* ── Panel body ── */}
      <div className={styles.panelBody} role="tabpanel">

        {/* ── Overview tab — always useful, no SHAP dependency ─────────────── */}
        {tab === "overview" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            {/* Node type badge */}
            <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
              <span
                style={{
                  background: style.color + "22",
                  border: `1px solid ${style.color}55`,
                  color: style.color,
                  padding: "3px 10px",
                  borderRadius: 6,
                  fontSize: 10,
                  fontWeight: 700,
                  fontFamily: "'Fira Code', monospace",
                  letterSpacing: 1,
                  textTransform: "uppercase",
                }}
              >
                {style.glyph} {style.label}
              </span>
              <SeverityBadge severity={node.severity} size="sm" />
            </div>

            {/* Threat score progress bar */}
            <div>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: "var(--text-muted)", marginBottom: 4, fontFamily: "'Fira Code', monospace" }}>
                <span>THREAT SCORE</span>
                <span style={{ color: sev, fontWeight: 700 }}>{node.risk ?? 0}%</span>
              </div>
              <div style={{ height: 6, background: "rgba(255,255,255,0.06)", borderRadius: 3, overflow: "hidden" }}>
                <div
                  style={{
                    height: "100%",
                    width: `${node.risk ?? 0}%`,
                    background: `linear-gradient(90deg, ${sev}, ${sev}88)`,
                    boxShadow: `0 0 10px ${sev}66`,
                    borderRadius: 3,
                    transition: "width 0.4s ease",
                  }}
                />
              </div>
            </div>

            {/* Key-value grid */}
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "auto 1fr",
                gap: "6px 14px",
                fontSize: 11,
                fontFamily: "'Fira Code', monospace",
              }}
            >
              {node.attack_type && (
                <>
                  <span style={{ color: "var(--text-muted)", whiteSpace: "nowrap" }}>Attack type</span>
                  <span style={{ color: sev, fontWeight: 700 }}>{node.attack_type}</span>
                </>
              )}
              {(node.endpoint_id || node.id) && (
                <>
                  <span style={{ color: "var(--text-muted)", whiteSpace: "nowrap" }}>Endpoint</span>
                  <span style={{ color: "var(--text-secondary)" }}>{node.endpoint_id ?? node.id}</span>
                </>
              )}
              {(node.src_ip || node.ip) && (
                <>
                  <span style={{ color: "var(--text-muted)", whiteSpace: "nowrap" }}>Source IP</span>
                  <span style={{ color: "var(--accent-cyan)" }}>{node.src_ip || node.ip}</span>
                </>
              )}
              {node.dst_ip && (
                <>
                  <span style={{ color: "var(--text-muted)", whiteSpace: "nowrap" }}>Dest IP</span>
                  <span style={{ color: "var(--accent-cyan)" }}>{node.dst_ip}</span>
                </>
              )}
              {node.timestamp && (
                <>
                  <span style={{ color: "var(--text-muted)", whiteSpace: "nowrap" }}>Time</span>
                  <span style={{ color: "var(--text-secondary)" }}>{formatTimestamp(node.timestamp)}</span>
                </>
              )}
              {node.mitre_technique && (
                <>
                  <span style={{ color: "var(--text-muted)", whiteSpace: "nowrap" }}>MITRE</span>
                  <span style={{ color: "#a78bfa", fontWeight: 700 }}>{node.mitre_technique}</span>
                </>
              )}
            </div>

            {/* Contributing models as chips */}
            <div>
              <div style={{ fontSize: 10, color: "var(--text-muted)", marginBottom: 6, fontFamily: "'Fira Code', monospace", letterSpacing: 1 }}>
                CONTRIBUTING MODELS
              </div>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                {sourceChips.map((src) => (
                  <span
                    key={src}
                    style={{
                      background: "rgba(59,130,246,0.12)",
                      border: "1px solid rgba(59,130,246,0.3)",
                      color: "#60a5fa",
                      padding: "3px 9px",
                      borderRadius: 5,
                      fontSize: 10,
                      fontWeight: 700,
                      fontFamily: "'Fira Code', monospace",
                    }}
                  >
                    {src}
                  </span>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ── SHAP tab — role-gated, graceful when SHAP missing ─────────────── */}
        {tab === "shap" && (
          <div className={styles.shap}>
            {role === "viewer" ? (
              /* Viewer: plain text only */
              <div
                style={{
                  padding: "14px 18px",
                  background: "rgba(71,85,105,0.08)",
                  border: "1px solid var(--border-color)",
                  borderRadius: 8,
                  fontSize: 13,
                  color: "var(--text-secondary)",
                  lineHeight: 1.6,
                  fontStyle: "italic",
                  margin: "8px 0",
                }}
              >
                Suspicious process behavior detected. Contact an analyst or admin for
                detailed feature attribution.
              </div>
            ) : (
              <>
                {shap.length === 0 ? (
                  /* SHAP missing — show info message + synthetic summary */
                  <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                    <div
                      style={{
                        display: "flex",
                        alignItems: "flex-start",
                        gap: 10,
                        padding: "12px 14px",
                        background: "rgba(71,85,105,0.08)",
                        border: "1px solid rgba(71,85,105,0.3)",
                        borderRadius: 8,
                      }}
                    >
                      <span style={{ fontSize: 18, lineHeight: 1, color: "var(--text-secondary)", flexShrink: 0 }}>ℹ</span>
                      <div style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.5 }}>
                        SHAP explanation not available for this event.
                      </div>
                    </div>

                    {/* Synthetic summary from node metadata */}
                    {sourceChips.length > 0 && (
                      <div
                        style={{
                          padding: "12px 14px",
                          background: "rgba(59,130,246,0.06)",
                          border: "1px solid rgba(59,130,246,0.2)",
                          borderRadius: 8,
                          fontSize: 12,
                          color: "var(--text-secondary)",
                          lineHeight: 1.6,
                        }}
                      >
                        <span style={{ color: "#60a5fa", fontWeight: 700 }}>Alert summary: </span>
                        This alert was triggered by elevated scores from:{" "}
                        {sourceChips.map((src, i) => (
                          <span key={src}>
                            {i > 0 && ", "}
                            <span style={{ color: "#60a5fa", fontWeight: 700 }}>
                              {src}
                            </span>
                            {node.risk != null && (
                              <span style={{ color: "var(--text-muted)" }}>
                                {" "}({(node.risk / 100).toFixed(2)})
                              </span>
                            )}
                          </span>
                        ))}
                        .
                      </div>
                    )}

                    {/* SHAP reason strings from node if available */}
                    {node.shap_reasons && node.shap_reasons.length > 0 && (
                      <div>
                        <div style={{ fontSize: 10, color: "var(--text-muted)", marginBottom: 6, fontFamily: "'Fira Code', monospace", letterSpacing: 1 }}>
                          DETECTION REASONS
                        </div>
                        {node.shap_reasons.map((r, i) => (
                          <div
                            key={i}
                            style={{
                              padding: "5px 10px",
                              marginBottom: 4,
                              background: "rgba(220,38,38,0.07)",
                              border: "1px solid rgba(220,38,38,0.2)",
                              borderRadius: 5,
                              fontSize: 11,
                              color: "#fca5a5",
                              fontFamily: "'Fira Code', monospace",
                            }}
                          >
                            {r}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ) : (
                  <>
                    <div className={styles.shapHead}>FEATURE CONTRIBUTIONS · ml-pipeline-v3</div>
                    {shap.map((s, i) => {
                      const pct = Math.abs(s.value) * 100 / 0.5;
                      const positive = s.dir === "+" || s.direction === "positive" || (s.value >= 0 && s.dir !== "−");
                      return (
                        <div key={i} className={styles.shapRow}>
                          <div className={styles.shapFeat}>{s.feature}</div>
                          <div className={styles.shapBarWrap}>
                            <div
                              className={styles.shapBar}
                              style={{
                                width: `${Math.min(pct, 100)}%`,
                                background: positive ? "#dc2626" : "#22c55e",
                                boxShadow: `0 0 8px ${positive ? "#dc2626" : "#22c55e"}66`,
                                marginLeft: positive ? 0 : "auto",
                              }}
                            />
                          </div>
                          {/* Admin: show raw SHAP value; Analyst: show direction label only */}
                          <div
                            className={styles.shapVal}
                            style={{ color: positive ? "#fca5a5" : "#86efac" }}
                          >
                            {role === "admin"
                              ? `${positive ? "+" : ""}${s.value.toFixed(2)}`
                              : (positive ? "HIGH" : "LOW")}
                          </div>
                        </div>
                      );
                    })}
                    <div className={styles.shapFoot}>
                      <span>
                        Higher values push toward{" "}
                        <strong style={{ color: "#fca5a5" }}>MALICIOUS</strong>;
                        negative values toward BENIGN.
                      </span>
                    </div>
                  </>
                )}
              </>
            )}
          </div>
        )}

        {/* Timeline tab */}
        {tab === "tl" && (
          <div className={styles.timeline}>
            {data.TIMELINE.length === 0 && (
              <div className={styles.empty}>No timeline events recorded.</div>
            )}
            {data.TIMELINE.map((entry, i) => {
              const isActive = entry.src === node.id || entry.dst === node.id;
              return (
                <div
                  key={i}
                  className={`${styles.timelineRow} ${isActive ? styles.timelineRowActive : ""}`}
                  onClick={() => onJumpToStep(i + 1)}
                  role="button"
                  tabIndex={0}
                  onKeyDown={(e) => e.key === "Enter" && onJumpToStep(i + 1)}
                  aria-label={`Jump to step ${i + 1}: ${entry.action}`}
                >
                  <div className={styles.tlStep}>
                    #{String(i + 1).padStart(2, "0")}
                  </div>
                  <div className={styles.tlTime}>{entry.ts}</div>
                  <div className={styles.tlAction}>
                    <span className={styles.tlActionName}>{entry.action}</span>
                    <span className={styles.tlEdge}>
                      {idLabel(data, entry.src)}{" "}
                      <span style={{ color: "#ef4444" }}>→</span>{" "}
                      {idLabel(data, entry.dst)}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* ── Info tab — raw metadata key-value table ─────────────────────── */}
        {tab === "info" && (
          <div style={{ overflowY: "auto" }}>
            {metaEntries.length === 0 ? (
              <div className={styles.empty}>No metadata available.</div>
            ) : (
              <table
                style={{
                  width: "100%",
                  borderCollapse: "collapse",
                  fontSize: 11,
                  fontFamily: "'Fira Code', monospace",
                }}
              >
                <tbody>
                  {metaEntries.map(([key, val]) => (
                    <tr
                      key={key}
                      style={{
                        borderBottom: "1px solid rgba(30,41,59,0.6)",
                      }}
                    >
                      <td
                        style={{
                          padding: "6px 8px 6px 0",
                          color: "var(--text-muted)",
                          whiteSpace: "nowrap",
                          verticalAlign: "top",
                          width: "38%",
                          textTransform: "lowercase",
                          letterSpacing: "0.3px",
                        }}
                      >
                        {key}
                      </td>
                      <td
                        style={{
                          padding: "6px 0 6px 8px",
                          color: "var(--text-secondary)",
                          wordBreak: "break-all",
                          verticalAlign: "top",
                        }}
                      >
                        {val}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}

        {/* Response tab */}
        {tab === "resp" && (
          <div className={styles.resp}>
            {responses.length === 0 && (
              <div className={styles.empty}>
                No automated response playbook matched this node.
              </div>
            )}
            {responses.map((r, i) => {
              const riskClass =
                r.risk === "low"
                  ? styles.respRiskLow
                  : r.risk === "med"
                  ? styles.respRiskMed
                  : styles.respRiskHigh;
              return (
                <div key={i} className={styles.respCard}>
                  <div className={styles.respHead}>
                    <span className={styles.respName}>{r.action}</span>
                    <span className={`${styles.respRisk} ${riskClass}`}>
                      {r.risk.toUpperCase()} RISK
                    </span>
                  </div>
                  <div className={styles.respBody}>
                    <div className={styles.respTarget}>target: {r.target}</div>
                    <div className={styles.respDur}>eta: {r.duration}</div>
                  </div>
                  <div className={styles.respActions}>
                    <button
                      className={`${styles.respBtn} ${styles.respBtnGo}`}
                      aria-label={`Execute: ${r.action}`}
                      onClick={() => onExecuteResponse?.(r.action, r.target)}
                    >
                      EXECUTE
                    </button>
                    <button
                      className={`${styles.respBtn} ${styles.respBtnCancel}`}
                      aria-label={`Dismiss: ${r.action}`}
                      onClick={() => onDismissResponse?.(r.action)}
                    >
                      DISMISS
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
