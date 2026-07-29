import React from "react";

interface StatCardProps {
  label: string;
  value: string | number;
  sub?: string;
  accent: string;
  glow?: boolean;
  icon?: string;
}

function StatCard({ label, value, sub, accent, glow, icon }: StatCardProps) {
  return (
    <div
      style={{
        background: "var(--bg-card, #1e293b)",
        border: `1px solid ${accent}33`,
        borderLeft: `4px solid ${accent}`,
        borderRadius: 12,
        padding: "18px 22px",
        flex: 1,
        minWidth: 130,
        position: "relative",
        overflow: "hidden",
        boxShadow: glow ? `0 0 20px ${accent}22, var(--shadow-md, 0 2px 8px rgba(0,0,0,0.3))` : "var(--shadow-sm, 0 2px 8px rgba(0,0,0,0.3))",
        transition: "box-shadow 0.3s ease, background 0.2s ease",
      }}
    >
      {/* Subtle background accent glow */}
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
      {icon && (
        <div style={{ fontSize: 20, marginBottom: 6, opacity: 0.8 }}>{icon}</div>
      )}
      <div
        style={{
          color: "var(--text-muted)",
          fontSize: 10,
          fontWeight: 700,
          textTransform: "uppercase",
          letterSpacing: 1.5,
        }}
      >
        {label}
      </div>
      <div
        style={{
          color: "var(--text-heading, #f1f5f9)",
          fontSize: 30,
          fontWeight: 800,
          marginTop: 4,
          letterSpacing: -1,
          lineHeight: 1.1,
        }}
      >
        {value}
      </div>
      {sub && (
        <div style={{ color: "var(--text-secondary, #94a3b8)", fontSize: 12, marginTop: 4 }}>{sub}</div>
      )}
    </div>
  );
}

export default React.memo(StatCard);
