import React from "react";
import { SEVERITY_COLOUR } from "./types";

interface SeverityBadgeProps {
  severity: string;
  size?: "sm" | "md";
}

function SeverityBadge({ severity, size = "md" }: SeverityBadgeProps) {
  const color = SEVERITY_COLOUR[severity] ?? "#6b7280";
  const padding = size === "sm" ? "1px 8px" : "3px 12px";
  const fontSize = size === "sm" ? 10 : 11;

  return (
    <span
      className="status-badge"
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 5,
        background: `${color}1a`,
        color,
        border: `1px solid ${color}44`,
        borderRadius: 20,
        padding,
        fontWeight: 700,
        fontSize,
        whiteSpace: "nowrap",
        letterSpacing: 0.5,
      }}
    >
      <span
        style={{
          display: "inline-block",
          width: size === "sm" ? 5 : 6,
          height: size === "sm" ? 5 : 6,
          borderRadius: "50%",
          background: color,
          boxShadow: `0 0 6px ${color}`,
          flexShrink: 0,
        }}
      />
      {severity}
    </span>
  );
}

export default React.memo(SeverityBadge);
