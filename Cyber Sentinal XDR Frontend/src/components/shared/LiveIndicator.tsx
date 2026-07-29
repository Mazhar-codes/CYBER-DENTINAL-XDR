import React from "react";

interface LiveIndicatorProps {
  active: boolean;
  label?: string;
}

export default function LiveIndicator({ active, label = "LIVE" }: LiveIndicatorProps) {
  if (!active) return null;

  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
        background: "#052e16",
        color: "#22c55e",
        borderRadius: 20,
        padding: "3px 12px",
        fontSize: 10,
        fontWeight: 700,
        border: "1px solid #166534",
        letterSpacing: 1,
      }}
    >
      <span
        style={{
          display: "inline-block",
          width: 6,
          height: 6,
          borderRadius: "50%",
          background: "#22c55e",
          boxShadow: "0 0 6px #22c55e",
          animation: "xdr-pulse 1.4s ease-in-out infinite",
        }}
      />
      {label}
    </span>
  );
}
