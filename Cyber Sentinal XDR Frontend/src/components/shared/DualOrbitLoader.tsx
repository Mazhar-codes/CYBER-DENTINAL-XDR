import React from 'react';

interface DualOrbitLoaderProps {
  /** Outer-ring diameter in px (default 52) */
  size?: number;
  /** Optional text rendered below the rings */
  label?: string;
}

/**
 * DualOrbitLoader
 *
 * Two concentric rings spinning in opposite directions with a glowing core dot.
 * Uses CSS custom properties so it adapts to dark / light theme automatically.
 * Keyframes (xdr-orbit-cw, xdr-orbit-ccw, xdr-core-pulse, xdr-label-blink)
 * are declared in src/index.css.
 */
const DualOrbitLoader: React.FC<DualOrbitLoaderProps> = ({
  size = 52,
  label,
}) => {
  const thick = Math.max(2, Math.round(size * 0.055));
  const inner = Math.round(size * 0.60);
  const core  = Math.round(size * 0.22);

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 14,
      }}
    >
      {/* Ring stack */}
      <div
        style={{
          position: 'relative',
          width:  size,
          height: size,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}
      >
        {/* Outer ring — clockwise, accent-cyan */}
        <div
          style={{
            position: 'absolute',
            inset: 0,
            border: `${thick}px solid transparent`,
            borderTopColor:   'var(--accent-cyan)',
            borderRightColor: 'var(--accent-cyan)',
            borderRadius: '50%',
            animation: 'xdr-orbit-cw 1.1s cubic-bezier(0.6,0,0.4,1) infinite',
            boxShadow: '0 0 10px var(--accent-cyan)',
          }}
        />

        {/* Inner ring — counter-clockwise, accent-amber */}
        <div
          style={{
            position: 'absolute',
            width:  inner,
            height: inner,
            border: `${thick}px solid transparent`,
            borderBottomColor: 'var(--accent-amber)',
            borderLeftColor:   'var(--accent-amber)',
            borderRadius: '50%',
            animation: 'xdr-orbit-ccw 0.75s cubic-bezier(0.6,0,0.4,1) infinite',
            boxShadow: '0 0 8px var(--accent-amber)',
            opacity: 0.9,
          }}
        />

        {/* Core dot */}
        <div
          style={{
            width:  core,
            height: core,
            borderRadius: '50%',
            background: 'var(--accent-cyan)',
            boxShadow: '0 0 14px var(--accent-cyan), 0 0 28px rgba(47,224,224,0.28)',
            animation: 'xdr-core-pulse 1.4s ease-in-out infinite',
          }}
        />
      </div>

      {/* Label */}
      {label && (
        <span
          style={{
            color: 'var(--accent-cyan)',
            fontFamily: "'Fira Code', monospace",
            fontSize: 11,
            letterSpacing: 2,
            textTransform: 'uppercase',
            animation: 'xdr-label-blink 2s ease-in-out infinite',
          }}
        >
          {label}
        </span>
      )}
    </div>
  );
};

export default DualOrbitLoader;
