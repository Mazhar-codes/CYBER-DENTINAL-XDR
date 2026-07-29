/**
 * ThemeToggle.tsx — Sun/Moon icon button that switches the XDR platform theme.
 *
 * Uses lucide-react for crisp SVG icons.
 * Wires into ThemeContext — no props required; self-contained.
 */
import React from 'react';
import { Sun, Moon } from 'lucide-react';
import { useThemeContext } from '../context/ThemeContext';

interface ThemeToggleProps {
  /** When true renders a compact (icon-only) version for collapsed sidebar */
  compact?: boolean;
}

export default function ThemeToggle({ compact = false }: ThemeToggleProps) {
  const { theme, toggleTheme } = useThemeContext();
  const isDark = theme === 'dark';

  return (
    <button
      onClick={toggleTheme}
      title={isDark ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
      aria-label={isDark ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: compact ? 0 : 10,
        padding: compact ? '8px 0' : '8px 12px',
        justifyContent: compact ? 'center' : 'flex-start',
        width: '100%',
        background: 'transparent',
        border: 'none',
        borderRadius: 8,
        cursor: 'pointer',
        color: isDark ? 'var(--accent-cyan)' : 'var(--accent-amber)',
        transition: 'color 0.3s ease, background 0.3s ease',
      }}
    >
      <span
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          width: 28,
          height: 28,
          borderRadius: 8,
          background: isDark
            ? 'rgba(47,224,224,0.12)'
            : 'rgba(245,158,11,0.14)',
          flexShrink: 0,
          transition: 'background 0.3s ease',
        }}
      >
        {isDark ? (
          <Moon size={15} strokeWidth={2} />
        ) : (
          <Sun size={15} strokeWidth={2} />
        )}
      </span>
      {!compact && (
        <span
          style={{
            fontSize: 13,
            fontWeight: 600,
            color: 'var(--text-secondary)',
            whiteSpace: 'nowrap',
            overflow: 'hidden',
            transition: 'color 0.3s ease',
          }}
        >
          {isDark ? 'Dark Mode' : 'Light Mode'}
        </span>
      )}
    </button>
  );
}
