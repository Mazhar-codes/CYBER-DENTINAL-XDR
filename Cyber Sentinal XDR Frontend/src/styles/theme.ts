export const theme = {
  colors: {
    bg: '#050b18',
    bgCard: 'rgba(0,20,40,0.85)',
    primary: '#00d4ff',     // cyan
    success: '#00ff88',     // green
    warning: '#ffaa00',     // amber
    danger: '#ff3366',      // red
    critical: '#ff0044',    // hot red
    border: 'rgba(0,212,255,0.3)',
    text: '#e0f4ff',
    textMuted: '#6b8fa3',
  },
  glow: {
    cyan: '0 0 20px rgba(0,212,255,0.5)',
    red: '0 0 30px rgba(255,0,68,0.6)',
    green: '0 0 20px rgba(0,255,136,0.4)',
  },
} as const;

export type Theme = typeof theme;
