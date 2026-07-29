/**
 * themeConfig.ts — single source of truth for Cyber Sentinel XDR color palettes.
 *
 * Values here MUST match the CSS custom properties in theme.css exactly.
 * Components that need JS-side color values (e.g. canvas renderers, ECharts
 * option objects) should import from here rather than hardcoding hex strings.
 * Inline-styled React components should prefer var(--...) CSS strings instead
 * so the browser's cascade handles switching without React re-renders.
 */

export type ThemeMode = 'dark' | 'light';

export interface ThemeColors {
  // Backgrounds
  bgPrimary: string;
  bgSecondary: string;
  bgCard: string;
  bgCardHover: string;
  bgSidebar: string;
  bgSurface: string;
  bgInput: string;

  // Text
  textPrimary: string;
  textSecondary: string;
  textMuted: string;
  textHeading: string;

  // Borders
  borderColor: string;
  borderColorStrong: string;

  // Accents
  accentCyan: string;
  accentCyanDim: string;
  accentGreen: string;
  accentAmber: string;
  accentRed: string;
  accentPurple: string;
  accentBlue: string;

  // Severity (same in both themes for semantic clarity)
  severityCritical: string;
  severityHigh: string;
  severityMedium: string;
  severityLow: string;

  // Scrollbar
  scrollbarTrack: string;
  scrollbarThumb: string;
  scrollbarThumbHover: string;

  // Table
  tableHeaderBg: string;
  tableRowHover: string;
  tableBorder: string;

  // Modal
  modalBg: string;
  modalOverlay: string;

  // Shadows
  shadowSm: string;
  shadowMd: string;
  shadowLg: string;
  shadowGlowCyan: string;
}

export const DARK_THEME: ThemeColors = {
  bgPrimary:    '#070A0F',
  bgSecondary:  '#1A1F2E',
  bgCard:       '#0F1520',
  bgCardHover:  '#1A2333',
  bgSidebar:    '#050709',
  bgSurface:    '#141B28',
  bgInput:      '#1A2333',

  textPrimary:   '#F5F5F5',
  textSecondary: '#94a3b8',
  textMuted:     '#64748b',
  textHeading:   '#FFFFFF',

  borderColor:        'rgba(47,224,224,0.10)',
  borderColorStrong:  'rgba(47,224,224,0.20)',

  accentCyan:    '#2FE0E0',
  accentCyanDim: 'rgba(47,224,224,0.15)',
  accentGreen:   '#10b981',
  accentAmber:   '#f59e0b',
  accentRed:     '#ef4444',
  accentPurple:  '#8b5cf6',
  accentBlue:    '#458393',

  severityCritical: '#ff2d55',
  severityHigh:     '#ff6b35',
  severityMedium:   '#f59e0b',
  severityLow:      '#10b981',

  scrollbarTrack:       '#070A0F',
  scrollbarThumb:       '#1e293b',
  scrollbarThumbHover:  '#334155',

  tableHeaderBg:  'rgba(47,224,224,0.06)',
  tableRowHover:  'rgba(255,255,255,0.03)',
  tableBorder:    'rgba(47,224,224,0.08)',

  modalBg:      '#0F1520',
  modalOverlay: 'rgba(0,0,0,0.75)',

  shadowSm:       '0 1px 4px rgba(0,0,0,0.5)',
  shadowMd:       '0 2px 12px rgba(0,0,0,0.6)',
  shadowLg:       '0 4px 24px rgba(0,0,0,0.7)',
  shadowGlowCyan: '0 0 20px rgba(47,224,224,0.2)',
};

export const LIGHT_THEME: ThemeColors = {
  bgPrimary:    '#FFF3C8',
  bgSecondary:  '#E5CB90',
  bgCard:       '#FFFBE8',
  bgCardHover:  '#FFF7D6',
  bgSidebar:    '#1A1F2E',
  bgSurface:    '#FFF8DC',
  bgInput:      '#FFFAE0',

  textPrimary:   '#1a1a1a',
  textSecondary: '#4a4a4a',
  textMuted:     '#7a7a6a',
  textHeading:   '#0a0a0a',

  borderColor:        'rgba(52,169,157,0.25)',
  borderColorStrong:  'rgba(52,169,157,0.45)',

  accentCyan:    '#34A99D',
  accentCyanDim: 'rgba(52,169,157,0.15)',
  accentGreen:   '#1a9a6a',
  accentAmber:   '#c07a00',
  accentRed:     '#dc2626',
  accentPurple:  '#7c3aed',
  accentBlue:    '#458393',

  severityCritical: '#dc2626',
  severityHigh:     '#ea580c',
  severityMedium:   '#ca8a04',
  severityLow:      '#15803d',

  scrollbarTrack:       '#E5CB90',
  scrollbarThumb:       '#c5a870',
  scrollbarThumbHover:  '#a58850',

  tableHeaderBg:  'rgba(52,169,157,0.08)',
  tableRowHover:  'rgba(52,169,157,0.05)',
  tableBorder:    'rgba(52,169,157,0.15)',

  modalBg:      '#FFFBE8',
  modalOverlay: 'rgba(0,0,0,0.45)',

  shadowSm:       '0 1px 4px rgba(0,0,0,0.10)',
  shadowMd:       '0 2px 12px rgba(0,0,0,0.14)',
  shadowLg:       '0 4px 24px rgba(0,0,0,0.18)',
  shadowGlowCyan: '0 0 20px rgba(52,169,157,0.20)',
};

export const THEMES: Record<ThemeMode, ThemeColors> = {
  dark:  DARK_THEME,
  light: LIGHT_THEME,
};
