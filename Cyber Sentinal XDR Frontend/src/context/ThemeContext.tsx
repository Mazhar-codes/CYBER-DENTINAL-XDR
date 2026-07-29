/**
 * ThemeContext.tsx — Theme provider for Cyber Sentinel XDR.
 *
 * Wraps the logic previously in useTheme.ts into a proper React Context so
 * any descendant can read { theme, toggleTheme, colors } without prop-drilling.
 *
 * The `xdr-theme` localStorage key is kept from the original useTheme.ts so
 * persisted preferences are preserved across upgrades.
 *
 * Most components should use `var(--bg-primary)` etc. directly in inline styles
 * (the browser's CSS cascade handles switching) rather than reading `colors` here.
 * Use `colors` only when you need a JS value (e.g. ECharts option objects, D3
 * canvas renderers, computed rgba strings).
 */
import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
} from 'react';
import { ThemeMode, ThemeColors, THEMES } from '../theme/themeConfig';

interface ThemeContextValue {
  theme: ThemeMode;
  toggleTheme: () => void;
  /** Resolved color object for the current theme — prefer CSS vars when possible */
  colors: ThemeColors;
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [theme, setTheme] = useState<ThemeMode>(() => {
    return (localStorage.getItem('xdr-theme') as ThemeMode) || 'dark';
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('xdr-theme', theme);
  }, [theme]);

  const toggleTheme = useCallback(() => {
    setTheme(prev => (prev === 'dark' ? 'light' : 'dark'));
  }, []);

  const colors = THEMES[theme];

  return (
    <ThemeContext.Provider value={{ theme, toggleTheme, colors }}>
      {children}
    </ThemeContext.Provider>
  );
}

/** Access theme state and colors from any post-login component */
export function useThemeContext(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) {
    throw new Error('useThemeContext must be used inside <ThemeProvider>');
  }
  return ctx;
}

/** Convenience alias — same as useThemeContext() but named to match the hook */
export { useThemeContext as useTheme };
