import { useState, useEffect, useCallback } from 'react';

export type ThemeMode = 'dark' | 'light';

/**
 * useTheme — manages the XDR platform dark/light theme.
 *
 * Reads initial value from localStorage ('xdr-theme'), defaults to 'dark'.
 * Sets data-theme attribute on document.documentElement on every change
 * so all CSS [data-theme="..."] selectors in theme.css switch automatically.
 */
export function useTheme() {
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

  return { theme, toggleTheme };
}
