import React, { createContext, useContext, useState, useEffect } from 'react';

export type ThemeMode = 'default' | 'vscode-dark' | 'vscode-light';

interface ThemeContextType {
  theme: ThemeMode;
  setTheme: (theme: ThemeMode) => void;
  themeName: string;
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined);

export const ThemeProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [theme, setThemeState] = useState<ThemeMode>(() => {
    const saved = localStorage.getItem('octolan_theme');
    if (saved === 'vscode-dark' || saved === 'vscode-light' || saved === 'default') {
      return saved;
    }
    return 'default';
  });

  const setTheme = (newTheme: ThemeMode) => {
    setThemeState(newTheme);
    localStorage.setItem('octolan_theme', newTheme);
  };

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    document.body.setAttribute('data-theme', theme);
  }, [theme]);

  const themeName = 
    theme === 'vscode-light' 
      ? 'VS Code 2026 Light' 
      : theme === 'vscode-dark' 
      ? 'VS Code Dark' 
      : 'Default (OctoLAN)';

  return (
    <ThemeContext.Provider value={{ theme, setTheme, themeName }}>
      {children}
    </ThemeContext.Provider>
  );
};

export const useTheme = (): ThemeContextType => {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return context;
};
