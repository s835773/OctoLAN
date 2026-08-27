import React, { useState, useRef, useEffect } from 'react';
import { useTheme, ThemeMode } from '../context/ThemeContext';
import { Palette, Check, Sun, Moon, Sparkles } from 'lucide-react';

export const ThemeSelector: React.FC = () => {
  const { theme, setTheme } = useTheme();
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Close dropdown on outside click
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const themes: { id: ThemeMode; name: string; description: string; icon: React.ReactNode; previewColors: string[] }[] = [
    {
      id: 'default',
      name: 'Default Mode',
      description: 'OctoLAN Security Dark (#0d1117 / GitHub Green)',
      icon: <Sparkles className="w-3.5 h-3.5 text-[#238636]" />,
      previewColors: ['#0d1117', '#161b22', '#238636', '#58a6ff']
    },
    {
      id: 'vscode-dark',
      name: 'VS Code Dark',
      description: 'Classic Visual Studio Code Dark (#1e1e1e / Blue)',
      icon: <Moon className="w-3.5 h-3.5 text-[#007acc]" />,
      previewColors: ['#1e1e1e', '#252526', '#007acc', '#4ec9b0']
    },
    {
      id: 'vscode-light',
      name: 'VS Code 2026 Light',
      description: 'Modern High-Contrast Clean Light (#ffffff / #005fb8)',
      icon: <Sun className="w-3.5 h-3.5 text-[#d97706]" />,
      previewColors: ['#ffffff', '#f3f3f3', '#005fb8', '#107c41']
    }
  ];

  const currentThemeObj = themes.find(t => t.id === theme) || themes[0];

  return (
    <div className="relative" ref={dropdownRef}>
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-1.5 px-2.5 py-1.5 rounded bg-[#010409] hover:bg-[#1f242c] text-xs font-medium text-[#c9d1d9] border border-[#30363d] transition active:scale-95"
        title="Switch UI Theme"
      >
        <Palette className="w-3.5 h-3.5 text-[#58a6ff]" />
        <span className="hidden sm:inline-block">{currentThemeObj.name}</span>
        <span className="flex items-center gap-0.5 ml-0.5">
          {currentThemeObj.previewColors.slice(0, 2).map((c, i) => (
            <span key={i} className="w-2 h-2 rounded-full border border-black/20" style={{ backgroundColor: c }} />
          ))}
        </span>
      </button>

      {isOpen && (
        <div className="absolute right-0 mt-1.5 w-64 rounded-lg bg-[#161b22] border border-[#30363d] shadow-xl py-1.5 z-50 animate-in fade-in slide-in-from-top-1 duration-150">
          <div className="px-3 py-1.5 border-b border-[#21262d] text-[11px] font-semibold text-[#8b949e] uppercase tracking-wider flex items-center justify-between">
            <span>Color Theme</span>
            <Palette className="w-3 h-3" />
          </div>

          <div className="p-1 space-y-1">
            {themes.map(t => {
              const isSelected = theme === t.id;
              return (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => {
                    setTheme(t.id);
                    setIsOpen(false);
                  }}
                  className={`w-full flex items-center justify-between px-2.5 py-2 rounded text-left text-xs transition ${
                    isSelected
                      ? 'bg-[#1f242c] text-[#f0f6fc] font-medium border border-[#30363d]'
                      : 'text-[#c9d1d9] hover:bg-[#1f242c]/60'
                  }`}
                >
                  <div className="flex items-center gap-2.5">
                    <div className="flex-shrink-0">{t.icon}</div>
                    <div>
                      <div className="flex items-center gap-1.5">
                        <span className="font-medium text-xs">{t.name}</span>
                      </div>
                      <div className="text-[10px] text-[#8b949e] line-clamp-1">{t.description}</div>
                    </div>
                  </div>

                  <div className="flex items-center gap-1.5">
                    <div className="flex -space-x-1">
                      {t.previewColors.map((col, idx) => (
                        <span
                          key={idx}
                          className="w-2.5 h-2.5 rounded-full border border-[#30363d]"
                          style={{ backgroundColor: col }}
                        />
                      ))}
                    </div>
                    {isSelected && <Check className="w-3.5 h-3.5 text-[#58a6ff]" />}
                  </div>
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};
