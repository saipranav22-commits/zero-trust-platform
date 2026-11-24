import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Search, X,
  LayoutDashboard, ShieldAlert, FileText, Activity,
  Users, Brain, Settings,
} from 'lucide-react';

interface CmdResult {
  id: string;
  label: string;
  description?: string;
  icon: React.ElementType;
  path: string;
  category: string;
}

const COMMANDS: CmdResult[] = [
  { id: 'dashboard', label: 'Dashboard', description: 'Security overview & KPIs', icon: LayoutDashboard, path: '/dashboard', category: 'Navigation' },
  { id: 'threats',   label: 'Threat Center', description: 'Detected threats & incidents', icon: ShieldAlert, path: '/threats', category: 'Navigation' },
  { id: 'audit',     label: 'Audit Explorer', description: 'Hash-chained audit logs', icon: FileText, path: '/audit', category: 'Navigation' },
  { id: 'activity',  label: 'Activity',       description: 'User activity analytics', icon: Activity,    path: '/activity', category: 'Navigation' },
  { id: 'ai',        label: 'Syvora AI',    description: 'AI-powered security analysis', icon: Brain, path: '/ai', category: 'Navigation' },
  { id: 'users',     label: 'User Management', description: 'Manage user accounts', icon: Users, path: '/users', category: 'Navigation' },
  { id: 'settings',  label: 'Settings',        description: 'Platform configuration', icon: Settings, path: '/settings', category: 'Navigation' },
];

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
}

export function CommandPalette({ open, onClose }: CommandPaletteProps) {
  const [query, setQuery] = useState('');
  const [activeIdx, setActiveIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();

  const filtered = query.trim()
    ? COMMANDS.filter(
        (c) =>
          c.label.toLowerCase().includes(query.toLowerCase()) ||
          c.description?.toLowerCase().includes(query.toLowerCase()) ||
          c.category.toLowerCase().includes(query.toLowerCase())
      )
    : COMMANDS;

  useEffect(() => {
    if (open) {
      setQuery('');
      setActiveIdx(0);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [open]);

  useEffect(() => {
    setActiveIdx(0);
  }, [query]);

  const go = (path: string) => {
    navigate(path);
    onClose();
  };

  const handleKey = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setActiveIdx((i) => Math.min(i + 1, filtered.length - 1)); }
    if (e.key === 'ArrowUp')   { e.preventDefault(); setActiveIdx((i) => Math.max(i - 1, 0)); }
    if (e.key === 'Enter' && filtered[activeIdx]) { go(filtered[activeIdx].path); }
    if (e.key === 'Escape') { onClose(); }
  };

  // Group by category
  const grouped = filtered.reduce<Record<string, CmdResult[]>>((acc, cmd) => {
    if (!acc[cmd.category]) acc[cmd.category] = [];
    acc[cmd.category].push(cmd);
    return acc;
  }, {});

  return (
    <AnimatePresence>
      {open && (
        <div className="cmd-overlay" onClick={onClose}>
          <motion.div
            className="cmd-panel"
            initial={{ opacity: 0, scale: 0.96, y: -12 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.96, y: -12 }}
            transition={{ duration: 0.15 }}
            onClick={(e) => e.stopPropagation()}
          >
            {/* Search input */}
            <div className="flex items-center gap-3 px-4 py-3.5 border-b border-[#2D3642]">
              <Search className="w-4 h-4 text-[#64748B] shrink-0" />
              <input
                ref={inputRef}
                className="cmd-input p-0 border-0 flex-1"
                placeholder="Search pages, actions…"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={handleKey}
              />
              {query && (
                <button onClick={() => setQuery('')} className="text-[#64748B] hover:text-[#94A3B8]">
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
              <kbd className="text-[10px] text-[#475569] bg-[#1F2530] border border-[#2D3642] px-1.5 py-0.5 rounded font-mono">ESC</kbd>
            </div>

            {/* Results */}
            <div className="max-h-72 overflow-y-auto py-2">
              {filtered.length === 0 ? (
                <p className="text-center text-sm text-[#64748B] py-8">No results for "{query}"</p>
              ) : (
                Object.entries(grouped).map(([cat, items]) => (
                  <div key={cat}>
                    <p className="text-[10px] font-semibold text-[#475569] uppercase tracking-widest px-4 py-2">{cat}</p>
                    {items.map((item, idx) => {
                      const globalIdx = filtered.indexOf(item);
                      const Icon = item.icon;
                      return (
                        <button
                          key={item.id}
                          className={`cmd-result w-full text-left ${globalIdx === activeIdx ? 'active' : ''}`}
                          onMouseEnter={() => setActiveIdx(globalIdx)}
                          onClick={() => go(item.path)}
                        >
                          <Icon className="cmd-result-icon w-4 h-4" />
                          <div className="flex-1 min-w-0">
                            <p className="text-sm font-medium">{item.label}</p>
                            {item.description && (
                              <p className="text-xs text-[#64748B] truncate">{item.description}</p>
                            )}
                          </div>
                          {globalIdx === activeIdx && (
                            <kbd className="text-[10px] text-[#64748B] bg-[#1F2530] border border-[#2D3642] px-1 py-0.5 rounded font-mono shrink-0">↵</kbd>
                          )}
                        </button>
                      );
                    })}
                  </div>
                ))
              )}
            </div>

            {/* Footer */}
            <div className="flex items-center gap-4 px-4 py-2.5 border-t border-[#2D3642] text-[10px] text-[#475569]">
              <span className="flex items-center gap-1"><kbd className="bg-[#1F2530] border border-[#2D3642] rounded px-1">↑↓</kbd> navigate</span>
              <span className="flex items-center gap-1"><kbd className="bg-[#1F2530] border border-[#2D3642] rounded px-1">↵</kbd> open</span>
              <span className="flex items-center gap-1"><kbd className="bg-[#1F2530] border border-[#2D3642] rounded px-1">ESC</kbd> close</span>
            </div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
}
