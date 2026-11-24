import { useState, useEffect, useCallback } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Search, Bell, RefreshCw, ChevronDown, Settings, LogOut, User, Trash2, CheckCheck, X } from 'lucide-react';
import { useAuthStore } from '@/store/auth.store';
import { authApi } from '@/api/auth.api';
import { notificationApi } from '@/api/notification.api';
import { CommandPalette } from './CommandPalette';
import toast from 'react-hot-toast';
import clsx from 'clsx';
import { formatDistanceToNow } from 'date-fns';
import type { Notification } from '@/types/notification';
import { useSseNotifications } from '@/hooks/useSseNotifications';

const PAGE_META: Record<string, { title: string; breadcrumb: string[] }> = {
  '/dashboard': { title: 'Security Overview',    breadcrumb: ['Syvora', 'Overview'] },
  '/threats':   { title: 'Threat Center',        breadcrumb: ['Syvora', 'Threat Center'] },
  '/audit':     { title: 'Audit Explorer',       breadcrumb: ['Syvora', 'Audit Explorer'] },
  '/activity':  { title: 'Activity Analytics',   breadcrumb: ['Syvora', 'Activity'] },
  '/ai':        { title: 'Syvora AI Copilot',    breadcrumb: ['Syvora', 'Syvora AI'] },
  '/users':     { title: 'User Management',      breadcrumb: ['Syvora', 'Access Control', 'Users'] },
  '/settings':  { title: 'Platform Settings',    breadcrumb: ['Syvora', 'Settings'] },
  '/alerts':    { title: 'Security Alerts',      breadcrumb: ['Syvora', 'Security Alerts'] },
};

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'text-[#DC2626]',
  HIGH:     'text-[#D97706]',
  MEDIUM:   'text-[#3B82F6]',
  LOW:      'text-[#16A34A]',
};

const SEVERITY_DOT: Record<string, string> = {
  CRITICAL: 'bg-[#DC2626]',
  HIGH:     'bg-[#D97706]',
  MEDIUM:   'bg-[#3B82F6]',
  LOW:      'bg-[#16A34A]',
};

interface TopBarProps {
  onRefresh?: () => void;
  isRefreshing?: boolean;
}

export function TopBar({ onRefresh, isRefreshing }: TopBarProps) {
  const location    = useLocation();
  const navigate    = useNavigate();
  const { user, refreshToken, logout, accessToken } = useAuthStore();
  const [cmdOpen, setCmdOpen]           = useState(false);
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const [notifOpen, setNotifOpen]       = useState(false);

  // ── Notification state ──────────────────────────────────────
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [unreadCount, setUnreadCount]     = useState(0);
  const [notifLoading, setNotifLoading]   = useState(false);
  const [selectedNotif, setSelectedNotif] = useState<Notification | null>(null);

  const meta = PAGE_META[location.pathname] ?? { title: 'Syvora', breadcrumb: ['Syvora'] };

  // ── Fetch notifications from backend ────────────────────────
  const fetchNotifications = useCallback(async () => {
    try {
      setNotifLoading(true);
      const [page, count] = await Promise.all([
        notificationApi.getNotifications({}, 0, 10),
        notificationApi.getUnreadCount(),
      ]);
      setNotifications(page.content);
      setUnreadCount(count);
    } catch {
      // silently fail — don't block UI
    } finally {
      setNotifLoading(false);
    }
  }, []);

  // ── Poll unread count every 30s when panel is closed ────────
  useEffect(() => {
    fetchNotifications();
    const interval = setInterval(() => {
      notificationApi.getUnreadCount()
        .then(setUnreadCount)
        .catch(() => {});
    }, 30000);
    return () => clearInterval(interval);
  }, [fetchNotifications]);

  // ── Fetch full list when bell is opened ─────────────────────
  useEffect(() => {
    if (notifOpen) fetchNotifications();
  }, [notifOpen, fetchNotifications]);

  // ── SSE real-time push ───────────────────────────────────────
  const handleNewNotification = useCallback((n: Notification) => {
    setNotifications((prev) => [n, ...prev]);
    setUnreadCount((c) => c + 1);
  }, []);

  useSseNotifications({ onNotification: handleNewNotification, token: accessToken });

  // ── Ctrl+K listener ─────────────────────────────────────────
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        setCmdOpen((v) => !v);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  // ── Actions ─────────────────────────────────────────────────
  const handleLogout = async () => {
    try { if (refreshToken) await authApi.logout(refreshToken); } catch {}
    logout();
    toast.success('Signed out of Syvora');
    navigate('/login');
  };

  const handleMarkAllRead = async () => {
    try {
      await notificationApi.markAllAsRead();
      setNotifications((prev) => prev.map((n) => ({ ...n, isRead: true })));
      setUnreadCount(0);
      toast.success('All alerts marked as read');
    } catch {
      toast.error('Failed to mark all as read');
    }
  };

  const handleReadNotification = async (n: Notification) => {
    // Mark as read in backend if unread
    if (!n.isRead) {
      try {
        await notificationApi.markAsRead(n.id);
        setNotifications((prev) =>
          prev.map((x) => (x.id === n.id ? { ...x, isRead: true } : x))
        );
        setUnreadCount((c) => Math.max(0, c - 1));
      } catch {
        // ignore read-mark failure
      }
    }
    // Open detail drawer
    setSelectedNotif(n);
  };

  const handleDeleteNotification = async (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    try {
      await notificationApi.deleteNotification(id);
      setNotifications((prev) => {
        const target = prev.find((x) => x.id === id);
        if (target && !target.isRead) setUnreadCount((c) => Math.max(0, c - 1));
        return prev.filter((x) => x.id !== id);
      });
      toast.success('Notification deleted');
    } catch {
      toast.error('Failed to delete notification');
    }
  };

  const handleNotifNavigate = (n: Notification) => {
    setNotifOpen(false);
    setSelectedNotif(null);
    if (n.actionUrl) {
      navigate(n.actionUrl);
    } else if (n.relatedThreatId) {
      navigate(`/threats`);
    } else if (n.category === 'AUDIT') {
      navigate('/audit');
    } else if (n.category === 'AI_REPORT') {
      navigate('/ai');
    } else if (n.category === 'AUTHENTICATION') {
      navigate('/users');
    }
  };

  const userInitial = user
    ? `${user.firstName?.[0] ?? ''}${user.lastName?.[0] ?? ''}`.toUpperCase()
    : '?';

  return (
    <>
      <CommandPalette open={cmdOpen} onClose={() => setCmdOpen(false)} />

      <header className="h-14 flex items-center gap-4 px-6 bg-[#0E1117] border-b border-[#2D3642] shrink-0 z-30">
        {/* Breadcrumb */}
        <div className="flex items-center gap-1.5 text-xs text-[#64748B] min-w-0">
          {meta.breadcrumb.map((crumb, i) => (
            <span key={i} className="flex items-center gap-1.5 min-w-0">
              {i > 0 && <span className="text-[#2D3642]">/</span>}
              <span className={i === meta.breadcrumb.length - 1 ? 'text-[#94A3B8] font-medium truncate' : 'text-[#475569]'}>
                {crumb}
              </span>
            </span>
          ))}
        </div>

        {/* Global Search (Ctrl+K) */}
        <button
          onClick={() => setCmdOpen(true)}
          className="flex items-center gap-2 flex-1 max-w-xs min-w-[180px] bg-[#1F2530] border border-[#2D3642]
                     rounded-lg px-3 py-2 text-sm text-[#64748B] hover:border-[#3A4150]
                     hover:text-[#94A3B8] transition-colors duration-150"
        >
          <Search className="w-3.5 h-3.5 shrink-0" />
          <span className="flex-1 text-left text-xs">Search pages, actions…</span>
          <kbd className="text-[10px] bg-[#0E1117] border border-[#2D3642] px-1.5 py-0.5 rounded font-mono shrink-0">
            ⌘K
          </kbd>
        </button>

        {/* Right side */}
        <div className="ml-auto flex items-center gap-1">
          {/* System Health */}
          <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-lg border border-[#2D3642] bg-[#1F2530] mr-2">
            <span className="w-1.5 h-1.5 rounded-full bg-[#16A34A] live-dot" />
            <span className="text-xs text-[#64748B] font-medium">Syvora Protection Active</span>
          </div>

          {/* Refresh */}
          {onRefresh && (
            <button onClick={onRefresh} className="sentinel-btn-icon" title="Refresh data">
              <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin' : ''}`} />
            </button>
          )}

          {/* Notifications Bell */}
          <div className="relative">
            <button
              onClick={() => { setNotifOpen((v) => !v); setUserMenuOpen(false); setSelectedNotif(null); }}
              className="sentinel-btn-icon relative"
              title="Notifications"
            >
              <Bell className="w-4 h-4" />
              {unreadCount > 0 && (
                <span className="absolute -top-0.5 -right-0.5 min-w-[16px] h-4 px-0.5 bg-[#DC2626] rounded-full
                                 flex items-center justify-center text-[9px] font-bold text-white animate-pulse">
                  {unreadCount > 99 ? '99+' : unreadCount}
                </span>
              )}
            </button>

            {/* Notification Panel */}
            {notifOpen && (
              <div className="absolute right-0 top-10 w-96 sentinel-card z-50 overflow-hidden shadow-2xl animate-in flex flex-col max-h-[520px]">
                {/* Header */}
                <div className="px-4 py-3 border-b border-[#2D3642] flex items-center justify-between shrink-0">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-semibold text-[#F8FAFC]">Syvora Notifications</span>
                    {unreadCount > 0 && (
                      <span className="text-[10px] bg-[#DC2626]/20 text-[#DC2626] px-1.5 py-0.5 rounded-full font-medium">
                        {unreadCount} unread
                      </span>
                    )}
                  </div>
                  {unreadCount > 0 && (
                    <button
                      onClick={handleMarkAllRead}
                      className="flex items-center gap-1 text-xs text-[#16A34A] cursor-pointer hover:text-[#15803D] transition-colors"
                    >
                      <CheckCheck className="w-3.5 h-3.5" />
                      Mark all read
                    </button>
                  )}
                </div>

                {/* Notification List */}
                <div className="overflow-y-auto flex-1">
                  {notifLoading ? (
                    Array.from({ length: 4 }).map((_, i) => (
                      <div key={i} className="px-4 py-3 border-b border-[#2D3642]/50">
                        <div className="skeleton h-3 w-3/4 rounded mb-2" />
                        <div className="skeleton h-2 w-full rounded mb-1" />
                        <div className="skeleton h-2 w-1/2 rounded" />
                      </div>
                    ))
                  ) : notifications.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-10 text-center px-4">
                      <Bell className="w-8 h-8 text-[#2D3642] mb-3" />
                      <p className="text-xs text-[#64748B]">No notifications yet</p>
                      <p className="text-[11px] text-[#475569] mt-1">Security events will appear here in real time</p>
                    </div>
                  ) : (
                    notifications.map((n) => (
                      <button
                        key={n.id}
                        onClick={() => handleReadNotification(n)}
                        className={clsx(
                          'w-full px-4 py-3 hover:bg-[#1F2530] transition-colors text-left flex items-start gap-3',
                          'border-b border-[#2D3642]/50 group',
                          !n.isRead && 'bg-[#16A34A]/5'
                        )}
                      >
                        {/* Severity dot */}
                        <span className={clsx('w-2 h-2 rounded-full mt-1.5 shrink-0', SEVERITY_DOT[n.severity] ?? 'bg-[#64748B]')} />
                        <div className="flex-1 min-w-0">
                          <p className={clsx('text-xs leading-relaxed truncate',
                            n.isRead ? 'text-[#64748B]' : 'text-[#F8FAFC] font-semibold'
                          )}>
                            {n.title}
                          </p>
                          <p className="text-[11px] text-[#475569] mt-0.5 line-clamp-2 leading-relaxed">
                            {n.description}
                          </p>
                          <div className="flex items-center gap-2 mt-1">
                            <span className={clsx('text-[10px] font-medium uppercase', SEVERITY_COLORS[n.severity] ?? 'text-[#64748B]')}>
                              {n.severity}
                            </span>
                            <span className="text-[10px] text-[#475569]">·</span>
                            <span className="text-[10px] text-[#475569]">
                              {formatDistanceToNow(new Date(n.createdAt), { addSuffix: true })}
                            </span>
                          </div>
                        </div>
                        {/* Delete button (shows on hover) */}
                        <button
                          onClick={(e) => handleDeleteNotification(e, n.id)}
                          className="opacity-0 group-hover:opacity-100 transition-opacity p-1 rounded hover:bg-[#DC2626]/20 text-[#64748B] hover:text-[#DC2626] shrink-0"
                          title="Delete notification"
                        >
                          <Trash2 className="w-3 h-3" />
                        </button>
                      </button>
                    ))
                  )}
                </div>

                {/* Footer */}
                <div className="px-4 py-2.5 border-t border-[#2D3642] shrink-0">
                  <button
                    onClick={() => { setNotifOpen(false); navigate('/alerts'); }}
                    className="text-xs text-[#64748B] hover:text-[#94A3B8] transition-colors w-full text-left"
                  >
                    View all security alerts →
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* User Menu */}
          <div className="relative ml-1">
            <button
              onClick={() => { setUserMenuOpen((v) => !v); setNotifOpen(false); }}
              className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg hover:bg-[#1F2530] transition-colors"
            >
              <div className="w-6 h-6 rounded-full bg-[#16A34A]/20 border border-[#16A34A]/30 flex items-center justify-center">
                <span className="text-[10px] text-[#16A34A] font-bold">{userInitial}</span>
              </div>
              <span className="hidden md:block text-xs text-[#94A3B8] max-w-[100px] truncate font-medium">
                {user ? `${user.firstName} ${user.lastName}` : 'User'}
              </span>
              <ChevronDown className="w-3 h-3 text-[#64748B]" />
            </button>

            {userMenuOpen && (
              <div className="absolute right-0 top-10 w-56 sentinel-card z-50 overflow-hidden shadow-2xl animate-in">
                <div className="px-4 py-3 border-b border-[#2D3642]">
                  <p className="text-xs font-semibold text-[#F8FAFC]">
                    {user ? `${user.firstName} ${user.lastName}` : 'User'}
                  </p>
                  <p className="text-[11px] text-[#64748B] mt-0.5 truncate">{user?.email}</p>
                  <p className="text-[10px] text-[#16A34A] mt-0.5 font-medium uppercase tracking-wider">Syvora Enterprise</p>
                </div>
                <div className="py-1">
                  <button
                    onClick={() => { navigate('/settings'); setUserMenuOpen(false); }}
                    className="w-full flex items-center gap-2.5 px-4 py-2.5 text-sm text-[#94A3B8] hover:text-[#F8FAFC] hover:bg-[#1F2530] transition-colors"
                  >
                    <User className="w-3.5 h-3.5" /> Profile & Settings
                  </button>
                  <button
                    onClick={() => { navigate('/settings'); setUserMenuOpen(false); }}
                    className="w-full flex items-center gap-2.5 px-4 py-2.5 text-sm text-[#94A3B8] hover:text-[#F8FAFC] hover:bg-[#1F2530] transition-colors"
                  >
                    <Settings className="w-3.5 h-3.5" /> Platform Settings
                  </button>
                  <div className="border-t border-[#2D3642] mt-1 pt-1">
                    <button
                      onClick={handleLogout}
                      className="w-full flex items-center gap-2.5 px-4 py-2.5 text-sm text-[#DC2626] hover:bg-[#DC2626]/10 transition-colors"
                    >
                      <LogOut className="w-3.5 h-3.5" /> Sign Out of Syvora
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </header>

      {/* Click-outside to close menus */}
      {(userMenuOpen || notifOpen) && (
        <div
          className="fixed inset-0 z-40"
          onClick={() => { setUserMenuOpen(false); setNotifOpen(false); }}
        />
      )}

      {/* Notification Detail Drawer */}
      {selectedNotif && (
        <div className="fixed inset-0 z-50 flex">
          <div className="absolute inset-0 bg-black/50" onClick={() => setSelectedNotif(null)} />
          <div className="absolute right-0 top-0 h-full w-[420px] bg-[#0E1117] border-l border-[#2D3642] flex flex-col shadow-2xl">
            {/* Drawer header */}
            <div className="px-6 py-4 border-b border-[#2D3642] flex items-center justify-between shrink-0">
              <div>
                <p className="text-xs text-[#64748B] uppercase tracking-wider mb-0.5">Notification Detail</p>
                <span className={clsx('text-xs font-bold uppercase', SEVERITY_COLORS[selectedNotif.severity])}>
                  {selectedNotif.severity} · {selectedNotif.category?.replace(/_/g, ' ')}
                </span>
              </div>
              <button
                onClick={() => setSelectedNotif(null)}
                className="p-1.5 rounded hover:bg-[#1F2530] text-[#64748B] hover:text-[#F8FAFC] transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Drawer body */}
            <div className="flex-1 overflow-y-auto px-6 py-5 space-y-5">
              <div>
                <h2 className="text-base font-semibold text-[#F8FAFC] leading-snug">{selectedNotif.title}</h2>
                <p className="text-xs text-[#64748B] mt-1">
                  {formatDistanceToNow(new Date(selectedNotif.createdAt), { addSuffix: true })} ·{' '}
                  {new Date(selectedNotif.createdAt).toLocaleString()}
                </p>
              </div>

              <div className="bg-[#171B22] border border-[#2D3642] rounded-xl p-4">
                <p className="text-xs text-[#94A3B8] leading-relaxed">{selectedNotif.description}</p>
              </div>

              {/* Meta grid */}
              <div className="grid grid-cols-2 gap-3">
                {[
                  { label: 'Severity', value: selectedNotif.severity },
                  { label: 'Category', value: selectedNotif.category?.replace(/_/g, ' ') },
                  { label: 'Created by', value: selectedNotif.createdBy ?? '—' },
                  { label: 'Read', value: selectedNotif.isRead ? 'Yes' : 'No' },
                ].map(({ label, value }) => (
                  <div key={label} className="bg-[#171B22] border border-[#2D3642] rounded-lg p-3">
                    <p className="text-[10px] text-[#64748B] uppercase tracking-wider mb-1">{label}</p>
                    <p className="text-xs font-medium text-[#F8FAFC]">{value}</p>
                  </div>
                ))}
              </div>

              {selectedNotif.relatedThreatId && (
                <div className="bg-[#171B22] border border-[#2D3642] rounded-xl p-4">
                  <p className="text-[10px] text-[#64748B] uppercase tracking-wider mb-1">Related Threat ID</p>
                  <p className="text-xs font-mono text-[#94A3B8] break-all">{selectedNotif.relatedThreatId}</p>
                </div>
              )}
            </div>

            {/* Drawer footer */}
            <div className="px-6 py-4 border-t border-[#2D3642] flex gap-3 shrink-0">
              <button
                onClick={() => handleNotifNavigate(selectedNotif)}
                className="flex-1 px-4 py-2.5 bg-[#16A34A] hover:bg-[#15803D] text-white text-xs font-semibold rounded-lg transition-colors"
              >
                Open Related Incident →
              </button>
              <button
                onClick={() => setSelectedNotif(null)}
                className="px-4 py-2.5 bg-[#1F2530] hover:bg-[#252A36] text-[#94A3B8] text-xs font-semibold rounded-lg transition-colors border border-[#2D3642]"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
