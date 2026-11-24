import { useState, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Bell, Search, Filter, Download, Trash2, CheckCheck, ChevronLeft, ChevronRight, X, ExternalLink } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { format, formatDistanceToNow } from 'date-fns';
import toast from 'react-hot-toast';
import clsx from 'clsx';
import { Layout } from '@/components/layout/Layout';
import { PageHeader } from '@/components/ui/PageHeader';
import { notificationApi } from '@/api/notification.api';
import type { Notification, NotificationFilters } from '@/types/notification';

const SEVERITY_DOT: Record<string, string> = {
  CRITICAL: 'bg-[#DC2626]',
  HIGH:     'bg-[#D97706]',
  MEDIUM:   'bg-[#3B82F6]',
  LOW:      'bg-[#16A34A]',
};
const SEVERITY_TEXT: Record<string, string> = {
  CRITICAL: 'text-[#DC2626]',
  HIGH:     'text-[#D97706]',
  MEDIUM:   'text-[#3B82F6]',
  LOW:      'text-[#16A34A]',
};
const SEVERITY_BG: Record<string, string> = {
  CRITICAL: 'bg-[#DC2626]/10 border-[#DC2626]/20',
  HIGH:     'bg-[#D97706]/10 border-[#D97706]/20',
  MEDIUM:   'bg-[#3B82F6]/10 border-[#3B82F6]/20',
  LOW:      'bg-[#16A34A]/10 border-[#16A34A]/20',
};
const CATEGORIES = ['ALL', 'THREAT_DETECTION', 'AUTHENTICATION', 'AI_REPORT', 'AUDIT', 'DATABASE', 'POLICY', 'SYSTEM'];
const SEVERITIES = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

export function SecurityAlertsPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  // ── Filters state ──────────────────────────────────────────
  const [search, setSearch]       = useState('');
  const [severity, setSeverity]   = useState('ALL');
  const [category, setCategory]   = useState('ALL');
  const [readFilter, setReadFilter] = useState<'ALL' | 'UNREAD' | 'READ'>('ALL');
  const [page, setPage]           = useState(0);
  const [selected, setSelected]   = useState<Notification | null>(null);
  const [showFilters, setShowFilters] = useState(false);

  const filters: NotificationFilters = {
    search: search || undefined,
    severity: severity !== 'ALL' ? severity : undefined,
    category: category !== 'ALL' ? category : undefined,
    isRead: readFilter === 'ALL' ? undefined : readFilter === 'READ',
  };

  // ── Query ──────────────────────────────────────────────────
  const { data, isLoading, refetch } = useQuery({
    queryKey: ['security-alerts', filters, page],
    queryFn: () => notificationApi.getNotifications(filters, page, 20),
    placeholderData: (prev) => prev,
  });

  // ── Mutations ──────────────────────────────────────────────
  const markReadMut = useMutation({
    mutationFn: notificationApi.markAsRead,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['security-alerts'] }),
  });

  const markAllMut = useMutation({
    mutationFn: notificationApi.markAllAsRead,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['security-alerts'] });
      toast.success('All alerts marked as read');
    },
    onError: () => toast.error('Failed to mark all as read'),
  });

  const deleteMut = useMutation({
    mutationFn: notificationApi.deleteNotification,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['security-alerts'] });
      toast.success('Alert deleted');
      if (selected) setSelected(null);
    },
    onError: () => toast.error('Failed to delete alert'),
  });

  // ── Handle notification click ──────────────────────────────
  const handleOpen = useCallback(async (n: Notification) => {
    setSelected(n);
    if (!n.isRead) {
      await markReadMut.mutateAsync(n.id).catch(() => {});
    }
  }, [markReadMut]);

  const handleNavigate = (n: Notification) => {
    setSelected(null);
    if (n.actionUrl) navigate(n.actionUrl);
    else if (n.relatedThreatId) navigate('/threats');
    else if (n.category === 'AUDIT') navigate('/audit');
    else if (n.category === 'AI_REPORT') navigate('/ai');
    else if (n.category === 'AUTHENTICATION') navigate('/users');
  };

  // ── CSV Export ─────────────────────────────────────────────
  const handleExportCSV = async () => {
    try {
      const all = await notificationApi.getNotifications(filters, 0, 10000);
      const headers = ['ID', 'Title', 'Description', 'Severity', 'Category', 'Read', 'Created At'];
      const rows = all.content.map((n) => [
        n.id, n.title, n.description, n.severity, n.category, String(n.isRead), n.createdAt,
      ]);
      const meta = [
        '# SYVORA', '# AI-Powered Zero Trust Security Platform',
        '# Security Alerts Export', '# Confidential',
        `# Generated At: ${new Date().toISOString()}`, '',
      ].join('\n');
      const csv = meta + [headers, ...rows]
        .map((r) => r.map((v) => `"${v.replace(/"/g, '""')}"`).join(','))
        .join('\n');
      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `syvora_alerts_${Date.now()}.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      toast.success('Alerts exported as CSV');
    } catch {
      toast.error('Export failed');
    }
  };

  const notifications = data?.content ?? [];
  const totalPages    = data?.totalPages ?? 0;
  const totalElements = data?.totalElements ?? 0;

  return (
    <Layout onRefresh={refetch} isRefreshing={isLoading}>
      <PageHeader
        title="Security Alerts"
        description="Centralised notification hub for all security events, threat detections, and system alerts"
        icon={<Bell className="w-5 h-5" />}
        onRefresh={refetch}
        isRefreshing={isLoading}
        onExport={handleExportCSV}
      />

      {/* Toolbar */}
      <div className="sentinel-toolbar">
        {/* Search */}
        <div className="relative flex-1 max-w-sm min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#64748B]" />
          <input
            type="text"
            placeholder="Search alerts…"
            value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(0); }}
            className="sentinel-input pl-9 w-full"
          />
        </div>

        {/* Filter toggle */}
        <button
          onClick={() => setShowFilters((v) => !v)}
          className={clsx('sentinel-btn-icon', showFilters && 'bg-[#1F2530] text-[#F8FAFC]')}
        >
          <Filter className="w-4 h-4" />
        </button>

        <div className="flex items-center gap-2 ml-auto">
          {/* Read filter */}
          {(['ALL', 'UNREAD', 'READ'] as const).map((f) => (
            <button
              key={f}
              onClick={() => { setReadFilter(f); setPage(0); }}
              className={clsx(
                'px-3 py-1.5 text-xs font-medium rounded-lg border transition-colors',
                readFilter === f
                  ? 'bg-[#16A34A]/20 border-[#16A34A]/30 text-[#16A34A]'
                  : 'border-[#2D3642] text-[#64748B] hover:text-[#94A3B8] hover:bg-[#1F2530]'
              )}
            >
              {f}
            </button>
          ))}

          {/* Mark all read */}
          <button
            onClick={() => markAllMut.mutate()}
            disabled={markAllMut.isPending}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-[#2D3642] text-[#64748B] hover:text-[#16A34A] hover:border-[#16A34A]/30 transition-colors"
          >
            <CheckCheck className="w-3.5 h-3.5" />
            Mark all read
          </button>

          {/* Export CSV */}
          <button
            onClick={handleExportCSV}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-[#2D3642] text-[#64748B] hover:text-[#94A3B8] transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            Export CSV
          </button>
        </div>
      </div>

      {/* Expanded Filters */}
      {showFilters && (
        <div className="sentinel-card p-4 flex flex-wrap gap-4 -mt-2">
          {/* Severity */}
          <div>
            <p className="text-[10px] text-[#64748B] uppercase tracking-wider mb-2">Severity</p>
            <div className="flex gap-1.5 flex-wrap">
              {SEVERITIES.map((s) => (
                <button
                  key={s}
                  onClick={() => { setSeverity(s); setPage(0); }}
                  className={clsx(
                    'px-2.5 py-1 text-[10px] font-medium rounded border uppercase tracking-wide transition-colors',
                    severity === s
                      ? s === 'ALL'
                        ? 'bg-[#1F2530] border-[#3A4150] text-[#F8FAFC]'
                        : clsx('border', SEVERITY_BG[s], SEVERITY_TEXT[s])
                      : 'border-[#2D3642] text-[#64748B] hover:bg-[#1F2530]'
                  )}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>

          {/* Category */}
          <div>
            <p className="text-[10px] text-[#64748B] uppercase tracking-wider mb-2">Category</p>
            <div className="flex gap-1.5 flex-wrap">
              {CATEGORIES.map((c) => (
                <button
                  key={c}
                  onClick={() => { setCategory(c); setPage(0); }}
                  className={clsx(
                    'px-2.5 py-1 text-[10px] font-medium rounded border transition-colors',
                    category === c
                      ? 'bg-[#1F2530] border-[#3A4150] text-[#F8FAFC]'
                      : 'border-[#2D3642] text-[#64748B] hover:bg-[#1F2530]'
                  )}
                >
                  {c.replace(/_/g, ' ')}
                </button>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Count row */}
      <div className="flex items-center justify-between px-1 text-xs text-[#64748B]">
        <span>{totalElements.toLocaleString()} alerts total</span>
      </div>

      {/* Alerts Table */}
      <div className="sentinel-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="sentinel-table">
            <thead className="sentinel-thead">
              <tr>
                <th className="sentinel-th w-2" />
                <th className="sentinel-th">Alert</th>
                <th className="sentinel-th">Severity</th>
                <th className="sentinel-th">Category</th>
                <th className="sentinel-th">Status</th>
                <th className="sentinel-th">Time</th>
                <th className="sentinel-th">Actions</th>
              </tr>
            </thead>
            <tbody>
              {isLoading
                ? Array.from({ length: 6 }).map((_, i) => (
                    <tr key={i}>
                      {Array.from({ length: 7 }).map((_, j) => (
                        <td key={j} className="sentinel-td">
                          <div className="skeleton h-4 w-24 rounded" />
                        </td>
                      ))}
                    </tr>
                  ))
                : notifications.map((n) => (
                    <tr
                      key={n.id}
                      onClick={() => handleOpen(n)}
                      className={clsx('sentinel-tr cursor-pointer', !n.isRead && 'bg-[#16A34A]/5')}
                    >
                      {/* Unread dot */}
                      <td className="sentinel-td">
                        {!n.isRead && (
                          <span className={clsx('w-2 h-2 rounded-full inline-block', SEVERITY_DOT[n.severity])} />
                        )}
                      </td>

                      {/* Title + description */}
                      <td className="sentinel-td max-w-[280px]">
                        <p className={clsx('text-xs truncate', n.isRead ? 'text-[#64748B]' : 'text-[#F8FAFC] font-semibold')}>
                          {n.title}
                        </p>
                        <p className="text-[11px] text-[#475569] truncate mt-0.5">{n.description}</p>
                      </td>

                      {/* Severity */}
                      <td className="sentinel-td">
                        <span className={clsx('text-xs font-bold uppercase', SEVERITY_TEXT[n.severity])}>
                          {n.severity}
                        </span>
                      </td>

                      {/* Category */}
                      <td className="sentinel-td">
                        <span className="text-xs text-[#64748B] font-mono">
                          {n.category?.replace(/_/g, ' ')}
                        </span>
                      </td>

                      {/* Read status */}
                      <td className="sentinel-td">
                        <span className={clsx(
                          'text-[10px] font-medium px-2 py-0.5 rounded-full border uppercase',
                          n.isRead
                            ? 'border-[#2D3642] text-[#475569] bg-transparent'
                            : 'border-[#16A34A]/30 text-[#16A34A] bg-[#16A34A]/10'
                        )}>
                          {n.isRead ? 'Read' : 'Unread'}
                        </span>
                      </td>

                      {/* Timestamp */}
                      <td className="sentinel-td text-[#64748B] text-xs whitespace-nowrap">
                        {formatDistanceToNow(new Date(n.createdAt), { addSuffix: true })}
                      </td>

                      {/* Actions */}
                      <td className="sentinel-td">
                        <div className="flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
                          <button
                            onClick={() => handleNavigate(n)}
                            className="p-1.5 rounded hover:bg-[#1F2530] text-[#64748B] hover:text-[#94A3B8] transition-colors"
                            title="Open related incident"
                          >
                            <ExternalLink className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => deleteMut.mutate(n.id)}
                            className="p-1.5 rounded hover:bg-[#DC2626]/20 text-[#64748B] hover:text-[#DC2626] transition-colors"
                            title="Delete alert"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
              {!isLoading && notifications.length === 0 && (
                <tr>
                  <td colSpan={7} className="text-center py-14">
                    <Bell className="w-8 h-8 text-[#2D3642] mx-auto mb-3" />
                    <p className="text-sm text-[#64748B]">No security alerts found</p>
                    <p className="text-xs text-[#475569] mt-1">Alerts appear here when threats or anomalies are detected</p>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-[#2D3642] bg-[#171B22]">
            <span className="text-xs text-[#64748B]">
              Page {page + 1} of {totalPages} · {totalElements.toLocaleString()} alerts
            </span>
            <div className="flex items-center gap-1">
              <button
                onClick={() => setPage((p) => p - 1)}
                disabled={page === 0}
                className="p-1.5 rounded bg-[#1F2530] border border-[#2D3642] text-[#94A3B8] hover:text-[#F8FAFC] disabled:opacity-40 transition-colors"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <button
                onClick={() => setPage((p) => p + 1)}
                disabled={page >= totalPages - 1}
                className="p-1.5 rounded bg-[#1F2530] border border-[#2D3642] text-[#94A3B8] hover:text-[#F8FAFC] disabled:opacity-40 transition-colors"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Detail Drawer */}
      {selected && (
        <div className="fixed inset-0 z-50 flex">
          <div className="absolute inset-0 bg-black/50" onClick={() => setSelected(null)} />
          <div className="absolute right-0 top-0 h-full w-[420px] bg-[#0E1117] border-l border-[#2D3642] flex flex-col shadow-2xl">
            <div className="px-6 py-4 border-b border-[#2D3642] flex items-center justify-between shrink-0">
              <div>
                <p className="text-xs text-[#64748B] uppercase tracking-wider mb-0.5">Alert Detail</p>
                <span className={clsx('text-xs font-bold uppercase', SEVERITY_TEXT[selected.severity])}>
                  {selected.severity} · {selected.category?.replace(/_/g, ' ')}
                </span>
              </div>
              <button
                onClick={() => setSelected(null)}
                className="p-1.5 rounded hover:bg-[#1F2530] text-[#64748B] hover:text-[#F8FAFC] transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto px-6 py-5 space-y-5">
              <div>
                <h2 className="text-base font-semibold text-[#F8FAFC] leading-snug">{selected.title}</h2>
                <p className="text-xs text-[#64748B] mt-1">
                  {format(new Date(selected.createdAt), 'PPpp')} ·{' '}
                  {formatDistanceToNow(new Date(selected.createdAt), { addSuffix: true })}
                </p>
              </div>

              <div className="bg-[#171B22] border border-[#2D3642] rounded-xl p-4">
                <p className="text-xs font-medium text-[#64748B] uppercase tracking-wider mb-2">Description</p>
                <p className="text-xs text-[#94A3B8] leading-relaxed">{selected.description}</p>
              </div>

              <div className="grid grid-cols-2 gap-3">
                {[
                  { label: 'Severity', value: selected.severity },
                  { label: 'Category', value: selected.category?.replace(/_/g, ' ') },
                  { label: 'Created by', value: selected.createdBy ?? '—' },
                  { label: 'Status', value: selected.isRead ? 'Read' : 'Unread' },
                ].map(({ label, value }) => (
                  <div key={label} className="bg-[#171B22] border border-[#2D3642] rounded-lg p-3">
                    <p className="text-[10px] text-[#64748B] uppercase tracking-wider mb-1">{label}</p>
                    <p className="text-xs font-medium text-[#F8FAFC]">{value}</p>
                  </div>
                ))}
              </div>

              {selected.relatedThreatId && (
                <div className="bg-[#171B22] border border-[#2D3642] rounded-xl p-4">
                  <p className="text-[10px] text-[#64748B] uppercase tracking-wider mb-1">Related Threat ID</p>
                  <p className="text-xs font-mono text-[#94A3B8] break-all">{selected.relatedThreatId}</p>
                </div>
              )}
            </div>

            <div className="px-6 py-4 border-t border-[#2D3642] flex gap-3 shrink-0">
              <button
                onClick={() => handleNavigate(selected)}
                className="flex-1 px-4 py-2.5 bg-[#16A34A] hover:bg-[#15803D] text-white text-xs font-semibold rounded-lg transition-colors"
              >
                Open Related Incident →
              </button>
              <button
                onClick={() => deleteMut.mutate(selected.id)}
                className="px-4 py-2.5 bg-[#DC2626]/10 hover:bg-[#DC2626]/20 text-[#DC2626] text-xs font-semibold rounded-lg transition-colors border border-[#DC2626]/20"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      )}
    </Layout>
  );
}
