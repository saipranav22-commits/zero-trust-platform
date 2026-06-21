import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Filter, Eye, CheckCircle, XCircle, Search, AlertOctagon } from 'lucide-react'
import { Layout } from '@/components/layout/Layout'
import { SeverityBadge, ThreatTypeLabel, ThreatStatusBadge } from '@/components/ui/Badge'
import { Pagination, EmptyState } from '@/components/ui/Shared'
import { threatApi } from '@/api/threat.api'
import { formatDistanceToNow } from 'date-fns'
import toast from 'react-hot-toast'
import type { ThreatEvent, ThreatStatus } from '@/types'

export function ThreatsPage() {
  const [page, setPage]     = useState(0)
  const [filters, setFilters] = useState({ threatType: '', severity: '', status: '', sourceIp: '' })
  const [selected, setSelected] = useState<ThreatEvent | null>(null)
  const [statusNote, setStatusNote] = useState('')
  const qc = useQueryClient()

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['threats', page, filters],
    queryFn: () => threatApi.getThreats({ ...filters, page, size: 20 }),
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, status, notes }: { id: string; status: ThreatStatus; notes?: string }) =>
      threatApi.updateStatus(id, status, notes),
    onSuccess: () => {
      toast.success('Status updated')
      setSelected(null)
      qc.invalidateQueries({ queryKey: ['threats'] })
    },
  })

  const THREAT_TYPES = ['', 'SQL_INJECTION', 'XSS', 'BRUTE_FORCE', 'PATH_TRAVERSAL', 'COMMAND_INJECTION']
  const SEVERITIES   = ['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
  const STATUSES     = ['', 'DETECTED', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE']

  return (
    <Layout title="Threat Analytics" subtitle="Detected security threats and attack events" onRefresh={refetch} isRefreshing={isLoading}>

      {/* Filters */}
      <div className="card p-4 mb-4 flex flex-wrap gap-3 items-center">
        <Filter className="w-4 h-4 text-slate-500 shrink-0" />
        <select className="input-dark w-auto min-w-[160px]" value={filters.threatType}
          onChange={(e) => { setFilters({ ...filters, threatType: e.target.value }); setPage(0) }}>
          <option value="">All Threat Types</option>
          {THREAT_TYPES.slice(1).map((t) => <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>)}
        </select>
        <select className="input-dark w-auto min-w-[130px]" value={filters.severity}
          onChange={(e) => { setFilters({ ...filters, severity: e.target.value }); setPage(0) }}>
          <option value="">All Severities</option>
          {SEVERITIES.slice(1).map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <select className="input-dark w-auto min-w-[140px]" value={filters.status}
          onChange={(e) => { setFilters({ ...filters, status: e.target.value }); setPage(0) }}>
          <option value="">All Statuses</option>
          {STATUSES.slice(1).map((s) => <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>)}
        </select>
        <div className="flex items-center gap-2 input-dark w-auto min-w-[180px]">
          <Search className="w-3.5 h-3.5 text-slate-500" />
          <input type="text" placeholder="Source IP…" value={filters.sourceIp}
            onChange={(e) => { setFilters({ ...filters, sourceIp: e.target.value }); setPage(0) }}
            className="bg-transparent outline-none text-sm flex-1 placeholder:text-slate-500" />
        </div>
        {Object.values(filters).some(Boolean) && (
          <button onClick={() => setFilters({ threatType: '', severity: '', status: '', sourceIp: '' })}
            className="text-xs text-red-400 hover:text-red-300 transition-colors">
            Clear filters
          </button>
        )}
      </div>

      {/* Table */}
      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="border-b border-slate-700/50">
              <tr>
                {['Type', 'Severity', 'Source IP', 'Target Resource', 'Rule', 'Status', 'Time', 'Actions'].map((h) => (
                  <th key={h} className="text-left py-3 px-4 text-xs font-semibold text-slate-500 uppercase tracking-wide whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {isLoading && Array.from({ length: 8 }).map((_, i) => (
                <tr key={i} className="border-b border-slate-700/20">
                  {Array.from({ length: 8 }).map((_, j) => (
                    <td key={j} className="py-3.5 px-4"><div className="skeleton h-4 rounded w-16" /></td>
                  ))}
                </tr>
              ))}
              {!isLoading && !data?.content?.length && (
                <tr><td colSpan={8}><EmptyState message="No threats found with the current filters" icon={<AlertOctagon className="w-6 h-6" />} /></td></tr>
              )}
              {data?.content?.map((t) => (
                <tr key={t.id} className="border-b border-slate-700/20 hover:bg-surface-700/30 transition-colors">
                  <td className="py-3.5 px-4"><ThreatTypeLabel type={t.threatType} /></td>
                  <td className="py-3.5 px-4"><SeverityBadge severity={t.severity} /></td>
                  <td className="py-3.5 px-4 font-mono text-xs text-slate-400">{t.sourceIp ?? '—'}</td>
                  <td className="py-3.5 px-4 text-xs text-slate-400 max-w-[180px] truncate">{t.targetResource ?? '—'}</td>
                  <td className="py-3.5 px-4 font-mono text-xs text-slate-500 max-w-[140px] truncate">{t.detectionRule ?? '—'}</td>
                  <td className="py-3.5 px-4"><ThreatStatusBadge status={t.status} /></td>
                  <td className="py-3.5 px-4 text-xs text-slate-500 whitespace-nowrap">
                    {formatDistanceToNow(new Date(t.createdAt), { addSuffix: true })}
                  </td>
                  <td className="py-3.5 px-4">
                    <div className="flex items-center gap-1">
                      <button onClick={() => setSelected(t)}
                        title="View details" className="p-1.5 rounded-md text-slate-500 hover:text-brand-400 hover:bg-brand-500/10 transition-all">
                        <Eye className="w-3.5 h-3.5" />
                      </button>
                      {t.status === 'DETECTED' && (
                        <button onClick={() => updateMutation.mutate({ id: t.id, status: 'INVESTIGATING' })}
                          title="Mark as Investigating" className="p-1.5 rounded-md text-slate-500 hover:text-purple-400 hover:bg-purple-500/10 transition-all">
                          <Search className="w-3.5 h-3.5" />
                        </button>
                      )}
                      {t.status !== 'RESOLVED' && t.status !== 'FALSE_POSITIVE' && (
                        <button onClick={() => updateMutation.mutate({ id: t.id, status: 'RESOLVED' })}
                          title="Resolve" className="p-1.5 rounded-md text-slate-500 hover:text-emerald-400 hover:bg-emerald-500/10 transition-all">
                          <CheckCircle className="w-3.5 h-3.5" />
                        </button>
                      )}
                      {t.status !== 'FALSE_POSITIVE' && t.status !== 'RESOLVED' && (
                        <button onClick={() => updateMutation.mutate({ id: t.id, status: 'FALSE_POSITIVE' })}
                          title="Mark False Positive" className="p-1.5 rounded-md text-slate-500 hover:text-slate-300 hover:bg-slate-500/10 transition-all">
                          <XCircle className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {data && data.totalPages > 1 && (
          <Pagination page={data.page} totalPages={data.totalPages}
            totalElements={data.totalElements} size={data.size} onPageChange={setPage} />
        )}
      </div>

      {/* Detail Modal */}
      {selected && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="glass rounded-2xl p-6 max-w-2xl w-full max-h-[80vh] overflow-y-auto animate-in">
            <div className="flex items-start justify-between mb-4">
              <div>
                <h3 className="font-semibold text-slate-100 text-lg">Threat Event Details</h3>
                <p className="text-xs text-slate-500 font-mono mt-0.5">{selected.id}</p>
              </div>
              <button onClick={() => setSelected(null)} className="text-slate-400 hover:text-slate-200 p-1">✕</button>
            </div>

            <div className="grid grid-cols-2 gap-3 mb-4">
              {[
                { label: 'Type',         val: <ThreatTypeLabel type={selected.threatType} /> },
                { label: 'Severity',     val: <SeverityBadge severity={selected.severity} /> },
                { label: 'Status',       val: <ThreatStatusBadge status={selected.status} /> },
                { label: 'Source IP',    val: <span className="font-mono text-xs text-slate-300">{selected.sourceIp ?? '—'}</span> },
                { label: 'Target',       val: <span className="text-xs text-slate-300 break-all">{selected.targetResource ?? '—'}</span> },
                { label: 'Method',       val: <span className="text-xs text-slate-300">{selected.targetMethod ?? '—'}</span> },
                { label: 'User Email',   val: <span className="text-xs text-slate-300">{selected.userEmail ?? '—'}</span> },
                { label: 'Detection Rule', val: <span className="font-mono text-xs text-slate-300">{selected.detectionRule ?? '—'}</span> },
              ].map(({ label, val }) => (
                <div key={label} className="bg-surface-800 rounded-lg p-3">
                  <p className="text-xs text-slate-500 mb-1">{label}</p>
                  <div>{val}</div>
                </div>
              ))}
            </div>

            {selected.attackPayload && (
              <div className="mb-4">
                <p className="text-xs text-slate-500 mb-1.5">Attack Payload</p>
                <pre className="bg-red-500/5 border border-red-500/20 rounded-lg p-3 text-xs font-mono text-red-300 overflow-x-auto whitespace-pre-wrap break-all">
                  {selected.attackPayload}
                </pre>
              </div>
            )}

            <div className="mb-4">
              <label className="text-xs text-slate-500 block mb-1.5">Resolution Notes (optional)</label>
              <textarea value={statusNote} onChange={(e) => setStatusNote(e.target.value)}
                rows={2} placeholder="Add investigation notes…"
                className="input-dark resize-none" />
            </div>

            <div className="flex gap-2 justify-end">
              <button onClick={() => setSelected(null)} className="btn-secondary">Close</button>
              {selected.status !== 'RESOLVED' && (
                <button onClick={() => updateMutation.mutate({ id: selected.id, status: 'RESOLVED', notes: statusNote })}
                  className="btn-primary">
                  <CheckCircle className="w-4 h-4" /> Mark Resolved
                </button>
              )}
              {selected.status !== 'FALSE_POSITIVE' && (
                <button onClick={() => updateMutation.mutate({ id: selected.id, status: 'FALSE_POSITIVE', notes: statusNote })}
                  className="btn-secondary">
                  <XCircle className="w-4 h-4" /> False Positive
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </Layout>
  )
}
