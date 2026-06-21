import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Shield, CheckCircle, XCircle, Filter, Search, FileText } from 'lucide-react'
import { Layout } from '@/components/layout/Layout'
import { AuditStatusBadge, RiskScoreBadge } from '@/components/ui/Badge'
import { Pagination, EmptyState } from '@/components/ui/Shared'
import { auditApi } from '@/api/threat.api'
import { formatDistanceToNow, format } from 'date-fns'
import toast from 'react-hot-toast'

export function AuditPage() {
  const [page, setPage] = useState(0)
  const [filters, setFilters] = useState({ userId: '', action: '', status: '' })

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['audit-logs', page, filters],
    queryFn: () => auditApi.getLogs({ ...filters, page, size: 20 }),
  })

  const verifyLog = async (id: string) => {
    try {
      const result = await auditApi.verifyIntegrity(id)
      if (result.integrityValid) {
        toast.success('✅ Log integrity verified — untampered')
      } else {
        toast.error('⚠️ INTEGRITY FAILURE — log may have been tampered!')
      }
    } catch {
      toast.error('Failed to verify log integrity')
    }
  }

  return (
    <Layout title="Audit Logs" subtitle="Immutable, hash-chained audit trail" onRefresh={refetch} isRefreshing={isLoading}>

      {/* Info Banner */}
      <div className="mb-4 p-3 rounded-xl bg-brand-500/8 border border-brand-500/15 flex items-center gap-3">
        <Shield className="w-5 h-5 text-brand-400 shrink-0" />
        <div>
          <p className="text-sm text-slate-200 font-medium">Tamper-Proof Audit Logging</p>
          <p className="text-xs text-slate-500">All logs are SHA-256 hash-chained. Click the verify button to check integrity of any entry.</p>
        </div>
      </div>

      {/* Filters */}
      <div className="card p-4 mb-4 flex flex-wrap gap-3 items-center">
        <Filter className="w-4 h-4 text-slate-500 shrink-0" />
        <div className="flex items-center gap-2 input-dark w-auto min-w-[200px]">
          <Search className="w-3.5 h-3.5 text-slate-500" />
          <input type="text" placeholder="User ID…" value={filters.userId}
            onChange={(e) => { setFilters({ ...filters, userId: e.target.value }); setPage(0) }}
            className="bg-transparent outline-none text-sm flex-1 placeholder:text-slate-500" />
        </div>
        <div className="flex items-center gap-2 input-dark w-auto min-w-[180px]">
          <Search className="w-3.5 h-3.5 text-slate-500" />
          <input type="text" placeholder="Action…" value={filters.action}
            onChange={(e) => { setFilters({ ...filters, action: e.target.value }); setPage(0) }}
            className="bg-transparent outline-none text-sm flex-1 placeholder:text-slate-500" />
        </div>
        <select className="input-dark w-auto min-w-[140px]" value={filters.status}
          onChange={(e) => { setFilters({ ...filters, status: e.target.value }); setPage(0) }}>
          <option value="">All Statuses</option>
          <option value="SUCCESS">SUCCESS</option>
          <option value="FAILURE">FAILURE</option>
          <option value="BLOCKED">BLOCKED</option>
        </select>
      </div>

      {/* Table */}
      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="border-b border-slate-700/50">
              <tr>
                {['User', 'Action', 'Resource', 'Source IP', 'Status', 'Risk', 'Time', 'Verify'].map((h) => (
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
                <tr><td colSpan={8}>
                  <EmptyState message="No audit logs found" icon={<FileText className="w-6 h-6" />} />
                </td></tr>
              )}
              {data?.content?.map((log) => (
                <tr key={log.id} className="border-b border-slate-700/20 hover:bg-surface-700/30 transition-colors group">
                  <td className="py-3.5 px-4">
                    <div>
                      <p className="text-xs text-slate-300 font-medium">{log.userEmail ?? '—'}</p>
                      <p className="text-xs text-slate-600 font-mono mt-0.5">{log.userId?.slice(0, 8)}…</p>
                    </div>
                  </td>
                  <td className="py-3.5 px-4">
                    <span className="font-mono text-xs text-slate-300 bg-surface-700 px-2 py-0.5 rounded">
                      {log.action}
                    </span>
                  </td>
                  <td className="py-3.5 px-4 text-xs text-slate-500">
                    {log.resourceType ?? '—'}{log.resourceId ? ` / ${log.resourceId.slice(0, 8)}…` : ''}
                  </td>
                  <td className="py-3.5 px-4 font-mono text-xs text-slate-400">{log.sourceIp ?? '—'}</td>
                  <td className="py-3.5 px-4"><AuditStatusBadge status={log.status} /></td>
                  <td className="py-3.5 px-4"><RiskScoreBadge score={log.riskScore} /></td>
                  <td className="py-3.5 px-4 text-xs text-slate-500 whitespace-nowrap">
                    {format(new Date(log.createdAt), 'MM/dd HH:mm:ss')}
                  </td>
                  <td className="py-3.5 px-4">
                    <button onClick={() => verifyLog(log.id)}
                      title="Verify hash integrity"
                      className="p-1.5 rounded-md text-slate-600 hover:text-emerald-400 hover:bg-emerald-500/10 transition-all opacity-0 group-hover:opacity-100">
                      <CheckCircle className="w-3.5 h-3.5" />
                    </button>
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
    </Layout>
  )
}
