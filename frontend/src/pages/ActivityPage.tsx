import { useQuery } from '@tanstack/react-query'
import { Layout } from '@/components/layout/Layout'
import { SectionHeader } from '@/components/ui/Shared'
import { ActivityTimelineChart, ActionTypeChart } from '@/components/charts/Charts'
import { AuditStatusBadge, RiskScoreBadge } from '@/components/ui/Badge'
import { dashboardApi } from '@/api/dashboard.api'
import { format } from 'date-fns'
import { Activity, TrendingDown, TrendingUp, Users } from 'lucide-react'
import { StatCard } from '@/components/ui/StatCard'

export function ActivityPage() {
  const { data, isLoading, refetch } = useQuery({
    queryKey: ['user-activity'],
    queryFn: () => dashboardApi.getUserActivity(30),
    refetchInterval: 60000,
  })

  return (
    <Layout title="User Activity" subtitle="Platform usage and behaviour analytics" onRefresh={refetch} isRefreshing={isLoading}>

      {/* KPIs */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <StatCard title="Total Actions (30d)" value={data?.totalActions ?? 0}
          icon={<Activity className="w-5 h-5 text-brand-400" />} iconBg="bg-brand-500/15" loading={isLoading} />
        <StatCard title="Failed Actions (30d)" value={data?.failedActions ?? 0}
          icon={<TrendingDown className="w-5 h-5 text-red-400" />} iconBg="bg-red-500/15" loading={isLoading} />
        <StatCard title="Failure Rate" value={`${data?.failureRate ?? 0}%`}
          icon={<TrendingUp className="w-5 h-5 text-orange-400" />} iconBg="bg-orange-500/15" loading={isLoading} />
        <StatCard title="Unique Actions" value={Object.keys(data?.byAction ?? {}).length}
          icon={<Users className="w-5 h-5 text-emerald-400" />} iconBg="bg-emerald-500/15" loading={isLoading} />
      </div>

      <div className="grid grid-cols-12 gap-4">
        {/* Activity Timeline */}
        <div className="col-span-12 lg:col-span-7 card p-5">
          <SectionHeader title="Activity Timeline" subtitle="Daily user actions over 30 days" />
          {isLoading ? <div className="skeleton h-52 rounded-lg" /> :
            <ActivityTimelineChart data={data?.activityTimeline ?? []} />}
        </div>

        {/* Action Breakdown */}
        <div className="col-span-12 lg:col-span-5 card p-5">
          <SectionHeader title="Top Actions" subtitle="Most frequent platform actions" />
          {isLoading ? <div className="skeleton h-52 rounded-lg" /> :
            <ActionTypeChart data={data?.byAction as Record<string, number> ?? {}} />}
        </div>

        {/* Recent Activity Feed */}
        <div className="col-span-12 card p-5">
          <SectionHeader title="Recent Activity" subtitle="Last 50 actions across the platform" />
          <div className="space-y-1 mt-2 max-h-[400px] overflow-y-auto">
            {isLoading && Array.from({ length: 10 }).map((_, i) => (
              <div key={i} className="flex items-center gap-3 py-2.5">
                <div className="skeleton w-5 h-5 rounded-full" />
                <div className="skeleton flex-1 h-4 rounded" />
                <div className="skeleton w-24 h-4 rounded" />
              </div>
            ))}
            {(data?.recentActivity ?? []).map((log) => (
              <div key={log.id}
                className="flex items-center gap-3 py-2.5 px-3 rounded-lg hover:bg-surface-700/40 transition-colors border-b border-slate-700/20 last:border-0">
                <AuditStatusBadge status={log.status} />
                <span className="font-mono text-xs text-slate-300 bg-surface-800 px-2 py-0.5 rounded border border-slate-700/50">
                  {log.action}
                </span>
                <span className="text-xs text-slate-500 flex-1 truncate">{log.userEmail ?? 'System'}</span>
                <RiskScoreBadge score={log.riskScore} />
                <span className="text-xs text-slate-600 font-mono whitespace-nowrap">
                  {format(new Date(log.createdAt), 'HH:mm:ss')}
                </span>
              </div>
            ))}
            {!isLoading && !data?.recentActivity?.length && (
              <p className="text-center py-8 text-slate-500 text-sm">No activity recorded yet</p>
            )}
          </div>
        </div>
      </div>
    </Layout>
  )
}
