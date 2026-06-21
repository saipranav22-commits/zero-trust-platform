import { useQuery } from '@tanstack/react-query'
import { ShieldAlert, Activity, Users, TrendingUp, AlertOctagon, Clock, Zap } from 'lucide-react'
import { Layout } from '@/components/layout/Layout'
import { StatCard } from '@/components/ui/StatCard'
import { SectionHeader } from '@/components/ui/Shared'
import { SeverityBadge, ThreatTypeLabel, ThreatStatusBadge } from '@/components/ui/Badge'
import { ThreatTimelineChart, AttackTypeDonutChart, SeverityBarChart } from '@/components/charts/Charts'
import { dashboardApi } from '@/api/dashboard.api'
import { formatDistanceToNow } from 'date-fns'

export function DashboardPage() {
  const { data: overview, isLoading: ovLoading, refetch: refetchOv } = useQuery({
    queryKey: ['dashboard-overview'],
    queryFn: dashboardApi.getOverview,
    refetchInterval: 30000,
  })

  const { data: analytics, isLoading: anLoading, refetch: refetchAn } = useQuery({
    queryKey: ['threat-analytics'],
    queryFn: () => dashboardApi.getThreatAnalytics(30),
  })

  const handleRefresh = () => { refetchOv(); refetchAn() }

  const score = overview?.securityScore ?? 0
  const scoreColor = score >= 80 ? 'text-emerald-400' : score >= 60 ? 'text-amber-400' : 'text-red-400'
  const scoreLabel = score >= 80 ? 'Good' : score >= 60 ? 'Fair' : score >= 40 ? 'Poor' : 'Critical'

  return (
    <Layout
      title="Security Overview"
      subtitle="Real-time threat intelligence and system health"
      onRefresh={handleRefresh}
      isRefreshing={ovLoading || anLoading}
    >
      {/* KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <StatCard
          title="Threats (24h)"
          value={overview?.totalThreatsLast24h ?? 0}
          icon={<ShieldAlert className="w-5 h-5 text-red-400" />}
          iconBg="bg-red-500/15"
          loading={ovLoading}
          subtitle={`${overview?.criticalThreatsLast24h ?? 0} critical`}
        />
        <StatCard
          title="Active Threats"
          value={overview?.activeThreats ?? 0}
          icon={<AlertOctagon className="w-5 h-5 text-orange-400" />}
          iconBg="bg-orange-500/15"
          loading={ovLoading}
          subtitle="Requiring attention"
        />
        <StatCard
          title="Active Users"
          value={overview?.totalActiveUsers ?? 0}
          icon={<Users className="w-5 h-5 text-brand-400" />}
          iconBg="bg-brand-500/15"
          loading={ovLoading}
          subtitle={`${overview?.failedLoginsLast24h ?? 0} failed logins`}
        />
        <StatCard
          title="Audit Events (24h)"
          value={overview?.totalAuditLogsLast24h ?? 0}
          icon={<Activity className="w-5 h-5 text-emerald-400" />}
          iconBg="bg-emerald-500/15"
          loading={ovLoading}
          subtitle="All logged actions"
        />
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-12 gap-4">

        {/* Security Score */}
        <div className="col-span-12 lg:col-span-3 card p-5 flex flex-col items-center justify-center">
          <p className="text-xs font-semibold text-slate-500 uppercase tracking-widest mb-4">Security Score</p>
          <div className="relative flex items-center justify-center w-36 h-36 mb-4">
            <svg className="-rotate-90 absolute" width="144" height="144">
              <circle cx="72" cy="72" r="60" fill="none" stroke="#1e293b" strokeWidth="10" />
              <circle cx="72" cy="72" r="60" fill="none"
                stroke={score >= 80 ? '#10b981' : score >= 60 ? '#f59e0b' : '#ef4444'}
                strokeWidth="10"
                strokeDasharray={`${2 * Math.PI * 60}`}
                strokeDashoffset={`${2 * Math.PI * 60 * (1 - score / 100)}`}
                strokeLinecap="round"
                style={{ transition: 'stroke-dashoffset 1.5s ease-out' }}
              />
            </svg>
            <div className="text-center z-10">
              <p className={`text-3xl font-bold ${scoreColor}`}>{score}</p>
              <p className="text-xs text-slate-500">/100</p>
            </div>
          </div>
          <p className={`text-sm font-semibold ${scoreColor}`}>{scoreLabel}</p>
          <p className="text-xs text-slate-500 mt-1 text-center">Based on last 24h activity</p>

          {/* Mini stats */}
          <div className="w-full mt-4 space-y-2">
            {[
              { label: 'Critical', val: overview?.criticalThreatsLast24h ?? 0, color: 'text-red-400' },
              { label: 'High', val: overview?.highThreatsLast24h ?? 0, color: 'text-orange-400' },
              { label: 'Failed Logins', val: overview?.failedLoginsLast24h ?? 0, color: 'text-amber-400' },
            ].map((s) => (
              <div key={s.label} className="flex justify-between text-xs">
                <span className="text-slate-500">{s.label}</span>
                <span className={`font-semibold ${s.color}`}>{s.val}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Threat Timeline */}
        <div className="col-span-12 lg:col-span-9 card p-5">
          <SectionHeader title="Threat Timeline" subtitle="Detections over the last 30 days" />
          {anLoading ? (
            <div className="skeleton h-52 rounded-lg" />
          ) : (
            <ThreatTimelineChart data={analytics?.timeline ?? []} />
          )}
        </div>

        {/* Attack Types */}
        <div className="col-span-12 md:col-span-6 lg:col-span-4 card p-5">
          <SectionHeader title="Attack Types" subtitle="Distribution by category" />
          {anLoading ? (
            <div className="skeleton h-52 rounded-lg" />
          ) : (
            <AttackTypeDonutChart data={analytics?.byType as Record<string, number> ?? {}} />
          )}
        </div>

        {/* Severity Distribution */}
        <div className="col-span-12 md:col-span-6 lg:col-span-4 card p-5">
          <SectionHeader title="Severity Breakdown" subtitle="Threats by severity level" />
          {anLoading ? (
            <div className="skeleton h-48 rounded-lg" />
          ) : (
            <SeverityBarChart data={analytics?.bySeverity as Record<string, number> ?? {}} />
          )}
        </div>

        {/* Top IPs */}
        <div className="col-span-12 lg:col-span-4 card p-5">
          <SectionHeader title="Top Attacker IPs" subtitle="Most frequent source IPs" />
          {anLoading ? (
            <div className="skeleton h-48 rounded-lg" />
          ) : (
            <div className="space-y-2 mt-2">
              {(analytics?.topIps ?? []).slice(0, 6).map((ip, i) => (
                <div key={i} className="flex items-center gap-3">
                  <span className="w-5 h-5 rounded bg-surface-700 text-slate-500 text-xs flex items-center justify-center font-mono">
                    {i + 1}
                  </span>
                  <span className="font-mono text-xs text-slate-300 flex-1">{ip.ip}</span>
                  <span className="text-xs font-semibold text-red-400">{ip.count}</span>
                  <div className="w-16 h-1.5 bg-surface-700 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-red-500/60 rounded-full transition-all duration-500"
                      style={{ width: `${Math.min(100, (ip.count / (analytics?.topIps?.[0]?.count || 1)) * 100)}%` }}
                    />
                  </div>
                </div>
              ))}
              {!analytics?.topIps?.length && (
                <p className="text-sm text-slate-500 text-center py-8">No attacker IP data yet</p>
              )}
            </div>
          )}
        </div>

        {/* Recent Threats */}
        <div className="col-span-12 card p-5">
          <SectionHeader
            title="Recent Threats"
            subtitle="Latest detected security events"
            actions={
              <a href="/threats" className="text-xs text-brand-400 hover:text-brand-300 transition-colors">
                View all →
              </a>
            }
          />
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-700/50">
                  {['Type', 'Severity', 'Source IP', 'Target', 'Status', 'Time'].map((h) => (
                    <th key={h} className="text-left py-2.5 px-3 text-xs font-semibold text-slate-500 uppercase tracking-wide">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {(overview?.recentThreats ?? []).length === 0 && !ovLoading && (
                  <tr>
                    <td colSpan={6} className="text-center py-8 text-slate-500 text-sm">
                      <Zap className="w-6 h-6 mx-auto mb-2 text-slate-600" />
                      No threats detected yet — system is secure
                    </td>
                  </tr>
                )}
                {ovLoading && Array.from({ length: 5 }).map((_, i) => (
                  <tr key={i} className="border-b border-slate-700/20">
                    {Array.from({ length: 6 }).map((_, j) => (
                      <td key={j} className="py-3 px-3">
                        <div className="skeleton h-4 rounded w-20" />
                      </td>
                    ))}
                  </tr>
                ))}
                {(overview?.recentThreats ?? []).map((t) => (
                  <tr key={t.id} className="border-b border-slate-700/20 hover:bg-surface-700/30 transition-colors">
                    <td className="py-3 px-3"><ThreatTypeLabel type={t.threatType} /></td>
                    <td className="py-3 px-3"><SeverityBadge severity={t.severity} /></td>
                    <td className="py-3 px-3">
                      <span className="font-mono text-xs text-slate-400">{t.sourceIp ?? '—'}</span>
                    </td>
                    <td className="py-3 px-3">
                      <span className="text-xs text-slate-400 truncate max-w-[140px] block">{t.targetResource ?? '—'}</span>
                    </td>
                    <td className="py-3 px-3"><ThreatStatusBadge status={t.status} /></td>
                    <td className="py-3 px-3">
                      <span className="text-xs text-slate-500 flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        {formatDistanceToNow(new Date(t.createdAt), { addSuffix: true })}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

      </div>
    </Layout>
  )
}
