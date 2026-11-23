import { useQuery } from '@tanstack/react-query';
import { ShieldAlert, AlertTriangle, Users, FileText, Clock, Zap, Shield } from 'lucide-react';
import { Layout } from '@/components/layout/Layout';
import { PageHeader } from '@/components/ui/PageHeader';
import { StatCard } from '@/components/ui/StatCard';
import { SectionHeader, SecurityScoreRing, LiveDot } from '@/components/ui/Shared';
import { SeverityBadge, ThreatTypeLabel, ThreatStatusBadge } from '@/components/ui/Badge';
import { ThreatTimelineChart, AttackTypeDonutChart, SeverityBarChart } from '@/components/charts/Charts';
import { dashboardApi } from '@/api/dashboard.api';
import { formatDistanceToNow } from 'date-fns';

export function DashboardPage() {
  const { data: overview, isLoading: ovLoading, refetch: refetchOv } = useQuery({
    queryKey: ['dashboard-overview'],
    queryFn: dashboardApi.getOverview,
    refetchInterval: 30000,
  });

  const { data: analytics, isLoading: anLoading, refetch: refetchAn } = useQuery({
    queryKey: ['threat-analytics'],
    queryFn: () => dashboardApi.getThreatAnalytics(30),
  });

  const handleRefresh = () => {
    refetchOv();
    refetchAn();
  };

  const score = overview?.securityScore ?? 0;
  const scoreColor = score >= 80 ? 'text-[#16A34A]' : score >= 60 ? 'text-[#D97706]' : 'text-[#DC2626]';
  const securityStatusText = score >= 80 ? 'Operational (Secure)' : score >= 60 ? 'Warning (Potential Risk)' : 'Critical (Active Threats Detected)';

  return (
    <Layout onRefresh={handleRefresh} isRefreshing={ovLoading || anLoading}>
      <PageHeader
        title="Welcome back,"
        description={`Your infrastructure is protected by Syvora. Security Status: ${securityStatusText}`}
        icon={<Shield className="w-5 h-5" />}
        onRefresh={handleRefresh}
        isRefreshing={ovLoading || anLoading}
        lastUpdated={new Date().toLocaleTimeString()}
      />

      {/* ─── Row 1: KPI Cards ─────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <StatCard
          title="Threats (24h)"
          value={overview?.totalThreatsLast24h ?? 0}
          icon={<ShieldAlert className="w-5 h-5" />}
          loading={ovLoading}
          subtitle={`${overview?.criticalThreatsLast24h ?? 0} critical`}
          trend={{ value: 12, positive: false }}
        />
        <StatCard
          title="Active Threats"
          value={overview?.activeThreats ?? 0}
          icon={<AlertTriangle className="w-5 h-5" />}
          loading={ovLoading}
          subtitle="Requiring attention"
        />
        <StatCard
          title="Active Users"
          value={overview?.totalActiveUsers ?? 0}
          icon={<Users className="w-5 h-5" />}
          loading={ovLoading}
          subtitle={`${overview?.failedLoginsLast24h ?? 0} failed logins`}
        />
        <StatCard
          title="Audit Events"
          value={overview?.totalAuditLogsLast24h ?? 0}
          icon={<FileText className="w-5 h-5" />}
          loading={ovLoading}
          subtitle="All logged actions"
        />
      </div>

      {/* ─── Row 2: Score + Timeline ──────────────── */}
      <div className="grid grid-cols-12 gap-6 mb-8">
        {/* Security Score */}
        <div className="col-span-12 lg:col-span-3 sentinel-card p-6 flex flex-col items-center">
          <p className="text-xs font-semibold text-[#64748B] uppercase tracking-widest mb-5 self-start">
            Security Posture
          </p>
          <div className="relative flex items-center justify-center mb-4">
            <SecurityScoreRing score={score} />
          </div>
          <p className={`text-sm font-semibold ${scoreColor} mb-1`}>
            {score >= 80 ? 'Secure' : score >= 60 ? 'Warning' : 'Critical Risk'}
          </p>

          {/* Mini stats */}
          <div className="w-full mt-5 pt-4 border-t border-[#2D3642] space-y-2.5">
            {[
              { label: 'Critical Severity', val: overview?.criticalThreatsLast24h ?? 0, color: 'text-[#DC2626]' },
              { label: 'High Severity', val: overview?.highThreatsLast24h ?? 0, color: 'text-[#D97706]' },
              { label: 'Failed Logins', val: overview?.failedLoginsLast24h ?? 0, color: 'text-[#D97706]' },
            ].map((s) => (
              <div key={s.label} className="flex justify-between text-xs">
                <span className="text-[#64748B] font-medium">{s.label}</span>
                <span className={`font-mono font-semibold ${s.color}`}>{s.val}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Threat Timeline */}
        <div className="col-span-12 lg:col-span-9 sentinel-card p-6">
          <SectionHeader title="Threat Timeline" subtitle="30 day detection history" />
          {anLoading ? (
            <div className="skeleton h-52 rounded-lg" />
          ) : (
            <ThreatTimelineChart data={analytics?.timeline ?? []} />
          )}
        </div>
      </div>

      {/* ─── Row 3: Charts + Top IPs ─────────────── */}
      <div className="grid grid-cols-12 gap-6 mb-8">
        {/* Attack Types */}
        <div className="col-span-12 md:col-span-6 lg:col-span-4 sentinel-card p-6">
          <SectionHeader title="Attack Types" subtitle="Distribution by category" />
          {anLoading ? (
            <div className="skeleton h-52 rounded-lg" />
          ) : (
            <AttackTypeDonutChart data={analytics?.byType as Record<string, number> ?? {}} />
          )}
        </div>

        {/* Severity Breakdown */}
        <div className="col-span-12 md:col-span-6 lg:col-span-4 sentinel-card p-6">
          <SectionHeader title="Severity Breakdown" subtitle="Threats by severity level" />
          {anLoading ? (
            <div className="skeleton h-48 rounded-lg" />
          ) : (
            <SeverityBarChart data={analytics?.bySeverity as Record<string, number> ?? {}} />
          )}
        </div>

        {/* Top Attacker IPs */}
        <div className="col-span-12 lg:col-span-4 sentinel-card p-6">
          <SectionHeader title="Top Attacker IPs" subtitle="Most frequent source IPs" />
          {anLoading ? (
            <div className="skeleton h-48 rounded-lg" />
          ) : (
            <div className="space-y-3 mt-1">
              {(analytics?.topIps ?? []).slice(0, 6).map((ip, i) => {
                const maxCount = analytics?.topIps?.[0]?.count || 1;
                return (
                  <div key={i} className="flex items-center gap-3">
                    <span className="w-5 h-5 rounded bg-[#1F2530] text-[#64748B] text-xs flex items-center justify-center font-mono border border-[#2D3642]">
                      {i + 1}
                    </span>
                    <span className="font-mono text-xs text-[#F8FAFC] flex-1">{ip.ip}</span>
                    <span className="text-xs font-semibold text-[#DC2626] w-8 text-right">{ip.count}</span>
                    <div className="w-16 h-1.5 bg-[#1F2530] rounded-full overflow-hidden border border-[#2D3642]">
                      <div
                        className="h-full bg-[#DC2626]/40 rounded-full transition-all duration-500"
                        style={{ width: `${Math.min(100, (ip.count / maxCount) * 100)}%` }}
                      />
                    </div>
                  </div>
                );
              })}
              {!analytics?.topIps?.length && (
                <p className="text-sm text-[#64748B] text-center py-8">No attacker IP data yet</p>
              )}
            </div>
          )}
        </div>
      </div>

      {/* ─── Row 4: Recent Threats ────────────────── */}
      <div className="sentinel-card p-6">
        <SectionHeader
          title="Recent Threats"
          subtitle="Latest detected security events"
          actions={
            <div className="flex items-center gap-2">
              <LiveDot />
              <a href="/threats" className="text-xs font-semibold text-[#16A34A] hover:text-[#15803D] transition-colors">
                View all Threats →
              </a>
            </div>
          }
        />
        <div className="overflow-x-auto">
          <table className="sentinel-table">
            <thead className="sentinel-thead">
              <tr>
                {['Type', 'Severity', 'Source IP', 'Target', 'Status', 'Time'].map((h) => (
                  <th key={h} className="sentinel-th">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {ovLoading && Array.from({ length: 5 }).map((_, i) => (
                <tr key={i}>
                  {Array.from({ length: 6 }).map((_, j) => (
                    <td key={j} className="sentinel-td">
                      <div className="skeleton h-4 rounded w-20" />
                    </td>
                  ))}
                </tr>
              ))}
              {(overview?.recentThreats ?? []).length === 0 && !ovLoading && (
                <tr>
                  <td colSpan={6} className="text-center py-12 text-[#64748B] text-sm">
                    <Zap className="w-5 h-5 mx-auto mb-2 text-[#2D3642]" />
                    No Critical Threats Detected — Your environment is currently secure. Protected by Syvora.
                  </td>
                </tr>
              )}
              {(overview?.recentThreats ?? []).map((t) => (
                <tr key={t.id} className="sentinel-tr">
                  <td className="sentinel-td"><ThreatTypeLabel type={t.threatType} /></td>
                  <td className="sentinel-td"><SeverityBadge severity={t.severity} /></td>
                  <td className="sentinel-td">
                    <span className="font-mono text-xs text-[#94A3B8]">{t.sourceIp ?? '—'}</span>
                  </td>
                  <td className="sentinel-td">
                    <span className="text-xs text-[#94A3B8] truncate max-w-[140px] block">{t.targetResource ?? '—'}</span>
                  </td>
                  <td className="sentinel-td"><ThreatStatusBadge status={t.status} /></td>
                  <td className="sentinel-td">
                    <span className="text-xs text-[#64748B] flex items-center gap-1 whitespace-nowrap font-medium">
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
    </Layout>
  );
}
