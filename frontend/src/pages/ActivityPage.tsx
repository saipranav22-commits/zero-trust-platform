import { useQuery } from '@tanstack/react-query';
import { format } from 'date-fns';
import { Activity, AlertTriangle, TrendingDown, Clock, Shield } from 'lucide-react';
import { Layout } from '@/components/layout/Layout';
import { PageHeader } from '@/components/ui/PageHeader';
import { StatCard } from '@/components/ui/StatCard';
import { SectionHeader } from '@/components/ui/Shared';
import { ActivityTimelineChart, ActionTypeChart } from '@/components/charts/Charts';
import { AuditStatusBadge, RiskScoreBadge } from '@/components/ui/Badge';
import { dashboardApi } from '@/api/dashboard.api';

export function ActivityPage() {
  const { data, isLoading } = useQuery({
    queryKey: ['user-activity'],
    queryFn: () => dashboardApi.getUserActivity(30),
    refetchInterval: 60000,
  });

  const totalActions = data?.totalActions ?? 0;
  const failedActions = data?.failedActions ?? 0;
  const failureRate = totalActions > 0 ? (failedActions / totalActions) * 100 : 0;
  const recentActivity = data?.recentActivity?.slice(0, 10) ?? [];

  return (
    <Layout onRefresh={() => {}} isRefreshing={isLoading}>
      <PageHeader
        title="Activity Analytics"
        description="Comprehensive audit of user actions, API hits, and database query executions"
        icon={<Activity className="w-5 h-5" />}
      />

      <div className="space-y-6">
        {/* Row 1: Stat Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <StatCard
            title="Total Actions Logged"
            value={totalActions}
            icon={<Activity className="w-5 h-5" />}
            loading={isLoading}
            subtitle="Platform transaction events"
          />
          <StatCard
            title="Failed Transactions"
            value={failedActions}
            icon={<AlertTriangle className="w-5 h-5" />}
            subtitle={`${failureRate.toFixed(1)}% failure rate`}
            loading={isLoading}
          />
          <StatCard
            title="Overall Failure Rate"
            value={Math.round(failureRate)}
            icon={<TrendingDown className="w-5 h-5" />}
            loading={isLoading}
            subtitle="Percentage of unsuccessful calls"
          />
        </div>

        {/* Row 2: Charts */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="sentinel-card p-6">
            <SectionHeader title="Activity Timeline" subtitle="Timeline of database transactional actions" />
            <div className="mt-4">
              <ActivityTimelineChart data={data?.activityTimeline ?? []} />
            </div>
          </div>
          <div className="sentinel-card p-6">
            <SectionHeader title="Action Distribution" subtitle="Categories of system operations performed" />
            <div className="mt-4">
              <ActionTypeChart data={data?.byAction ?? {}} />
            </div>
          </div>
        </div>

        {/* Row 3: Recent Activity Table */}
        <div className="sentinel-card overflow-hidden">
          <div className="px-6 py-4 border-b border-[#2D3642]">
            <SectionHeader title="Recent Platform Activity" subtitle="Last 10 user security operations" />
          </div>
          <div className="overflow-x-auto">
            <table className="sentinel-table">
              <thead className="sentinel-thead">
                <tr>
                  <th className="sentinel-th">Action Type</th>
                  <th className="sentinel-th">User Profile</th>
                  <th className="sentinel-th">Execution Status</th>
                  <th className="sentinel-th">Risk Level</th>
                  <th className="sentinel-th">Source IP Address</th>
                  <th className="sentinel-th">Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {isLoading
                  ? Array.from({ length: 5 }).map((_, i) => (
                      <tr key={i}>
                        {Array.from({ length: 6 }).map((_, j) => (
                          <td key={j} className="sentinel-td">
                            <div className="skeleton h-4 w-24 rounded" />
                          </td>
                        ))}
                      </tr>
                    ))
                  : recentActivity.map((entry: any, index: number) => (
                      <tr key={entry.id ?? index} className="sentinel-tr">
                        <td className="sentinel-td font-semibold text-[#F8FAFC]">
                          <span className="font-mono text-xs text-[#F8FAFC] bg-[#1F2530] px-2 py-0.5 rounded border border-[#2D3642]">
                            {entry.action}
                          </span>
                        </td>
                        <td className="sentinel-td text-[#94A3B8] font-medium">
                          {entry.userEmail ?? entry.userId ?? '—'}
                        </td>
                        <td className="sentinel-td">
                          <AuditStatusBadge status={entry.status} />
                        </td>
                        <td className="sentinel-td">
                          <RiskScoreBadge score={entry.riskScore} />
                        </td>
                        <td className="sentinel-td text-[#94A3B8] font-mono text-xs">
                          {entry.sourceIp ?? '—'}
                        </td>
                        <td className="sentinel-td text-[#64748B] whitespace-nowrap font-medium">
                          <span className="inline-flex items-center gap-1.5">
                            <Clock className="w-3.5 h-3.5" />
                            {entry.createdAt
                              ? format(new Date(entry.createdAt), 'MMM d, HH:mm:ss')
                              : '—'}
                          </span>
                        </td>
                      </tr>
                    ))}
                {!isLoading && recentActivity.length === 0 && (
                  <tr>
                    <td colSpan={6} className="text-center py-12 text-sm text-[#64748B]">
                      No activity logs registered in the selected window.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </Layout>
  );
}
