import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  ResponsiveContainer, LineChart, Line
} from 'recharts'
import { EmptyState } from '@/components/ui/Shared'

const CHART_COLORS = {
  SQL_INJECTION:       '#ef4444',
  XSS:                 '#f97316',
  BRUTE_FORCE:         '#eab308',
  CREDENTIAL_STUFFING: '#ec4899',
  DATA_EXFILTRATION:   '#a855f7',
  SUSPICIOUS_ACTIVITY: '#64748b',
  PATH_TRAVERSAL:      '#06b6d4',
  COMMAND_INJECTION:   '#f43f5e',
  CRITICAL: '#ef4444',
  HIGH:     '#f97316',
  MEDIUM:   '#f59e0b',
  LOW:      '#10b981',
  default:  '#6366f1',
}

const tooltipStyle = {
  backgroundColor: '#1e293b',
  border: '1px solid rgba(148,163,184,0.1)',
  borderRadius: '8px',
  color: '#cbd5e1',
  fontSize: '12px',
}

// ─── Threat Timeline Chart ────────────────────────────
export function ThreatTimelineChart({ data }: { data: Array<{ date: string; count: number }> }) {
  if (!data?.length) return <EmptyState message="No timeline data available" />
  return (
    <ResponsiveContainer width="100%" height={220}>
      <AreaChart data={data} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
        <defs>
          <linearGradient id="threatGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%"  stopColor="#6366f1" stopOpacity={0.4} />
            <stop offset="95%" stopColor="#6366f1" stopOpacity={0.02} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" />
        <XAxis dataKey="date" tick={{ fill: '#94a3b8', fontSize: 11 }} tickLine={false} axisLine={false}
               tickFormatter={(v) => v.slice(5)} />
        <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} tickLine={false} axisLine={false} />
        <Tooltip contentStyle={tooltipStyle} />
        <Area type="monotone" dataKey="count" stroke="#6366f1" strokeWidth={2}
              fill="url(#threatGrad)" name="Threats" dot={false} activeDot={{ r: 4 }} />
      </AreaChart>
    </ResponsiveContainer>
  )
}

// ─── Activity Timeline Chart ──────────────────────────
export function ActivityTimelineChart({ data }: { data: Array<{ date: string; count: number }> }) {
  if (!data?.length) return <EmptyState message="No activity data available" />
  return (
    <ResponsiveContainer width="100%" height={200}>
      <LineChart data={data} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" />
        <XAxis dataKey="date" tick={{ fill: '#94a3b8', fontSize: 11 }} tickLine={false} axisLine={false}
               tickFormatter={(v) => v.slice(5)} />
        <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} tickLine={false} axisLine={false} />
        <Tooltip contentStyle={tooltipStyle} />
        <Line type="monotone" dataKey="count" stroke="#10b981" strokeWidth={2}
              name="Actions" dot={false} activeDot={{ r: 4 }} />
      </LineChart>
    </ResponsiveContainer>
  )
}

// ─── Attack Type Donut Chart ──────────────────────────
export function AttackTypeDonutChart({ data }: { data: Record<string, number> }) {
  const entries = Object.entries(data || {}).map(([name, value]) => ({ name, value }))
  if (!entries.length) return <EmptyState message="No attack data yet" />

  return (
    <ResponsiveContainer width="100%" height={220}>
      <PieChart>
        <Pie data={entries} cx="50%" cy="50%" innerRadius={55} outerRadius={85}
             paddingAngle={3} dataKey="value" nameKey="name">
          {entries.map((entry, i) => (
            <Cell key={i}
              fill={CHART_COLORS[entry.name as keyof typeof CHART_COLORS] ?? CHART_COLORS.default}
              opacity={0.9}
            />
          ))}
        </Pie>
        <Tooltip contentStyle={tooltipStyle} formatter={(v) => [v, 'Attacks']} />
        <Legend
          formatter={(v) => v.replace(/_/g, ' ')}
          wrapperStyle={{ fontSize: '11px', color: '#94a3b8' }}
        />
      </PieChart>
    </ResponsiveContainer>
  )
}

// ─── Severity Bar Chart ───────────────────────────────
export function SeverityBarChart({ data }: { data: Record<string, number> }) {
  const entries = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((k) => ({
    name: k, count: data?.[k] ?? 0,
    fill: CHART_COLORS[k as keyof typeof CHART_COLORS]
  }))
  return (
    <ResponsiveContainer width="100%" height={180}>
      <BarChart data={entries} layout="vertical" margin={{ top: 0, right: 20, left: 10, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" horizontal={false} />
        <XAxis type="number" tick={{ fill: '#94a3b8', fontSize: 11 }} tickLine={false} axisLine={false} />
        <YAxis type="category" dataKey="name" tick={{ fill: '#94a3b8', fontSize: 11 }} tickLine={false} axisLine={false} width={60} />
        <Tooltip contentStyle={tooltipStyle} />
        <Bar dataKey="count" name="Threats" radius={[0, 4, 4, 0]}>
          {entries.map((entry, i) => (
            <Cell key={i} fill={entry.fill} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}

// ─── Top IPs Bar Chart ────────────────────────────────
export function TopIpsChart({ data }: { data: Array<{ ip: string; count: number }> }) {
  if (!data?.length) return <EmptyState message="No IP data available" />
  const masked = data.map((d) => ({
    ...d,
    ip: d.ip ? d.ip.replace(/\.\d+$/, '.***') : 'unknown',
  }))
  return (
    <ResponsiveContainer width="100%" height={Math.max(data.length * 36, 180)}>
      <BarChart data={masked} layout="vertical" margin={{ top: 0, right: 20, left: 20, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" horizontal={false} />
        <XAxis type="number" tick={{ fill: '#94a3b8', fontSize: 11 }} tickLine={false} axisLine={false} />
        <YAxis type="category" dataKey="ip" tick={{ fill: '#94a3b8', fontSize: 10, fontFamily: 'JetBrains Mono' }}
               tickLine={false} axisLine={false} width={95} />
        <Tooltip contentStyle={tooltipStyle} />
        <Bar dataKey="count" name="Attacks" fill="#6366f1" radius={[0, 4, 4, 0]} />
      </BarChart>
    </ResponsiveContainer>
  )
}

// ─── Action Type Bar Chart ─────────────────────────────
export function ActionTypeChart({ data }: { data: Record<string, number> }) {
  const entries = Object.entries(data || {})
    .map(([name, count]) => ({ name: name.replace(/_/g, ' '), count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 8)
  if (!entries.length) return <EmptyState message="No action data yet" />
  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={entries} margin={{ top: 5, right: 10, left: -20, bottom: 40 }}>
        <CartesianGrid strokeDasharray="3 3" />
        <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 10 }} tickLine={false} axisLine={false}
               angle={-30} textAnchor="end" />
        <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} tickLine={false} axisLine={false} />
        <Tooltip contentStyle={tooltipStyle} />
        <Bar dataKey="count" name="Count" fill="#10b981" radius={[4, 4, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  )
}
