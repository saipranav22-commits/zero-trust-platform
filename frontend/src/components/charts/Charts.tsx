import React from 'react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  LineChart,
  Line,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from 'recharts';
import { EmptyState } from '@/components/ui/Shared';
import { BarChart3 } from 'lucide-react';

/* ─── Shared Tooltip Style ─── */

const tooltipStyle = {
  contentStyle: {
    backgroundColor: '#1F2530',
    border: '1px solid #2D3642',
    borderRadius: '8px',
    color: '#F8FAFC',
    fontSize: '12px',
    padding: '8px 12px',
  },
  itemStyle: { color: '#F8FAFC' },
  labelStyle: { color: '#94A3B8', marginBottom: '4px' },
};

const axisTickStyle = { fill: '#64748B', fontSize: 11 };

/* ─── Threat Timeline Chart (Area) ─── */

interface ThreatTimelineChartProps {
  data: Array<{ date: string; count: number }>;
}

export const ThreatTimelineChart: React.FC<ThreatTimelineChartProps> = ({ data }) => {
  if (!data || data.length === 0) {
    return <EmptyState icon={<BarChart3 size={20} />} message="No threat data available" description="All clear. No critical threats detected." />;
  }

  return (
    <ResponsiveContainer width="100%" height={220}>
      <AreaChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: -12 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#2D3642" vertical={false} />
        <XAxis dataKey="date" tick={axisTickStyle} axisLine={false} tickLine={false} />
        <YAxis tick={axisTickStyle} axisLine={false} tickLine={false} />
        <Tooltip {...tooltipStyle} />
        <Area
          type="monotone"
          dataKey="count"
          stroke="#16A34A"
          strokeWidth={1.5}
          fill="#16A34A"
          fillOpacity={0.08}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
};

/* ─── Activity Timeline Chart (Line) ─── */

interface ActivityTimelineChartProps {
  data: Array<{ date: string; count: number }>;
}

export const ActivityTimelineChart: React.FC<ActivityTimelineChartProps> = ({ data }) => {
  if (!data || data.length === 0) {
    return <EmptyState icon={<BarChart3 size={20} />} message="No activity data available" description="Activity tracking is operational." />;
  }

  return (
    <ResponsiveContainer width="100%" height={220}>
      <LineChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: -12 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#2D3642" vertical={false} />
        <XAxis dataKey="date" tick={axisTickStyle} axisLine={false} tickLine={false} />
        <YAxis tick={axisTickStyle} axisLine={false} tickLine={false} />
        <Tooltip {...tooltipStyle} />
        <Line
          type="monotone"
          dataKey="count"
          stroke="#16A34A"
          strokeWidth={1.5}
          dot={false}
        />
      </LineChart>
    </ResponsiveContainer>
  );
};

/* ─── Attack Type Donut Chart ─── */

const DONUT_PALETTE = [
  '#16A34A',
  '#D97706',
  '#DC2626',
  '#64748B',
  '#475569',
  '#374151',
  '#1F2937',
  '#0F172A',
];

interface AttackTypeDonutChartProps {
  data: Record<string, number>;
}

export const AttackTypeDonutChart: React.FC<AttackTypeDonutChartProps> = ({ data }) => {
  const entries = Object.entries(data).filter(([, v]) => v > 0);

  if (entries.length === 0) {
    return <EmptyState icon={<BarChart3 size={20} />} message="No attack type data" description="System is quiet." />;
  }

  const chartData = entries.map(([name, value]) => ({
    name: name.replace(/_/g, ' '),
    value,
  }));

  return (
    <ResponsiveContainer width="100%" height={220}>
      <PieChart>
        <Pie
          data={chartData}
          cx="50%"
          cy="50%"
          innerRadius={55}
          outerRadius={80}
          paddingAngle={2}
          dataKey="value"
          stroke="none"
        >
          {chartData.map((_, index) => (
            <Cell key={`cell-${index}`} fill={DONUT_PALETTE[index % DONUT_PALETTE.length]} />
          ))}
        </Pie>
        <Tooltip {...tooltipStyle} />
      </PieChart>
    </ResponsiveContainer>
  );
};

/* ─── Severity Bar Chart (Horizontal) ─── */

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#DC2626',
  HIGH: '#D97706',
  MEDIUM: '#64748B',
  LOW: '#16A34A',
};

interface SeverityBarChartProps {
  data: Record<string, number>;
}

export const SeverityBarChart: React.FC<SeverityBarChartProps> = ({ data }) => {
  const entries = Object.entries(data);

  if (entries.length === 0) {
    return <EmptyState icon={<BarChart3 size={20} />} message="No severity data" description="No logged threat events." />;
  }

  const chartData = entries.map(([name, value]) => ({
    name,
    value,
    fill: SEVERITY_COLORS[name] ?? '#16A34A',
  }));

  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={chartData} layout="vertical" margin={{ top: 4, right: 4, bottom: 0, left: 8 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#2D3642" horizontal={false} />
        <XAxis type="number" tick={axisTickStyle} axisLine={false} tickLine={false} />
        <YAxis
          type="category"
          dataKey="name"
          tick={axisTickStyle}
          axisLine={false}
          tickLine={false}
          width={70}
        />
        <Tooltip {...tooltipStyle} />
        <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={18}>
          {chartData.map((entry, index) => (
            <Cell key={`cell-${index}`} fill={entry.fill} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
};

/* ─── Action Type Chart (Vertical Bar) ─── */

interface ActionTypeChartProps {
  data: Record<string, number>;
}

export const ActionTypeChart: React.FC<ActionTypeChartProps> = ({ data }) => {
  const entries = Object.entries(data);

  if (entries.length === 0) {
    return <EmptyState icon={<BarChart3 size={20} />} message="No action data" description="Operations logs are empty." />;
  }

  const chartData = entries.map(([name, value]) => ({
    name: name.replace(/_/g, ' '),
    value,
  }));

  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={chartData} margin={{ top: 4, right: 4, bottom: 0, left: -12 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#2D3642" vertical={false} />
        <XAxis dataKey="name" tick={axisTickStyle} axisLine={false} tickLine={false} />
        <YAxis tick={axisTickStyle} axisLine={false} tickLine={false} />
        <Tooltip {...tooltipStyle} />
        <Bar dataKey="value" fill="#16A34A" radius={[4, 4, 0, 0]} barSize={28} />
      </BarChart>
    </ResponsiveContainer>
  );
};

/* ─── Top IPs Chart (Horizontal Bar) ─── */

interface TopIpsChartProps {
  data: Array<{ ip: string; count: number }>;
}

export const TopIpsChart: React.FC<TopIpsChartProps> = ({ data }) => {
  if (!data || data.length === 0) {
    return <EmptyState icon={<BarChart3 size={20} />} message="No IP data available" description="All clear." />;
  }

  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={data} layout="vertical" margin={{ top: 4, right: 4, bottom: 0, left: 8 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#2D3642" horizontal={false} />
        <XAxis type="number" tick={axisTickStyle} axisLine={false} tickLine={false} />
        <YAxis
          type="category"
          dataKey="ip"
          tick={{ ...axisTickStyle, fontFamily: 'monospace' }}
          axisLine={false}
          tickLine={false}
          width={110}
        />
        <Tooltip {...tooltipStyle} />
        <Bar dataKey="count" fill="#16A34A" radius={[0, 4, 4, 0]} barSize={18} />
      </BarChart>
    </ResponsiveContainer>
  );
};
