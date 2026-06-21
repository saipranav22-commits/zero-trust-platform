import { type ReactNode } from 'react'
import { TrendingUp, TrendingDown, Minus } from 'lucide-react'
import clsx from 'clsx'

interface StatCardProps {
  title: string
  value: string | number
  icon: ReactNode
  iconBg: string
  change?: number
  subtitle?: string
  loading?: boolean
}

export function StatCard({ title, value, icon, iconBg, change, subtitle, loading }: StatCardProps) {
  if (loading) {
    return (
      <div className="card p-5">
        <div className="flex items-start justify-between mb-4">
          <div className="skeleton w-10 h-10 rounded-lg" />
          <div className="skeleton w-16 h-5 rounded-full" />
        </div>
        <div className="skeleton w-20 h-8 rounded mb-2" />
        <div className="skeleton w-28 h-4 rounded" />
      </div>
    )
  }

  return (
    <div className="card-hover p-5 group">
      <div className="flex items-start justify-between mb-3">
        <div className={clsx('w-10 h-10 rounded-lg flex items-center justify-center shrink-0', iconBg)}>
          {icon}
        </div>
        {change !== undefined && (
          <div className={clsx(
            'flex items-center gap-1 text-xs font-medium px-2 py-0.5 rounded-full',
            change > 0 ? 'text-red-400 bg-red-500/10' :
            change < 0 ? 'text-emerald-400 bg-emerald-500/10' :
            'text-slate-400 bg-slate-500/10'
          )}>
            {change > 0 ? <TrendingUp className="w-3 h-3" /> :
             change < 0 ? <TrendingDown className="w-3 h-3" /> :
             <Minus className="w-3 h-3" />}
            {Math.abs(change)}%
          </div>
        )}
      </div>

      <div className="mt-2">
        <p className="text-2xl font-bold text-slate-100 tabular-nums">
          {typeof value === 'number' ? value.toLocaleString() : value}
        </p>
        <p className="text-sm text-slate-400 mt-0.5">{title}</p>
        {subtitle && <p className="text-xs text-slate-500 mt-1">{subtitle}</p>}
      </div>
    </div>
  )
}
