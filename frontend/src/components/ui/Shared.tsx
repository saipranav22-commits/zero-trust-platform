import { type ReactNode } from 'react'
import { ChevronLeft, ChevronRight } from 'lucide-react'

// ─── Skeleton ───────────────────────────────────────
export function Skeleton({ className = '' }: { className?: string }) {
  return <div className={`skeleton ${className}`} />
}

// ─── Empty State ─────────────────────────────────────
export function EmptyState({ message, icon }: { message: string; icon?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-slate-500">
      <div className="w-12 h-12 rounded-full bg-surface-700 flex items-center justify-center mb-3 text-slate-600">
        {icon ?? '🔍'}
      </div>
      <p className="text-sm">{message}</p>
    </div>
  )
}

// ─── Pagination ──────────────────────────────────────
interface PaginationProps {
  page: number
  totalPages: number
  totalElements: number
  size: number
  onPageChange: (p: number) => void
}

export function Pagination({ page, totalPages, totalElements, size, onPageChange }: PaginationProps) {
  const from = page * size + 1
  const to   = Math.min((page + 1) * size, totalElements)

  return (
    <div className="flex items-center justify-between px-1 py-3 border-t border-slate-700/50">
      <p className="text-xs text-slate-500">
        Showing <span className="text-slate-300 font-medium">{from}–{to}</span> of{' '}
        <span className="text-slate-300 font-medium">{totalElements.toLocaleString()}</span> results
      </p>
      <div className="flex items-center gap-1">
        <button
          onClick={() => onPageChange(page - 1)}
          disabled={page === 0}
          className="p-1.5 rounded-md text-slate-400 hover:text-slate-200 hover:bg-surface-700 disabled:opacity-30 disabled:cursor-not-allowed transition-all"
        >
          <ChevronLeft className="w-4 h-4" />
        </button>
        {Array.from({ length: Math.min(totalPages, 5) }, (_, i) => {
          const pageNum = Math.max(0, page - 2) + i
          if (pageNum >= totalPages) return null
          return (
            <button
              key={pageNum}
              onClick={() => onPageChange(pageNum)}
              className={`w-8 h-8 rounded-md text-xs font-medium transition-all ${
                pageNum === page
                  ? 'bg-brand-500/20 text-brand-400 border border-brand-500/30'
                  : 'text-slate-400 hover:bg-surface-700 hover:text-slate-200'
              }`}
            >
              {pageNum + 1}
            </button>
          )
        })}
        <button
          onClick={() => onPageChange(page + 1)}
          disabled={page >= totalPages - 1}
          className="p-1.5 rounded-md text-slate-400 hover:text-slate-200 hover:bg-surface-700 disabled:opacity-30 disabled:cursor-not-allowed transition-all"
        >
          <ChevronRight className="w-4 h-4" />
        </button>
      </div>
    </div>
  )
}

// ─── Section Header ───────────────────────────────────
export function SectionHeader({ title, subtitle, actions }: {
  title: string; subtitle?: string; actions?: ReactNode
}) {
  return (
    <div className="flex items-start justify-between mb-5">
      <div>
        <h2 className="text-base font-semibold text-slate-100">{title}</h2>
        {subtitle && <p className="text-sm text-slate-500 mt-0.5">{subtitle}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  )
}

// ─── Security Score Ring ──────────────────────────────
export function SecurityScoreRing({ score, size = 120 }: { score: number; size?: number }) {
  const r  = (size - 20) / 2
  const cx = size / 2
  const cy = size / 2
  const circumference = 2 * Math.PI * r
  const offset = circumference - (score / 100) * circumference

  const color =
    score >= 80 ? '#10b981' :
    score >= 60 ? '#f59e0b' :
    score >= 40 ? '#f97316' : '#ef4444'

  return (
    <div className="flex flex-col items-center gap-2">
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="#1e293b" strokeWidth="8" />
        <circle
          cx={cx} cy={cy} r={r} fill="none" stroke={color} strokeWidth="8"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          style={{ transition: 'stroke-dashoffset 1s ease-out' }}
        />
      </svg>
      <div className={`absolute flex flex-col items-center`} style={{ marginTop: -(size / 2 + 16) }}>
        <span className="text-2xl font-bold text-slate-100">{score}</span>
        <span className="text-xs text-slate-500">/100</span>
      </div>
    </div>
  )
}
