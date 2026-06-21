import { Bell, Search, RefreshCw } from 'lucide-react'
import { useAuthStore } from '@/store/auth.store'

interface HeaderProps {
  title: string
  subtitle?: string
  onRefresh?: () => void
  isRefreshing?: boolean
}

export function Header({ title, subtitle, onRefresh, isRefreshing }: HeaderProps) {
  const { user } = useAuthStore()

  return (
    <header className="h-16 border-b border-slate-700/50 bg-surface-900/80 backdrop-blur-sm flex items-center px-6 gap-4 sticky top-0 z-30">
      {/* Page Title */}
      <div className="flex-1">
        <h1 className="text-base font-semibold text-slate-100">{title}</h1>
        {subtitle && <p className="text-xs text-slate-500">{subtitle}</p>}
      </div>

      {/* Search (decorative) */}
      <div className="hidden md:flex items-center gap-2 bg-surface-800 border border-slate-700/50 rounded-lg px-3 py-1.5 w-48">
        <Search className="w-3.5 h-3.5 text-slate-500" />
        <span className="text-xs text-slate-500">Search...</span>
        <kbd className="ml-auto text-xs text-slate-600 bg-surface-700 px-1.5 py-0.5 rounded border border-slate-600">
          ⌘K
        </kbd>
      </div>

      {/* Refresh */}
      {onRefresh && (
        <button
          onClick={onRefresh}
          className="p-2 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-surface-700 transition-all duration-150"
          title="Refresh data"
        >
          <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin' : ''}`} />
        </button>
      )}

      {/* Notifications */}
      <button className="relative p-2 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-surface-700 transition-all duration-150">
        <Bell className="w-4 h-4" />
        <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full ring-1 ring-surface-900" />
      </button>

      {/* Time */}
      <div className="hidden lg:flex flex-col items-end">
        <p className="text-xs text-slate-300 font-medium font-mono">
          {new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })}
        </p>
        <p className="text-xs text-slate-500">
          {new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}
        </p>
      </div>
    </header>
  )
}
